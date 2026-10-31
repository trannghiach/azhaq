// Package engine runs collectors over seeds: it schedules work within
// budgets and scope, writes observations into the store, turns hints into
// new seeds and builds the map of a run.
package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/trannghiach/azhaq/catalog"
	"github.com/trannghiach/azhaq/internal/egress"
	"github.com/trannghiach/azhaq/internal/ledger"
	"github.com/trannghiach/azhaq/internal/neterr"
	"github.com/trannghiach/azhaq/internal/normalize"
	"github.com/trannghiach/azhaq/internal/timing"
	"github.com/trannghiach/azhaq/internal/webextract"
	"github.com/trannghiach/azhaq/store"
	"github.com/trannghiach/azhaq/types"
)

type Engine struct {
	Cat   *catalog.Catalog
	Store *store.Store
	// Workers, when set, hands tasks to other processes (azhaq worker).
	Workers *Workers
	// Observe, when set, sees every observation once it is stored, from
	// any goroutine: commands print results as they come.
	Observe func(ent types.Entity, o types.Observation)
	// Client is what the engine's own request goes with (whether
	// http://host/ is the https site, see scheme.go); nil is fetch's.
	Client *http.Client

	secured sync.Map // hosts whose http URLs are the https site's (scheme.go)
	recent  sync.Map // entities upserted a moment ago (upsertRecent)
	denied  sync.Map // URLs a -deny-path rule kept out, noted once
}

func (e *Engine) Plan(seeds []types.Seed) []types.WorkItem {
	var items []types.WorkItem
	for _, raw := range seeds {
		s := normalize.Seed(raw)
		if s.Key() == "" {
			continue
		}
		for _, col := range e.Cat.Where(s.Type) {
			items = append(items, types.WorkItem{
				ID:        workID(col.Name(), s),
				Collector: col.Name(),
				Seed:      s,
			})
		}
	}
	return items
}

func (e *Engine) Run(ctx context.Context, item types.WorkItem) (types.RunMeta, error) {
	col, ok := e.Cat.Get(item.Collector)
	if !ok {
		return types.RunMeta{ItemID: item.ID, Status: types.StatusError, Error: "unknown collector"}, fmt.Errorf("unknown collector %q", item.Collector)
	}
	seed := normalize.Seed(item.Seed)
	idKey := workID(col.Name(), seed)
	seen, err := e.Store.Seen(idKey)
	if err != nil {
		return types.RunMeta{ItemID: item.ID, Status: types.StatusError, Error: err.Error()}, err
	}
	if seen {
		return types.RunMeta{ItemID: item.ID, Status: types.StatusOK}, nil
	}

	now := time.Now().UTC()
	ent, err := e.Store.UpsertEntity(seed.Type, seed.Key(), now)
	if err != nil {
		return types.RunMeta{ItemID: item.ID, Status: types.StatusError, Error: err.Error()}, err
	}
	e.linkSeed(seed, ent, now)
	e.linkInDomain(seed, ent, now)

	meta := types.RunMeta{ItemID: item.ID, Status: types.StatusOK}
	// Observations and their links go in one transaction: a sweep with
	// thousands of hits spent most of its time committing.
	writeMany := func(obs []types.Observation) (err error) {
		e.Store.Batch(func() {
			if len(obs) > 1 {
				if err = e.Store.AddObservations(ent.ID, obs); err != nil {
					return
				}
				e.linkFactsMany(ent, obs, time.Now().UTC())
				if e.Observe != nil {
					for _, o := range obs {
						e.Observe(ent, o)
					}
				}
				return
			}
			for _, o := range obs {
				if _, err = e.Store.AddObservation(ent.ID, o); err != nil {
					return
				}
				e.linkFacts(ent, o, time.Now().UTC())
				if e.Observe != nil {
					e.Observe(ent, o)
				}
			}
		})
		return err
	}
	write := func(o types.Observation) error { return writeMany([]types.Observation{o}) }
	// Under a request budget, what a task reports is held until it ends: a
	// refused request can pass for a missing page (a catch-all check that
	// never ran), so the reports of a task the budget stopped are dropped
	// and its run after azhaq resume reports again.
	var mu sync.Mutex
	var held []types.Observation
	hold := egress.MaxRequests() > 0
	if s, ok := col.(catalog.Standing); ok && s.Standing() {
		hold = false
	}
	emit := func(o types.Observation) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if o.ObservedAt.IsZero() {
			o.ObservedAt = time.Now().UTC()
		}
		if o.Collector == "" {
			o.Collector = col.Name()
		}
		mu.Lock()
		defer mu.Unlock()
		meta.EmitCount++
		if hold {
			held = append(held, o)
			return nil
		}
		return write(o)
	}
	emitMany := func(obs []types.Observation) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		mu.Lock()
		defer mu.Unlock()
		for i := range obs {
			if obs[i].ObservedAt.IsZero() {
				obs[i].ObservedAt = time.Now().UTC()
			}
			if obs[i].Collector == "" {
				obs[i].Collector = col.Name()
			}
			meta.EmitCount++
		}
		if hold {
			held = append(held, obs...)
			return nil
		}
		return writeMany(obs)
	}
	release := func() error {
		mu.Lock()
		defer mu.Unlock()
		if err := writeMany(held); err != nil {
			return err
		}
		held = nil
		return nil
	}

	done := timing.Start(ctx, col.Name(), seed.Key())
	ctx, refused, used := egress.WatchBudget(ledger.WithCollector(ctx, col.Name()))
	got, err := col.Run(types.WithBatchEmit(ctx, emitMany), seed, emit)
	done()
	if errors.Is(err, neterr.ErrBudget) || refused() {
		// Not done, whatever the collector made of the refusal: nothing
		// waiting on it is dropped, and azhaq resume runs it again.
		meta.Status, meta.Error, meta.Drop = types.StatusCapped, neterr.ErrBudget.Error(), false
		meta.Requests, meta.EmitCount = used(), 0
		var keep []types.Observation
		for _, o := range held {
			if o.Keep {
				keep = append(keep, o)
			}
		}
		if err := writeMany(keep); err != nil {
			return meta, err
		}
		e.markCapped()
		return meta, neterr.ErrBudget
	}
	if down := egress.Stopped(ctx); down != nil {
		// Its origin stopped answering: not done either, listed as left
		// alone with the reason, and azhaq resume tries it again.
		meta.Status, meta.Error, meta.Drop = types.StatusCapped, down.Error(), false
		meta.Requests, meta.EmitCount = used(), 0
		e.noteError(ent.ID, col.Name(), down)
		e.markCapped()
		return meta, down
	}
	if err := release(); err != nil {
		return types.RunMeta{ItemID: item.ID, Status: types.StatusError, Error: err.Error()}, err
	}
	if ctx.Err() != nil {
		meta.Status = types.StatusCancelled
		meta.Error = ctx.Err().Error()
		return meta, ctx.Err()
	}
	meta.Drop = got.Drop
	if err != nil {
		meta.Status = types.StatusError
		meta.Error = err.Error()
		e.noteError(ent.ID, col.Name(), err)
		_ = e.Store.MarkSeen(idKey)
		return meta, err
	}
	if got.Status != "" {
		meta.Status = got.Status
	}
	meta.NextHints = append(got.NextHints, derivedSeeds(seed)...)
	if err := e.Store.MarkSeen(idKey); err != nil {
		return meta, err
	}
	return meta, nil
}

// BatchResult is the outcome of one seed inside a batch.
type BatchResult struct {
	Seed types.Seed
	Meta types.RunMeta
}

// RunBatch runs seeds through a Batcher in one call. Each seed keeps its own
// idempotency key, entity, observations and hints, exactly as Run would give
// it; seeds that already ran are left out of the call.
func (e *Engine) RunBatch(ctx context.Context, name string, seeds []types.Seed) ([]BatchResult, error) {
	col, ok := e.Cat.Get(name)
	if !ok {
		return nil, fmt.Errorf("unknown collector %q", name)
	}
	b, ok := col.(catalog.Batcher)
	if !ok {
		return nil, fmt.Errorf("collector %q does not run batches", name)
	}
	now := time.Now().UTC()
	ents := map[string]types.Entity{}
	var todo []types.Seed
	for _, raw := range seeds {
		seed := normalize.Seed(raw)
		k := seedKey(seed)
		if _, dup := ents[k]; dup || seed.Key() == "" {
			continue
		}
		seen, err := e.Store.Seen(workID(name, seed))
		if err != nil {
			return nil, err
		}
		if seen {
			continue
		}
		ent, err := e.Store.UpsertEntity(seed.Type, seed.Key(), now)
		if err != nil {
			return nil, err
		}
		e.linkSeed(seed, ent, now)
		e.linkInDomain(seed, ent, now)
		ents[k] = ent
		todo = append(todo, seed)
	}
	if len(todo) == 0 {
		return nil, nil
	}
	// A stop does not refuse what a batch already has: the names answered
	// before it are kept, and the collector leaves out the rest.
	emit := func(seed types.Seed, o types.Observation) error {
		ent, ok := ents[seedKey(normalize.Seed(seed))]
		if !ok {
			return fmt.Errorf("%s: observation for a seed outside the batch: %s", name, seed.Key())
		}
		if o.ObservedAt.IsZero() {
			o.ObservedAt = time.Now().UTC()
		}
		if o.Collector == "" {
			o.Collector = name
		}
		if _, err := e.Store.AddObservation(ent.ID, o); err != nil {
			return err
		}
		e.linkFacts(ent, o, time.Now().UTC())
		if e.Observe != nil {
			e.Observe(ent, o)
		}
		return nil
	}
	done := timing.Start(ctx, name, fmt.Sprintf("%d seeds", len(todo)))
	metas, err := b.RunBatch(ctx, todo, emit)
	done()
	stopped := ctx.Err() != nil
	if stopped && (err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) {
		err = nil
	}
	out := make([]BatchResult, 0, len(todo))
	for i, seed := range todo {
		var m types.RunMeta
		if i < len(metas) {
			m = metas[i]
		}
		if m.Status == "" {
			m.Status = types.StatusOK
		}
		if stopped && (m.Status != types.StatusOK || m.EmitCount == 0) {
			continue // not answered before the stop: azhaq resume asks it
		}
		if err != nil {
			m.Status = types.StatusError
			m.Error = err.Error()
			e.noteError(ents[seedKey(seed)].ID, name, err)
		} else {
			m.NextHints = append(m.NextHints, derivedSeeds(seed)...)
		}
		_ = e.Store.MarkSeen(workID(name, seed))
		out = append(out, BatchResult{Seed: seed, Meta: m})
	}
	return out, err
}

func (e *Engine) linkFacts(from types.Entity, o types.Observation, now time.Time) {
	e.linkFoundURL(from, o, now)
	e.linkDNS(from, o, now)
	e.linkNames(from, o, now)
}

// linkNames keeps every name a subdomain source gave as an entity, found
// by its domain, whether or not the run goes on to resolve it.
func (e *Engine) linkNames(from types.Entity, o types.Observation, now time.Time) {
	if o.Kind != "subdomains" {
		return
	}
	var p struct {
		Names []string `json:"names"`
	}
	if json.Unmarshal(o.Payload, &p) != nil || len(p.Names) == 0 {
		return
	}
	_ = e.Store.UpsertMany(types.TypeHostname, p.Names, now, from.ID, "FOUND")
}

func (e *Engine) linkFoundURL(from types.Entity, o types.Observation, now time.Time) {
	u, ok := e.foundTarget(o)
	if !ok {
		return
	}
	var p struct {
		From string `json:"from"`
	}
	_ = json.Unmarshal(o.Payload, &p)
	to, err := e.Store.UpsertEntity(types.TypeURL, u, now)
	if err != nil {
		return
	}
	// A route a script on another host names is found by that script.
	if f, err := normalize.URL(p.From); err == nil && p.From != "" && f != u {
		if s, err := e.Store.UpsertEntity(types.TypeURL, e.onHTTPS(f), now); err == nil {
			from = s
		}
	}
	_ = e.Store.AddEdge(from.ID, to.ID, "FOUND", now)
	if host, ip := hostOf(u); host != "" {
		if ip {
			h, err := e.Store.UpsertEntity(types.TypeIPAddress, host, now)
			if err == nil {
				_ = e.Store.AddEdge(to.ID, h.ID, "ON_HOST", now)
			}
			return
		}
		h, err := e.upsertRecent(types.TypeHostname, host, now)
		if err == nil {
			_ = e.Store.AddEdge(to.ID, h.ID, "ON_HOST", now)
		}
	}
}

// foundTarget is the URL a "url" observation names, as the map keeps it.
func (e *Engine) foundTarget(o types.Observation) (string, bool) {
	if o.Kind != "url" {
		return "", false
	}
	var p struct {
		URL  string `json:"url"`
		Role string `json:"role"`
	}
	if err := json.Unmarshal(o.Payload, &p); err != nil || p.URL == "" {
		return "", false
	}
	u, err := FoundKey(p.URL, p.Role)
	if err != nil || webextract.JunkURL(u) {
		return "", false
	}
	base, frag, _ := strings.Cut(u, "#")
	u = e.onHTTPS(base)
	if frag != "" {
		u += "#" + frag
	}
	return u, true
}

// hostOf is the host of a URL, and whether it is an IP address.
func hostOf(u string) (string, bool) {
	host := normalize.HostFromURL(u)
	if ip := net.ParseIP(host); ip != nil {
		return ip.String(), true
	}
	return host, false
}

// linkFactsMany is linkFacts for the observations of one entity written
// together; the URLs a sweep found are linked a statement for all of them,
// not a few for each.
func (e *Engine) linkFactsMany(from types.Entity, obs []types.Observation, now time.Time) {
	var urls, hosts, ips []string
	var edges []store.Edge
	seenHost := map[string]bool{}
	for _, o := range obs {
		var p struct {
			From string `json:"from"`
		}
		u, ok := e.foundTarget(o)
		if ok {
			_ = json.Unmarshal(o.Payload, &p)
		}
		if !ok || p.From != "" {
			e.linkFacts(from, o, now)
			continue
		}
		urls = append(urls, u)
		edges = append(edges, store.Edge{From: from.ID, To: store.EntityID(types.TypeURL, u), Type: "FOUND"})
		if host, ip := hostOf(u); host != "" {
			t := types.TypeHostname
			if ip {
				t = types.TypeIPAddress
			}
			edges = append(edges, store.Edge{From: store.EntityID(types.TypeURL, u), To: store.EntityID(t, host), Type: "ON_HOST"})
			if !seenHost[host] {
				seenHost[host] = true
				if ip {
					ips = append(ips, host)
				} else {
					hosts = append(hosts, host)
				}
			}
		}
	}
	if len(urls) == 0 {
		return
	}
	_ = e.Store.UpsertEntities(types.TypeURL, urls, now)
	for _, h := range hosts {
		_, _ = e.upsertRecent(types.TypeHostname, h, now)
	}
	_ = e.Store.UpsertEntities(types.TypeIPAddress, ips, now)
	_ = e.Store.AddEdges(edges, now)
}

// upsertRecent is UpsertEntity, except that an entity upserted a moment ago
// is not upserted again: a sweep's thousands of hits name the same host.
func (e *Engine) upsertRecent(t types.SeedType, key string, now time.Time) (types.Entity, error) {
	k := string(t) + " " + key
	if at, ok := e.recent.Load(k); ok && now.Sub(at.(time.Time)) < 2*time.Second {
		return types.Entity{ID: store.EntityID(t, key), Type: t, Key: key, FirstSeen: now, LastSeen: now}, nil
	}
	ent, err := e.Store.UpsertEntity(t, key, now)
	if err == nil {
		e.recent.Store(k, now)
	}
	return ent, err
}

func (e *Engine) linkDNS(from types.Entity, o types.Observation, now time.Time) {
	if o.Kind != "dns" {
		return
	}
	var p struct {
		IPs   []string `json:"ips"`
		CNAME string   `json:"cname"`
	}
	if err := json.Unmarshal(o.Payload, &p); err != nil {
		return
	}
	host := from.Key
	for _, raw := range p.IPs {
		ip := net.ParseIP(strings.TrimSpace(raw))
		if ip == nil {
			continue
		}
		key := ip.String()
		to, err := e.Store.UpsertEntity(types.TypeIPAddress, key, now)
		if err != nil {
			continue
		}
		_ = e.Store.AddEdge(from.ID, to.ID, "RESOLVES_TO", now)
	}
	cname := normalize.Hostname(p.CNAME)
	if cname == "" || cname == host || !normalize.SameSite(host, cname) {
		return
	}
	to, err := e.Store.UpsertEntity(types.TypeHostname, cname, now)
	if err != nil {
		return
	}
	_ = e.Store.AddEdge(from.ID, to.ID, "CNAME", now)
	e.linkInDomain(types.Seed{Type: types.TypeHostname, Keys: map[string]string{"fqdn": cname}}, to, now)
}

func (e *Engine) linkSeed(seed types.Seed, ent types.Entity, now time.Time) {
	if seed.Type != types.TypeURL {
		return
	}
	host := normalize.HostFromURL(seed.Key())
	if host == "" {
		return
	}
	if ip := net.ParseIP(host); ip != nil {
		h, err := e.Store.UpsertEntity(types.TypeIPAddress, ip.String(), now)
		if err != nil {
			return
		}
		_ = e.Store.AddEdge(ent.ID, h.ID, "ON_HOST", now)
		return
	}
	h, err := e.Store.UpsertEntity(types.TypeHostname, host, now)
	if err != nil {
		return
	}
	_ = e.Store.AddEdge(ent.ID, h.ID, "ON_HOST", now)
	e.linkInDomain(types.Seed{Type: types.TypeHostname, Keys: map[string]string{"fqdn": host}}, h, now)
}

// NoteExternalError records a connector/CLI failure on the first seed so
// Summary errors= counts it even when native collectors still run.
func (e *Engine) NoteExternalError(seeds []types.Seed, collector string, err error) error {
	if e == nil || e.Store == nil || err == nil {
		return nil
	}
	now := time.Now().UTC()
	targets := ExpandSeeds(seeds)
	if len(targets) == 0 {
		targets = []types.Seed{{Type: types.TypeOrganization, Keys: map[string]string{"name": collector}}}
	}
	s := normalize.Seed(targets[0])
	if s.Key() == "" {
		s = types.Seed{Type: types.TypeOrganization, Keys: map[string]string{"name": collector}}
	}
	ent, e2 := e.Store.UpsertEntity(s.Type, s.Key(), now)
	if e2 != nil {
		return e2
	}
	e.noteError(ent.ID, collector, err)
	return nil
}

// noteDenied records a URL a -deny-path rule kept out of the run.
func (e *Engine) noteDenied(raw, rule string) {
	if e == nil || e.Store == nil {
		return
	}
	if n, err := normalize.URL(raw); err == nil {
		raw = n
	}
	if _, dup := e.denied.LoadOrStore(raw, true); dup {
		return
	}
	e.noteSkip(types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": raw}}, egress.DenyReason(rule))
}

// noteSkip records a URL the run found and did not request, and why.
func (e *Engine) noteSkip(seed types.Seed, reason string) {
	if e == nil || e.Store == nil {
		return
	}
	now := time.Now().UTC()
	ent, err := e.Store.UpsertEntity(seed.Type, seed.Key(), now)
	if err != nil {
		return
	}
	payload, _ := json.Marshal(map[string]string{"skipped": reason})
	_, _ = e.Store.AddObservation(ent.ID, types.Observation{
		Collector: "azhaq-http", Source: "run", Kind: "skipped", Payload: payload, ObservedAt: now,
	})
}

func (e *Engine) noteError(entityID, collector string, err error) {
	if err == nil {
		return
	}
	payload, _ := json.Marshal(map[string]string{"error": err.Error(), "collector": collector})
	_, _ = e.Store.AddObservation(entityID, types.Observation{
		Collector:  collector,
		Source:     "run",
		Kind:       "error",
		Payload:    payload,
		Confidence: 0,
		ObservedAt: time.Now().UTC(),
	})
}

func (e *Engine) linkInDomain(seed types.Seed, ent types.Entity, now time.Time) {
	host := ""
	switch seed.Type {
	case types.TypeHostname:
		host = seed.Key()
	case types.TypeURL:
		host = normalize.HostFromURL(seed.Key())
	default:
		return
	}
	d := normalize.RegistrableDomain(host)
	if d == "" {
		return
	}
	de, err := e.Store.UpsertEntity(types.TypeDomain, d, now)
	if err != nil {
		return
	}
	_ = e.Store.AddEdge(ent.ID, de.ID, "IN_DOMAIN", now)
}

func derivedSeeds(seed types.Seed) []types.Seed {
	var out []types.Seed
	host := ""
	switch seed.Type {
	case types.TypeURL:
		host = normalize.HostFromURL(seed.Key())
		if host != "" && net.ParseIP(host) == nil {
			out = append(out, types.Seed{Type: types.TypeHostname, Keys: map[string]string{"fqdn": host, types.FromURLKey: seed.Key()}})
		}
		if ip := net.ParseIP(host); ip != nil {
			out = append(out, types.Seed{Type: types.TypeIPAddress, Keys: map[string]string{"ip": ip.String()}})
		}
	case types.TypeHostname:
		if seed.Keys["from"] == "prefix" {
			// Found by network (reverse DNS, an address's certificate): a
			// neighbour on shared hosting, perhaps. Its domain is not
			// enumerated unless asked with -domain.
			return out
		}
		host = seed.Key()
	}
	if d := normalize.RegistrableDomain(host); d != "" && !normalize.Tenant(host) {
		out = append(out, types.Seed{Type: types.TypeDomain, Keys: map[string]string{"domain": d, types.DerivedKey: "1"}})
	}
	return out
}

func workID(collector string, s types.Seed) string {
	sum := sha256.Sum256([]byte(collector + "\x00" + string(s.Type) + "\x00" + s.Key()))
	return hex.EncodeToString(sum[:16])
}
