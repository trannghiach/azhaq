// Package engine runs collectors over seeds: it schedules work within
// budgets and scope, writes observations into the store, turns hints into
// new seeds and builds the map of a run.
package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/trannghiach/azhaq/catalog"
	"github.com/trannghiach/azhaq/internal/normalize"
	"github.com/trannghiach/azhaq/internal/timing"
	"github.com/trannghiach/azhaq/store"
	"github.com/trannghiach/azhaq/types"
)

type Engine struct {
	Cat   *catalog.Catalog
	Store *store.Store
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
		if _, err := e.Store.AddObservation(ent.ID, o); err != nil {
			return err
		}
		e.linkFacts(ent, o, time.Now().UTC())
		meta.EmitCount++
		return nil
	}

	done := timing.Start(ctx, col.Name(), seed.Key())
	got, err := col.Run(ctx, seed, emit)
	done()
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
	emit := func(seed types.Seed, o types.Observation) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
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
		return nil
	}
	done := timing.Start(ctx, name, fmt.Sprintf("%d seeds", len(todo)))
	metas, err := b.RunBatch(ctx, todo, emit)
	done()
	if ctx.Err() != nil {
		return nil, ctx.Err()
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
}

func (e *Engine) linkFoundURL(from types.Entity, o types.Observation, now time.Time) {
	if o.Kind != "url" {
		return
	}
	var p struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(o.Payload, &p); err != nil || p.URL == "" {
		return
	}
	u, err := normalize.URL(p.URL)
	if err != nil {
		return
	}
	to, err := e.Store.UpsertEntity(types.TypeURL, u, now)
	if err != nil {
		return
	}
	_ = e.Store.AddEdge(from.ID, to.ID, "FOUND", now)
	if host := normalize.HostFromURL(u); host != "" {
		if ip := net.ParseIP(host); ip != nil {
			h, err := e.Store.UpsertEntity(types.TypeIPAddress, ip.String(), now)
			if err == nil {
				_ = e.Store.AddEdge(to.ID, h.ID, "ON_HOST", now)
			}
			return
		}
		h, err := e.Store.UpsertEntity(types.TypeHostname, host, now)
		if err == nil {
			_ = e.Store.AddEdge(to.ID, h.ID, "ON_HOST", now)
		}
	}
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
			out = append(out, types.Seed{Type: types.TypeHostname, Keys: map[string]string{"fqdn": host}})
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
	if d := normalize.RegistrableDomain(host); d != "" {
		out = append(out, types.Seed{Type: types.TypeDomain, Keys: map[string]string{"domain": d, types.DerivedKey: "1"}})
	}
	return out
}

func workID(collector string, s types.Seed) string {
	sum := sha256.Sum256([]byte(collector + "\x00" + string(s.Type) + "\x00" + s.Key()))
	return hex.EncodeToString(sum[:16])
}
