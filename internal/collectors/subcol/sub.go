// Package subcol finds subdomains of a domain through passive sources:
// certificate transparency, search engines, archives and DNS datasets.
// Most sources are subfinder's (MIT), run in-process with Azhaq's limiter
// and keys from a local provider file.
package subcol

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"

	"github.com/trannghiach/azhaq/catalog"
	"github.com/trannghiach/azhaq/internal/limit"
	"github.com/trannghiach/azhaq/internal/normalize"
	"github.com/trannghiach/azhaq/internal/timing"
	"github.com/trannghiach/azhaq/types"
)

const Name = "azhaq-subdomains"

// fanoutTimeout bounds each source for a domain derived from a URL: the
// run is about the application, and crt.sh alone can take 35 s.
var fanoutTimeout = 15 * time.Second

const (
	maxNames = 20000
	// DefaultSourceTimeout bounds each passive source apart from the run's
	// -timeout (-source-timeout): a slow one (crt.sh) is abandoned and
	// listed, retryable and non-fatal while the others answered.
	DefaultSourceTimeout = 60 * time.Second
	// lateGrace is how long after a source's deadline Run still waits for
	// it: some sources ignore the context (subfinder's crt.sh tries a
	// Postgres connection first).
	lateGrace = 2 * time.Second
	// emitGrace is how long before the run's deadline Run stops waiting on
	// sources: the engine drops what a task emits once its context has
	// ended, so what the sources gave by then is emitted while the run is
	// live, as a partial result, not thrown away.
	emitGrace = 5 * time.Second
	maxBody   = 32 << 20
)

func init() {
	// subfinder's sources log through gologger; Azhaq reports per source.
	gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)
}

// Options choose sources and supply keys.
type Options struct {
	Client  *http.Client        // for sources; default: 60 s timeout, proxy from env
	Keys    map[string][]string // per source, from the provider file
	Only    []string            // run only these sources
	Exclude []string            // never run these
	All     bool                // also run sources outside the default set
	// SourceTimeout bounds each source (-source-timeout; default
	// DefaultSourceTimeout). It is not the run's -timeout: a source past it
	// is abandoned and listed as failed, and the others' names are kept.
	SourceTimeout time.Duration
	// Verify returns the names that resolve, not to a wildcard of domain
	// (what is kept of the names only a padding source gave), and how many
	// it could not check (the resolvers failed). Nil keeps them all.
	Verify func(ctx context.Context, domain string, names []string) (live []string, unchecked int)
}

type Collector struct {
	opts    Options
	sources []source
	limiter *limit.Limiter
}

func New(o Options) *Collector {
	if o.Client == nil {
		o.Client = &http.Client{Timeout: 60 * time.Second, Transport: http.DefaultTransport.(*http.Transport).Clone()}
	}
	if o.SourceTimeout <= 0 {
		o.SourceTimeout = DefaultSourceTimeout
	}
	all := allSources()
	l := limit.New(0, 1)
	for _, s := range all {
		if s.perSec > 0 {
			l.Set(s.name, s.perSec)
		}
	}
	return &Collector{opts: o, sources: all, limiter: l}
}

func Register(cat *catalog.Catalog, o Options) {
	cat.MustRegister(New(o))
}

func (c *Collector) Name() string { return Name }

// Info: this collector only asks third parties or DNS resolvers.
func (c *Collector) Info() catalog.Info { return catalog.Info{Kind: catalog.Passive} }

func (c *Collector) Inputs() []types.SeedType { return []types.SeedType{types.TypeDomain} }

func (c *Collector) Outputs() []string { return []string{"subdomains"} }

// Asks names the sources a run asks about a domain.
func (c *Collector) Asks(seed types.Seed) []string {
	domain := normalize.Hostname(seed.Keys["domain"])
	if domain == "" || normalize.SpecialUse(domain) {
		return nil
	}
	run, _ := c.plan()
	out := make([]string, 0, len(run))
	for _, s := range run {
		out = append(out, s.name)
	}
	return out
}

// plan picks the sources for a run and says why the others are left out.
func (c *Collector) plan() (run []source, skipped map[string]string) {
	only := set(c.opts.Only)
	exclude := set(c.opts.Exclude)
	skipped = map[string]string{}
	for _, s := range c.sources {
		switch {
		case exclude[s.name]:
			continue
		case len(only) > 0 && !only[s.name]:
			continue
		case len(only) == 0 && !c.opts.All && !s.deflt:
			continue
		case s.need == requiredKey && len(c.opts.Keys[s.name]) == 0:
			skipped[s.name] = "needs a key"
			continue
		}
		run = append(run, s)
	}
	return run, skipped
}

type outcome struct {
	names []string
	err   error
	took  time.Duration
}

func (c *Collector) Run(ctx context.Context, seed types.Seed, emit func(types.Observation) error) (types.RunMeta, error) {
	domain := normalize.Hostname(seed.Keys["domain"])
	if domain == "" {
		return types.RunMeta{Status: types.StatusError, Error: "empty domain"}, nil
	}
	if normalize.SpecialUse(domain) {
		payload, _ := json.Marshal(map[string]any{"domain": domain, "count": 0, "skipped": "reserved"})
		return types.RunMeta{Status: types.StatusOK, EmitCount: 1}, emit(types.Observation{
			Collector: Name, Source: "subdomains", Kind: "subdomains", Payload: payload, ObservedAt: time.Now().UTC(),
		})
	}
	run, skipped := c.plan()
	ext, err := subscraping.NewSubdomainExtractor(domain)
	if err != nil {
		return types.RunMeta{Status: types.StatusError, Error: err.Error()}, err
	}
	timeout := c.opts.SourceTimeout
	if seed.Derived() && timeout > fanoutTimeout {
		timeout = fanoutTimeout
	}
	// What a source still running is marked with when Run stops waiting.
	errSource := fmt.Errorf("no answer in %s (-source-timeout)", timeout)
	// wait is how long Run waits on the sources: their bound plus a grace
	// for the ones that ignore the context, but never past the run's
	// deadline, less the time to emit what was gathered.
	wait := timeout + lateGrace
	errLate := errSource
	if dl, ok := ctx.Deadline(); ok {
		left := time.Until(dl)
		grace := min(emitGrace, left/4)
		if left-grace < wait {
			wait = max(left-grace, 0)
			errLate = errors.New(types.CutShort)
		}
	}
	results := make([]outcome, len(run))
	var hintMu sync.Mutex
	hinted := map[string]bool{}
	early := true
	// Each source's names go to DNS as soon as it answers.
	finished := false // set once Run stops waiting; late sources are ignored
	pass := func(names []string) {
		hintMu.Lock()
		defer hintMu.Unlock()
		if finished || !early {
			return // nothing listens: the names go in NextHints at the end
		}
		var seeds []types.Seed
		for _, raw := range names {
			if n := clean(raw, domain); n != "" && !hinted[n] && len(hinted) < maxNames {
				hinted[n] = true
				seeds = append(seeds, types.Seed{Type: types.TypeHostname, Keys: map[string]string{"fqdn": n}})
			}
		}
		if early && !catalog.Hint(ctx, seeds...) {
			early = false
			for _, s := range seeds {
				delete(hinted, s.Keys["fqdn"])
			}
		}
	}
	var wg sync.WaitGroup
	reported := make([]bool, len(run))
	for i, s := range run {
		wg.Add(1)
		go func(i int, s source) {
			defer wg.Done()
			sctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			sess := &subscraping.Session{
				Extractor:           ext,
				Client:              c.opts.Client,
				RequestLimiter:      c.limiter,
				Timeout:             int(timeout / time.Second),
				MaxResponseBodySize: maxBody,
			}
			done := timing.Start(ctx, "source."+s.name)
			t0 := time.Now()
			names, err := s.collect(sctx, domain, c.opts.Keys[s.name], sess)
			done()
			if sctx.Err() != nil && ctx.Err() == nil && (err == nil || contextEnded(err)) {
				err = errSource // the names it gave by then are kept
			}
			hintMu.Lock()
			if !finished {
				results[i] = outcome{names: names, err: err, took: time.Since(t0)}
				reported[i] = true
			}
			hintMu.Unlock()
			if !s.verify {
				pass(names) // a padding source's names wait for their check
			}
		}(i, s)
	}
	all := make(chan struct{})
	go func() { wg.Wait(); close(all) }()
	t0 := time.Now()
	timer := time.NewTimer(wait)
	defer timer.Stop()
	// late is what the sources still running are marked with; cut says the
	// run, not a source's bound, stopped the wait: the result is partial.
	late, cut := errSource, false
	select {
	case <-all:
	case <-ctx.Done():
	case <-timer.C:
		late, cut = errLate, errLate != errSource
	}
	if ctx.Err() != nil {
		// Ctrl-C, or the deadline came first: the sources that gave up
		// with the run are not failures of their own.
		late, cut = fmt.Errorf("stopped with the run (%v)", ctx.Err()), true
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			late = errors.New(types.CutShort)
		}
	}
	// The names gathered so far are emitted whatever stopped the wait: a
	// recon tool never throws away work it already did.
	hintMu.Lock()
	finished = true
	partial := false
	for i := range run {
		switch {
		case !reported[i]:
			results[i] = outcome{err: late, took: time.Since(t0)}
			partial = partial || cut
		case ctx.Err() != nil && contextEnded(results[i].err):
			results[i].err = late
			partial = true
		}
	}
	hintMu.Unlock()

	seen := map[string]bool{}
	var names []string
	foundBy := map[string][]string{} // name → the sources that gave it
	status := map[string]any{}
	var failed []string
	for i, s := range run {
		r := results[i]
		row := map[string]any{"count": 0, "seconds": round(r.took.Seconds())}
		n := 0
		mine := map[string]bool{}
		for _, raw := range r.names {
			name := clean(raw, domain)
			if name == "" || mine[name] {
				continue
			}
			mine[name] = true
			n++
			if !seen[name] && len(names) < maxNames {
				seen[name] = true
				names = append(names, name)
			}
			if seen[name] {
				foundBy[name] = append(foundBy[name], s.name)
			}
		}
		row["count"] = n
		if r.err != nil {
			row["error"] = shorten(r.err.Error())
			failed = append(failed, s.name)
		}
		status[s.name] = row
	}
	for name, why := range skipped {
		status[name] = map[string]any{"skipped": why}
	}
	names, foundBy = c.verifyPadded(ctx, domain, run, names, foundBy, status, cut)
	sort.Strings(names)
	for _, by := range foundBy {
		sort.Strings(by)
	}
	payload := map[string]any{"domain": domain, "names": names, "count": len(names), "sources": status, "found_by": foundBy}
	meta := types.RunMeta{Status: types.StatusOK, EmitCount: 1}
	if len(failed) > 0 {
		sort.Strings(failed)
		payload["warning"] = "failed: " + strings.Join(failed, ", ")
		if len(names) == 0 || partial {
			// Nothing found and something broke: not an honest zero. Or
			// the run stopped the wait: what is here is what the sources
			// gave by then, not the whole answer.
			payload["degraded"] = true
			meta.Status = types.StatusDegraded
		}
	}
	if partial {
		payload["partial"] = true
	}
	raw, _ := json.Marshal(payload)
	if err := emit(types.Observation{
		Collector: Name, Source: "subdomains", Kind: "subdomains",
		Payload: raw, Confidence: 0.8, ObservedAt: time.Now().UTC(),
	}); err != nil {
		if ctx.Err() != nil {
			// The engine takes nothing from a task whose run has ended.
			return types.RunMeta{Status: types.StatusCancelled}, ctx.Err()
		}
		return meta, err
	}
	for _, n := range names {
		if !hinted[n] {
			meta.NextHints = append(meta.NextHints, types.Seed{Type: types.TypeHostname, Keys: map[string]string{"fqdn": n}})
		}
	}
	return meta, nil
}

// verifyPadded drops the names only padding sources gave (source.verify)
// that do not resolve, and notes in each such source's status how many it
// kept.
func (c *Collector) verifyPadded(ctx context.Context, domain string, run []source, names []string, foundBy map[string][]string, status map[string]any, cut bool) ([]string, map[string][]string) {
	padding := map[string]bool{}
	for _, s := range run {
		if s.verify {
			padding[s.name] = true
		}
	}
	if len(padding) == 0 || c.opts.Verify == nil {
		return names, foundBy
	}
	var check []string
	for _, n := range names {
		only := true
		for _, by := range foundBy[n] {
			if !padding[by] {
				only = false
				break
			}
		}
		if only {
			check = append(check, n)
		}
	}
	if len(check) == 0 {
		return names, foundBy
	}
	live := map[string]bool{}
	var unchecked int
	// Near the -timeout there is no room for a DNS pass over the padding
	// sources' hundreds of names without blowing the deadline and losing the
	// whole result: drop their unverified names, emit the rest, resume later.
	vctx, skip := ctx, cut
	if dl, ok := ctx.Deadline(); ok {
		if left := time.Until(dl); left < emitGrace {
			skip = true
		} else {
			var cancel context.CancelFunc
			vctx, cancel = context.WithTimeout(ctx, left-emitGrace)
			defer cancel()
		}
	}
	if skip {
		unchecked = len(check)
	} else {
		var got []string
		got, unchecked = c.opts.Verify(vctx, domain, check)
		for _, n := range got {
			live[n] = true
		}
	}
	drop := map[string]bool{}
	for _, n := range check {
		if !live[n] {
			drop[n] = true
			delete(foundBy, n)
		}
	}
	kept := names[:0]
	for _, n := range names {
		if !drop[n] {
			kept = append(kept, n)
		}
	}
	for name := range padding {
		if row, ok := status[name].(map[string]any); ok {
			row["kept"] = len(check) - len(drop)
			row["dropped_unresolved"] = len(drop)
			if unchecked > 0 {
				// Said, not silent: these may hold a real name. azhaq resume
				// checks them.
				why := "the DNS lookups failed"
				if skip {
					why = types.CutShort
				}
				row["error"] = fmt.Sprintf("%d of its names not checked: %s; azhaq resume checks them", unchecked, why)
			}
		}
	}
	return kept, foundBy
}

// clean returns name in canonical form if it is domain or under it.
func clean(name, domain string) string {
	n := normalize.Hostname(strings.TrimPrefix(strings.TrimSpace(name), "*."))
	if n == "" || strings.ContainsAny(n, " /:@*") {
		return ""
	}
	if n != domain && !strings.HasSuffix(n, "."+domain) {
		return ""
	}
	return n
}

func set(xs []string) map[string]bool {
	m := map[string]bool{}
	for _, x := range xs {
		if x = strings.ToLower(strings.TrimSpace(x)); x != "" {
			m[x] = true
		}
	}
	return m
}

func round(f float64) float64 { return float64(int(f*10+0.5)) / 10 }

// contextEnded reports whether err is a context's end, not the source's
// own failure. subfinder's sources join their errors as text.
func contextEnded(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "context canceled") || strings.Contains(s, "context deadline exceeded")
}

func shorten(s string) string {
	if len(s) > 200 {
		return s[:200] + "…"
	}
	return s
}
