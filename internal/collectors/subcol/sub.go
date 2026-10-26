// Package subcol finds subdomains of a domain through passive sources:
// certificate transparency, search engines, archives and DNS datasets.
// Most sources are subfinder's (MIT), run in-process with Azhaq's limiter
// and keys from a local provider file.
package subcol

import (
	"context"
	"encoding/json"
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
	maxNames      = 20000
	sourceTimeout = 45 * time.Second
	maxBody       = 32 << 20
)

func init() {
	// subfinder's sources log through gologger; Azhaq reports per source.
	gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)
}

// Options choose sources and supply keys.
type Options struct {
	Client  *http.Client        // for sources; default: 30 s timeout, proxy from env
	Keys    map[string][]string // per source, from the provider file
	Only    []string            // run only these sources
	Exclude []string            // never run these
	All     bool                // also run sources outside the default set
	Timeout time.Duration       // per source
}

type Collector struct {
	opts    Options
	sources []source
	limiter *limit.Limiter
}

func New(o Options) *Collector {
	if o.Client == nil {
		o.Client = &http.Client{Timeout: 30 * time.Second, Transport: http.DefaultTransport.(*http.Transport).Clone()}
	}
	if o.Timeout <= 0 {
		o.Timeout = sourceTimeout
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
	timeout := c.opts.Timeout
	if seed.Derived() && timeout > fanoutTimeout {
		timeout = fanoutTimeout
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
		if finished {
			return
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
			if err == nil && sctx.Err() != nil && ctx.Err() == nil {
				err = sctx.Err()
			}
			hintMu.Lock()
			if !finished {
				results[i] = outcome{names: names, err: err, took: time.Since(t0)}
				reported[i] = true
			}
			hintMu.Unlock()
			pass(names)
		}(i, s)
	}
	// Some sources ignore the context (subfinder's crt.sh tries a Postgres
	// connection first); stop waiting a little after the deadline.
	all := make(chan struct{})
	go func() { wg.Wait(); close(all) }()
	t0 := time.Now()
	select {
	case <-all:
	case <-ctx.Done():
	case <-time.After(timeout + 2*time.Second):
	}
	hintMu.Lock()
	finished = true
	for i := range run {
		if !reported[i] {
			results[i] = outcome{err: context.DeadlineExceeded, took: time.Since(t0)}
		}
	}
	hintMu.Unlock()
	if ctx.Err() != nil {
		return types.RunMeta{Status: types.StatusCancelled}, ctx.Err()
	}

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
	sort.Strings(names)
	for _, by := range foundBy {
		sort.Strings(by)
	}
	payload := map[string]any{"domain": domain, "names": names, "count": len(names), "sources": status, "found_by": foundBy}
	meta := types.RunMeta{Status: types.StatusOK, EmitCount: 1}
	if len(failed) > 0 {
		sort.Strings(failed)
		payload["warning"] = "failed: " + strings.Join(failed, ", ")
		if len(names) == 0 {
			// Nothing found and something broke: not an honest zero.
			payload["degraded"] = true
			meta.Status = types.StatusDegraded
		}
	}
	raw, _ := json.Marshal(payload)
	if err := emit(types.Observation{
		Collector: Name, Source: "subdomains", Kind: "subdomains",
		Payload: raw, Confidence: 0.8, ObservedAt: time.Now().UTC(),
	}); err != nil {
		return meta, err
	}
	for _, n := range names {
		if !hinted[n] {
			meta.NextHints = append(meta.NextHints, types.Seed{Type: types.TypeHostname, Keys: map[string]string{"fqdn": n}})
		}
	}
	return meta, nil
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

func shorten(s string) string {
	if len(s) > 200 {
		return s[:200] + "…"
	}
	return s
}
