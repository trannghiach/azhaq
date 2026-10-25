// Package urlcol lists the URLs archives and scanners have seen for a
// domain and its subdomains: the Wayback Machine, Common Crawl, AlienVault
// OTX, urlscan.io and arquivo.pt. Every URL can go to a file (-urls); the
// graph gets one URL per template, the most telling first.
package urlcol

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/trannghiach/azhaq/catalog"
	"github.com/trannghiach/azhaq/internal/normalize"
	"github.com/trannghiach/azhaq/internal/timing"
	"github.com/trannghiach/azhaq/internal/webextract"
	"github.com/trannghiach/azhaq/types"
)

const Name = "azhaq-urls"

const (
	maxEmit  = 200    // template rows in the graph per domain
	maxHints = 40     // of which fetched when the run is not passive
	maxURLs  = 500000 // kept per domain
)

// Options configure the sources.
type Options struct {
	Client   *http.Client
	Keys     map[string][]string // urlscan's key, from the provider file
	Out      string              // write every URL here, one per line
	Timeout  time.Duration       // per source; default 3 minutes
	MaxPages int                 // per source; default 50
}

type Collector struct {
	opts    Options
	sources []source
	pauses  map[string]time.Duration
	outMu   sync.Mutex
}

func New(o Options) *Collector {
	if o.Client == nil {
		o.Client = &http.Client{Timeout: 60 * time.Second, Transport: http.DefaultTransport.(*http.Transport).Clone()}
	}
	if o.Timeout <= 0 {
		o.Timeout = 3 * time.Minute
	}
	if o.MaxPages <= 0 {
		o.MaxPages = 50
	}
	return &Collector{opts: o, sources: allSources(), pauses: map[string]time.Duration{
		"wayback": time.Second, "commoncrawl": time.Second, "otx": 500 * time.Millisecond, "urlscan": 2 * time.Second,
	}}
}

func (c *Collector) Name() string { return Name }

// Info: this collector only asks third parties.
func (c *Collector) Info() catalog.Info { return catalog.Info{Kind: catalog.Passive} }

func (c *Collector) Inputs() []types.SeedType { return []types.SeedType{types.TypeDomain} }

func (c *Collector) Outputs() []string { return []string{"url"} }

type outcome struct {
	count, pages int
	err          error
	took         time.Duration
}

func (c *Collector) Run(ctx context.Context, seed types.Seed, emit func(types.Observation) error) (types.RunMeta, error) {
	domain := normalize.Hostname(seed.Keys["domain"])
	if domain == "" {
		return types.RunMeta{Status: types.StatusError, Error: "empty domain"}, nil
	}
	if normalize.SpecialUse(domain) {
		payload, _ := json.Marshal(map[string]any{"domain": domain, "count": 0, "skipped": "reserved"})
		return types.RunMeta{Status: types.StatusOK, EmitCount: 1}, emit(types.Observation{
			Collector: Name, Source: "archives", Kind: "urls", Payload: payload, ObservedAt: time.Now().UTC(),
		})
	}

	var mu sync.Mutex
	seen := map[string]bool{}
	var all []string
	results := make([]outcome, len(c.sources))
	var wg sync.WaitGroup
	for i, s := range c.sources {
		wg.Add(1)
		go func(i int, s source) {
			defer wg.Done()
			sctx, cancel := context.WithTimeout(ctx, c.opts.Timeout)
			defer cancel()
			g := &getter{client: c.opts.Client, pause: c.pauses[s.name], maxPages: c.opts.MaxPages, retries: 3}
			key := ""
			if ks := c.opts.Keys[s.name]; len(ks) > 0 {
				key = ks[0]
			}
			count := 0
			add := func(urls []string) {
				mu.Lock()
				defer mu.Unlock()
				for _, raw := range urls {
					u, ok := clean(raw, domain)
					if !ok {
						continue
					}
					count++
					if !seen[u] && len(all) < maxURLs {
						seen[u] = true
						all = append(all, u)
					}
				}
			}
			done := timing.Start(ctx, "urls."+s.name)
			t0 := time.Now()
			pages, err := s.fetch(sctx, g, domain, key, add)
			done()
			if err == nil && sctx.Err() != nil && ctx.Err() == nil {
				err = sctx.Err()
			}
			mu.Lock()
			results[i] = outcome{count: count, pages: pages, err: err, took: time.Since(t0)}
			mu.Unlock()
		}(i, s)
	}
	wg.Wait()
	if ctx.Err() != nil {
		return types.RunMeta{Status: types.StatusCancelled}, ctx.Err()
	}
	sort.Strings(all)
	if err := c.write(all); err != nil {
		return types.RunMeta{Status: types.StatusError, Error: err.Error()}, err
	}

	status := map[string]any{}
	var failed []string
	for i, s := range c.sources {
		r := results[i]
		row := map[string]any{"count": r.count, "pages": r.pages, "seconds": float64(r.took.Milliseconds()/100) / 10}
		if r.err != nil {
			row["error"] = shorten(r.err.Error())
			failed = append(failed, s.name)
		}
		status[s.name] = row
	}
	tmpl, assets := templates(all)
	payload := map[string]any{"domain": domain, "count": len(all), "templates": len(tmpl), "assets": assets, "sources": status}
	if c.opts.Out != "" {
		payload["file"] = c.opts.Out
	}
	meta := types.RunMeta{Status: types.StatusOK, EmitCount: 1}
	if len(failed) > 0 {
		sort.Strings(failed)
		payload["warning"] = "failed: " + strings.Join(failed, ", ")
		// A refused archive may hold URLs the others lack.
		payload["degraded"] = true
		meta.Status = types.StatusDegraded
	}
	raw, _ := json.Marshal(payload)
	if err := emit(types.Observation{
		Collector: Name, Source: "archives", Kind: "urls", Payload: raw, Confidence: 0.7, ObservedAt: time.Now().UTC(),
	}); err != nil {
		return meta, err
	}
	for i, t := range rank(tmpl) {
		if i >= maxEmit {
			break
		}
		row := map[string]any{"url": t.example, "via": "archive", "count": t.count}
		if t.count > 1 {
			row["template"] = t.key
		}
		raw, _ := json.Marshal(row)
		if err := emit(types.Observation{
			Collector: Name, Source: "archives", Kind: "url", Payload: raw, Confidence: 0.6, ObservedAt: time.Now().UTC(),
		}); err != nil {
			return meta, err
		}
		meta.EmitCount++
		if len(meta.NextHints) < maxHints && webextract.Hintable(t.example) {
			meta.NextHints = append(meta.NextHints, types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": t.example}})
		}
	}
	return meta, nil
}

// clean keeps http(s) URLs on domain or its subdomains, normalized.
func clean(raw, domain string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
		return "", false
	}
	u, err := normalize.URL(raw)
	if err != nil {
		return "", false
	}
	host := normalize.HostFromURL(u)
	if host != domain && !strings.HasSuffix(host, "."+domain) {
		return "", false
	}
	return u, true
}

type template struct {
	key, example string
	count        int
	score        int
}

// templates groups URLs that differ only by an ID or a value; static
// assets are counted and left out.
func templates(urls []string) ([]template, int) {
	idx := map[string]int{}
	var out []template
	assets := 0
	for _, u := range urls {
		if webextract.ClassifyURL(u) == "asset" {
			assets++
			continue
		}
		k := webextract.Template(u)
		if i, ok := idx[k]; ok {
			out[i].count++
			continue
		}
		idx[k] = len(out)
		out = append(out, template{key: k, example: u, count: 1, score: score(u)})
	}
	return out, assets
}

// score ranks what is worth a look: parameters, APIs and server-side
// pages before plain pages.
func score(u string) int {
	s := 0
	if strings.Contains(u, "?") {
		s += 2
	}
	if webextract.ClassifyURL(u) == "api" {
		s += 2
	}
	p := strings.ToLower(strings.SplitN(u, "?", 2)[0])
	for _, ext := range []string{".php", ".asp", ".aspx", ".jsp", ".do", ".action", ".cgi", ".json", ".xml"} {
		if strings.HasSuffix(p, ext) {
			s++
			break
		}
	}
	return s
}

func rank(ts []template) []template {
	out := append([]template(nil), ts...)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].score != out[j].score {
			return out[i].score > out[j].score
		}
		if out[i].count != out[j].count {
			return out[i].count > out[j].count
		}
		return out[i].key < out[j].key
	})
	return out
}

// write appends urls to the -urls file.
func (c *Collector) write(urls []string) error {
	if c.opts.Out == "" || len(urls) == 0 {
		return nil
	}
	c.outMu.Lock()
	defer c.outMu.Unlock()
	f, err := os.OpenFile(c.opts.Out, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	w := bufio.NewWriter(f)
	for _, u := range urls {
		w.WriteString(u)
		w.WriteByte('\n')
	}
	if err := w.Flush(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func shorten(s string) string {
	if len(s) > 200 {
		return s[:200] + "…"
	}
	return s
}
