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
	"net/url"
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
		// A Wayback page of a large domain is tens of MB and takes minutes.
		o.Client = &http.Client{Timeout: 5 * time.Minute, Transport: http.DefaultTransport.(*http.Transport).Clone()}
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

// Asks names the archives a run asks about a domain: every one, keyed or
// not.
func (c *Collector) Asks(seed types.Seed) []string {
	domain := normalize.Hostname(seed.Keys["domain"])
	if domain == "" || normalize.SpecialUse(domain) {
		return nil
	}
	out := make([]string, 0, len(c.sources))
	for _, s := range c.sources {
		out = append(out, s.name)
	}
	return out
}

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

	// A domain derived from a URL gets 15 s per source: the run is about
	// the application.
	timeout := c.opts.Timeout
	if seed.Derived() && timeout > 15*time.Second {
		timeout = 15 * time.Second
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
			sctx, cancel := context.WithTimeout(ctx, timeout)
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
	nAssets := 0
	for _, t := range assets {
		nAssets += t.count
	}
	payload := map[string]any{"domain": domain, "count": len(all), "templates": len(tmpl), "assets": nAssets, "sources": status}
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
	// Pages first; the static assets an archive holds are listed after
	// them, as hints only: an image or a font is never worth a request.
	for i, t := range append(rank(tmpl), rank(assets)...) {
		if i >= maxEmit {
			break
		}
		row := map[string]any{"url": t.example, "via": "archive", "count": t.count}
		if t.count > 1 {
			row["template"] = t.key
		}
		if t.asset {
			row["asset"] = true
		}
		raw, _ := json.Marshal(row)
		if err := emit(types.Observation{
			Collector: Name, Source: "archives", Kind: "url", Payload: raw, Confidence: 0.6, ObservedAt: time.Now().UTC(),
		}); err != nil {
			return meta, err
		}
		meta.EmitCount++
		if !t.asset && len(meta.NextHints) < maxHints && webextract.Hintable(t.example) {
			meta.NextHints = append(meta.NextHints, types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": t.example, types.ViaKey: types.ViaArchive}})
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
	if err != nil || webextract.JunkURL(u) {
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
	asset        bool // a static file: listed, never requested
}

// templates groups URLs that differ only by an ID or a value: pages, and
// the static assets apart.
func templates(urls []string) (pages, assets []template) {
	idx := map[string]int{}
	var out []template
	for _, u := range urls {
		k := webextract.Template(u)
		if i, ok := idx[k]; ok {
			out[i].count++
			continue
		}
		idx[k] = len(out)
		out = append(out, template{key: k, example: u, count: 1, score: score(u), asset: static(u)})
	}
	for _, t := range out {
		if t.asset {
			assets = append(assets, t)
		} else {
			pages = append(pages, t)
		}
	}
	return pages, assets
}

// mediaHosts are the words in a hostname that say it serves files, not
// pages: an archive's URLs on such a host are images and the like.
var mediaHosts = map[string]bool{
	"img": true, "image": true, "images": true, "photo": true, "photos": true, "static": true,
	"assets": true, "media": true, "font": true, "fonts": true, "cdn": true, "thumb": true,
	"thumbs": true, "thumbnails": true, "avatar": true, "avatars": true,
}

// mediaExt are the extensions of files that are never a route, where they
// end a segment that is not the last (an image served under a variant
// path: /x_original.png/<hash>).
var mediaExt = []string{
	".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico", ".bmp", ".avif",
	".woff", ".woff2", ".ttf", ".otf", ".eot", ".css", ".mp4", ".webm", ".mp3", ".ogg",
}

// static says whether an archived URL is a file no route sits behind: an
// asset by its extension, one whose extension sits on an earlier path
// segment, one an archive cut short of its extension (a segment ending in
// a bare dot), or any URL on a host whose name says it serves media.
func static(raw string) bool {
	if webextract.ClassifyURL(raw) == "asset" {
		return true
	}
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	first, _, _ := strings.Cut(strings.ToLower(u.Hostname()), ".")
	for _, word := range strings.Split(first, "-") {
		if mediaHosts[word] {
			return true
		}
	}
	segs := strings.Split(strings.ToLower(u.Path), "/")
	for i, seg := range segs {
		if seg == "" {
			continue
		}
		if i == len(segs)-1 && strings.HasSuffix(seg, ".") {
			return true
		}
		for _, ext := range mediaExt {
			if i < len(segs)-1 && strings.HasSuffix(seg, ext) {
				return true
			}
		}
	}
	return false
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
