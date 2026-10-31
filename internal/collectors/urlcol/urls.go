// Package urlcol lists the URLs archives and scanners have seen for a
// domain and its subdomains: the Wayback Machine, Common Crawl, AlienVault
// OTX, urlscan.io and arquivo.pt. Every URL can go to a file (-urls); the
// graph gets one URL per template, the most telling first.
package urlcol

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"os"
	"slices"
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
	OutFrom  bool                // and the source that gave it first, after a tab
	Timeout  time.Duration       // per source; default 3 minutes
	MaxPages int                 // per source; default 50
	MaxURLs  int                 // kept per domain; default 500,000

	Apex      bool              // the domain's own host only, not its subdomains
	Only      []string          // ask only these sources; default all
	Filters   Filters           // sent to the archives that can apply them
	Blacklist []string          // drop URLs whose path ends in one of these extensions
	FirstPath bool              // keep one URL for each host and path
	Retries   *int              // per request, on 429, 503 and network errors; default: a 429 or 503 until the source's time is spent, a network error 3 times
	Pause     *time.Duration    // between a source's requests; default per source, 0 none
	Proxy     string            // http, https or socks5 address, when no Client is given
	Bases     map[string]string // replaces a source's address (a mirror, a test server)

	// OnURL gets each URL the first time it is seen, as the pages arrive.
	// With Raw it gets every row on the domain exactly as the archive gave
	// it: no normalising, junk filter or deduplication.
	OnURL func(url, source string)
	Raw   bool
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
		o.Client = &http.Client{Timeout: 5 * time.Minute, Transport: transport(o.Proxy)}
	}
	if o.Timeout <= 0 {
		o.Timeout = 3 * time.Minute
	}
	if o.MaxPages <= 0 {
		o.MaxPages = 50
	}
	if o.MaxURLs <= 0 {
		o.MaxURLs = maxURLs
	}
	pauses := map[string]time.Duration{
		"wayback": time.Second, "commoncrawl": time.Second, "otx": 500 * time.Millisecond, "urlscan": 2 * time.Second,
	}
	if o.Pause != nil {
		for _, s := range allSources() {
			pauses[s.name] = *o.Pause
		}
	}
	c := &Collector{opts: o, pauses: pauses}
	for _, s := range allSources() {
		if len(o.Only) == 0 || slices.Contains(o.Only, s.name) {
			c.sources = append(c.sources, s)
		}
	}
	return c
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
		if c.skips(s) == "" {
			out = append(out, s.name)
		}
	}
	return out
}

// skips says why a source is not asked: it cannot apply a filter that was
// given, and its URLs would pass it unfiltered.
func (c *Collector) skips(s source) string {
	if lack := c.opts.Filters.needs() &^ s.can; lack != 0 {
		var what []string
		if lack&byStatus != 0 {
			what = append(what, "status")
		}
		if lack&byMime != 0 {
			what = append(what, "type")
		}
		if lack&byDate != 0 {
			what = append(what, "date")
		}
		return "holds no " + strings.Join(what, " or ") + " of its captures to filter on"
	}
	return ""
}

type outcome struct {
	count, pages   int
	err            error
	took           time.Duration
	capped         bool
	skipped        string
	tries, retried int // requests sent, and sent again
	waited         time.Duration
}

// cutGrace is how long before the run's deadline the sources stop, so
// what they found can still be recorded.
const cutGrace = 3 * time.Second

func (c *Collector) Run(ctx context.Context, seed types.Seed, emit func(types.Observation) error) (types.RunMeta, error) {
	domain := normalize.Hostname(seed.Keys["domain"])
	if domain == "" {
		return types.RunMeta{Status: types.StatusError, Error: "empty domain"}, nil
	}
	if normalize.SpecialUse(domain) || normalize.Unlisted(domain) {
		why := "reserved"
		if !normalize.SpecialUse(domain) {
			why = "not a public domain: the archives only hold names under public TLDs"
		}
		payload, _ := json.Marshal(map[string]any{"domain": domain, "count": 0, "skipped": why})
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
	// The sources stop a little before the run's -timeout, so the summary
	// can still be recorded with what they had read.
	var cutoff time.Time
	if dl, ok := ctx.Deadline(); ok {
		left := time.Until(dl)
		cutoff = dl.Add(-min(cutGrace, left/4))
	}

	out := newOutFilter(c.opts.Blacklist, c.opts.FirstPath)
	deferFirst := c.opts.FirstPath && c.opts.OnURL == nil // sorted output keeps the first in order, not of arrival
	if deferFirst {
		out.first = false
	}
	var mu sync.Mutex
	seen := map[string]bool{}
	from := map[string]string{} // URL → the source that gave it first
	var all []string
	dropped := 0 // URLs past the cap
	results := make([]outcome, len(c.sources))
	var wg sync.WaitGroup
	for i, s := range c.sources {
		if why := c.skips(s); why != "" {
			results[i].skipped = why
			continue
		}
		wg.Add(1)
		go func(i int, s source) {
			defer wg.Done()
			sctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			byRun := false
			if !cutoff.IsZero() && time.Until(cutoff) < timeout {
				cancel()
				sctx, cancel = context.WithDeadline(ctx, cutoff)
				defer cancel()
				byRun = true
			}
			g := &getter{client: c.opts.Client, pause: c.pauses[s.name], maxPages: c.opts.MaxPages, retries: -1,
				apex: c.opts.Apex, filters: c.opts.Filters, base: c.opts.Bases[s.name], raw: c.opts.Raw}
			if c.opts.Retries != nil {
				g.retries = *c.opts.Retries
			}
			key := ""
			if ks := c.opts.Keys[s.name]; len(ks) > 0 {
				key = ks[0]
			}
			count := 0
			// The host alone is how wayback, Common Crawl and arquivo are
			// asked; otx and urlscan answer for the domain with its
			// subdomains, and gau prints those too.
			apex := c.opts.Apex && s.name != "otx" && s.name != "urlscan"
			add := func(urls []string) {
				mu.Lock()
				defer mu.Unlock()
				for _, raw := range urls {
					if c.opts.Raw && c.opts.OnURL != nil && onDomain(raw, domain, apex) && !out.blocked(raw) && !out.repeat(raw) {
						c.opts.OnURL(raw, s.name)
					}
					u, ok := clean(raw, domain, apex)
					if !ok || out.blocked(u) {
						continue
					}
					count++
					if seen[u] || (!c.opts.Raw && out.repeat(u)) {
						continue
					}
					if len(all) >= c.opts.MaxURLs {
						dropped++
						continue
					}
					seen[u] = true
					from[u] = s.name
					all = append(all, u)
					if !c.opts.Raw && c.opts.OnURL != nil {
						c.opts.OnURL(u, s.name)
					}
				}
			}
			done := timing.Start(ctx, "urls."+s.name)
			t0 := time.Now()
			pages, err := s.fetch(sctx, g, domain, key, add)
			done()
			if sctx.Err() != nil && ctx.Err() == nil {
				// The run's limit, or this source's own.
				if byRun && time.Now().After(cutoff.Add(-time.Second)) {
					err = errors.New(types.CutShort)
				} else if err == nil {
					err = sctx.Err()
				}
			}
			mu.Lock()
			results[i] = outcome{count: count, pages: pages, err: err, took: time.Since(t0), capped: g.capped && err == nil,
				tries: g.tries, retried: g.retried, waited: g.waited}
			mu.Unlock()
		}(i, s)
	}
	wg.Wait()
	sort.Strings(all)
	if deferFirst {
		all = firstPerPath(all)
	}
	// What was found is kept whatever stopped the run: a recon tool never
	// throws away work it already did.
	if err := c.write(all, from); err != nil {
		return types.RunMeta{Status: types.StatusError, Error: err.Error()}, err
	}
	if ctx.Err() != nil {
		return types.RunMeta{Status: types.StatusCancelled}, ctx.Err()
	}

	status := map[string]any{}
	var failed, capped []string
	for i, s := range c.sources {
		r := results[i]
		if r.skipped != "" {
			status[s.name] = map[string]any{"skipped": r.skipped}
			continue
		}
		row := map[string]any{"count": r.count, "pages": r.pages, "seconds": float64(r.took.Milliseconds()/100) / 10}
		if r.tries > 0 {
			row["requests"] = r.tries
		}
		if r.retried > 0 {
			row["retried"] = r.retried
			row["waited_seconds"] = float64(r.waited.Milliseconds()/100) / 10
		}
		if r.err != nil {
			row["error"] = shorten(r.err.Error())
			failed = append(failed, s.name)
		}
		if r.capped {
			row["capped"] = true
			capped = append(capped, s.name)
		}
		status[s.name] = row
	}
	tmpl, assets := templates(all)
	nAssets := 0
	for _, t := range assets {
		nAssets += t.count
	}
	payload := map[string]any{"domain": domain, "count": len(all), "templates": len(tmpl), "assets": nAssets, "sources": status}
	if len(capped) > 0 {
		sort.Strings(capped)
		payload["capped"] = capped
	}
	if dropped > 0 {
		payload["truncated"] = dropped
	}
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

// clean keeps http(s) URLs on domain (and its subdomains, unless apex),
// normalized.
func clean(raw, domain string, apex bool) (string, bool) {
	raw = strings.TrimSpace(raw)
	if l := strings.ToLower(raw[:min(len(raw), 8)]); !strings.HasPrefix(l, "http://") && !strings.HasPrefix(l, "https://") {
		return "", false
	}
	u, err := normalize.URL(raw)
	if err != nil || webextract.JunkURL(u) {
		return "", false
	}
	if !hostOn(normalize.HostFromURL(u), domain, apex) {
		return "", false
	}
	return u, true
}

func hostOn(host, domain string, apex bool) bool {
	return host == domain || (!apex && strings.HasSuffix(host, "."+domain))
}

// onDomain is hostOn for a URL as an archive gave it.
func onDomain(raw, domain string, apex bool) bool {
	u, err := url.Parse(raw)
	return err == nil && hostOn(strings.ToLower(u.Hostname()), domain, apex)
}

// firstPerPath keeps the first of each host and path in urls, which are sorted.
func firstPerPath(urls []string) []string {
	f := newOutFilter(nil, true)
	out := urls[:0]
	for _, u := range urls {
		if !f.repeat(u) {
			out = append(out, u)
		}
	}
	return out
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
	// A media-named host (img.*, cdn-photos.*) mostly serves files, but a
	// page or an API on it (/login, /api/users, ?q=…) is a route and is
	// asked; only a URL ending in an opaque id (a hash, a numbered variant)
	// with no extension is taken for an asset.
	if u.RawQuery == "" && webextract.ClassifyURL(raw) != "api" && mediaHost(u.Hostname()) && opaqueID(lastSeg(u.Path)) {
		return true
	}
	return false
}

// mediaHost says a hostname's first label names a file store (img, cdn,
// media, cdn-photos).
func mediaHost(host string) bool {
	first, _, _ := strings.Cut(strings.ToLower(host), ".")
	for _, word := range strings.Split(first, "-") {
		if mediaHosts[word] {
			return true
		}
	}
	return false
}

func lastSeg(p string) string {
	p = strings.Trim(p, "/")
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[i+1:]
	}
	return p
}

// opaqueID is a path segment that names nothing a reader would type: eight
// or more characters of hex digits, digits, dashes and underscores, with a
// digit among them (a UUID, a content hash, an image variant id). A word
// like "login" or "dashboard" is not one.
func opaqueID(seg string) bool {
	if len(seg) < 8 {
		return false
	}
	digit := false
	for _, r := range seg {
		switch {
		case r >= '0' && r <= '9':
			digit = true
		case r >= 'a' && r <= 'f', r == '-', r == '_':
		default:
			return false
		}
	}
	return digit
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

// write appends urls to the -urls file, each with its source when asked.
func (c *Collector) write(urls []string, from map[string]string) error {
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
		if c.opts.OutFrom {
			w.WriteByte('\t')
			w.WriteString(from[u])
		}
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
