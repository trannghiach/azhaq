// Package dirscol guesses paths on a web service from a wordlist (-dirs,
// active): ffuf and feroxbuster's job. Each directory is calibrated first
// with paths that cannot exist, so a server that answers everything
// (single-page apps, soft 404s, login redirects) does not flood the results.
package dirscol

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/trannghiach/azhaq/catalog"
	"github.com/trannghiach/azhaq/internal/fetch"
	"github.com/trannghiach/azhaq/internal/limit"
	"github.com/trannghiach/azhaq/internal/neterr"
	"github.com/trannghiach/azhaq/internal/normalize"
	"github.com/trannghiach/azhaq/internal/webextract"
	"github.com/trannghiach/azhaq/types"
)

const Name = "azhaq-dirs"

// Options shape a sweep.
type Options struct {
	Words      []string
	Extensions []string // "php" also tries word.php
	Depth      int      // directory levels to descend; 1 is the start only
	Threads    int      // requests in flight per service
	Rate       float64  // requests per second per host; 0: no limit
	Match      []int    // statuses reported; default ffuf's
	// AllGets also sends, with a session, the words that read like an
	// action (delete, reset, logout…); by default they are listed, not
	// requested.
	AllGets bool
}

// DefaultMatch is ffuf's default -mc.
var DefaultMatch = []int{200, 201, 202, 203, 204, 205, 206, 207, 208, 226, 301, 302, 307, 401, 403, 405, 500}

type Collector struct {
	Client *http.Client
	Opts   Options

	limiter *limit.Limiter
	swept   sync.Map // directory URL → true
}

func New(client *http.Client, o Options) *Collector {
	if o.Depth <= 0 {
		o.Depth = 1
	}
	if o.Threads <= 0 {
		o.Threads = 40
	}
	if o.Rate <= 0 {
		o.Rate = 1e6 // no pace but the threads', as ffuf
	}
	if len(o.Match) == 0 {
		o.Match = DefaultMatch
	}
	// Redirects are answers here: a directory is the path that redirects
	// to itself with a slash.
	c := *fetch.Client(client)
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Collector{Client: &c, Opts: o, limiter: limit.New(o.Rate, max(1, int(o.Rate/10)))}
}

func (c *Collector) Name() string { return Name }

// Standing: a hit is checked against the directory's calibration before
// it is reported, so a run the budget stops keeps the hits it found.
func (c *Collector) Standing() bool { return true }

// Info: many requests to the target; needs -dirs and -allow, and waits for
// the HTTP collector so it starts from a service that answered.
func (c *Collector) Info() catalog.Info {
	return catalog.Info{Kind: catalog.Active, Flag: "dirs", After: "azhaq-http"}
}

func (c *Collector) Inputs() []types.SeedType { return []types.SeedType{types.TypeURL} }

func (c *Collector) Outputs() []string { return []string{"url"} }

// Skip: a sweep starts at a service's front page; deeper directories are
// reached by recursion inside the sweep.
func (c *Collector) Skip(seed types.Seed) bool {
	u, err := url.Parse(seed.Keys["url"])
	return err != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || len(c.Opts.Words) == 0
}

// hit is one guessed path that answered.
type hit struct {
	URL      string `json:"url"`
	Status   int    `json:"status"`
	Length   int    `json:"length"`
	Words    int    `json:"words"`
	Lines    int    `json:"lines"`
	Location string `json:"location,omitempty"`
}

func (c *Collector) Run(ctx context.Context, seed types.Seed, emit func(types.Observation) error) (types.RunMeta, error) {
	start, err := normalize.URL(seed.Keys["url"])
	if err != nil {
		return types.RunMeta{Status: types.StatusError, Error: err.Error()}, err
	}
	u, _ := url.Parse(start)
	base := u.Scheme + "://" + u.Host + "/"
	meta := types.RunMeta{Status: types.StatusOK}
	queue := []dirLevel{{url: base, depth: 1}}
	var all []hit
	var skipped []string // guesses not sent: nobody saw them exist, so they are no URLs of the map
	requests, filtered := 0, 0
	// Each hit is kept as it is found, as ffuf prints it: a run stopped by
	// Ctrl-C or the budget keeps what it found so far.
	var emitErr error
	found := func(h hit) {
		row := map[string]any{"url": h.URL, "via": "dirs", "status": h.Status, "length": h.Length, "words": h.Words, "lines": h.Lines}
		if h.Location != "" {
			row["location"] = h.Location
		}
		raw, _ := json.Marshal(row)
		if err := emit(types.Observation{Collector: Name, Source: base, Kind: "url", Payload: raw, Confidence: 0.8, ObservedAt: time.Now().UTC()}); err != nil {
			if emitErr == nil {
				emitErr = err
			}
			return
		}
		meta.EmitCount++
		meta.NextHints = append(meta.NextHints, types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": h.URL}})
	}
	for len(queue) > 0 && ctx.Err() == nil && emitErr == nil {
		d := queue[0]
		queue = queue[1:]
		if _, done := c.swept.LoadOrStore(d.url, true); done {
			continue
		}
		hits, n, f, held, spent := c.sweep(ctx, d.url, found)
		if spent {
			// The sweep is redone whole by azhaq resume; what it found is
			// kept, and found again.
			c.swept.Delete(d.url)
			return types.RunMeta{Status: types.StatusCapped, EmitCount: meta.EmitCount, NextHints: meta.NextHints}, neterr.ErrBudget
		}
		requests += n
		filtered += f
		all = append(all, hits...)
		skipped = append(skipped, held...)
		for _, h := range hits {
			if d.depth < c.Opts.Depth && isDir(h) {
				queue = append(queue, dirLevel{url: strings.TrimSuffix(h.URL, "/") + "/", depth: d.depth + 1})
			}
		}
	}
	if emitErr != nil {
		return meta, emitErr
	}
	if ctx.Err() != nil {
		return types.RunMeta{Status: types.StatusCancelled, EmitCount: meta.EmitCount, NextHints: meta.NextHints}, ctx.Err()
	}
	summary, _ := json.Marshal(map[string]any{
		"base": base, "words": len(c.Opts.Words), "extensions": c.Opts.Extensions, "requests": requests,
		"hits": len(all), "filtered": filtered, "depth": c.Opts.Depth,
	})
	if err := emit(types.Observation{Collector: Name, Source: base, Kind: "dirs", Payload: summary, Confidence: 0.9, ObservedAt: time.Now().UTC()}); err != nil {
		return meta, err
	}
	meta.EmitCount++
	if len(skipped) > 0 {
		raw, _ := json.Marshal(map[string]any{"skipped": "with a session, a GET there could change something", "urls": skipped})
		if err := emit(types.Observation{Collector: Name, Source: base, Kind: "skipped", Payload: raw, Confidence: 0.9, ObservedAt: time.Now().UTC()}); err != nil {
			return meta, err
		}
		meta.EmitCount++
	}
	return meta, nil
}

type dirLevel struct {
	url   string
	depth int
}

// isDir: a path that redirects to itself with a slash, as servers do for
// directories.
func isDir(h hit) bool {
	if h.Location == "" {
		return false
	}
	return strings.TrimSuffix(h.Location, "/") == h.URL || strings.HasSuffix(h.Location, strings.TrimPrefix(h.URL, schemeHost(h.URL))+"/")
}

func schemeHost(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// sweep guesses every word (and word.ext) under dir, handing each hit to
// found as it comes (one at a time); held lists the URLs not sent
// because, with a session, a GET there could change something; spent
// says the request budget ran out before it was through.
func (c *Collector) sweep(ctx context.Context, dir string, found func(hit)) (_ []hit, _ int, _ int, held []string, spent bool) {
	cal := c.calibrate(ctx, dir)
	careful := fetch.HasSession() && !c.Opts.AllGets
	var targets []string
	for _, w := range c.Opts.Words {
		w = strings.TrimPrefix(strings.TrimSpace(w), "/")
		if w == "" || strings.HasPrefix(w, "#") {
			continue
		}
		words := []string{w}
		for _, ext := range c.Opts.Extensions {
			words = append(words, w+"."+strings.TrimPrefix(ext, "."))
		}
		for _, t := range words {
			if careful && (webextract.StateChanging(dir+escapeWord(t)) != "" || fetch.EndsSession(dir+escapeWord(t))) {
				held = append(held, dir+escapeWord(t))
				continue
			}
			targets = append(targets, t)
		}
	}
	var mu sync.Mutex
	var hits []hit
	filtered := 0
	sem := make(chan struct{}, c.Opts.Threads)
	var wg sync.WaitGroup
	host := schemeHost(dir)
	var out atomic.Bool
	for _, t := range targets {
		if ctx.Err() != nil || out.Load() {
			break
		}
		if err := c.limiter.Wait(ctx, host); err != nil {
			break
		}
		sem <- struct{}{}
		wg.Add(1)
		go func(word string) {
			defer wg.Done()
			defer func() { <-sem }()
			target := dir + escapeWord(word)
			r, err := c.get(ctx, target)
			if errors.Is(err, neterr.ErrBudget) {
				out.Store(true)
			}
			if err != nil || !c.matches(r.Status) {
				return
			}
			mu.Lock()
			defer mu.Unlock()
			if cal.explains(r, word) {
				filtered++
				return
			}
			h := hit{URL: target, Status: r.Status, Length: r.Length, Words: r.Words, Lines: r.Lines, Location: r.Location}
			hits = append(hits, h)
			found(h)
		}(t)
	}
	wg.Wait()
	return hits, len(targets), filtered, held, out.Load()
}

func escapeWord(w string) string {
	parts := strings.Split(w, "/")
	for i, p := range parts {
		parts[i] = url.PathEscape(p)
	}
	return strings.Join(parts, "/")
}

func (c *Collector) matches(status int) bool {
	for _, m := range c.Opts.Match {
		if m == status {
			return true
		}
	}
	return false
}

// response is what the sweep compares: never the body itself.
type response struct {
	Status, Length, Words, Lines int
	Location                     string
}

func (c *Collector) get(ctx context.Context, target string) (response, error) {
	if fetch.EndsSession(target) {
		return response{}, neterr.ErrEndsSession
	}
	// A guess the run made before it was stopped is not sent again.
	if fetch.Memos != nil {
		if raw, ok := fetch.Memos.Recall("dirs " + target); ok {
			var r response
			if json.Unmarshal(raw, &r) == nil {
				return r, nil
			}
		}
	}
	r, err := c.send(ctx, target)
	if err == nil && fetch.Memos != nil {
		if raw, err := json.Marshal(r); err == nil {
			fetch.Memos.Remember("dirs "+target, raw)
		}
	}
	return r, err
}

func (c *Collector) send(ctx context.Context, target string) (response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return response{}, err
	}
	fetch.ApplyHeaders(req)
	if err := fetch.Spend(ctx); err != nil {
		return response{}, err
	}
	resp, err := c.Client.Do(req)
	if err != nil {
		return response{}, err
	}
	defer resp.Body.Close()
	// Words and lines from the first MB; the length is the whole body's,
	// as ffuf reports it (read up to 64 MB).
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	rest, _ := io.Copy(io.Discard, io.LimitReader(resp.Body, 63<<20))
	return response{
		Status:   resp.StatusCode,
		Length:   len(body) + int(rest),
		Words:    bytes.Count(body, []byte{' '}) + 1,
		Lines:    bytes.Count(bytes.TrimSpace(body), []byte{'\n'}) + 1,
		Location: resp.Header.Get("Location"),
	}, nil
}

// calibration holds what a directory answers for paths that cannot exist.
type calibration struct {
	base []response
	echo map[int]bool // statuses whose body or redirect echoes the path
}

// calibrate asks for random names of the shapes ffuf's -ac uses (a word,
// admin…, .htaccess…, a directory) and one per extension. A file that
// exists keeps its place even when its content equals the catch-all page.
func (c *Collector) calibrate(ctx context.Context, dir string) calibration {
	cal := calibration{echo: map[int]bool{}}
	shapes := []string{randWord(), "admin" + randWord(), ".htaccess" + randWord(), randWord() + "/"}
	for _, ext := range c.Opts.Extensions {
		shapes = append(shapes, randWord()+"."+strings.TrimPrefix(ext, "."))
	}
	for _, s := range shapes {
		r, err := c.get(ctx, dir+s)
		if err != nil {
			continue
		}
		cal.base = append(cal.base, r)
		if strings.Contains(r.Location, strings.TrimSuffix(s, "/")) {
			cal.echo[r.Status] = true
		}
	}
	return cal
}

// explains is true when r looks like an answer to a path that does not
// exist: same status as a calibration answer and the same size, word and
// line counts, or a redirect that echoes the path the way calibration did.
func (cal calibration) explains(r response, word string) bool {
	for _, b := range cal.base {
		if r.Status != b.Status {
			continue
		}
		if r.Length == b.Length || (r.Words == b.Words && r.Lines == b.Lines) {
			return true
		}
		// Bodies that echo the path differ by the path's length.
		if r.Words == b.Words && abs(r.Length-b.Length) <= 2*len(word)+32 && r.Lines == b.Lines {
			return true
		}
		if r.Location != "" && b.Location != "" && cal.echo[r.Status] && strings.Contains(r.Location, word) {
			return true
		}
		if r.Location != "" && r.Location == b.Location {
			return true
		}
	}
	return false
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func randWord() string { return fetch.RandomName() }

// ParseStatuses reads "200,301-302" into a list.
func ParseStatuses(spec string) ([]int, error) {
	var out []int
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		lo, hi, isRange := strings.Cut(part, "-")
		a, err := strconv.Atoi(lo)
		if err != nil {
			return nil, err
		}
		b := a
		if isRange {
			if b, err = strconv.Atoi(hi); err != nil {
				return nil, err
			}
		}
		for s := a; s <= b; s++ {
			out = append(out, s)
		}
	}
	return out, nil
}
