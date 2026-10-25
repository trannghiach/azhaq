// Package paramcol finds query parameters a page reads but does not link
// (-params, active): arjun's method. Parameters go out in large groups
// with random values; a group that changes the answer (status, size,
// a value reflected back) is split in halves until the names are found.
// GET only: guessing names on POST could submit something.
package paramcol

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/trannghiach/azhaq/catalog"
	"github.com/trannghiach/azhaq/internal/fetch"
	"github.com/trannghiach/azhaq/internal/limit"
	"github.com/trannghiach/azhaq/internal/normalize"
	"github.com/trannghiach/azhaq/internal/webextract"
	"github.com/trannghiach/azhaq/types"
)

const Name = "azhaq-params"

// Options shape the search.
type Options struct {
	Words   []string
	Chunk   int     // names per request; default 250, as arjun
	PerHost int     // pages searched per host; default 20
	Rate    float64 // requests per second per host; default 20
}

type Collector struct {
	Client *http.Client
	Opts   Options

	limiter *limit.Limiter
	mu      sync.Mutex
	perHost map[string]int
	done    map[string]bool
}

func New(client *http.Client, o Options) *Collector {
	if o.Chunk <= 0 {
		o.Chunk = 250
	}
	if o.PerHost <= 0 {
		o.PerHost = 20
	}
	if o.Rate <= 0 {
		o.Rate = 20
	}
	c := *fetch.Client(client)
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Collector{Client: &c, Opts: o, limiter: limit.New(o.Rate, max(1, int(o.Rate/5))), perHost: map[string]int{}, done: map[string]bool{}}
}

func (c *Collector) Name() string { return Name }

// Info: tens of requests per page; needs -params and -allow, and waits for
// the HTTP collector so only pages that answered are searched.
func (c *Collector) Info() catalog.Info {
	return catalog.Info{Kind: catalog.Active, Flag: "params", After: "azhaq-http"}
}

func (c *Collector) Inputs() []types.SeedType { return []types.SeedType{types.TypeURL} }

func (c *Collector) Outputs() []string { return []string{"params"} }

// Skip declines assets, scripts and templates: the search is for pages and
// API routes.
func (c *Collector) Skip(seed types.Seed) bool {
	raw := seed.Keys["url"]
	if len(c.Opts.Words) == 0 || strings.Contains(raw, "{") {
		return true
	}
	switch webextract.ClassifyURL(raw) {
	case "asset", "script":
		return true
	}
	return false
}

func (c *Collector) Run(ctx context.Context, seed types.Seed, emit func(types.Observation) error) (types.RunMeta, error) {
	raw, err := normalize.URL(seed.Keys["url"])
	if err != nil {
		return types.RunMeta{Status: types.StatusError, Error: err.Error()}, err
	}
	u, _ := url.Parse(raw)
	page := u.Scheme + "://" + u.Host + u.Path // one search per path, whatever the query
	c.mu.Lock()
	if c.done[page] || c.perHost[u.Host] >= c.Opts.PerHost {
		c.mu.Unlock()
		return types.RunMeta{Status: types.StatusOK}, nil
	}
	c.done[page] = true
	c.perHost[u.Host]++
	c.mu.Unlock()

	known := map[string]bool{}
	for k := range u.Query() {
		known[k] = true
	}
	s := &search{c: c, ctx: ctx, base: u, known: known}
	if !s.calibrate() {
		return types.RunMeta{Status: types.StatusOK}, nil // the page changes by itself or does not answer
	}
	var words []string
	seen := map[string]bool{}
	for _, w := range c.Opts.Words {
		w = strings.TrimSpace(w)
		if w != "" && !known[w] && !seen[w] {
			seen[w] = true
			words = append(words, w)
		}
	}
	found := map[string]string{}
	for i := 0; i < len(words) && ctx.Err() == nil; i += c.Opts.Chunk {
		s.narrow(words[i:min(i+c.Opts.Chunk, len(words))], found)
	}
	if ctx.Err() != nil {
		return types.RunMeta{Status: types.StatusCancelled}, ctx.Err()
	}
	names := make([]string, 0, len(found))
	for n := range found {
		names = append(names, n)
	}
	sort.Strings(names)
	row := map[string]any{"url": page, "requests": s.requests, "params": names}
	if len(found) > 0 {
		row["why"] = found
	}
	payload, _ := json.Marshal(row)
	if err := emit(types.Observation{Collector: Name, Source: page, Kind: "params", Payload: payload, Confidence: 0.8, ObservedAt: time.Now().UTC()}); err != nil {
		return types.RunMeta{}, err
	}
	return types.RunMeta{Status: types.StatusOK, EmitCount: 1}, nil
}

// answer is what a request is compared on.
type answer struct {
	status, length, words, lines int
	body                         []byte
}

type search struct {
	c        *Collector
	ctx      context.Context
	base     *url.URL
	known    map[string]bool
	ref      answer
	slack    int // size difference the page shows between identical requests
	requests int
}

func (s *search) get(params map[string]string) (answer, bool) {
	if err := s.c.limiter.Wait(s.ctx, s.base.Host); err != nil {
		return answer{}, false
	}
	u := *s.base
	q := u.Query()
	for k, v := range params {
		q.Set(k, v)
	}
	u.RawQuery = q.Encode()
	if fetch.EndsSession(u.String()) {
		return answer{}, false
	}
	req, err := http.NewRequestWithContext(s.ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return answer{}, false
	}
	fetch.ApplyHeaders(req)
	s.requests++
	resp, err := s.c.Client.Do(req)
	if err != nil {
		return answer{}, false
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	return answer{
		status: resp.StatusCode, length: len(body), body: body,
		words: bytes.Count(body, []byte{' '}) + 1, lines: bytes.Count(bytes.TrimSpace(body), []byte{'\n'}) + 1,
	}, true
}

// calibrate takes the page twice with one random parameter: an unknown
// name should change nothing, and what does change between the two is the
// page's own noise.
func (s *search) calibrate() bool {
	a, ok := s.get(map[string]string{randValue(): randValue()})
	if !ok {
		return false
	}
	b, ok := s.get(map[string]string{randValue(): randValue()})
	if !ok || a.status != b.status {
		return false
	}
	s.ref = a
	s.slack = abs(a.length - b.length)
	return s.slack < a.length/2+64
}

// differs says why an answer is not the reference, or "".
func (s *search) differs(a answer, values map[string]string) string {
	if a.status != s.ref.status {
		return "status"
	}
	for _, v := range values {
		if bytes.Contains(a.body, []byte(v)) {
			return "reflected"
		}
	}
	if abs(a.length-s.ref.length) > s.slack+s.slack/2+16 {
		return "size"
	}
	if s.slack == 0 && (a.words != s.ref.words || a.lines != s.ref.lines) {
		return "size"
	}
	return ""
}

// narrow finds which names in group change the answer, halving the group
// while it does.
func (s *search) narrow(group []string, found map[string]string) {
	if len(group) == 0 || s.ctx.Err() != nil {
		return
	}
	values := map[string]string{}
	for _, n := range group {
		values[n] = randValue()
	}
	a, ok := s.get(values)
	if !ok {
		return
	}
	why := s.differs(a, values)
	if why == "" {
		return
	}
	if len(group) == 1 {
		if why == "reflected" {
			// Which value came back tells which name it was.
			found[group[0]] = why
			return
		}
		// Confirm: a single change must show again.
		b, ok := s.get(map[string]string{group[0]: randValue()})
		if ok && s.differs(b, nil) != "" {
			found[group[0]] = why
		}
		return
	}
	if why == "reflected" {
		// The reflected value names the parameter directly.
		for n, v := range values {
			if bytes.Contains(a.body, []byte(v)) {
				found[n] = why
			}
		}
		rest := make([]string, 0, len(group))
		for _, n := range group {
			if _, ok := found[n]; !ok {
				rest = append(rest, n)
			}
		}
		if len(rest) == len(group) {
			return
		}
		group = rest
		if len(group) == 0 {
			return
		}
		// Others in the group may change the answer in other ways.
		s.narrow(group, found)
		return
	}
	half := len(group) / 2
	s.narrow(group[:half], found)
	s.narrow(group[half:], found)
}

func randValue() string {
	var b [5]byte
	_, _ = rand.Read(b[:])
	return "az" + hex.EncodeToString(b[:])
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}
