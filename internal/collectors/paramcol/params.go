// Package paramcol finds query parameters a page reads but does not link
// (-params, active): arjun's method. Parameters go out in large groups
// with random values; a group that changes the answer (status, size,
// headers, a redirect, a value or a name reflected back) is split in
// halves until the names are found. A page that answers any name (an
// error page that prints the query string back) is asked the same with
// random names of the same lengths, and only what that control does not
// show counts. Names a page's own HTML and scripts hold are asked first,
// and a short table of toggle names (debug, test…) is asked again with
// the values that switch them on.
// GET by default. -X POST, JSON and XML send the names in a body: those
// requests may change data, so they are opt-in (Options.Writes).
package paramcol

import (
	"context"
	"encoding/json"
	"fmt"
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

// Methods a search may use.
const (
	GET  = "GET"
	POST = "POST"
	JSON = "JSON"
	XML  = "XML"
)

// Target is how one page is asked, when it differs from the options: a
// page imported from a Burp export or a raw request.
type Target struct {
	Method  string   `json:"method,omitempty"`
	Include string   `json:"include,omitempty"` // sent with every request
	Header  []string `json:"header,omitempty"`  // "Name: value"
}

// Options shape the search.
type Options struct {
	Words   []string
	Chunk   int     // names per request at most; default 500 (arjun: 250); fewer where the server refuses a long query
	PerHost int     // pages searched per host; default 20
	Rate    float64 // requests per second per host; 0: no limit, as arjun
	// Backoff are the waits before asking again after a 429, 418 or 503;
	// a Retry-After longer than one is used instead. Default 1, 2 and 4 s.
	Backoff []time.Duration
	Threads int // requests in flight per page; default 5, as arjun
	// Method is GET (the default), POST (form body), JSON or XML. A body
	// sends names that may change data: Writes must say that is wanted.
	Method string
	Writes bool
	// Include is sent with every request: a query for GET, the fixed part
	// of the body otherwise (a form, a JSON object, or a template with
	// $arjun$ where the names go).
	Include string
	// Delay is waited before each request, one at a time. Stable is one
	// at a time with 3 to 9 s before each request and 30 s after a refused
	// connection.
	Delay  time.Duration
	Stable bool
	// Timeout is waited for each request (default 15 s); one that times
	// out is asked again with 5 s more, up to 20 s.
	Timeout time.Duration
	// Targets are pages asked otherwise than the options say.
	Targets map[string]Target
}

type Collector struct {
	Client *http.Client
	Opts   Options

	limiter *limit.Limiter
	mu      sync.Mutex
	perHost map[string]int
	done    map[string]bool
	hold    map[string]time.Time // a host that asked for time: no request before
}

func New(client *http.Client, o Options) *Collector {
	o.Method = strings.ToUpper(o.Method)
	if o.Method == "" {
		o.Method = GET
	}
	if o.Chunk <= 0 {
		o.Chunk = 500
	}
	if o.PerHost <= 0 {
		o.PerHost = 20
	}
	if o.Rate <= 0 {
		o.Rate = 1e6 // no pace but the answers', as arjun
	}
	if len(o.Backoff) == 0 {
		o.Backoff = []time.Duration{time.Second, 2 * time.Second, 4 * time.Second}
	}
	if o.Threads <= 0 {
		o.Threads = 5
	}
	if o.Stable || o.Delay > 0 {
		o.Threads = 1
	}
	if o.Timeout <= 0 {
		o.Timeout = 15 * time.Second
	}
	if client == nil {
		// The answer to a long query may take a while to start.
		client = fetch.Patient(20*time.Second, 40*time.Second)
	}
	c := *fetch.Client(client)
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Collector{Client: &c, Opts: o, limiter: limit.New(o.Rate, max(1, int(o.Rate/5))), perHost: map[string]int{}, done: map[string]bool{}, hold: map[string]time.Time{}}
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

// minFlood is how large a group must be for most of it changing the
// answer to mean the page answers any name.
const minFlood = 8

func (c *Collector) Run(ctx context.Context, seed types.Seed, emit func(types.Observation) error) (types.RunMeta, error) {
	raw, err := normalize.URL(seed.Keys["url"])
	if err != nil {
		return types.RunMeta{Status: types.StatusError, Error: err.Error()}, err
	}
	u, _ := url.Parse(raw)
	page := u.Scheme + "://" + u.Host + u.Path // one search per path, whatever the query
	tg := c.Opts.Targets[page]
	if tg.Method == "" {
		tg.Method = c.Opts.Method
	}
	tg.Method = strings.ToUpper(tg.Method)
	if tg.Include == "" {
		tg.Include = c.Opts.Include
	}
	c.mu.Lock()
	if c.done[page] {
		c.mu.Unlock()
		return types.RunMeta{Status: types.StatusOK}, nil
	}
	if c.perHost[u.Host] >= c.Opts.PerHost {
		c.mu.Unlock()
		return types.RunMeta{Status: types.StatusOK, EmitCount: 1}, noted(emit, page, fmt.Sprintf("%s: not searched, %d pages of %s were searched already (-params-per-host)", page, c.Opts.PerHost, u.Host))
	}
	c.done[page] = true
	c.perHost[u.Host]++
	c.mu.Unlock()
	if tg.Method != GET && !c.Opts.Writes {
		return types.RunMeta{Status: types.StatusOK, EmitCount: 1}, noted(emit, page, fmt.Sprintf("%s: not searched, %s sends requests that may change data and was not asked for", page, tg.Method))
	}

	s := newSearch(c, ctx, u, tg)
	meta, err := s.run(page, emit)
	if s.err != nil {
		return s.spent(page)
	}
	return meta, err
}

// spent gives the page back for azhaq resume, which searches it again.
func (s *search) spent(page string) (types.RunMeta, error) {
	s.c.mu.Lock()
	delete(s.c.done, page)
	s.c.perHost[s.base.Host]--
	s.c.mu.Unlock()
	return types.RunMeta{Status: types.StatusCapped}, s.err
}

// give emits the page's row and says what cut the search short: a page
// that limits requests or stops answering fails with the names found so
// far kept, and names in groups that got no answer are not judged.
func (s *search) give(page string, emit func(types.Observation) error, found map[string]string, values map[string]string, notes []string) (types.RunMeta, error) {
	names := make([]string, 0, len(found))
	for n := range found {
		names = append(names, n)
	}
	sort.Strings(names)
	row := map[string]any{"url": page, "method": s.method, "requests": s.requests.Load(), "params": names}
	if len(found) > 0 {
		row["why"] = found
	}
	if len(values) > 0 {
		row["values"] = values
	}
	var fail error
	s.mu.Lock()
	stopped, lost, lostWhy := s.stopped, s.lost, s.lostWhy
	if s.note != "" && len(found) == 0 {
		notes = append(notes, page+": "+s.note)
	}
	s.mu.Unlock()
	switch {
	case stopped != nil:
		fail = stopped
		notes = append(notes, fmt.Sprintf("%s: %s, so the page was not fully searched (lower -rate, or wait and run again)", page, stopped))
	case lost > 0:
		fail = fmt.Errorf("%d requests got no answer (%s)", lost, lostWhy)
		if int64(lost) >= s.requests.Load() {
			notes = append(notes, fmt.Sprintf("%s: did not answer (%s); nothing was searched", page, lostWhy))
		} else {
			notes = append(notes, fmt.Sprintf("%s: %d of %d requests got no answer (%s); the names in those groups were not judged", page, lost, s.requests.Load(), lostWhy))
		}
	}
	if s.method != GET {
		row["writes"] = s.requests.Load()
		notes = append(notes, fmt.Sprintf("%s: %d %s requests were sent with the names in the body; they may have changed data on the target", page, s.requests.Load(), s.method))
	}
	if len(notes) > 0 {
		row["note"] = strings.Join(notes, "; ")
	}
	payload, _ := json.Marshal(row)
	if err := emit(types.Observation{Collector: Name, Source: page, Kind: "params", Payload: payload, Confidence: 0.8, ObservedAt: time.Now().UTC()}); err != nil {
		return types.RunMeta{}, err
	}
	if fail != nil {
		return types.RunMeta{Status: types.StatusError, Error: fail.Error(), EmitCount: 1}, fail
	}
	return types.RunMeta{Status: types.StatusOK, EmitCount: 1}, nil
}

// skipped says the page was not searched and why.
func (s *search) skipped(emit func(types.Observation) error, page string) error {
	why := s.skip
	if why == "" {
		why = "the page changes by itself"
	}
	return noted(emit, page, fmt.Sprintf("%s: not searched, %s", page, why))
}

// noted emits a page's row with no parameters and a note for the summary: a
// page not searched is said, not dropped. (The summary's list of requests
// not sent omits pages the run asked, so a note carries it.)
func noted(emit func(types.Observation) error, page, note string) error {
	payload, _ := json.Marshal(map[string]any{"url": page, "requests": 0, "params": []string{}, "note": note})
	return emit(types.Observation{Collector: Name, Source: page, Kind: "params", Payload: payload, Confidence: 0.8, ObservedAt: time.Now().UTC()})
}

// holdFor makes every request to host wait until d from now: it asked.
func (c *Collector) holdFor(host string, d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if t := time.Now().Add(d); t.After(c.hold[host]) {
		c.hold[host] = t
	}
}

// held is how long until host may be asked again.
func (c *Collector) held(host string) time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return time.Until(c.hold[host])
}
