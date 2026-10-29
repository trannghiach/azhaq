package fuzz

import (
	"context"
	"errors"
	"math/rand/v2"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/trannghiach/azhaq/internal/neterr"
)

// Config is one run.
type Config struct {
	Template Template
	Lists    []List
	Mode     Mode
	Set      *Set
	Sender   Sender
	Threads  int

	Calibrate  bool
	CalKeyword string // the keyword calibration replaces; FUZZ by default

	Recursion bool
	Depth     int // 0: no limit

	// Allow, when set, says whether a request's host is in scope; one that
	// is not is not sent.
	Allow func(host string) bool
	// OriginTrips unanswered requests in a row stop the run: the target is
	// down. Zero: never.
	OriginTrips int

	// OnResult gets each match, one at a time.
	OnResult func(Result)
}

// Result is one match, with ffuf's JSON field names.
type Result struct {
	Input            map[string]string `json:"-"`
	Position         int               `json:"position"`
	Status           int               `json:"status"`
	Length           int64             `json:"length"`
	Words            int64             `json:"words"`
	Lines            int64             `json:"lines"`
	ContentType      string            `json:"content-type"`
	RedirectLocation string            `json:"redirectlocation"`
	URL              string            `json:"url"`
	Duration         int64             `json:"duration"`
	Host             string            `json:"host"`
	Method           string            `json:"-"`
}

// Stats says how the run went.
type Stats struct {
	Requests   int      // sent, retries and calibration included
	Matches    int      // results given
	Errors     int      // requests that failed, after one retry
	OutOfScope int      // inputs not sent for their host
	Jobs       int      // the start and each directory recursion followed
	Spent      bool     // the request budget ran out
	Down       []string // origins that stopped answering
	Filters    []string // what calibration added, "size 1234"
	Notes      []string
}

type job struct {
	tmpl  Template
	depth int
}

type engine struct {
	cfg Config

	calMu      sync.Mutex
	calibrated bool

	outMu sync.Mutex // Stats, results and the queue
	stats Stats
	queue []job

	stop      atomic.Bool
	silent    atomic.Int64 // unanswered in a row
	downOrigs map[string]bool
}

// Run sends every input of every job through the template and gives the
// matches to cfg.OnResult. It returns when the inputs are used up, the
// budget is spent, the target stops answering or ctx ends.
func Run(ctx context.Context, cfg Config) Stats {
	if cfg.Threads <= 0 {
		cfg.Threads = 40
	}
	if cfg.CalKeyword == "" {
		cfg.CalKeyword = "FUZZ"
	}
	e := &engine{cfg: cfg, downOrigs: map[string]bool{}}
	e.queue = []job{{tmpl: cfg.Template}}
	for len(e.queue) > 0 && ctx.Err() == nil && !e.stop.Load() {
		j := e.queue[0]
		e.queue = e.queue[1:]
		e.stats.Jobs++
		e.runJob(ctx, j)
	}
	for o := range e.downOrigs {
		e.stats.Down = append(e.stats.Down, o)
	}
	return e.stats
}

// activeLists are the lists whose keyword the job's request holds.
func (e *engine) activeLists(t Template) []List {
	var out []List
	for _, l := range e.cfg.Lists {
		if t.Has(l.Keyword) {
			out = append(out, l)
		}
	}
	return out
}

func (e *engine) runJob(ctx context.Context, j job) {
	lists := e.activeLists(j.tmpl)
	total := Total(e.cfg.Mode, lists)
	sem := make(chan struct{}, e.cfg.Threads)
	var wg sync.WaitGroup
	for i := 0; i < total; i++ {
		if ctx.Err() != nil || e.stop.Load() {
			break
		}
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			continue
		}
		if e.stop.Load() {
			<-sem
			break
		}
		wg.Add(1)
		go func(i int) {
			defer func() { <-sem; wg.Done() }()
			e.task(ctx, j, At(e.cfg.Mode, lists, i), i+1)
		}(i)
	}
	wg.Wait()
}

func (e *engine) task(ctx context.Context, j job, input map[string]string, pos int) {
	req := j.tmpl.Expand(input)
	req.Position = pos
	if e.cfg.Allow != nil && !e.cfg.Allow(hostOf(req.URL)) {
		e.count(func(s *Stats) { s.OutOfScope++ })
		return
	}
	resp, err := e.send(ctx, &req)
	if err != nil {
		return
	}
	e.calibrate(ctx, j.tmpl, input)
	if e.cfg.Set.Matches(resp) {
		e.emit(resp, &req)
	}
	if e.cfg.Recursion {
		e.recurse(j, resp)
	}
}

// send sends req, once more if it failed. An error is counted and, when it
// says the target does not answer, noted; the budget running out stops the run.
func (e *engine) send(ctx context.Context, req *Request) (*Response, error) {
	var err error
	for try := 0; try < 2; try++ {
		var resp *Response
		keep := e.cfg.Set.NeedBody()
		e.count(func(s *Stats) { s.Requests++ })
		resp, err = e.cfg.Sender.Send(ctx, req, keep)
		if err == nil {
			e.silent.Store(0)
			return resp, nil
		}
		if errors.Is(err, neterr.ErrBudget) {
			e.count(func(s *Stats) { s.Requests--; s.Spent = true })
			e.stop.Store(true)
			return nil, err
		}
		if ctx.Err() != nil {
			return nil, err
		}
	}
	e.count(func(s *Stats) { s.Errors++ })
	if neterr.Unanswered(err) && e.cfg.OriginTrips > 0 && int(e.silent.Add(1)) >= e.cfg.OriginTrips {
		e.outMu.Lock()
		e.downOrigs[originOf(req.URL)] = true
		e.outMu.Unlock()
		e.stop.Store(true)
	}
	return nil, err
}

func (e *engine) count(f func(*Stats)) {
	e.outMu.Lock()
	f(&e.stats)
	e.outMu.Unlock()
}

func (e *engine) emit(r *Response, req *Request) {
	res := Result{
		Input: req.Input, Position: req.Position, Status: r.Status, Length: r.Length, Words: r.Words, Lines: r.Lines,
		ContentType: r.ContentType, RedirectLocation: RedirectLocation(r, false), URL: req.URL, Duration: r.Duration,
		Host: hostHeaderOf(req), Method: req.Method,
	}
	e.outMu.Lock()
	e.stats.Matches++
	if e.cfg.OnResult != nil {
		e.cfg.OnResult(res)
	}
	e.outMu.Unlock()
}

// recurse queues the directory a redirect to the same URL and a slash
// names: ffuf's default strategy, taken from any answer, matched or not.
func (e *engine) recurse(j job, r *Response) {
	if r.Status < 300 || r.Status > 399 || strings.TrimSpace(r.Header.Get("Location")) == "" {
		return
	}
	if r.Request.URL+"/" != RedirectLocation(r, true) {
		return
	}
	if e.cfg.Depth > 0 && j.depth >= e.cfg.Depth {
		return
	}
	t := j.tmpl
	t.URL = r.Request.URL + "/FUZZ"
	e.outMu.Lock()
	e.queue = append(e.queue, job{tmpl: t, depth: j.depth + 1})
	e.outMu.Unlock()
}

// calibrate asks for names that cannot exist, once, and filters out what
// they answer. Every task waits for it before its answer is judged, as in
// ffuf.
func (e *engine) calibrate(ctx context.Context, t Template, input map[string]string) {
	if !e.cfg.Calibrate {
		return
	}
	e.calMu.Lock()
	defer e.calMu.Unlock()
	if e.calibrated {
		return
	}
	e.calibrated = true
	if !t.Has(e.cfg.CalKeyword) {
		e.count(func(s *Stats) {
			s.Notes = append(s.Notes, "auto-calibration needs the keyword "+e.cfg.CalKeyword+" in the request (-ack names another): nothing was calibrated")
		})
		return
	}
	for _, group := range calibrationGroups() {
		var resps []*Response
		for _, s := range group {
			in := make(map[string]string, len(input))
			for k, v := range input {
				in[k] = v
			}
			in[e.cfg.CalKeyword] = s
			req := t.Expand(in)
			if e.cfg.Allow != nil && !e.cfg.Allow(hostOf(req.URL)) {
				continue
			}
			resp, err := e.send(ctx, &req)
			if err != nil || !e.cfg.Set.Matches(resp) {
				continue
			}
			resps = append(resps, resp)
		}
		e.calibrateFilters(resps)
	}
}

// calibrationGroups are ffuf's basic strategy: a name, admin…, .htaccess…,
// each at two lengths.
func calibrationGroups() [][]string {
	return [][]string{
		{"admin" + randomName(16), "admin" + randomName(8)},
		{".htaccess" + randomName(16), ".htaccess" + randomName(8)},
		{randomName(16), randomName(8)},
	}
}

const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func randomName(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[rand.IntN(len(letters))]
	}
	return string(b)
}

// calibrateFilters works down from the most specific thing the answers
// share: the size, else the words, else the lines.
func (e *engine) calibrateFilters(rs []*Response) {
	if len(rs) == 0 {
		return
	}
	for _, c := range []struct {
		kind string
		of   func(*Response) int64
	}{
		{"size", func(r *Response) int64 { return r.Length }},
		{"word", func(r *Response) int64 { return r.Words }},
		{"line", func(r *Response) int64 { return r.Lines }},
	} {
		same := true
		for _, r := range rs {
			if c.of(r) != c.of(rs[0]) {
				same = false
			}
		}
		if !same {
			continue
		}
		if e.cfg.Set.filtered(rs[0]) {
			return // an existing filter already holds them back
		}
		v := strconv.FormatInt(c.of(rs[0]), 10)
		if e.cfg.Set.AddFilter(c.kind, v) == nil {
			e.count(func(s *Stats) { s.Filters = append(s.Filters, c.kind+" "+v) })
		}
		return
	}
}

func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

func originOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	return u.Scheme + "://" + u.Host
}

// hostHeaderOf is the host the answer came from: the Host header when the
// request set one, as ffuf's "host" field.
func hostHeaderOf(req *Request) string {
	for _, h := range req.Headers {
		if h.Name == "Host" {
			return h.Value
		}
	}
	u, err := url.Parse(req.URL)
	if err != nil {
		return ""
	}
	return u.Host
}
