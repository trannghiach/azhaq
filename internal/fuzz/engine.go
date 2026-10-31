package fuzz

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/trannghiach/azhaq/internal/neterr"
	"github.com/trannghiach/azhaq/scope"
)

// Config is one run.
type Config struct {
	Template Template
	Lists    []List
	Mode     Mode // clusterbomb, pitchfork or sniper
	Set      *Set
	Sender   Sender
	Threads  int

	Calibrate  bool
	CalKeyword string // the keyword calibration replaces; FUZZ by default
	// CalGroups are the names calibration asks, a group at a time (see
	// CalibrationGroups); empty: the basic ones.
	CalGroups [][]string

	Recursion bool
	Depth     int    // 0: no limit
	Strategy  string // "default": directories that redirect to themselves; "greedy": every match
	// MaxTimeJob ends a job (the first one, or a directory found) after this
	// long and goes on with the next; 0: no limit.
	MaxTimeJob time.Duration

	// Delay is how long each request's thread waits after it: Min, or
	// between Min and Max when Max is set.
	DelayMin, DelayMax time.Duration

	// Start skips the first inputs of the first request: where a stopped
	// run left off (-start).
	Start int

	// StopOn403 (-sf) stops the run when over 95% of the first 50 or more
	// answers are 403; StopOnAll (-sa) also on 429 over 20% and on errors.
	StopOn403, StopOnAll bool
	// Allow, when set, says whether a request's host is in scope; one that
	// is not is not sent. The hosts its Host-naming headers name count too,
	// except the headers in OpenHeaders (lower-case names): the user typed
	// them, with no scope rule, so what they name is what was authorized.
	Allow       func(host string) bool
	OpenHeaders map[string]bool
	// OriginTrips unanswered requests in a row stop the run: the target is
	// down. Zero: never. With TripOnAnyError every error counts, not only a
	// missing answer (-se).
	OriginTrips    int
	TripOnAnyError bool

	// Replay, when set, gets each match to send through the replay proxy.
	Replay Replayer
	// Control, when set, lets the run be steered while it goes.
	Control *Control
	// Progress, when set, is kept up to date for a status line.
	Progress *Progress

	// OnResult gets each match, one at a time.
	OnResult func(Result)
	// OnError gets each request that failed, after its second try.
	OnError func(*Request, error)
}

// Progress is what a status line shows, kept by the run.
type Progress struct {
	Total   atomic.Int64 // inputs of the job running
	Done    atomic.Int64 // inputs answered or failed in it
	Job     atomic.Int64 // the job number, 1 for the first
	Queued  atomic.Int64 // directories waiting
	Errors  atomic.Int64
	Matches atomic.Int64
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
	ResultFile       string            `json:"-"` // set when -od keeps the exchange
	Job              int               `json:"-"` // 1 for the first job; each directory found is another
	// RawRequest and RawResponse are set when the sender keeps them (-od).
	RawRequest, RawResponse string `json:"-"`
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
	StoppedBy  string   // a guard of the run that ended it (-sf, -sa)
	Replayed   int      // matches sent through the replay proxy
	ReplayErr  int      // replays that failed
	Timeouts   []string // requests that timed out while -mt or -ft is on: their inputs
	CutJobs    []string // jobs ended by -maxtime-job, with how far each got
	Notes      []string
	// Done: inputs of the first request answered in a row from Start, so a
	// stopped run goes on from Start+Done. Queued: recursions not started.
	Done, Queued int
}

type job struct {
	tmpl  Template
	depth int
	n     int    // 1 for the first job
	hash  string // five hex digits that name the job: FFUFHASH is these and the position
}

type engine struct {
	cfg Config

	calMu      sync.Mutex
	calibrated map[string]bool // by host and directory with -ach, else "" once
	calGroups  [][]string

	outMu sync.Mutex // Stats, results and the queue
	stats Stats
	queue []job

	stop      atomic.Bool
	skipJob   atomic.Bool
	silent    atomic.Int64 // unanswered in a row
	downOrigs map[string]bool

	// per job, for -sf and -sa
	dispatched, n403, n429 atomic.Int64
	jobNum                 atomic.Int64
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
	if cfg.Strategy == "" {
		cfg.Strategy = "default"
	}
	if cfg.Progress == nil {
		cfg.Progress = new(Progress)
	}
	e := &engine{cfg: cfg, downOrigs: map[string]bool{}, calibrated: map[string]bool{}}
	e.calGroups = cfg.CalGroups
	if len(e.calGroups) == 0 {
		e.calGroups, _ = CalibrationGroups(nil, nil)
	}
	if cfg.Control != nil {
		cfg.Control.attach(e)
	}
	e.queue = []job{{tmpl: cfg.Template}}
	first := true
	for len(e.queue) > 0 && ctx.Err() == nil && !e.stop.Load() {
		e.outMu.Lock()
		j := e.queue[0]
		e.queue = e.queue[1:]
		e.stats.Jobs++
		j.n = e.stats.Jobs
		j.hash = fmt.Sprintf("%05x", rand.IntN(1<<20))
		e.cfg.Progress.Queued.Store(int64(len(e.queue)))
		e.outMu.Unlock()
		e.runJob(ctx, j, first)
		first = false
	}
	e.stats.Queued = len(e.queue)
	for o := range e.downOrigs {
		e.stats.Down = append(e.stats.Down, o)
	}
	for _, l := range cfg.Lists {
		if l.Failed != nil && l.Failed.Load() > 0 {
			e.stats.Notes = append(e.stats.Notes, fmt.Sprintf("the command of keyword %s failed %d times: those inputs were empty words (as in ffuf)", l.Keyword, l.Failed.Load()))
		}
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

// tracker is where a stopped run goes on: the first input, counting from
// start, not answered. Answers come out of order, so those past the first gap
// wait in a small set; memory is the gap's width, not the product of the lists.
type tracker struct {
	mu    sync.Mutex
	low   int
	ahead map[int]struct{}
}

func (t *tracker) done(i int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if i != t.low {
		if t.ahead == nil {
			t.ahead = map[int]struct{}{}
		}
		t.ahead[i] = struct{}{}
		return
	}
	t.low++
	for {
		if _, ok := t.ahead[t.low]; !ok {
			return
		}
		delete(t.ahead, t.low)
		t.low++
	}
}

func (t *tracker) first() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.low
}

func (e *engine) runJob(ctx context.Context, j job, first bool) {
	e.skipJob.Store(false)
	e.dispatched.Store(0)
	e.n403.Store(0)
	e.n429.Store(0)
	e.jobNum.Store(int64(j.n))
	pr := e.cfg.Progress
	pr.Job.Store(int64(j.n))
	pr.Done.Store(0)

	tmpls := []Template{j.tmpl}
	if e.cfg.Mode == Sniper {
		tmpls = SniperTemplates(j.tmpl)
	}
	lists := e.activeLists(tmpls[0])
	per := Total(e.cfg.Mode, lists)
	total := per * len(tmpls)
	pr.Total.Store(int64(total))
	start := 0
	if first {
		start = min(e.cfg.Start, total)
	}
	tr := &tracker{low: start}
	sem := make(chan struct{}, e.cfg.Threads)
	var wg sync.WaitGroup
	began := time.Now()
	defer func() {
		if first {
			e.stats.Done = tr.first() - start
		}
	}()
	for i := start; i < total; i++ {
		if ctx.Err() != nil || e.stop.Load() || e.skipJob.Load() {
			break
		}
		if e.cfg.MaxTimeJob > 0 && time.Since(began) >= e.cfg.MaxTimeJob {
			e.count(func(s *Stats) {
				s.CutJobs = append(s.CutJobs, fmt.Sprintf("%s after %d of %d inputs", j.tmpl.URL, i-start, total-start))
			})
			break
		}
		if reason := e.checkStop(); reason != "" {
			e.count(func(s *Stats) { s.StoppedBy = reason })
			e.stop.Store(true)
			break
		}
		if e.cfg.Control != nil {
			e.cfg.Control.wait(ctx)
		}
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			continue
		}
		if e.stop.Load() || e.skipJob.Load() {
			<-sem
			break
		}
		e.dispatched.Add(1)
		wg.Add(1)
		go func(i int) {
			defer func() { <-sem; wg.Done() }()
			if e.task(ctx, j, tmpls[i/per], At(e.cfg.Mode, lists, i%per), i%per+1) {
				tr.done(i)
			}
			pr.Done.Add(1)
			e.sleepDelay(ctx)
		}(i)
	}
	wg.Wait()
}

// sleepDelay is -p: the thread waits before taking its next input.
func (e *engine) sleepDelay(ctx context.Context) {
	d := e.cfg.DelayMin
	if e.cfg.DelayMax > e.cfg.DelayMin {
		d += time.Duration(rand.Int64N(int64(e.cfg.DelayMax - e.cfg.DelayMin)))
	}
	if d <= 0 {
		return
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
	case <-ctx.Done():
	}
}

// checkStop is ffuf's CheckStop for -sf and -sa: with over 50 inputs asked, 403
// over 95% of them, or (-sa) 429 over 20%, ends the run.
func (e *engine) checkStop() string {
	n := e.dispatched.Load()
	if n <= 50 || !(e.cfg.StopOn403 || e.cfg.StopOnAll) {
		return ""
	}
	if float64(e.n403.Load())/float64(n) > 0.95 {
		return fmt.Sprintf("over 95%% of the first %d answers were 403 (-sf/-sa): the target is refusing, or the run is blocked", n)
	}
	if e.cfg.StopOnAll && float64(e.n429.Load())/float64(n) > 0.2 {
		return fmt.Sprintf("over 20%% of the first %d answers were 429 (-sa): the target is rate limiting; lower -rate or -t", n)
	}
	return ""
}

// task sends one input; false when a stop (budget, kill file, the run's
// end) kept it from being asked, so a resume asks it again.
func (e *engine) task(ctx context.Context, j job, tmpl Template, input map[string]string, pos int) bool {
	input["FFUFHASH"] = j.hash + strconv.FormatInt(int64(pos), 16)
	req := tmpl.Expand(input)
	req.Position = pos
	if !e.inScope(&req) {
		e.count(func(s *Stats) { s.OutOfScope++ })
		return true
	}
	resp, err := e.send(ctx, &req)
	if err != nil {
		return !errors.Is(err, neterr.ErrBudget) && ctx.Err() == nil
	}
	switch resp.Status {
	case 403:
		e.n403.Add(1)
	case 429:
		e.n429.Add(1)
	}
	e.calibrate(ctx, tmpl, input, &req)
	if e.cfg.Set.Matches(resp) {
		e.replay(ctx, &req)
		e.emit(resp, &req, j.n)
		if e.cfg.Recursion && e.cfg.Strategy == "greedy" {
			e.recurseGreedy(j, resp)
		}
	}
	if e.cfg.Recursion && e.cfg.Strategy != "greedy" {
		e.recurse(j, resp)
	}
	return true
}

func (e *engine) replay(ctx context.Context, req *Request) {
	if e.cfg.Replay == nil {
		return
	}
	err := e.cfg.Replay.Replay(ctx, req)
	e.count(func(s *Stats) {
		if err != nil {
			s.ReplayErr++
		} else {
			s.Replayed++
		}
	})
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
	e.cfg.Progress.Errors.Add(1)
	if e.cfg.OnError != nil {
		e.cfg.OnError(req, err)
	}
	if os.IsTimeout(err) && e.cfg.Set.HasKind("time") {
		e.count(func(s *Stats) {
			if len(s.Timeouts) < 5 {
				s.Timeouts = append(s.Timeouts, inputText(req.Input))
			}
		})
	}
	if e.cfg.OriginTrips > 0 && (e.cfg.TripOnAnyError || neterr.Unanswered(err)) && int(e.silent.Add(1)) >= e.cfg.OriginTrips {
		e.outMu.Lock()
		e.downOrigs[originOf(req.URL)] = true
		e.outMu.Unlock()
		e.stop.Store(true)
	}
	return nil, err
}

func inputText(in map[string]string) string {
	keys := make([]string, 0, len(in))
	for k := range in {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		fmt.Fprintf(&b, "%s : %s  ", k, in[k])
	}
	return strings.TrimSpace(b.String())
}

func (e *engine) count(f func(*Stats)) {
	e.outMu.Lock()
	f(&e.stats)
	e.outMu.Unlock()
}

func (e *engine) emit(r *Response, req *Request, jobNum int) {
	res := Result{
		Input: req.Input, Position: req.Position, Status: r.Status, Length: r.Length, Words: r.Words, Lines: r.Lines,
		ContentType: r.ContentType, RedirectLocation: RedirectLocation(r, false), URL: req.URL, Duration: r.Duration,
		Host: hostHeaderOf(req), Method: req.Method, Job: jobNum,
		RawRequest: r.RawRequest, RawResponse: r.RawResponse,
	}
	e.outMu.Lock()
	e.stats.Matches++
	e.cfg.Progress.Matches.Add(1)
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
	e.enqueue(j, r.Request.URL)
}

// recurseGreedy is -recursion-strategy greedy: every match is a directory to
// go into.
func (e *engine) recurseGreedy(j job, r *Response) { e.enqueue(j, r.Request.URL) }

func (e *engine) enqueue(j job, base string) {
	if e.cfg.Depth > 0 && j.depth >= e.cfg.Depth {
		return
	}
	t := j.tmpl
	t.URL = base + "/FUZZ"
	e.outMu.Lock()
	e.queue = append(e.queue, job{tmpl: t, depth: j.depth + 1})
	e.cfg.Progress.Queued.Store(int64(len(e.queue)))
	e.outMu.Unlock()
}

// CalibrationGroups are the names calibration asks, a group at a time: a
// group's answers must share a size (else word or line count) for it to
// become a filter. strategies are "basic" (admin…, .htaccess… and a random
// name, each at two lengths) and "advanced" (those and the same as
// directories), or the name of a file of ffuf's kind in
// ~/.config/ffuf/autocalibration; custom (-acc) replaces them all.
func CalibrationGroups(strategies, custom []string) ([][]string, error) {
	if len(custom) > 0 {
		return [][]string{append([]string(nil), custom...)}, nil
	}
	if len(strategies) == 0 {
		strategies = []string{"basic"}
	}
	var keys []string
	groups := map[string][]string{}
	add := func(k string, v []string) {
		if _, ok := groups[k]; !ok {
			keys = append(keys, k)
		}
		for _, w := range v {
			if !slices.Contains(groups[k], w) {
				groups[k] = append(groups[k], w)
			}
		}
	}
	basic := func() {
		add("basic_admin", []string{"admin" + randomName(16), "admin" + randomName(8)})
		add("htaccess", []string{".htaccess" + randomName(16), ".htaccess" + randomName(8)})
		add("basic_random", []string{randomName(16), randomName(8)})
	}
	for _, st := range strategies {
		switch st {
		case "basic":
			basic()
		case "advanced":
			basic()
			add("admin_dir", []string{"admin" + randomName(16) + "/", "admin" + randomName(8) + "/"})
			add("random_dir", []string{randomName(16) + "/", randomName(8) + "/"})
		default:
			raw, err := readStrategy(st)
			if err != nil {
				return nil, fmt.Errorf("-acs %s: %v", st, err)
			}
			var m map[string][]string
			if err := json.Unmarshal(raw, &m); err != nil {
				return nil, fmt.Errorf("-acs %s: %v", st, err)
			}
			names := make([]string, 0, len(m))
			for k := range m {
				names = append(names, k)
			}
			sort.Strings(names)
			for _, k := range names {
				add(k, m[k])
			}
		}
	}
	out := make([][]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, groups[k])
	}
	return out, nil
}

// readStrategy reads a strategy named like ffuf's: NAME.json in its
// autocalibration folder, or a path to such a file.
func readStrategy(name string) ([]byte, error) {
	if raw, err := os.ReadFile(name); err == nil {
		return raw, nil
	}
	if home, err := os.UserHomeDir(); err == nil {
		if raw, err := os.ReadFile(filepath.Join(home, ".config", "ffuf", "autocalibration", name+".json")); err == nil {
			return raw, nil
		}
	}
	return nil, fmt.Errorf("not basic, advanced, a file, or ~/.config/ffuf/autocalibration/%s.json", name)
}

// calibrate asks for names that cannot exist, once, and filters out what
// they answer (once for each host and directory with PerHost). Every task
// waits for it before its answer is judged, as in ffuf.
func (e *engine) calibrate(ctx context.Context, t Template, input map[string]string, asked *Request) {
	if !e.cfg.Calibrate {
		return
	}
	key := ""
	if e.cfg.Set.PerHost {
		key = HostKey(asked)
	}
	e.calMu.Lock()
	defer e.calMu.Unlock()
	if e.calibrated[key] {
		return
	}
	e.calibrated[key] = true
	if !t.Has(e.cfg.CalKeyword) {
		e.count(func(s *Stats) {
			s.Notes = append(s.Notes, "auto-calibration needs the keyword "+e.cfg.CalKeyword+" in the request (-ack names another): nothing was calibrated")
		})
		return
	}
	for _, group := range e.calGroups {
		var resps []*Response
		for _, s := range group {
			in := make(map[string]string, len(input))
			for k, v := range input {
				in[k] = v
			}
			in[e.cfg.CalKeyword] = s
			req := t.Expand(in)
			if !e.inScope(&req) {
				continue
			}
			resp, err := e.send(ctx, &req)
			if err != nil || !e.cfg.Set.Matches(resp) {
				continue
			}
			resps = append(resps, resp)
		}
		e.calibrateFilters(resps, key)
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
func (e *engine) calibrateFilters(rs []*Response, key string) {
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
		var err error
		if e.cfg.Set.PerHost {
			err = e.cfg.Set.AddFilterFor(key, c.kind, v)
		} else {
			err = e.cfg.Set.AddFilter(c.kind, v)
		}
		if err == nil {
			what := c.kind + " " + v
			if key != "" {
				what += " for " + key
			}
			e.count(func(s *Stats) { s.Filters = append(s.Filters, what) })
		}
		return
	}
	e.count(func(s *Stats) {
		s.Notes = append(s.Notes, "auto-calibration: answers to names that cannot exist share no size, word count or line count, so a group of them set no filter")
	})
}

// inScope says whether req may be sent: its URL's host and every host a
// Host-naming header of it names (a front end routes by those) pass Allow.
func (e *engine) inScope(req *Request) bool {
	return InScope(e.cfg.Allow, req, e.cfg.OpenHeaders)
}

// InScope is that check for any sender of a request: allow nil lets all
// through, and the headers named in open (lower case) are not held to it.
func InScope(allow func(string) bool, req *Request, open map[string]bool) bool {
	if allow == nil {
		return true
	}
	if !allow(hostOf(req.URL)) {
		return false
	}
	for _, h := range req.Headers {
		if !scope.NamesHost(h.Name) || open[strings.ToLower(h.Name)] {
			continue
		}
		for _, host := range scope.HeaderHosts(h.Value) {
			if !allow(host) {
				return false
			}
		}
	}
	return true
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
		if strings.EqualFold(h.Name, "Host") {
			return h.Value
		}
	}
	u, err := url.Parse(req.URL)
	if err != nil {
		return ""
	}
	return u.Host
}
