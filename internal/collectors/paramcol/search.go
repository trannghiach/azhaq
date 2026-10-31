package paramcol

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/trannghiach/azhaq/engine"
	"github.com/trannghiach/azhaq/internal/fetch"
	"github.com/trannghiach/azhaq/internal/neterr"
	"github.com/trannghiach/azhaq/internal/webextract"
	"github.com/trannghiach/azhaq/types"
)

// answer is what a request is compared on.
type answer struct {
	status, length, words, lines int
	body                         []byte
	hdr                          []string // header names, lower case, sorted
	loc                          string   // path of the Location header
	ctype                        string
}

func answerOf(resp *http.Response, body []byte) answer {
	a := withBody(answer{status: resp.StatusCode}, body)
	for k := range resp.Header {
		a.hdr = append(a.hdr, strings.ToLower(k))
	}
	sort.Strings(a.hdr)
	if l := resp.Header.Get("Location"); l != "" {
		if u, err := url.Parse(l); err == nil {
			a.loc = u.Path
		} else {
			a.loc = l
		}
	}
	a.ctype = strings.ToLower(resp.Header.Get("Content-Type"))
	return a
}

func withBody(a answer, body []byte) answer {
	a.length, a.body = len(body), body
	a.words = bytes.Count(body, []byte{' '}) + 1
	a.lines = bytes.Count(bytes.TrimSpace(body), []byte{'\n'}) + 1
	return a
}

// pair is one name=value of a request; a list, as a control may repeat a name.
type pair struct{ name, value string }

type search struct {
	c       *Collector
	ctx     context.Context
	base    *url.URL
	method  string
	include string
	header  []string
	known   map[string]bool
	// fixed are names found earlier, sent with every request of a later
	// pass (see deepen); fixedW is what they add to a request, in bytes.
	fixed   []pair
	fixedW  int
	sem     chan struct{}
	session bool // the run or the page's own headers carry a session

	ref       answer
	slack     int // size difference the page shows between identical requests
	lineSlack int // and in lines
	hdrNoise  map[string]bool
	// exact: three identical requests got the same body, so any other body,
	// by one byte, is a change (a page of one error message among several).
	exact      bool
	refWords   map[string]bool // the words of the reference answers
	noEcho     bool            // the page prints any name it gets: no name is evidence
	controlled bool            // see calibrate
	requests   atomic.Int64

	mu sync.Mutex
	// most and maxBytes are the largest group sent: smaller than any whose
	// control changed the status (a query too long for the server).
	most     int
	maxBytes int
	err      error // the request budget ran out
	// stopped: the page limits requests (429, 418, 503) and kept doing so
	// after the waits; the search ends there.
	stopped error
	// lost counts requests that got no answer, lostWhy the last cause;
	// skip says why calibration left the page alone.
	lost    int
	lostWhy string
	skip    string
	note    string // said in the page's row
	floodAt int    // the first chunk of a page that answers any name
	badXML  int    // names that cannot be XML elements
}

func newSearch(c *Collector, ctx context.Context, u *url.URL, tg Target) *search {
	s := &search{c: c, ctx: ctx, base: u, method: tg.Method, include: tg.Include, header: tg.Header,
		known: map[string]bool{}, sem: make(chan struct{}, c.Opts.Threads), most: c.Opts.Chunk, floodAt: math.MaxInt}
	if tg.Method == GET {
		// Servers commonly refuse a request line past 8 KB (nginx, Apache,
		// older Node): stay under it
		// and under a lower one when it shows one.
		s.maxBytes = getBytes - len(u.RawQuery) - len(tg.Include)
	}
	s.session = fetch.HasSession()
	for _, h := range tg.Header {
		if k, v, ok := strings.Cut(h, ":"); ok && fetch.SessionHeader(strings.TrimSpace(k), strings.TrimSpace(v)) {
			s.session = true
		}
	}
	for k := range u.Query() {
		s.known[k] = true
	}
	for _, k := range includedNames(tg.Method, tg.Include) {
		s.known[k] = true
	}
	return s
}

func (s *search) halted() bool {
	if s.ctx.Err() != nil {
		return true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err != nil || s.stopped != nil
}

// chunk is a group of names searched on its own: what its halves found and
// how many names it tried alone.
type chunk struct {
	idx   int
	names []string
	fixed string // a value every name gets; empty: a random one each

	mu          sync.Mutex
	found       map[string]string
	alone, hits int
	// reads: random names made like the chunk's changed nothing, so the
	// names that do are read, however many.
	reads        bool
	any          bool // the page answers any name
	tried, count int  // what said so
}

func (ck *chunk) set(name, why string) {
	ck.mu.Lock()
	ck.found[name] = why
	ck.mu.Unlock()
}

func (ck *chunk) has(name string) bool {
	ck.mu.Lock()
	defer ck.mu.Unlock()
	_, ok := ck.found[name]
	return ok
}

// flooded: nearly every name tested alone changed the answer, as on a
// page that reacts to any name. The chunk is not narrowed further.
func (ck *chunk) flooded() bool {
	ck.mu.Lock()
	defer ck.mu.Unlock()
	return !ck.reads && ck.hits >= 2*minFlood && ck.hits*4 > ck.alone*3
}

// run searches the page and emits its row.
func (s *search) run(page string, emit func(types.Observation) error) (types.RunMeta, error) {
	words := s.candidates()
	if !s.calibrate(words) {
		switch {
		case s.err != nil:
			return types.RunMeta{}, nil // spent
		case s.ctx.Err() != nil:
			return types.RunMeta{Status: types.StatusCancelled}, s.ctx.Err()
		}
		s.mu.Lock()
		failed := s.stopped != nil || s.lost > 0
		s.mu.Unlock()
		if failed {
			return s.give(page, emit, nil, nil, nil)
		}
		// The page changes by itself, or is not one to search: said.
		return types.RunMeta{Status: types.StatusOK, EmitCount: 1}, s.skipped(emit, page)
	}
	// What the page itself names goes first, then the list.
	own := s.harvest(s.ref)
	var names []string
	seen := map[string]bool{}
	for _, n := range own {
		if !s.known[n] && !seen[n] {
			seen[n] = true
			names = append(names, n)
		}
	}
	for _, n := range words {
		if !seen[n] {
			seen[n] = true
			names = append(names, n)
		}
	}
	chunks := s.plan(names)
	// The toggle names are asked beside the list, to spend no time after it.
	var toggled []toggleAnswer
	var tw sync.WaitGroup
	tw.Add(1)
	go func() {
		defer tw.Done()
		toggled = s.askToggles()
	}()
	s.searchChunks(chunks)
	tw.Wait()
	if s.ctx.Err() != nil {
		return types.RunMeta{Status: types.StatusCancelled}, s.ctx.Err()
	}
	s.mu.Lock()
	spent := s.err != nil
	s.mu.Unlock()
	if spent {
		return types.RunMeta{}, nil
	}
	found := map[string]string{}
	notes := s.gather(page, chunks, found)
	floodAt := s.floodAt
	values := map[string]string{}
	if floodAt == math.MaxInt && !s.halted() {
		s.toggles(toggled, found, values)
		// Only a page that refuses a request without its input (400, 422)
		// reports required fields one at a time; a page that answers is not
		// asked again, which keeps a plain sweep as cheap as arjun's.
		if st := s.ref.status; st == http.StatusBadRequest || st == http.StatusUnprocessableEntity {
			notes = append(notes, s.deepen(page, names, found, values)...)
		}
		switch {
		case s.ctx.Err() != nil:
			return types.RunMeta{Status: types.StatusCancelled}, s.ctx.Err()
		case s.spentNow():
			return types.RunMeta{}, nil
		}
	}
	s.mu.Lock()
	bad := s.badXML
	s.mu.Unlock()
	if bad > 0 {
		notes = append(notes, fmt.Sprintf("%s: %d names are not valid XML element names and were not sent", page, bad))
	}
	return s.give(page, emit, found, values, notes)
}

// gather adds what chunks found to found, up to the first group of a page
// that answers any name, and says that page.
func (s *search) gather(page string, chunks []*chunk, found map[string]string) []string {
	var notes []string
	for _, ck := range chunks {
		if ck.idx > s.floodAt {
			break
		}
		if ck.any {
			rest := "not searched for parameters"
			if len(found) > 0 {
				rest = "not searched further"
			}
			notes = append(notes, fmt.Sprintf("%s answers names it does not read (%d of %d names tried changed the answer): %s", page, ck.count, ck.tried, rest))
			break
		}
		for n, why := range ck.found {
			found[n] = why
		}
	}
	return notes
}

func (s *search) spentNow() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err != nil
}

// deepPasses is how often the names not found are asked again.
const deepPasses = 3

// deepen asks the names not found again with the names found so far in
// every request, against a reference taken the same way: a required field
// that the page reports one at a time (the first missing one) changes
// nothing until the ones before it are given. It repeats while a pass
// finds more, at most deepPasses times, and adds what it finds to found
// (and values, for a toggle), with a why that says what was present.
func (s *search) deepen(page string, names []string, found, values map[string]string) []string {
	var notes []string
	given := map[string]string{} // the value each found name is sent with
	for pass := 0; pass < deepPasses && len(found) > 0 && !s.halted(); pass++ {
		var rest []string
		for _, n := range names {
			if _, ok := found[n]; !ok {
				rest = append(rest, n)
			}
		}
		present := make([]string, 0, len(found))
		for n := range found {
			present = append(present, n)
		}
		sort.Strings(present)
		prevW := s.fixedW
		s.fixed, s.fixedW = s.fixed[:0], 0
		for _, n := range present {
			v := values[n]
			if v == "" {
				if given[n] == "" {
					given[n] = randValue()
				}
				v = given[n]
			}
			s.fixed = append(s.fixed, pair{n, v})
			s.fixedW += s.weight(pair{n, v})
			s.known[n] = true
		}
		s.mu.Lock()
		if s.maxBytes > 0 {
			s.maxBytes = max(s.maxBytes-(s.fixedW-prevW), 1)
		}
		s.mu.Unlock()
		s.noEcho, s.exact, s.controlled, s.skip, s.floodAt = false, false, false, "", math.MaxInt
		if !s.calibrate(rest) {
			if s.skip != "" && !s.halted() {
				notes = append(notes, fmt.Sprintf("%s: names not found were not asked again with %s present: %s", page, joinNames(present), s.skip))
			}
			break
		}
		chunks := s.plan(rest)
		var toggled []toggleAnswer
		var tw sync.WaitGroup
		tw.Add(1)
		go func() {
			defer tw.Done()
			toggled = s.askToggles()
		}()
		s.searchChunks(chunks)
		tw.Wait()
		if s.halted() {
			break
		}
		more := map[string]string{}
		notes = append(notes, s.gather(page, chunks, more)...)
		if s.floodAt == math.MaxInt {
			// toggles skips what found holds: it gets both.
			for n, why := range found {
				more[n] = why
			}
			s.toggles(toggled, more, values)
		}
		added := 0
		for n, why := range more {
			if _, ok := found[n]; !ok {
				found[n] = why + ", once " + presence(present) + " present"
				added++
			}
		}
		if added == 0 {
			break
		}
	}
	s.fixed, s.fixedW = nil, 0
	return notes
}

// joinNames is "a", "a and b", "a, b and c"; past three, "a, b, c and 2 more".
func joinNames(n []string) string {
	if len(n) > 3 {
		return fmt.Sprintf("%s and %d more", strings.Join(n[:3], ", "), len(n)-3)
	}
	if len(n) < 2 {
		return strings.Join(n, "")
	}
	return strings.Join(n[:len(n)-1], ", ") + " and " + n[len(n)-1]
}

func presence(n []string) string {
	if len(n) == 1 {
		return n[0] + " was"
	}
	return joinNames(n) + " were"
}

// candidates are the names to try: trimmed, without repeats, without what
// the request already carries and, with a session, without what reads like
// an action.
func (s *search) candidates() []string {
	var words []string
	seen := map[string]bool{}
	careful := s.session && !s.c.Opts.AllGets
	for _, w := range s.c.Opts.Words {
		w = strings.TrimSpace(w)
		if w == "" || s.known[w] || seen[w] {
			continue
		}
		if careful && webextract.StateChanging("/?action="+url.QueryEscape(w)) != "" {
			continue // with a session, a name like delete or logout is not sent
		}
		if s.method == XML && !xmlName(w) {
			s.badXML++
			continue
		}
		seen[w] = true
		words = append(words, w)
	}
	return words
}

// plan cuts names into the groups sent: at most Chunk names and, when the
// server showed a limit, at most maxBytes.
func (s *search) plan(names []string) []*chunk {
	var out []*chunk
	cut := func(list []string) {
		for len(list) > 0 {
			n, w := 0, 0
			for n < len(list) && n < s.c.Opts.Chunk {
				pw := s.weight(pair{list[n], strings.Repeat("v", valueLen)})
				if s.maxBytes > 0 && n > 0 && w+pw > s.maxBytes {
					break
				}
				w += pw
				n++
			}
			out = append(out, &chunk{idx: len(out), names: list[:n], found: map[string]string{}})
			list = list[n:]
		}
	}
	cut(names)
	return out
}

// searchChunks runs the groups, Threads of them at a time. A page that
// answers any name ends the search at its first such group: later groups
// are dropped, earlier ones stand.
func (s *search) searchChunks(chunks []*chunk) {
	work := make(chan *chunk)
	var wg sync.WaitGroup
	for i := 0; i < min(s.c.Opts.Threads, len(chunks)); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ck := range work {
				s.mu.Lock()
				skip := ck.idx > s.floodAt
				s.mu.Unlock()
				if !skip && !s.halted() {
					s.runChunk(ck)
				}
			}
		}()
	}
	for _, ck := range chunks {
		work <- ck
	}
	close(work)
	wg.Wait()
}

func (s *search) runChunk(ck *chunk) {
	s.narrow(ck, ck.names)
	hits := 0
	for _, n := range ck.names {
		if ck.has(n) {
			hits++
		}
	}
	tried := len(ck.names)
	stopped := ck.flooded()
	if stopped {
		hits, tried = ck.hits, ck.alone
	}
	if !stopped && (len(ck.names) < minFlood || hits*2 <= len(ck.names)) || s.halted() {
		return
	}
	// Most names "change" the answer: a page that reacts to names it
	// does not read, or one that reads most of a short list (names
	// taken from its own scripts). Random names made like these tell.
	if s.anyName(ck.names) {
		if s.halted() {
			return
		}
		ck.any, ck.count, ck.tried = true, hits, tried
		s.mu.Lock()
		s.floodAt = min(s.floodAt, ck.idx)
		s.mu.Unlock()
		return
	}
	if stopped {
		// The narrowing stopped at what looked like a flood: finish it.
		var left []string
		for _, n := range ck.names {
			if !ck.has(n) {
				left = append(left, n)
			}
		}
		ck.mu.Lock()
		ck.reads = true
		ck.mu.Unlock()
		s.narrow(ck, left)
		ck.mu.Lock()
		ck.reads = false
		ck.mu.Unlock()
	}
}

// anyName says whether random names made like group's (as many, letters,
// as long and at least 6, which no page reads) change the answer too: the
// page reacts to names it does not read. A request that could not be sent
// says nothing to keep group's finds on.
func (s *search) anyName(group []string) bool {
	names := make([]string, min(len(group), s.maxGroup()))
	for i := range names {
		names[i] = randomName(max(6, len(group[i])))
	}
	v, ok := s.test(names, "")
	return !ok || v.crowd || v.why != "" || len(v.reflected) > 0 || len(v.named) > 0
}

// floodedAt is the first group of the page that answers any name, or a
// number past every group.
func (s *search) floodedAt() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.floodAt
}

// maxGroup is the most names one request carries now.
func (s *search) maxGroup() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.most
}

// tooBig says group is larger than the server took.
func (s *search) tooBig(group []string) bool {
	s.mu.Lock()
	most, maxBytes := s.most, s.maxBytes
	s.mu.Unlock()
	if len(group) > most {
		return true
	}
	if maxBytes > 0 && len(group) > 1 {
		w := 0
		for _, n := range group {
			w += s.weight(pair{n, strings.Repeat("v", valueLen)})
		}
		return w > maxBytes
	}
	return false
}

// shrink: group was refused, whatever its names.
func (s *search) shrink(group []string) {
	w := 0
	for _, n := range group {
		w += s.weight(pair{n, strings.Repeat("v", valueLen)})
	}
	s.mu.Lock()
	s.most = min(s.most, len(group)-1)
	if s.maxBytes == 0 || w-1 < s.maxBytes {
		s.maxBytes = w - 1
	}
	s.mu.Unlock()
}

// limiting: the statuses of a server telling the client to slow down.
func limiting(code int) bool {
	return code == http.StatusTooManyRequests || code == http.StatusTeapot || code == http.StatusServiceUnavailable
}

// get asks the page with q added. A 429, 418 or 503 that the page did not
// give for unknown names before is waited out, as long as its Retry-After
// says (at most 30 s) or 1, 2 and 4 s; if it persists the search stops
// with s.stopped set.
func (s *search) get(q []pair) (answer, bool) { return s.ask(q, false) }

// ask is get; quiet: a request that gets no answer is not counted as lost
// (probing how long a query the server takes).
func (s *search) ask(q []pair, quiet bool) (answer, bool) {
	for attempt := 0; ; attempt++ {
		a, wait, ok := s.once(q, quiet)
		if wait == 0 {
			return a, ok
		}
		if attempt >= len(s.c.Opts.Backoff) {
			s.mu.Lock()
			if s.stopped == nil {
				s.stopped = fmt.Errorf("HTTP %d from the target: it limits requests", a.status)
			}
			s.mu.Unlock()
			return answer{}, false
		}
		wait = min(max(wait, s.c.Opts.Backoff[attempt]), 30*time.Second)
		s.c.holdFor(s.base.Host, wait) // every request of the host waits, not only this one
		if !s.sleep(wait) {
			return answer{}, false
		}
	}
}

// sleep waits d; false if the run ended first.
func (s *search) sleep(d time.Duration) bool {
	if d <= 0 {
		return s.ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-s.ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// lose counts a request that got no answer.
func (s *search) lose(quiet bool, err error) {
	if quiet || s.ctx.Err() != nil {
		return
	}
	s.mu.Lock()
	s.lost++
	s.lostWhy = engine.ShortError(err.Error())
	s.mu.Unlock()
}

// once sends one request. wait is not zero when the page limited it: the
// time its Retry-After asks for, or 1 ns.
func (s *search) once(q []pair, quiet bool) (a answer, wait time.Duration, ok bool) {
	select {
	case s.sem <- struct{}{}:
		defer func() { <-s.sem }()
	case <-s.ctx.Done():
		return answer{}, 0, false
	}
	if d := s.c.held(s.base.Host); d > 0 && !s.sleep(d) {
		return answer{}, 0, false
	}
	// One at a time and paced, when the user asked for it.
	if s.c.Opts.Stable {
		if !s.sleep(3*time.Second + time.Duration(randInt(6000))*time.Millisecond) {
			return answer{}, 0, false
		}
	} else if s.c.Opts.Delay > 0 && !s.sleep(s.c.Opts.Delay) {
		return answer{}, 0, false
	}
	if err := s.c.limiter.Wait(s.ctx, s.base.Host); err != nil {
		return answer{}, 0, false
	}
	if fetch.EndsSessionWith(s.base.String(), s.session) {
		s.mu.Lock()
		s.skip = "the page's address ends the session"
		s.mu.Unlock()
		return answer{}, 0, false
	}
	var resp *http.Response
	var body []byte
	timeout := s.c.Opts.Timeout
	refused := 0
	for {
		req, err := s.newRequest(q)
		if err != nil {
			return answer{}, 0, false
		}
		if err := fetch.Spend(s.ctx); err != nil {
			if errors.Is(err, neterr.ErrBudget) {
				s.mu.Lock()
				s.err = err
				s.mu.Unlock()
			}
			return answer{}, 0, false
		}
		s.requests.Add(1)
		rctx, cancel := context.WithTimeout(s.ctx, timeout)
		resp, err = s.c.Client.Do(req.WithContext(rctx))
		if err == nil {
			body, err = io.ReadAll(io.LimitReader(resp.Body, 2<<20))
			resp.Body.Close()
			if err != nil {
				err = fmt.Errorf("answer cut off: %w", err)
			}
		}
		cancel()
		if err == nil {
			break
		}
		if s.ctx.Err() != nil {
			return answer{}, 0, false
		}
		switch {
		case timedOut(err) && timeout+5*time.Second <= 20*time.Second:
			// A slow page is asked again with more time, as arjun does.
			timeout += 5 * time.Second
			continue
		case s.c.Opts.Stable && refusedConn(err) && refused < 3:
			// A fragile server that refuses connections is given time.
			refused++
			if !s.sleep(30 * time.Second) {
				return answer{}, 0, false
			}
			continue
		}
		s.lose(quiet, err)
		return answer{}, 0, false
	}
	a = answerOf(resp, body)
	s.mu.Lock()
	refStatus := s.ref.status
	s.mu.Unlock()
	if limiting(resp.StatusCode) && resp.StatusCode != refStatus {
		wait = time.Nanosecond
		if n, err := strconv.Atoi(strings.TrimSpace(resp.Header.Get("Retry-After"))); err == nil && n > 0 {
			wait = time.Duration(n) * time.Second
		}
		return a, wait, false
	}
	return a, 0, true
}

func timedOut(err error) bool {
	var ne net.Error
	return errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout())
}

func refusedConn(err error) bool {
	return strings.Contains(err.Error(), "connection refused")
}

// calibrate takes the page twice with one random parameter, then once
// with a group of them as large as a chunk: one unknown name should change
// nothing, what changes between the first two is the page's own noise,
// and a page that answers the group otherwise is searched with controls.
// A server that refuses the group (a query too long: another status) is
// asked with fewer names until it answers as before: that is the size of a
// group.
func (s *search) calibrate(words []string) bool {
	one := randomPairs(1)
	// The two baselines and the crowd are independent: one round trip.
	crowd := s.crowd(words)
	var a, b, c answer
	var okA, okB, okC bool
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); a, okA = s.get(one) }()
	go func() { defer wg.Done(); b, okB = s.get(randomPairs(1)) }()
	c, okC = s.ask(crowd, true)
	wg.Wait()
	if !okA || !okB {
		return false
	}
	if a.status != b.status {
		s.skip = fmt.Sprintf("the page answers %d, then %d, to the same request", a.status, b.status)
		return false
	}
	if why := notText(a.ctype); why != "" {
		s.skip = why
		return false
	}
	if s.method != GET && (a.status == http.StatusMethodNotAllowed || a.status == http.StatusNotImplemented) {
		s.skip = fmt.Sprintf("the page answers %d to %s", a.status, s.method)
		return false
	}
	s.mu.Lock()
	s.ref = a
	s.mu.Unlock()
	if a.status >= 500 {
		// The page may be failing for every request, not reading names.
		s.note = fmt.Sprintf("the page answers %d to a request with one unknown name; a failing page hides parameters", a.status)
	}
	s.slack = abs(a.length - b.length)
	if s.slack >= a.length/2+64 {
		s.skip = fmt.Sprintf("the page changes by itself (%d and %d bytes for the same request)", a.length, b.length)
		return false
	}
	s.lineSlack = abs(a.lines - b.lines)
	s.hdrNoise = map[string]bool{}
	for _, h := range symDiff(a.hdr, b.hdr) {
		s.hdrNoise[h] = true
	}
	s.refWords = wordSet(a.body, wordSet(b.body, nil))
	if len(echoed(a.body, pairNames(one), nil)) > 0 {
		s.noEcho = true
	}
	if !okC {
		s.mu.Lock()
		hard := s.stopped != nil || s.err != nil
		s.mu.Unlock()
		if hard || s.ctx.Err() != nil {
			return false
		}
	}
	if !okC || c.status != a.status {
		// The server took one name but not this many.
		var fit []pair
		var ok bool
		fit, c, ok = s.fit(crowd, a)
		if !ok {
			return false
		}
		crowd = fit
	}
	if len(echoed(c.body, pairNames(crowd), nil)) > 0 {
		s.noEcho = true
	}
	s.controlled = len(tokens(a.body, one)) > 0 || s.differs(c, s.ref, crowd)
	s.exact = !s.controlled && bytes.Equal(a.body, b.body) && bytes.Equal(strip(c, crowd).body, a.body)
	return true
}

// crowd is as many random names as a group holds, as long as the words'.
func (s *search) crowd(words []string) []pair {
	n := min(s.c.Opts.Chunk, max(len(words), 1))
	out := make([]pair, 0, n)
	w := 0
	for i := 0; i < n; i++ {
		l := 8
		if len(words) > 0 {
			l = max(6, len(words[i%len(words)]))
		}
		p := pair{randomName(l), randValue()}
		if w += s.weight(p); s.maxBytes > 0 && w > s.maxBytes && len(out) > 0 {
			break
		}
		out = append(out, p)
	}
	return out
}

// getBytes is the longest query a first request carries.
const getBytes = 7600

// fit finds how many of crowd's names the server answers as it does one:
// halving down, then closing in. It sets the largest group (names and
// bytes) it took, and returns that crowd and its answer.
func (s *search) fit(crowd []pair, ref answer) ([]pair, answer, bool) {
	good, bad := 1, len(crowd)
	var goodAns answer
	ok := func(n int) bool {
		a, got := s.ask(crowd[:n], true)
		s.mu.Lock()
		hard := s.stopped != nil || s.err != nil
		s.mu.Unlock()
		if hard {
			return false
		}
		if got && a.status == ref.status {
			good, goodAns = n, a
			return true
		}
		bad = n
		return false
	}
	for n := len(crowd) / 2; n > 1; n /= 2 {
		if ok(n) {
			break
		}
		if s.halted() {
			return nil, answer{}, false
		}
	}
	for bad-good > 1 && float64(bad) > float64(good)*1.5 {
		ok((good + bad) / 2)
		if s.halted() {
			return nil, answer{}, false
		}
	}
	if s.halted() {
		return nil, answer{}, false
	}
	if good < 2 {
		s.skip = "the page refuses a request with more than one extra parameter"
		return nil, answer{}, false
	}
	if goodAns.status == 0 {
		goodAns = ref
	}
	w := 0
	for _, p := range crowd[:good] {
		w += s.weight(p)
	}
	s.mu.Lock()
	s.most = min(s.most, good)
	s.maxBytes = w * 95 / 100
	s.mu.Unlock()
	return crowd[:good], goodAns, true
}

// differs says whether a, the answer to q, is not ref: another status, a
// value of q in it, another size, other headers, another redirect, or a
// name of q printed in it.
func (s *search) differs(a, ref answer, q []pair) bool {
	return s.judge(a, ref) != "" || len(tokens(a.body, q)) > 0 || len(s.named(a, q)) > 0
}

// judge names how a differs from ref apart from reflected values and
// names: status, size, headers, location or lines; empty if it does not.
func (s *search) judge(a, ref answer) string {
	switch {
	case a.status != ref.status:
		return "status"
	case s.resized(a, ref):
		return "size"
	case s.headers(a, ref):
		return "headers"
	case a.loc != ref.loc:
		return "location"
	case abs(a.lines-ref.lines) > s.lineSlack:
		return "lines"
	case s.exact && !bytes.Equal(a.body, ref.body):
		return "body"
	}
	return ""
}

// resized: the sizes differ by more than the page's noise.
func (s *search) resized(a, ref answer) bool {
	if abs(a.length-ref.length) > s.slack+s.slack/2+16 {
		return true
	}
	return s.slack == 0 && (a.words != ref.words || a.lines != ref.lines)
}

// headers: a header the reference lacks, or lacks one it has, other than
// those that came and went between the two identical requests.
func (s *search) headers(a, ref answer) bool {
	for _, h := range symDiff(a.hdr, ref.hdr) {
		if !s.hdrNoise[h] {
			return true
		}
	}
	return false
}

// named lists the names of q (of at least 5 characters) the answer prints
// between quotes or spaces, which the reference answers do not hold: the
// page says what it did with a name.
func (s *search) named(a answer, q []pair) []string {
	if s.noEcho {
		return nil
	}
	return echoed(a.body, pairNames(q), s.refWords)
}

// verdict is what a group of names did to the answer.
type verdict struct {
	why       string   // what some name of the group changed in the answer
	reflected []string // names whose value came back more often than a control's
	named     []string // names the answer prints
	crowd     bool     // the control changed the status too: the group's size did, not its names
}

// test sends group with random values, or with value when it is given.
// Against ref when the page ignores unknown names; otherwise, once the
// answer differs from ref, against a control of random names as long as
// the group's: what the control shows too (an echoed query string, the
// error a long query gets) is no evidence.
func (s *search) test(group []string, value string) (verdict, bool) {
	q := make([]pair, len(group))
	for i, n := range group {
		q[i] = pair{n, value}
		if value == "" {
			q[i].value = randValue()
		}
	}
	a, ok := s.get(q)
	if !ok {
		return verdict{}, false
	}
	if !s.differs(a, s.ref, q) {
		return verdict{}, true
	}
	base, echo := s.ref, 0
	var control []pair
	if s.controlled {
		control = controlFor(group, value)
		c, ok := s.get(control)
		if !ok {
			return verdict{}, false
		}
		base = c
		for _, n := range tokens(c.body, control) {
			echo = max(echo, n)
		}
	}
	var v verdict
	counts := tokens(a.body, q)
	for _, p := range q {
		if counts[p.value] > echo {
			v.reflected = append(v.reflected, p.name)
		}
	}
	v.named = s.named(a, q)
	// The values are taken out of both answers: a reflection is judged
	// above, by its count, and is not a change of size as well.
	v.why = s.judge(strip(a, q), strip(base, control))
	v.crowd = s.controlled && base.status != s.ref.status && a.status == base.status
	return v, true
}

// narrow finds which names in group change the answer, halving the group
// while it does.
func (s *search) narrow(ck *chunk, group []string) {
	if len(group) == 0 || s.halted() || ck.flooded() || ck.idx > s.floodedAt() {
		return
	}
	if s.tooBig(group) {
		// A group this large is refused whatever its names.
		s.halves(ck, group, nil)
		return
	}
	if v, ok := s.ask1(ck, group); ok {
		s.process(ck, group, v, false)
	}
}

// ask1 is test for a group of ck, counting singles for the flood rule.
func (s *search) ask1(ck *chunk, group []string) (verdict, bool) {
	if len(group) == 1 {
		ck.mu.Lock()
		ck.alone++
		ck.mu.Unlock()
	}
	return s.test(group, ck.fixed)
}

// process acts on v, what group did to the answer: records what it
// found, and splits it while it changes the answer. inferred: v is its
// parent's, the group's other half having changed nothing.
func (s *search) process(ck *chunk, group []string, v verdict, inferred bool) {
	if v.crowd && len(group) > 1 {
		s.shrink(group)
	}
	for _, n := range v.reflected {
		if slicesHas(group, n) {
			ck.set(n, "reflected") // the value that came back names the parameter
		}
	}
	for _, n := range v.named {
		// A name the page prints is asked again alone: it must print it again.
		if slicesHas(group, n) && !ck.has(n) {
			if w, ok := s.test([]string{n}, ck.fixed); ok && slicesHas(w.named, n) {
				ck.set(n, "named")
			}
		}
	}
	if v.why == "" && !v.crowd {
		return
	}
	if len(v.reflected) > 0 || len(v.named) > 0 {
		// Others in the group may change the answer in other ways.
		var rest []string
		for _, n := range group {
			if !ck.has(n) {
				rest = append(rest, n)
			}
		}
		if len(rest) < len(group) {
			s.narrow(ck, rest)
			return
		}
	}
	if len(group) == 1 {
		if v.crowd {
			return
		}
		// Confirm: a single change must show again. (An inferred one has: its
		// group changed the answer, its other half did not, and alone it
		// does again.)
		if !inferred {
			if w, ok := s.test(group, ck.fixed); !ok || w.why == "" || w.crowd {
				return
			}
		}
		ck.set(group[0], v.why)
		ck.mu.Lock()
		ck.hits++
		ck.mu.Unlock()
		return
	}
	s.halves(ck, group, &v)
}

// parallelHalves is the group size from which the halves go side by side;
// unpaced is the rate that means no pace.
const (
	parallelHalves = 4
	unpaced        = 1e6
)

// halves narrows each half of group, in turn, not at the same time:
// reaching single names early is what stops the search on a page that
// answers any name (groups of a list run side by side instead). When the
// first half changes nothing and the group's change was in what the
// answer holds (not a reflected value or name), the second half has the
// names: it is split without being asked first.
func (s *search) halves(ck *chunk, group []string, v *verdict) {
	half := len(group) / 2
	first, second := group[:half], group[half:]
	if len(group) >= parallelHalves && s.c.Opts.Rate >= unpaced {
		// With no pace to keep, big halves are asked at the same time: the
		// time it takes is the depth, not the count. (With a pace, requests
		// are the cost, and the second half is inferred.)
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.narrow(ck, first)
		}()
		s.narrow(ck, second)
		wg.Wait()
		return
	}
	if v == nil || v.why == "" || v.crowd || len(v.reflected) > 0 || len(v.named) > 0 {
		s.narrow(ck, first)
		s.narrow(ck, second)
		return
	}
	if len(first) == 0 || s.halted() || ck.flooded() || ck.idx > s.floodedAt() {
		return
	}
	w, ok := s.ask1(ck, first)
	if !ok {
		return
	}
	s.process(ck, first, w, false)
	if w.why == "" && !w.crowd && len(w.reflected) == 0 && len(w.named) == 0 && !s.halted() {
		if len(second) == 1 {
			ck.mu.Lock()
			ck.alone++
			ck.mu.Unlock()
		}
		s.process(ck, second, *v, true)
		return
	}
	s.narrow(ck, second)
}

// tokens counts how often each value of q appears in body, the values
// that do. Every value is "az" and 8 hex digits, so the body is read once.
func tokens(body []byte, q []pair) map[string]int {
	if len(q) == 0 {
		return nil
	}
	want := make(map[string]bool, len(q))
	for _, p := range q {
		want[p.value] = true
	}
	var out map[string]int
	for i := 0; ; {
		j := bytes.Index(body[i:], []byte("az"))
		if j < 0 {
			return out
		}
		i += j
		if i+valueLen <= len(body) && want[string(body[i:i+valueLen])] {
			if out == nil {
				out = map[string]int{}
			}
			out[string(body[i:i+valueLen])]++
			i += valueLen
			continue
		}
		i++
	}
}

// strip is a without the values of q in its body.
func strip(a answer, q []pair) answer {
	counts := tokens(a.body, q)
	if len(counts) == 0 {
		return a
	}
	body := a.body
	for v := range counts {
		body = bytes.ReplaceAll(body, []byte(v), nil)
	}
	return withBody(a, body)
}

// valueLen is the length of randValue's values.
const valueLen = 10

func randValue() string {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return "az" + hex.EncodeToString(b[:])
}

func randInt(n int) int {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return int(uint32(b[0])|uint32(b[1])<<8|uint32(b[2])<<16|uint32(b[3])<<24) % n
}

// randomName is n letters no page reads.
func randomName(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	for j := range b {
		b[j] = 'a' + b[j]%26
	}
	return string(b)
}

// randomPairs are n names no page reads, with random values.
func randomPairs(n int) []pair {
	out := make([]pair, n)
	for i := range out {
		out[i] = pair{randValue(), randValue()}
	}
	return out
}

func pairNames(q []pair) []string {
	out := make([]string, len(q))
	for i, p := range q {
		out[i] = p.name
	}
	return out
}

// controlAlphabet is what control names are made of after their "~": all
// of it is sent as it is.
const controlAlphabet = "abcdefghijklmnopqrstuvwxyz0123456789_-"

// controlFor is a name for each of group's, as long once escaped, that no
// page reads ("~" and letters; "~" is never escaped), with random values
// (or value): a page that prints the query back prints the same length
// for both. The names differ from each other where their length allows,
// as a page that counts the names would see fewer of them otherwise.
func controlFor(group []string, value string) []pair {
	out := make([]pair, len(group))
	used := map[string]bool{}
	for i, n := range group {
		l := max(1, len(url.QueryEscape(n)))
		var name string
		for try := 0; try < 20; try++ {
			b := make([]byte, l)
			_, _ = rand.Read(b)
			b[0] = '~'
			for j := 1; j < l; j++ {
				b[j] = controlAlphabet[int(b[j])%len(controlAlphabet)]
			}
			if name = string(b); !used[name] {
				break
			}
		}
		used[name] = true
		out[i] = pair{name, value}
		if value == "" {
			out[i].value = randValue()
		}
	}
	return out
}

// notText says why a content type is not a page to search: arjun's rule,
// text, html, json and xml only.
func notText(ctype string) string {
	if ctype == "" {
		return ""
	}
	for _, t := range []string{"text", "html", "json", "xml"} {
		if strings.Contains(ctype, t) {
			return ""
		}
	}
	return "the page is not text, HTML, JSON or XML (" + strings.SplitN(ctype, ";", 2)[0] + ")"
}

func symDiff(a, b []string) []string {
	in := map[string]int{}
	for _, x := range a {
		in[x] |= 1
	}
	for _, x := range b {
		in[x] |= 2
	}
	var out []string
	for x, v := range in {
		if v != 3 {
			out = append(out, x)
		}
	}
	return out
}

func slicesHas(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
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

// isWord says b can be part of a parameter name in a page's text.
func isWord(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '_' || b == '-' || b == '.'
}

// wordSet adds to into every run of word characters in body.
func wordSet(body []byte, into map[string]bool) map[string]bool {
	if into == nil {
		into = map[string]bool{}
	}
	for i := 0; i < len(body); {
		if !isWord(body[i]) {
			i++
			continue
		}
		j := i
		for j < len(body) && isWord(body[j]) {
			j++
		}
		if j-i >= 5 && j-i <= 64 {
			into[string(body[i:j])] = true
		}
		i = j
	}
	return into
}

// echoed lists the names (at least 5 characters, not in skip) that body
// prints inside quotes or between spaces: "name", 'name' or  name .
func echoed(body []byte, names []string, skip map[string]bool) []string {
	var cand []string
	for _, n := range names {
		if len(n) >= 5 && !skip[n] {
			cand = append(cand, n)
		}
	}
	if len(cand) == 0 {
		return nil
	}
	set := map[string]bool{}
	for i := 0; i < len(body); i++ {
		d := body[i]
		if d != '"' && d != '\'' && d != ' ' {
			continue
		}
		j := i + 1
		for j < len(body) && isWord(body[j]) {
			j++
		}
		if j-i-1 >= 5 && j-i-1 <= 64 && j < len(body) && body[j] == d {
			set[string(body[i+1:j])] = true
		}
		// A closing delimiter may open the next token: do not skip it.
		if j > i+1 {
			i = j - 1
		}
	}
	var out []string
	for _, n := range cand {
		if set[n] {
			out = append(out, n)
		}
	}
	return out
}
