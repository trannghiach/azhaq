// Package paramcol finds query parameters a page reads but does not link
// (-params, active): arjun's method. Parameters go out in large groups
// with random values; a group that changes the answer (status, size,
// a value reflected back) is split in halves until the names are found.
// A page that answers any name (an error page that prints the query
// string back) is asked the same with random names of the same lengths,
// and only what that control does not show counts.
// GET only: guessing names on POST could submit something.
package paramcol

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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
	"github.com/trannghiach/azhaq/internal/neterr"
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
	// AllGets also sends, with a session, names that read like an action
	// (delete, reset…); by default they are left out.
	AllGets bool
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
	s := &search{c: c, ctx: ctx, base: u, known: known, most: c.Opts.Chunk}
	if !s.calibrate() {
		if s.err != nil {
			return s.spent(page)
		}
		return types.RunMeta{Status: types.StatusOK}, nil // the page changes by itself or does not answer
	}
	var words []string
	seen := map[string]bool{}
	careful := fetch.HasSession() && !c.Opts.AllGets
	for _, w := range c.Opts.Words {
		w = strings.TrimSpace(w)
		if careful && webextract.StateChanging("/?action="+url.QueryEscape(w)) != "" {
			continue // with a session, a name like delete or logout is not sent
		}
		if w != "" && !known[w] && !seen[w] {
			seen[w] = true
			words = append(words, w)
		}
	}
	found := map[string]string{}
	note := ""
	for i := 0; i < len(words) && ctx.Err() == nil && s.err == nil; i += c.Opts.Chunk {
		chunk := words[i:min(i+c.Opts.Chunk, len(words))]
		s.alone, s.hits = 0, 0
		s.narrow(chunk, found)
		hits := 0
		for _, n := range chunk {
			if _, ok := found[n]; ok {
				hits++
			}
		}
		tried := len(chunk)
		stopped := s.flooded()
		if stopped {
			hits, tried = s.hits, s.alone
		}
		if !stopped && (len(chunk) < minFlood || hits*2 <= len(chunk)) || ctx.Err() != nil || s.err != nil {
			continue
		}
		// Most names "change" the answer: a page that reacts to names it
		// does not read, or one that reads most of a short list (names
		// taken from its own scripts). Random names made like these tell.
		if s.anyName(chunk) {
			if s.err != nil {
				break
			}
			for _, n := range chunk {
				delete(found, n) // this group's; earlier ones were told apart
			}
			rest := "not searched for parameters"
			if len(found) > 0 {
				rest = "not searched further"
			}
			note = fmt.Sprintf("%s answers names it does not read (%d of %d names tried changed the answer): %s", page, hits, tried, rest)
			break
		}
		if stopped {
			// The narrowing stopped at what looked like a flood: finish it.
			var left []string
			for _, n := range chunk {
				if _, ok := found[n]; !ok {
					left = append(left, n)
				}
			}
			s.reads = true
			s.narrow(left, found)
			s.reads = false
		}
	}
	if ctx.Err() != nil {
		return types.RunMeta{Status: types.StatusCancelled}, ctx.Err()
	}
	if s.err != nil {
		return s.spent(page)
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
	if note != "" {
		row["note"] = note
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

func answerOf(status int, body []byte) answer {
	return answer{
		status: status, length: len(body), body: body,
		words: bytes.Count(body, []byte{' '}) + 1, lines: bytes.Count(bytes.TrimSpace(body), []byte{'\n'}) + 1,
	}
}

// pair is one name=value of a query; a list, as a control may repeat a name.
type pair struct{ name, value string }

type search struct {
	c     *Collector
	ctx   context.Context
	base  *url.URL
	known map[string]bool
	ref   answer
	slack int // size difference the page shows between identical requests
	// controlled: the page answers a crowd of unknown names differently
	// from one (it prints the query back, or counts them), so a group is
	// judged against random names of the same lengths, not against ref.
	controlled bool
	requests   int
	err        error // the request budget ran out
	// Names of the current chunk tested alone, and those that changed
	// the answer.
	alone, hits int
	// most is the largest group sent: smaller than any whose control
	// changed the status (a query too long for the server).
	most int
	// reads: random names made like the chunk's changed nothing, so the
	// names that do are read, however many.
	reads bool
}

// flooded: nearly every name tested alone changed the answer, as on a
// page that reacts to any name. The chunk is not narrowed further.
func (s *search) flooded() bool {
	return !s.reads && s.hits >= 2*minFlood && s.hits*4 > s.alone*3
}

// anyName says whether random names made like group's (as many, letters,
// as long and at least 6, which no page reads) change the answer too: the
// page reacts to names it does not read. A request that could not be sent
// says nothing to keep group's finds on.
func (s *search) anyName(group []string) bool {
	names := make([]string, min(len(group), s.most))
	for i := range names {
		b := make([]byte, max(6, len(group[i])))
		_, _ = rand.Read(b)
		for j := range b {
			b[j] = 'a' + b[j]%26
		}
		names[i] = string(b)
	}
	v, ok := s.test(names)
	return !ok || v.crowd || v.why != "" || len(v.reflected) > 0
}

// spent gives the page back for azhaq resume, which searches it again.
func (s *search) spent(page string) (types.RunMeta, error) {
	s.c.mu.Lock()
	delete(s.c.done, page)
	s.c.perHost[s.base.Host]--
	s.c.mu.Unlock()
	return types.RunMeta{Status: types.StatusCapped}, s.err
}

func (s *search) get(q []pair) (answer, bool) {
	if err := s.c.limiter.Wait(s.ctx, s.base.Host); err != nil {
		return answer{}, false
	}
	u := *s.base
	var b strings.Builder
	b.WriteString(u.RawQuery)
	for _, p := range q {
		if b.Len() > 0 {
			b.WriteByte('&')
		}
		b.WriteString(url.QueryEscape(p.name) + "=" + url.QueryEscape(p.value))
	}
	u.RawQuery = b.String()
	if fetch.EndsSession(u.String()) {
		return answer{}, false
	}
	req, err := http.NewRequestWithContext(s.ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return answer{}, false
	}
	fetch.ApplyHeaders(req)
	if err := fetch.Spend(s.ctx); err != nil {
		if errors.Is(err, neterr.ErrBudget) {
			s.err = err
		}
		return answer{}, false
	}
	s.requests++
	resp, err := s.c.Client.Do(req)
	if err != nil {
		return answer{}, false
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	return answerOf(resp.StatusCode, body), true
}

// calibrate takes the page twice with one random parameter, then once
// with a group of them as large as a chunk: one unknown name should change
// nothing, what changes between the first two is the page's own noise,
// and a page that answers the group otherwise is searched with controls.
func (s *search) calibrate() bool {
	one := randomPairs(1)
	a, ok := s.get(one)
	if !ok {
		return false
	}
	b, ok := s.get(randomPairs(1))
	if !ok || a.status != b.status {
		return false
	}
	s.ref = a
	s.slack = abs(a.length - b.length)
	if s.slack >= a.length/2+64 {
		return false
	}
	crowd := randomPairs(s.c.Opts.Chunk)
	c, ok := s.get(crowd)
	if !ok {
		return false
	}
	s.controlled = len(tokens(a.body, one)) > 0 || s.differs(c, s.ref, crowd)
	return true
}

// differs says whether a, the answer to q, is not ref: another status, a
// value of q in it, or another size.
func (s *search) differs(a, ref answer, q []pair) bool {
	return a.status != ref.status || len(tokens(a.body, q)) > 0 || s.resized(a, ref)
}

// resized: the sizes differ by more than the page's noise.
func (s *search) resized(a, ref answer) bool {
	if abs(a.length-ref.length) > s.slack+s.slack/2+16 {
		return true
	}
	return s.slack == 0 && (a.words != ref.words || a.lines != ref.lines)
}

// verdict is what a group of names did to the answer.
type verdict struct {
	why       string   // status or size: some name of the group changed the answer
	reflected []string // names whose value came back more often than a control's
	crowd     bool     // the control changed the status too: the group's size did, not its names
}

// test sends group with random values. Against ref when the page ignores
// unknown names; otherwise, once the answer differs from ref, against a
// control of random names as long as the group's: what the control shows
// too (an echoed query string, the error a long query gets) is no
// evidence.
func (s *search) test(group []string) (verdict, bool) {
	q := make([]pair, len(group))
	for i, n := range group {
		q[i] = pair{n, randValue()}
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
		control = controlFor(group)
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
	// The values are taken out of both answers: a reflection is judged
	// above, by its count, and is not a change of size as well.
	sa, sb := strip(a, q), strip(base, control)
	switch {
	case sa.status != sb.status:
		v.why = "status"
	case s.resized(sa, sb):
		v.why = "size"
	}
	v.crowd = s.controlled && base.status != s.ref.status && a.status == base.status
	return v, true
}

// narrow finds which names in group change the answer, halving the group
// while it does.
func (s *search) narrow(group []string, found map[string]string) {
	if len(group) == 0 || s.ctx.Err() != nil || s.err != nil || s.flooded() {
		return
	}
	if len(group) > s.most {
		// A group this large is refused whatever its names.
		half := len(group) / 2
		s.narrow(group[:half], found)
		s.narrow(group[half:], found)
		return
	}
	if len(group) == 1 {
		s.alone++
	}
	v, ok := s.test(group)
	if !ok {
		return
	}
	if v.crowd && len(group) > 1 {
		s.most = min(s.most, len(group)-1)
	}
	for _, n := range v.reflected {
		found[n] = "reflected" // the value that came back names the parameter
	}
	if v.why == "" && !v.crowd {
		return
	}
	if len(v.reflected) > 0 {
		// Others in the group may change the answer in other ways.
		var rest []string
		for _, n := range group {
			if _, ok := found[n]; !ok {
				rest = append(rest, n)
			}
		}
		s.narrow(rest, found)
		return
	}
	if len(group) == 1 {
		if v.crowd {
			return
		}
		// Confirm: a single change must show again.
		if w, ok := s.test(group); ok && w.why != "" && !w.crowd {
			found[group[0]] = v.why
			s.hits++
		}
		return
	}
	half := len(group) / 2
	s.narrow(group[:half], found)
	s.narrow(group[half:], found)
}

// tokens counts how often each value of q appears in body, the values
// that do. Every value is "az" and 10 hex digits, so the body is read
// once.
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
	return answerOf(a.status, body)
}

// valueLen is the length of randValue's values.
const valueLen = 12

func randValue() string {
	var b [5]byte
	_, _ = rand.Read(b[:])
	return "az" + hex.EncodeToString(b[:])
}

// randomPairs are n names no page reads, with random values.
func randomPairs(n int) []pair {
	out := make([]pair, n)
	for i := range out {
		out[i] = pair{randValue(), randValue()}
	}
	return out
}

// controlFor is a name for each of group's, as long once escaped, that no
// page reads ("~" and letters; "~" is never escaped), with random values:
// a page that prints the query back prints the same length for both.
func controlFor(group []string) []pair {
	out := make([]pair, len(group))
	for i, n := range group {
		l := max(1, len(url.QueryEscape(n)))
		name := make([]byte, l)
		_, _ = rand.Read(name)
		name[0] = '~'
		for j := 1; j < l; j++ {
			name[j] = 'a' + name[j]%26
		}
		out[i] = pair{string(name), randValue()}
	}
	return out
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}
