package fuzz

import (
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Response is what the matchers and filters see of an answer.
type Response struct {
	Status      int
	Header      http.Header
	Body        []byte // kept only when a regexp reads it
	Length      int64
	Words       int64
	Lines       int64
	ContentType string
	Duration    int64 // nanoseconds to the first byte
	Request     *Request
	// RawRequest and RawResponse are the exchange as text, kept for -od.
	RawRequest, RawResponse string
}

// Filter says whether a response has some property: a status in a list, a
// size in a range, a pattern.
type Filter interface {
	Match(*Response) bool
	// Repr is the value as given, so a second value can be added to it.
	Repr() string
}

type span struct{ min, max int64 }

var rangeRE = regexp.MustCompile(`^(\d+)-(\d+)$`)

func parseSpan(s string) (span, error) {
	if m := rangeRE.FindStringSubmatch(s); m != nil {
		lo, err1 := strconv.ParseInt(m[1], 10, 0)
		hi, err2 := strconv.ParseInt(m[2], 10, 0)
		if err1 != nil || err2 != nil {
			return span{}, fmt.Errorf("invalid value %s", s)
		}
		if lo >= hi {
			return span{}, fmt.Errorf("minimum has to be smaller than maximum")
		}
		return span{lo, hi}, nil
	}
	n, err := strconv.ParseInt(s, 10, 0)
	if err != nil {
		return span{}, fmt.Errorf("invalid value %s", s)
	}
	return span{n, n}, nil
}

// numeric is a list of values and ranges ("200-299,301") over one count.
type numeric struct {
	spans []span
	all   bool // status "all"
	of    func(*Response) int64
	raw   string
}

func newNumeric(flag, value string, of func(*Response) int64, allowAll bool) (*numeric, error) {
	n := &numeric{of: of, raw: value}
	for _, part := range strings.Split(value, ",") {
		if allowAll && part == "all" {
			n.all = true
			continue
		}
		sp, err := parseSpan(part)
		if err != nil {
			return nil, fmt.Errorf("%s: invalid value %q", flag, part)
		}
		n.spans = append(n.spans, sp)
	}
	return n, nil
}

func (n *numeric) Match(r *Response) bool {
	if n.all {
		return true
	}
	v := n.of(r)
	for _, s := range n.spans {
		if s.min <= v && v <= s.max {
			return true
		}
	}
	return false
}

func (n *numeric) Repr() string { return n.raw }

// timed is -mt and -ft: the time to the first byte, over or under a number of
// milliseconds.
type timed struct {
	ms  int64
	gt  bool
	raw string
}

func newTimed(flag, value string) (*timed, error) {
	gt, lt := strings.HasPrefix(value, ">"), strings.HasPrefix(value, "<")
	if gt == lt {
		return nil, fmt.Errorf("%s: invalid value %q: want >MS or <MS, in milliseconds", flag, value)
	}
	ms, err := strconv.ParseInt(value[1:], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("%s: invalid value %q: want >MS or <MS, in milliseconds", flag, value)
	}
	return &timed{ms: ms, gt: gt, raw: value}, nil
}

func (t *timed) Match(r *Response) bool {
	ms := r.Duration / int64(time.Millisecond)
	if t.gt {
		return ms > t.ms
	}
	return ms < t.ms
}

func (t *timed) Repr() string { return t.raw }

// pattern matches the response headers (as "Name: value" lines) followed
// by the body; a keyword in it stands for the input's value, quoted.
type pattern struct {
	raw   string
	fixed *regexp.Regexp // set when no keyword is in the pattern
}

func newPattern(flag, value string, keywords []string) (*pattern, error) {
	re, err := regexp.Compile(value)
	if err != nil {
		return nil, fmt.Errorf("%s: invalid regexp %q", flag, value)
	}
	p := &pattern{raw: value, fixed: re}
	for _, k := range keywords {
		if strings.Contains(value, k) {
			p.fixed = nil
		}
	}
	return p, nil
}

func (p *pattern) Match(r *Response) bool {
	re := p.fixed
	if re == nil {
		src := p.raw
		if r.Request != nil {
			for k, v := range r.Request.Input {
				src = strings.ReplaceAll(src, k, regexp.QuoteMeta(v))
			}
		}
		var err error
		if re, err = regexp.Compile(src); err != nil {
			return false
		}
	}
	var data []byte
	for k, vs := range r.Header {
		for _, v := range vs {
			data = append(data, k+": "+v+"\r\n"...)
		}
	}
	return re.Match(append(data, r.Body...))
}

func (p *pattern) Repr() string { return p.raw }

// Set is the matchers and filters of a run, by kind: status, size, word,
// line and regexp. A second value for a kind is added to the first (an OR),
// as in ffuf.
type Set struct {
	mu       sync.RWMutex
	matchers map[string]Filter
	filters  map[string]Filter
	keywords []string // for patterns that name an input
	// MatcherAnd and FilterAnd turn the "any" of each side into "all".
	MatcherAnd, FilterAnd bool
	// PerHost (-ach) gives each host and directory its own filters, which
	// start as a copy of the general ones and get what calibrating it finds.
	PerHost     bool
	hostFilters map[string]map[string]Filter
}

func NewSet(keywords []string) *Set {
	return &Set{matchers: map[string]Filter{}, filters: map[string]Filter{}, keywords: keywords}
}

var flagOf = map[string][2]string{
	"status": {"-mc", "-fc"}, "size": {"-ms", "-fs"}, "word": {"-mw", "-fw"}, "line": {"-ml", "-fl"}, "regexp": {"-mr", "-fr"}, "time": {"-mt", "-ft"},
}

func (s *Set) make(kind, value string, filter bool) (Filter, error) {
	flag := flagOf[kind][0]
	if filter {
		flag = flagOf[kind][1]
	}
	switch kind {
	case "status":
		return newNumeric(flag, value, func(r *Response) int64 { return int64(r.Status) }, true)
	case "size":
		return newNumeric(flag, value, func(r *Response) int64 { return r.Length }, false)
	case "word":
		return newNumeric(flag, value, func(r *Response) int64 { return r.Words }, false)
	case "line":
		return newNumeric(flag, value, func(r *Response) int64 { return r.Lines }, false)
	case "regexp":
		return newPattern(flag, value, s.keywords)
	case "time":
		return newTimed(flag, value)
	}
	return nil, fmt.Errorf("no kind %q", kind)
}

func (s *Set) add(m map[string]Filter, kind, value string, filter bool) error {
	f, err := s.make(kind, value, filter)
	if err != nil {
		return err
	}
	if old := m[kind]; old != nil && kind == "time" {
		return fmt.Errorf("%s: only one value, >MS or <MS", flagOf[kind][b2i(filter)])
	} else if old != nil && kind != "regexp" {
		if f, err = s.make(kind, old.Repr()+","+value, filter); err != nil {
			return err
		}
	}
	m[kind] = f
	return nil
}

// AddMatcher adds a matcher of kind (status, size, word, line, regexp).
func (s *Set) AddMatcher(kind, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.add(s.matchers, kind, value, false)
}

// AddFilter adds a filter of kind.
func (s *Set) AddFilter(kind, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.add(s.filters, kind, value, true)
}

// HasKind says a matcher or filter of kind is set.
func (s *Set) HasKind(kind string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.matchers[kind] != nil || s.filters[kind] != nil
}

// RemoveFilter drops the filter of kind ("none" in the control file).
func (s *Set) RemoveFilter(kind string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.filters, kind)
}

// ReplaceFilter sets the filter of kind to value alone.
func (s *Set) ReplaceFilter(kind, value string) error {
	f, err := s.make(kind, value, true)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.filters[kind] = f
	return nil
}

// KeptBy says r (a result as it was kept, without its headers and body)
// passes the filters now: a filter set while the run goes drops the matches
// already kept too. Pattern filters, which need the body, are left out.
func (s *Set) KeptBy(r *Response) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var fs []Filter
	for k, f := range s.filters {
		if k != "regexp" {
			fs = append(fs, f)
		}
	}
	for _, f := range fs {
		if f.Match(r) {
			if !s.FilterAnd {
				return false
			}
		} else if s.FilterAnd {
			return true
		}
	}
	return !(len(fs) > 0 && s.FilterAnd)
}

// AddFilterFor adds a filter of kind for one host and directory (see HostKey).
func (s *Set) AddFilterFor(key, kind, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.hostFilters == nil {
		s.hostFilters = map[string]map[string]Filter{}
	}
	fs, ok := s.hostFilters[key]
	if !ok {
		fs = make(map[string]Filter, len(s.filters))
		for k, v := range s.filters {
			fs[k] = v
		}
		s.hostFilters[key] = fs
	}
	return s.add(fs, kind, value, true)
}

// filtersOf is the filters that apply to r: its host's own with PerHost.
func (s *Set) filtersOf(r *Response) map[string]Filter {
	if s.PerHost && r.Request != nil {
		if fs, ok := s.hostFilters[HostKey(r.Request)]; ok {
			return fs
		}
	}
	return s.filters
}

// HostKey is the host asked for and the directory of the path: what -ach
// calibrates for.
func HostKey(req *Request) string {
	u, err := url.Parse(req.URL)
	if err != nil {
		return req.URL
	}
	host := hostHeaderOf(req)
	parts := strings.Split(u.Path, "/")
	return host + strings.TrimSpace(strings.Join(parts[:len(parts)-1], "/"))
}

// NeedBody says a matcher or filter reads the body.
func (s *Set) NeedBody() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.matchers["regexp"] != nil || s.filters["regexp"] != nil
}

// Matches is ffuf's rule: some matcher holds (every one, with MatcherAnd)
// and no filter does (not every one, with FilterAnd).
func (s *Set) Matches(r *Response) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	matched := false
	for _, m := range s.matchers {
		if m.Match(r) {
			matched = true
		} else if s.MatcherAnd {
			return false
		}
	}
	if !matched {
		return false
	}
	filters := s.filtersOf(r)
	for _, f := range filters {
		if f.Match(r) {
			if !s.FilterAnd {
				return false
			}
		} else if s.FilterAnd {
			return true
		}
	}
	return !(len(filters) > 0 && s.FilterAnd)
}

// filtered says some current filter holds for r.
func (s *Set) filtered(r *Response) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, f := range s.filtersOf(r) {
		if f.Match(r) {
			return true
		}
	}
	return false
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}
