// Package probefilter holds azhaq probe's matchers and filters: httpx's
// -mc/-fc, -ml/-fl, -mlc/-flc, -mwc/-fwc, -mfc/-ffc, -ms/-fs, -mr/-fe,
// -mcdn/-fcdn, -mrt/-frt and -mdc/-fdc, with its semantics (ProjectDiscovery
// httpx, MIT): a row is dropped when any filter hits, and kept when every
// matcher given holds.
package probefilter

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Row is one answer, as the matchers read it.
type Row struct {
	Status  int
	Length  int
	Lines   int
	Words   int
	Favicon string
	CDN     string
	Time    time.Duration
	Raw     string         // the response as sent: head and body
	Vars    map[string]any // the row's fields, for -mdc and -fdc
}

// Set is the matchers and filters of a run. The zero value keeps every row.
type Set struct {
	MatchStatus, FilterStatus   []Range
	MatchLength, FilterLength   []Range
	MatchLines, FilterLines     []Range
	MatchWords, FilterWords     []Range
	MatchFavicon, FilterFavicon []string
	MatchString, FilterString   []string
	MatchRegex, FilterRegex     []*regexp.Regexp
	MatchCDN, FilterCDN         []string
	MatchTime, FilterTime       *TimeTest
	MatchExpr, FilterExpr       *Expr
}

// Empty says no matcher or filter was given.
func (s *Set) Empty() bool {
	return s == nil || len(s.MatchStatus)+len(s.FilterStatus)+len(s.MatchLength)+len(s.FilterLength)+
		len(s.MatchLines)+len(s.FilterLines)+len(s.MatchWords)+len(s.FilterWords)+len(s.MatchFavicon)+
		len(s.FilterFavicon)+len(s.MatchString)+len(s.FilterString)+len(s.MatchRegex)+len(s.FilterRegex)+
		len(s.MatchCDN)+len(s.FilterCDN) == 0 && s.MatchTime == nil && s.FilterTime == nil &&
		s.MatchExpr == nil && s.FilterExpr == nil
}

// NeedsRaw says a matcher reads the response as sent.
func (s *Set) NeedsRaw() bool {
	return s != nil && (len(s.MatchString)+len(s.FilterString)+len(s.MatchRegex)+len(s.FilterRegex) > 0 || s.MatchExpr != nil || s.FilterExpr != nil)
}

// Keep says whether the row passes. An error is a condition that could not
// be evaluated: the row is dropped and the caller says so.
func (s *Set) Keep(r Row) (bool, error) {
	if s.Empty() {
		return true, nil
	}
	var firstErr error
	eval := func(e *Expr) bool {
		ok, err := e.Eval(r.Vars)
		if err != nil && firstErr == nil {
			firstErr = err
		}
		return ok
	}
	// Filters first: any hit drops the row.
	if s.FilterExpr != nil && eval(s.FilterExpr) {
		return false, firstErr
	}
	if in(s.FilterStatus, r.Status) || in(s.FilterLength, r.Length) || in(s.FilterLines, r.Lines) || in(s.FilterWords, r.Words) {
		return false, nil
	}
	for _, re := range s.FilterRegex {
		if re.MatchString(r.Raw) {
			return false, nil
		}
	}
	if containsAnyFold(r.Raw, s.FilterString) || anyEqualFold(r.Favicon, s.FilterFavicon, true) {
		return false, nil
	}
	if len(s.FilterCDN) > 0 && anyEqualFold(r.CDN, s.FilterCDN, false) {
		return false, nil
	}
	if s.FilterTime != nil && s.FilterTime.Holds(r.Time) {
		return false, nil
	}
	// Matchers: all that were given must hold.
	if len(s.MatchStatus) > 0 && !in(s.MatchStatus, r.Status) {
		return false, nil
	}
	if len(s.MatchLength) > 0 && !in(s.MatchLength, r.Length) {
		return false, nil
	}
	if len(s.MatchLines) > 0 && !in(s.MatchLines, r.Lines) {
		return false, nil
	}
	if len(s.MatchWords) > 0 && !in(s.MatchWords, r.Words) {
		return false, nil
	}
	for _, re := range s.MatchRegex {
		if !re.MatchString(r.Raw) {
			return false, nil
		}
	}
	if len(s.MatchString) > 0 && !containsAnyFold(r.Raw, s.MatchString) {
		return false, nil
	}
	if len(s.MatchFavicon) > 0 && !anyEqualFold(r.Favicon, s.MatchFavicon, false) {
		return false, nil
	}
	if len(s.MatchCDN) > 0 && !anyEqualFold(r.CDN, s.MatchCDN, false) {
		return false, nil
	}
	if s.MatchTime != nil && !s.MatchTime.Holds(r.Time) {
		return false, nil
	}
	if s.MatchExpr != nil && !eval(s.MatchExpr) {
		return false, firstErr
	}
	return true, firstErr
}

func containsAnyFold(s string, subs []string) bool {
	if len(subs) == 0 {
		return false
	}
	low := strings.ToLower(s)
	for _, x := range subs {
		if strings.Contains(low, strings.ToLower(x)) {
			return true
		}
	}
	return false
}

// anyEqualFold: v equals one of the list (contains, for a filter, as httpx
// does for favicon hashes).
func anyEqualFold(v string, list []string, contains bool) bool {
	for _, x := range list {
		if strings.EqualFold(v, x) || contains && v != "" && strings.Contains(strings.ToLower(v), strings.ToLower(x)) {
			return true
		}
	}
	return false
}

// Range is a number or a span of numbers: 200, 200-299, or 4xx.
type Range struct{ Lo, Hi int }

func in(rs []Range, n int) bool {
	for _, r := range rs {
		if n >= r.Lo && n <= r.Hi {
			return true
		}
	}
	return false
}

// ParseRanges reads a comma-separated list of numbers, spans (200-299) and
// status classes (4xx).
func ParseRanges(flag, s string) ([]Range, error) {
	var out []Range
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if len(p) == 3 && strings.HasSuffix(strings.ToLower(p), "xx") {
			if d, err := strconv.Atoi(p[:1]); err == nil {
				out = append(out, Range{d * 100, d*100 + 99})
				continue
			}
		}
		lo, hi := p, p
		if a, b, ok := strings.Cut(p, "-"); ok && a != "" {
			lo, hi = a, b
		}
		x, err1 := strconv.Atoi(strings.TrimSpace(lo))
		y, err2 := strconv.Atoi(strings.TrimSpace(hi))
		if err1 != nil || err2 != nil || x > y {
			return nil, fmt.Errorf("%s: %q is not a number or a span such as 200-299", flag, p)
		}
		out = append(out, Range{x, y})
	}
	return out, nil
}

// Regexes compiles patterns, saying which flag one came from.
func Regexes(flag string, pats []string) ([]*regexp.Regexp, error) {
	var out []*regexp.Regexp
	for _, p := range pats {
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", flag, err)
		}
		out = append(out, re)
	}
	return out, nil
}

// TimeTest is a response-time condition: an operator and a duration.
type TimeTest struct {
	Op string
	D  time.Duration
}

var timeOps = []string{">=", "<=", "!=", "=", "<", ">"}

// ParseTime reads '< 1', '>= 500ms', '!=2s'; a bare number is seconds.
func ParseTime(flag, s string) (*TimeTest, error) {
	for _, op := range timeOps {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(s), op); ok {
			v := strings.TrimSpace(rest)
			d, err := time.ParseDuration(v)
			if err != nil {
				if f, ferr := strconv.ParseFloat(v, 64); ferr == nil {
					d, err = time.Duration(f*float64(time.Second)), nil
				}
			}
			if err != nil {
				return nil, fmt.Errorf("%s: %q is not a duration such as 1s or 500ms", flag, v)
			}
			return &TimeTest{op, d}, nil
		}
	}
	return nil, fmt.Errorf("%s: want an operator (%s) and a time, such as '< 1'", flag, strings.Join(timeOps, " "))
}

// Holds says the time passes the condition.
func (t *TimeTest) Holds(d time.Duration) bool {
	switch t.Op {
	case ">":
		return d > t.D
	case ">=":
		return d >= t.D
	case "<":
		return d < t.D
	case "<=":
		return d <= t.D
	case "=":
		return d == t.D
	case "!=":
		return d != t.D
	}
	return false
}
