package main

import (
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/trannghiach/azhaq/internal/normalize"
)

// parseSourceRates reads -source-rates: name=N/unit pairs, unit s, m or h
// (subfinder's -rls: hackertarget=10/m). The result is requests per second.
func parseSourceRates(spec string) (map[string]float64, error) {
	var out map[string]float64
	for _, part := range splitList(spec) {
		name, rate, ok := strings.Cut(part, "=")
		n, unit, ok2 := strings.Cut(rate, "/")
		count, err := strconv.ParseFloat(n, 64)
		if !ok || !ok2 || err != nil || count < 0 || name == "" {
			return nil, fmt.Errorf("%q is not name=N/unit", part)
		}
		per := map[string]time.Duration{"s": time.Second, "m": time.Minute, "h": time.Hour}[unit]
		if per == 0 {
			return nil, fmt.Errorf("%q: the unit is s, m or h", part)
		}
		if out == nil {
			out = map[string]float64{}
		}
		out[strings.ToLower(strings.TrimSpace(name))] = count / per.Seconds()
	}
	return out, nil
}

// subsDomains cleans what -d, -dL and stdin gave, as subfinder does: commas
// split, quotes, comments, a scheme, a path, a port, a leading *. and a
// trailing dot dropped, lower case. What is no domain (an IP address, a
// word with no dot) is left out with a note, not an error, unless nothing
// is left.
func subsDomains(raw []string) (domains, notes []string) {
	seen := map[string]bool{}
	for _, line := range raw {
		for _, tok := range strings.Split(line, ",") {
			d := cleanDomain(tok)
			switch {
			case d == "":
			case net.ParseIP(d) != nil:
				notes = append(notes, fmt.Sprintf("%s is an IP address, not a domain: no source was asked about it", d))
			case !strings.Contains(d, ".") || strings.ContainsAny(d, " @\\"):
				notes = append(notes, fmt.Sprintf("%q is not a domain such as example.com: left out", strings.TrimSpace(tok)))
			case !seen[d]:
				seen[d] = true
				domains = append(domains, d)
			}
		}
	}
	return domains, notes
}

func cleanDomain(s string) string {
	s, _, _ = strings.Cut(s, "#")
	s = strings.ToLower(strings.Trim(strings.TrimSpace(s), "\"'` \t"))
	s = strings.TrimPrefix(strings.TrimPrefix(s, "https://"), "http://")
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if h, _, err := net.SplitHostPort(s); err == nil {
		s = h
	}
	s = strings.TrimPrefix(s, "*.")
	return normalize.Hostname(strings.TrimSuffix(s, "."))
}

// subsFilter is -m, -f, -match-regex and -filter-regex: a name is kept when
// it matches a -m or a -match-regex (when any is given) and matches no -f
// and no -filter-regex. The glob is subfinder's: * for anything, the rest
// literal.
type subsFilter struct{ match, filter []*regexp.Regexp }

func compileSubsFilter(match, filter, matchRegex, filterRegex []string) (*subsFilter, error) {
	var f subsFilter
	var err error
	if f.match, err = compileNameFilters("-m", "-match-regex", match, matchRegex); err != nil {
		return nil, err
	}
	if f.filter, err = compileNameFilters("-f", "-filter-regex", filter, filterRegex); err != nil {
		return nil, err
	}
	return &f, nil
}

func compileNameFilters(flagGlob, flagRe string, globs, regexes []string) ([]*regexp.Regexp, error) {
	var out []*regexp.Regexp
	for _, g := range globs {
		re, err := regexp.Compile("^" + strings.ReplaceAll(regexp.QuoteMeta(g), `\*`, ".*") + "$")
		if err != nil {
			return nil, fmt.Errorf("%s %q: %w", flagGlob, g, err)
		}
		out = append(out, re)
	}
	for _, p := range regexes {
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("%s %q: %w", flagRe, p, err)
		}
		out = append(out, re)
	}
	return out, nil
}

func (f *subsFilter) keep(name string) bool {
	if f == nil {
		return true
	}
	for _, re := range f.filter {
		if re.MatchString(name) {
			return false
		}
	}
	if len(f.match) == 0 {
		return true
	}
	for _, re := range f.match {
		if re.MatchString(name) {
			return true
		}
	}
	return false
}

// listOrFile reads a comma list, or the lines of the file a value names
// (subfinder's -m, -f).
func listOrFile(values []string) []string {
	var out []string
	for _, v := range values {
		for _, item := range splitList(v) {
			if raw, err := os.ReadFile(item); err == nil {
				for _, l := range strings.Split(string(raw), "\n") {
					if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
						out = append(out, l)
					}
				}
				continue
			}
			out = append(out, item)
		}
	}
	return out
}
