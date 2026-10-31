package paramcol

import (
	"net/url"
	"sort"
	"strings"
)

// inURL tests the parameters the page's URL already carries, which the list
// skips: a name is found when asking without it (it is renamed to a name no
// page reads, so the query keeps its length) changes the answer as the
// reference shows it, or, failing that, when another value does. Each
// change must show twice. The page must not print what it is sent: then
// the value test is left out, and a name is judged by the rename alone.
func (s *search) inURL() map[string]string {
	found := map[string]string{}
	var names []string
	for n := range s.base.Query() {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if s.halted() {
			break
		}
		if why := s.ownRename(n); why != "" {
			found[n] = why
		} else if why := s.ownValue(n); why != "" {
			found[n] = why
		}
	}
	return found
}

// ownRename is how the answer changes when name is not in the query, twice.
func (s *search) ownRename(name string) string {
	var first string
	for range 2 {
		alt := *s.base
		alt.RawQuery = editQuery(s.base.RawQuery, name, controlFor([]string{name}, "")[0].name, nil)
		a, ok := s.askAt(&alt, randomPairs(1), false)
		if !ok {
			return ""
		}
		why := s.judge(a, s.ref)
		if why == "" || first != "" && why != first {
			return ""
		}
		first = why
	}
	return first
}

// ownValue is how the answer changes when name has another value, twice.
func (s *search) ownValue(name string) string {
	if s.noEcho || s.controlled {
		return ""
	}
	var first string
	for range 2 {
		v := randValue()
		alt := *s.base
		alt.RawQuery = editQuery(s.base.RawQuery, name, name, &v)
		rnd := randomPairs(1)
		a, ok := s.askAt(&alt, rnd, false)
		if !ok {
			return ""
		}
		q := append([]pair{{name, v}}, rnd...)
		why := s.judge(strip(a, q), s.ref)
		if why == "" && tokens(a.body, q)[v] > 0 {
			why = "reflected"
		}
		if why == "" || first != "" && why != first {
			return ""
		}
		first = why
	}
	return first
}

// editQuery renames each name=value of raw whose name is name to newName,
// and gives it newValue unless that is nil.
func editQuery(raw, name, newName string, newValue *string) string {
	parts := strings.Split(raw, "&")
	for i, p := range parts {
		k, v, hasEq := strings.Cut(p, "=")
		if dec, err := url.QueryUnescape(k); err != nil || dec != name {
			continue
		}
		parts[i] = url.QueryEscape(newName)
		switch {
		case newValue != nil:
			parts[i] += "=" + url.QueryEscape(*newValue)
		case hasEq:
			parts[i] += "=" + v
		}
	}
	return strings.Join(parts, "&")
}
