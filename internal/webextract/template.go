package webextract

import (
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/trannghiach/azhaq/internal/normalize"
)

var (
	numSeg  = regexp.MustCompile(`^\d+$`)
	uuidSeg = regexp.MustCompile(`^(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	hexSeg  = regexp.MustCompile(`^(?i)[0-9a-f]{16,}$`)
)

// Template replaces the variable parts of a URL with placeholders, so
// pages that differ only by an ID or a query value group together:
//
//	/catalog/product?productId=7 → /catalog/product?productId={n}
//	/users/42/orders             → /users/{n}/orders
//
// Path segments become {n}, {uuid} or {hex} only when they look like IDs.
// Every query value is a placeholder: {n} for numbers, {v} otherwise.
// A URL without variable parts is returned normalized and unchanged.
func Template(raw string) string {
	n, err := normalize.URL(raw)
	if err != nil {
		return raw
	}
	u, err := url.Parse(n)
	if err != nil {
		return n
	}
	segs := strings.Split(u.EscapedPath(), "/")
	for i, s := range segs {
		switch {
		case s == "":
		case numSeg.MatchString(s):
			segs[i] = "{n}"
		case uuidSeg.MatchString(s):
			segs[i] = "{uuid}"
		case hexSeg.MatchString(s):
			segs[i] = "{hex}"
		}
	}
	out := u.Scheme + "://" + u.Host + strings.Join(segs, "/")
	if u.RawQuery == "" {
		return out
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return n
	}
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		ph := "{v}"
		if vs := q[k]; len(vs) > 0 && numSeg.MatchString(vs[0]) {
			ph = "{n}"
		}
		parts = append(parts, url.QueryEscape(k)+"="+ph)
	}
	return out + "?" + strings.Join(parts, "&")
}

// Templated is true when Template changed something beyond normalization.
func Templated(raw string) bool {
	n, err := normalize.URL(raw)
	if err != nil {
		return false
	}
	return Template(n) != n
}
