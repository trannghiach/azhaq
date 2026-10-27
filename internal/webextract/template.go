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
	// A query value that names a page (content=about.htm, view=list,
	// lang=en): kept, so each one is a page of its own.
	selectorVal = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.\-]{0,31}$`)
	digitRun    = regexp.MustCompile(`\d`)
	// fileVal names a file: content=inside_about.htm.
	fileVal = regexp.MustCompile(`(?i)\.(html?|jspx?|php\d?|aspx?|cfm|do|action|txt|xml|json|pdf|md)$`)
)

// selectorKeys are parameters whose word value picks a page or a view,
// not a record: each value is a page of its own. A user name, a token or
// an id under any other name is folded like a number.
var selectorKeys = map[string]bool{
	"content": true, "page": true, "view": true, "section": true, "tab": true, "lang": true, "locale": true,
	"type": true, "category": true, "cat": true, "sort": true, "order": true, "mode": true, "p": true,
	"file": true, "doc": true, "topic": true, "display": true, "layout": true, "template": true, "show": true,
	"menu": true, "module": true, "mod": true, "option": true, "path": true, "report": true, "screen": true,
}

// queryPlaceholder is what a query value becomes in a template: {n} for
// a number, the value itself for a word that names a page, {v} for
// anything else (tokens, URLs, free text).
func queryPlaceholder(k, v string) string {
	switch {
	case numSeg.MatchString(v):
		return "{n}"
	case freeText(k):
		return "{v}"
	case selectorVal.MatchString(v) && !hexSeg.MatchString(v) && !(len(v) >= 12 && len(digitRun.FindAllString(v, -1)) >= 4) &&
		(fileVal.MatchString(v) || selectorKeys[strings.ToLower(k)]):
		return url.QueryEscape(v)
	default:
		return "{v}"
	}
}

// Template replaces the variable parts of a URL with placeholders, so
// pages that differ only by an ID or a query value group together:
//
//	/catalog/product?productId=7 → /catalog/product?productId={n}
//	/users/42/orders             → /users/{n}/orders
//
// Path segments become {n}, {uuid} or {hex} only when they look like IDs.
// Query values become {n} for numbers and {v} for tokens and free text;
// a word that names a page (index.jsp?content=about.htm) stays, so the
// pages a selector parameter leads to are not folded into one.
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
		if vs := q[k]; len(vs) == 1 {
			ph = queryPlaceholder(k, vs[0])
		}
		parts = append(parts, url.QueryEscape(k)+"="+ph)
	}
	return out + "?" + strings.Join(parts, "&")
}

// freeText names a parameter whose value is typed or tracked, not a page
// picked: a search, a redirect, a campaign tag.
func freeText(k string) bool {
	k = strings.ToLower(k)
	switch k {
	case "q", "query", "search", "s", "k", "keyword", "keywords", "term", "terms", "text", "searchterm", "search_query",
		"next", "return", "returnurl", "return_url", "returnto", "redirect", "redirect_uri", "redirect_url", "url", "ref", "referrer", "callback", "continue", "from", "to":
		return true
	}
	return strings.HasPrefix(k, "utm_")
}

// Templated is true when Template changed something beyond normalization.
func Templated(raw string) bool {
	n, err := normalize.URL(raw)
	if err != nil {
		return false
	}
	return Template(n) != n
}
