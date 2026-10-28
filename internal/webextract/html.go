package webextract

import (
	"bytes"
	"io"
	"net/url"
	"strings"

	"golang.org/x/net/html"

	"github.com/trannghiach/azhaq/internal/normalize"
)

var skipScheme = map[string]bool{
	"javascript": true, "mailto": true, "tel": true, "data": true, "blob": true,
}

var skipExt = map[string]bool{
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".svg": true,
	".ico": true, ".webp": true, ".woff": true, ".woff2": true, ".ttf": true,
	".eot": true, ".css": true, ".map": true, ".js": true, ".mjs": true, ".cjs": true,
	".mp4": true, ".webm": true,
}

type Form struct {
	Method string
	Action string
	// Enctype is how a POST form encodes its fields, lower case:
	// application/x-www-form-urlencoded unless it says multipart/form-data
	// or text/plain. Empty for GET.
	Enctype string
	ID      string
	Name    string
	Fields  []string
	Files   []string // the fields that are file inputs
}

// Forms returns <form> elements and script-driven forms: any element with a
// data-action attribute (data-method gives the method) whose inputs are
// posted by JavaScript. page is the page's URL; a <base href> moves the
// actions it resolves.
func Forms(body []byte, page *url.URL) []Form {
	if page == nil {
		return nil
	}
	base := docBase(body, page)
	var out []Form
	z := html.NewTokenizer(bytes.NewReader(body))
	var cur *Form
	curTag, depth := "", 0
	open := func(tok html.Token, method, action string) {
		if cur != nil {
			out = append(out, *cur)
		}
		method = strings.ToUpper(method)
		if method == "" {
			method = "GET"
		}
		cur = &Form{
			Method: method,
			Action: formAction(page, base, action),
			ID:     attr(tok.Attr, "id"),
			Name:   attr(tok.Attr, "name"),
		}
		if method == "POST" {
			cur.Enctype = enctype(attr(tok.Attr, "enctype"))
		}
		curTag, depth = strings.ToLower(tok.Data), 1
	}
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			break
		}
		if tt != html.StartTagToken && tt != html.SelfClosingTagToken {
			if tt == html.EndTagToken && cur != nil && strings.EqualFold(z.Token().Data, curTag) {
				if depth--; depth == 0 {
					out = append(out, *cur)
					cur = nil
				}
			}
			continue
		}
		tok := z.Token()
		tag := strings.ToLower(tok.Data)
		if cur != nil && tag == curTag && tt == html.StartTagToken && tag != "form" {
			depth++
		}
		if tag == "form" {
			open(tok, attr(tok.Attr, "method"), attr(tok.Attr, "action"))
			continue
		}
		if act := attr(tok.Attr, "data-action"); act != "" && tt == html.StartTagToken {
			open(tok, attr(tok.Attr, "data-method"), act)
			continue
		}
		switch tag {
		case "input", "select", "textarea", "button":
			if cur == nil {
				continue
			}
			name := attr(tok.Attr, "name")
			if name == "" || nameIn(cur.Fields, name) {
				continue
			}
			cur.Fields = append(cur.Fields, name)
			if tag == "input" && strings.EqualFold(attr(tok.Attr, "type"), "file") {
				cur.Files = append(cur.Files, name)
			}
		}
	}
	if cur != nil {
		out = append(out, *cur)
	}
	return out
}

// formAction is where a form submits, as browsers take it. An empty
// action is the page's own URL with its query; any other resolves against
// the base, a fragment alone (action="#") to the base itself. The
// fragment is never sent.
func formAction(page, base *url.URL, action string) string {
	action = strings.TrimSpace(action)
	if action == "" || strings.HasPrefix(action, "#") {
		to := page
		if action != "" {
			to = base
		}
		u, err := normalize.URL(to.String())
		if err != nil {
			return ""
		}
		return u
	}
	u, _ := resolve(base, action)
	return u
}

// AppRoot is where a single-page app's router takes its paths from: the
// folder of the page's <base href>, or the root of its origin.
func AppRoot(body []byte, page *url.URL) *url.URL {
	root := &url.URL{Scheme: page.Scheme, Host: page.Host, Path: "/"}
	if b := docBase(body, page); b != page {
		root.Scheme, root.Host = b.Scheme, b.Host
		root.Path = b.Path[:strings.LastIndex(b.Path, "/")+1]
		if root.Path == "" {
			root.Path = "/"
		}
	}
	return root
}

// docBase is what a page's relative URLs resolve against: its first
// <base href>, itself resolved against the page's URL, or the page's URL.
func docBase(body []byte, page *url.URL) *url.URL {
	z := html.NewTokenizer(bytes.NewReader(body))
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			return page
		}
		if tt != html.StartTagToken && tt != html.SelfClosingTagToken {
			continue
		}
		tok := z.Token()
		if !strings.EqualFold(tok.Data, "base") {
			continue
		}
		href := attr(tok.Attr, "href")
		if href == "" {
			continue
		}
		u, err := page.Parse(href)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			return page
		}
		return u
	}
}

// enctype is a POST form's encoding as browsers read the attribute: an
// unknown value is the default.
func enctype(v string) string {
	switch v = strings.ToLower(strings.TrimSpace(v)); v {
	case "multipart/form-data", "text/plain":
		return v
	}
	return "application/x-www-form-urlencoded"
}

func nameIn(xs []string, n string) bool {
	for _, x := range xs {
		if x == n {
			return true
		}
	}
	return false
}

func Generator(body []byte) string {
	z := html.NewTokenizer(bytes.NewReader(body))
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			return ""
		}
		if tt != html.StartTagToken && tt != html.SelfClosingTagToken {
			continue
		}
		tok := z.Token()
		if !strings.EqualFold(tok.Data, "meta") {
			continue
		}
		if !strings.EqualFold(attr(tok.Attr, "name"), "generator") {
			continue
		}
		return strings.TrimSpace(attr(tok.Attr, "content"))
	}
}

// Links are a page's links, iframes and GET form actions, resolved
// against its <base href> when it has one, else against base, its URL.
func Links(body []byte, base *url.URL) []string {
	if base == nil {
		return nil
	}
	base = docBase(body, base)
	var out []string
	seen := map[string]bool{}
	z := html.NewTokenizer(bytes.NewReader(body))
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			if z.Err() != io.EOF {
				break
			}
			break
		}
		if tt != html.StartTagToken && tt != html.SelfClosingTagToken {
			continue
		}
		tok := z.Token()
		attr := hrefAttr(tok.Data, tok.Attr)
		if attr == "" {
			continue
		}
		if u, ok := resolve(base, attr); ok {
			if !seen[u] {
				seen[u] = true
				out = append(out, u)
			}
		}
	}
	return out
}

// ScriptSrcs are a page's script URLs, resolved as Links are.
func ScriptSrcs(body []byte, base *url.URL) []string {
	if base == nil {
		return nil
	}
	base = docBase(body, base)
	var out []string
	seen := map[string]bool{}
	z := html.NewTokenizer(bytes.NewReader(body))
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			break
		}
		if tt != html.StartTagToken && tt != html.SelfClosingTagToken {
			continue
		}
		tok := z.Token()
		if !strings.EqualFold(tok.Data, "script") {
			continue
		}
		src := attr(tok.Attr, "src")
		if src == "" {
			continue
		}
		if u, ok := resolve(base, src); ok {
			if !seen[u] {
				seen[u] = true
				out = append(out, u)
			}
		}
	}
	return out
}

func InlineScripts(body []byte) []string {
	var out []string
	for _, s := range InlineScriptsAt(body) {
		out = append(out, s.Text)
	}
	return out
}

// Inline is a script inside a page, and the line and column of the page
// it starts at.
type Inline struct {
	Text      string
	Line, Col int
}

// InlineScriptsAt is InlineScripts with where each script starts.
func InlineScriptsAt(body []byte) []Inline {
	var out []Inline
	var loc *Locator
	z := html.NewTokenizer(bytes.NewReader(body))
	inScript := false
	off := 0 // where the token starts: the raw tokens follow each other
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			break
		}
		n := len(z.Raw())
		switch tt {
		case html.StartTagToken:
			tok := z.Token()
			if strings.EqualFold(tok.Data, "script") && attr(tok.Attr, "src") == "" {
				inScript = true
			}
		case html.EndTagToken:
			if strings.EqualFold(z.Token().Data, "script") {
				inScript = false
			}
		case html.TextToken:
			if inScript {
				if loc == nil {
					loc = NewLocator(string(body))
				}
				line, col := loc.LineCol(off)
				out = append(out, Inline{Text: string(z.Text()), Line: line, Col: col})
			}
		}
		off += n
	}
	return out
}

func hrefAttr(tag string, attrs []html.Attribute) string {
	switch strings.ToLower(tag) {
	case "a", "link":
		return attr(attrs, "href")
	case "form":
		method := strings.ToUpper(attr(attrs, "method"))
		if method != "" && method != "GET" {
			return ""
		}
		return attr(attrs, "action")
	case "iframe", "frame", "embed":
		return attr(attrs, "src")
	default:
		return ""
	}
}

func attr(attrs []html.Attribute, key string) string {
	for _, a := range attrs {
		if strings.EqualFold(a.Key, key) {
			return strings.TrimSpace(a.Val)
		}
	}
	return ""
}

func resolve(base *url.URL, ref string) (string, bool) {
	ref = strings.TrimSpace(ref)
	if ref == "" || strings.HasPrefix(ref, "#") {
		return "", false
	}
	u, err := base.Parse(ref)
	if err != nil {
		return "", false
	}
	if skipScheme[strings.ToLower(u.Scheme)] {
		return "", false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", false
	}
	n, err := normalize.URL(u.String())
	if err != nil {
		return "", false
	}
	return n, true
}

func SameOrigin(a, b string) bool {
	ua, err1 := url.Parse(a)
	ub, err2 := url.Parse(b)
	if err1 != nil || err2 != nil {
		return false
	}
	return strings.EqualFold(ua.Scheme, ub.Scheme) &&
		strings.EqualFold(ua.Hostname(), ub.Hostname()) &&
		port(ua) == port(ub)
}

func port(u *url.URL) string {
	if u.Port() != "" {
		return u.Port()
	}
	if u.Scheme == "https" {
		return "443"
	}
	return "80"
}

func Hintable(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	if JunkURL(raw) {
		return false
	}
	path := strings.ToLower(u.Path)
	for ext := range skipExt {
		if strings.HasSuffix(path, ext) {
			return false
		}
	}
	return true
}

// Icons returns the page's icon links, .ico files first, as absolute URLs
// or data: URLs. A <base href> moves relative links the way browsers do.
func Icons(body []byte, base *url.URL) []string {
	if base == nil {
		return nil
	}
	base = docBase(body, base)
	var hrefs []string
	z := html.NewTokenizer(bytes.NewReader(body))
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			break
		}
		if tt != html.StartTagToken && tt != html.SelfClosingTagToken {
			continue
		}
		tok := z.Token()
		switch strings.ToLower(tok.Data) {
		case "link":
			href := attr(tok.Attr, "href")
			if href == "" {
				continue
			}
			for _, rel := range strings.Fields(strings.ToLower(attr(tok.Attr, "rel"))) {
				if rel == "icon" || rel == "shortcut" || rel == "shortcut-icon" || rel == "apple-touch-icon" || rel == "mask-icon" {
					hrefs = append(hrefs, href)
					break
				}
			}
		}
	}
	var ico, other []string
	seen := map[string]bool{}
	for _, h := range hrefs {
		var u string
		if strings.HasPrefix(strings.ToLower(h), "data:") {
			u = h
		} else if p, err := base.Parse(h); err == nil && (p.Scheme == "http" || p.Scheme == "https") {
			p.Fragment = ""
			u = p.String()
		}
		if u == "" || seen[u] {
			continue
		}
		seen[u] = true
		if strings.HasSuffix(strings.ToLower(strings.SplitN(u, "?", 2)[0]), ".ico") {
			ico = append(ico, u)
		} else {
			other = append(other, u)
		}
	}
	return append(ico, other...)
}
