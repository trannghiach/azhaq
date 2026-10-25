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
	ID     string
	Name   string
	Fields []string
}

// Forms returns <form> elements and script-driven forms: any element with a
// data-action attribute (data-method gives the method) whose inputs are
// posted by JavaScript.
func Forms(body []byte, base *url.URL) []Form {
	if base == nil {
		return nil
	}
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
		if action == "" {
			action = base.Path
		}
		act := ""
		if u, ok := resolve(base, action); ok {
			act = u
		}
		cur = &Form{
			Method: method,
			Action: act,
			ID:     attr(tok.Attr, "id"),
			Name:   attr(tok.Attr, "name"),
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
		}
	}
	if cur != nil {
		out = append(out, *cur)
	}
	return out
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

func ParamNames(body []byte, base *url.URL) []string {
	seen := map[string]bool{}
	var out []string
	add := func(name string) {
		name = strings.TrimSpace(name)
		if name == "" || seen[name] {
			return
		}
		seen[name] = true
		out = append(out, name)
	}
	for _, link := range Links(body, base) {
		u, err := url.Parse(link)
		if err != nil {
			continue
		}
		for k := range u.Query() {
			add(k)
		}
	}
	for _, f := range Forms(body, base) {
		for _, name := range f.Fields {
			add(name)
		}
	}
	return out
}

func Links(body []byte, base *url.URL) []string {
	if base == nil {
		return nil
	}
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

func ScriptSrcs(body []byte, base *url.URL) []string {
	if base == nil {
		return nil
	}
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
	z := html.NewTokenizer(bytes.NewReader(body))
	inScript := false
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			break
		}
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
				out = append(out, string(z.Text()))
			}
		}
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
		case "base":
			if b := attr(tok.Attr, "href"); b != "" {
				if u, err := base.Parse(b); err == nil {
					base = u
				}
			}
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
