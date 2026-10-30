package webextract

import (
	"bytes"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/net/html"
)

// PageRef is a URL a page names: the tag and attribute it sits in, and the
// method a script-driven tag sends it with (hx-post), "" for a GET.
type PageRef struct {
	URL, Tag, Attr, Method string
}

// Links are a page's links, iframes, images, GET form actions and the
// other URLs its markup names, resolved against its <base href> when it
// has one, else against base, its URL.
func Links(body []byte, base *url.URL) []string {
	var out []string
	for _, r := range LinkRefs(body, base) {
		if r.Method == "" {
			out = append(out, r.URL)
		}
	}
	return out
}

// LinkRefs is Links with where each URL was read and the writes the page's
// htmx attributes name (hx-post, hx-put, hx-patch), which are listed and
// never asked.
func LinkRefs(body []byte, base *url.URL) []PageRef {
	if base == nil {
		return nil
	}
	base = docBase(body, base)
	var out []PageRef
	seen := map[string]bool{}
	add := func(raw, tag, attr, method string, own bool) {
		u, ok := resolve(base, raw)
		if !ok || seen[u+"\x00"+method] || (own && !SameOrigin(base.String(), u)) {
			return
		}
		seen[u+"\x00"+method] = true
		out = append(out, PageRef{URL: u, Tag: tag, Attr: attr, Method: method})
	}
	z := html.NewTokenizer(bytes.NewReader(body))
	inObject := 0
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			break
		}
		if tt == html.EndTagToken {
			switch strings.ToLower(z.Token().Data) {
			case "object":
				inObject = max(0, inObject-1)
			}
			continue
		}
		if tt != html.StartTagToken && tt != html.SelfClosingTagToken {
			continue
		}
		tok := z.Token()
		tag := strings.ToLower(tok.Data)
		a := func(k string) string { return attr(tok.Attr, k) }
		if tt == html.StartTagToken {
			if tag == "object" {
				inObject++
			}
		}
		one := func(attrs ...string) {
			for _, k := range attrs {
				if v := a(k); v != "" {
					add(v, tag, k, "", false)
				}
			}
		}
		switch tag {
		case "a", "area":
			one("href")
			for _, p := range strings.Fields(a("ping")) {
				add(p, tag, "ping", "", false)
			}
		case "link", "base":
			one("href")
		case "form":
			if m := strings.ToUpper(a("method")); m == "" || m == "GET" {
				one("action")
			}
		case "iframe", "frame", "embed":
			one("src")
		case "img":
			one("src", "dynsrc", "longdesc", "lowsrc")
			for _, v := range srcSet(a("srcset")) {
				add(v, tag, "srcset", "", false)
			}
		case "source":
			one("src")
			for _, v := range srcSet(a("srcset")) {
				add(v, tag, "srcset", "", false)
			}
		case "video":
			one("src", "poster")
		case "audio", "track", "script":
			one("src")
		case "input":
			if strings.EqualFold(a("type"), "image") {
				one("src")
			}
			one("formaction")
		case "object":
			one("data", "codebase")
		case "param":
			if v := a("value"); inObject > 0 && handlerURL.MatchString(v) {
				add(v, "object", "value", "", false)
			}
		case "applet":
			one("archive", "codebase")
		case "body", "table", "td", "th":
			one("background")
		case "blockquote", "q":
			one("cite")
		case "button":
			one("formaction")
		case "isindex":
			one("action")
		case "import":
			one("implementation")
		case "html":
			one("manifest")
		case "image", "use":
			one("href", "xlink:href")
		case "meta":
			if v := metaRefresh(a("content")); v != "" && strings.EqualFold(a("http-equiv"), "refresh") {
				add(v, tag, "refresh", "", false)
			}
		}
		for _, k := range []string{"hx-get", "hx-post", "hx-put", "hx-patch"} {
			if v := a(k); v != "" {
				m := ""
				if k != "hx-get" {
					m = strings.ToUpper(strings.TrimPrefix(k, "hx-"))
				}
				add(v, tag, k, m, false)
			}
		}
		// What the tag's scripts would open: the page's own only, as
		// a handler opening another site is not a link of the page.
		for _, ref := range handlerRefs(tok.Attr) {
			add(ref, tag, "handler", "", true)
		}
	}
	return out
}

// srcSet reads the URLs of a srcset: candidates separated by commas, each
// a URL and an optional descriptor.
func srcSet(v string) []string {
	var out []string
	for _, c := range strings.Split(v, ",") {
		if f := strings.Fields(c); len(f) > 0 {
			out = append(out, f[0])
		}
	}
	return out
}

// metaRefresh is the URL of a refresh's content ("5; url=/next").
func metaRefresh(content string) string {
	_, rest, ok := strings.Cut(content, ";")
	if !ok {
		return ""
	}
	rest = strings.TrimSpace(rest)
	if len(rest) >= 4 && strings.EqualFold(rest[:4], "url=") {
		rest = rest[4:]
	}
	return strings.Trim(strings.TrimSpace(rest), `"'`)
}

// HeaderRefs are the URLs a response's headers name: Link (RFC 8288),
// Content-Location and Refresh. A Location is the redirect itself.
func HeaderRefs(h http.Header, base *url.URL) []PageRef {
	if base == nil {
		return nil
	}
	var out []PageRef
	add := func(raw, attr string) {
		if u, ok := resolve(base, raw); ok {
			out = append(out, PageRef{URL: u, Tag: "header", Attr: attr})
		}
	}
	for _, l := range h.Values("Link") {
		for _, part := range splitLinkHeader(l) {
			if s, e := strings.Index(part, "<"), strings.Index(part, ">"); s >= 0 && e > s {
				add(part[s+1:e], "link")
			}
		}
	}
	if v := strings.TrimSpace(h.Get("Content-Location")); v != "" {
		add(v, "content-location")
	}
	if v := metaRefresh(h.Get("Refresh")); v != "" {
		add(v, "refresh")
	}
	return out
}

// splitLinkHeader splits a Link header's values at the commas that are
// not inside <...>.
func splitLinkHeader(v string) []string {
	var out []string
	depth, start := 0, 0
	for i, r := range v {
		switch r {
		case '<':
			depth++
		case '>':
			depth--
		case ',':
			if depth <= 0 {
				out = append(out, v[start:i])
				start = i + 1
			}
		}
	}
	return append(out, v[start:])
}
