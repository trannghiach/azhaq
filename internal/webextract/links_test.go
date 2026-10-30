package webextract

import (
	"net/http"
	"net/url"
	"slices"
	"testing"
)

func TestLinksReadEveryMarkupSink(t *testing.T) {
	page := `<html><head><meta http-equiv="refresh" content="5; url=/meta"><link rel=stylesheet href="/s.css"></head><body>
<img src="/pic"><img srcset="/p2 1x, /p3 2x"><area href="/area"><video poster="/poster"><source src="/vsrc"></video>
<button formaction="/btn">x</button><object data="/obj"></object><div hx-get="/hget"></div><div hx-post="/hpost"></div>
<input type=image src="/imginput"><blockquote cite="/cite">q</blockquote><a href="/a" ping="/ping">a</a>
<form action="/f" method="post"></form><form action="/g"></form></body></html>`
	got := Links([]byte(page), &url.URL{Scheme: "http", Host: "h", Path: "/"})
	for _, p := range []string{"/meta", "/pic", "/p2", "/p3", "/area", "/poster", "/vsrc", "/btn", "/obj", "/hget", "/imginput", "/cite", "/a", "/ping", "/g", "/s.css"} {
		if !slices.Contains(got, "http://h"+p) {
			t.Errorf("%s is not read: %v", p, got)
		}
	}
	for _, p := range []string{"/hpost", "/f"} {
		if slices.Contains(got, "http://h"+p) {
			t.Errorf("%s is a write and is not a link: %v", p, got)
		}
	}
	var post *PageRef
	for _, r := range LinkRefs([]byte(page), &url.URL{Scheme: "http", Host: "h", Path: "/"}) {
		if r.URL == "http://h/hpost" {
			post = &r
		}
	}
	if post == nil || post.Method != "POST" || post.Tag != "div" || post.Attr != "hx-post" {
		t.Errorf("hx-post: %+v", post)
	}
}

func TestHeaderRefs(t *testing.T) {
	h := http.Header{}
	h.Add("Link", `</a>; rel=preload, <https://x.test/b>; rel=next`)
	h.Set("Content-Location", "/c")
	h.Set("Refresh", "0; url=/d")
	var got []string
	for _, r := range HeaderRefs(h, &url.URL{Scheme: "http", Host: "h", Path: "/"}) {
		got = append(got, r.URL)
	}
	for _, w := range []string{"http://h/a", "https://x.test/b", "http://h/c", "http://h/d"} {
		if !slices.Contains(got, w) {
			t.Errorf("%s missing from %v", w, got)
		}
	}
}

func TestBareStrings(t *testing.T) {
	page := &url.URL{Scheme: "http", Host: "h", Path: "/"}
	cases := []struct {
		s      string
		link   string
		reason string
	}{
		{"users.php", "http://h/users.php", ""},
		{"admin/", "http://h/admin/", ""},
		{"./local/route", "http://h/local/route", ""},
		{"text/plain", "", ReasonNotPath + " (a media type)"},
		{"vendor.min.js", "", ReasonAsset},
		{"/img/a.png", "", ReasonAsset},
		{"/x/${id}", "", ReasonExpression},
		{"a\\b/c", "", ReasonExpression},
		{"/1234", "", ReasonNotPath},
		{"api/v1", "", ReasonNotPath},
	}
	for _, c := range cases {
		link, reason := BareString(c.s, page)
		if (c.link != "" && link == "") || (c.link == "" && link != "") || reason != c.reason {
			t.Errorf("%q = %q, %q; want %q, %q", c.s, link, reason, c.link, c.reason)
		}
	}
}

func TestCandidatesKeepTheScriptRelativeReading(t *testing.T) {
	page := &url.URL{Scheme: "http", Host: "h", Path: "/"}
	src := &url.URL{Scheme: "http", Host: "h", Path: "/assets/app.js"}
	cs := Candidates(`var a = "./go/there"; var b = "users.php";`, page, src, true)
	var alt int
	for _, c := range cs {
		if c.Alt != "" {
			alt++
		}
	}
	if len(cs) != 2 || alt != 2 {
		t.Errorf("%+v", cs)
	}
}

// Juice Shop's minified scripts: a division the page pattern reads as a
// .do path, and user-agent strings searched for, are no URLs; a path
// passed on is.
func TestCandidatesLeaveCodeAndSearchedStrings(t *testing.T) {
	page := &url.URL{Scheme: "http", Host: "h", Path: "/"}
	src := `b=b*(h=="-"?-1:1)+a.number/t.doc.lines;(t.indexOf("Trident/")!==-1||t.indexOf( 'Edge/')!==-1);` +
		`let o=i.url.replace("/api/old/","/api/new/");go("/rest/user/login.do");var p="admin/"`
	got := map[string]string{}
	for _, c := range Candidates(src, page, page, true) {
		got[c.Text] = c.Reason
	}
	want := map[string]string{"a.number/t.do": ReasonCode, "Trident/": ReasonSearched, "Edge/": ReasonSearched,
		"/api/old/": ReasonSearched, "/api/new/": "", "/rest/user/login.do": "", "admin/": ""}
	for s, r := range want {
		if g, ok := got[s]; !ok || g != r {
			t.Errorf("%q: reason %q (found %v), want %q", s, g, ok, r)
		}
	}
}
