package webextract

import (
	"net/url"
	"strings"
	"testing"
)

func TestLinksSamePage(t *testing.T) {
	base, _ := url.Parse("https://app.test/")
	html := []byte(`<a href="/login">l</a><a href="https://evil.test/x">e</a><a href="mailto:a@b">m</a>`)
	got := Links(html, base)
	if len(got) != 2 {
		t.Fatalf("got %v", got)
	}
	if !contains(got, "https://app.test/login") || !contains(got, "https://evil.test/x") {
		t.Fatalf("got %v", got)
	}
	if SameOrigin("https://app.test/", "https://evil.test/x") {
		t.Fatal("evil should not be same origin")
	}
}

func TestJSURLs(t *testing.T) {
	base, _ := url.Parse("https://app.test/page")
	got := JSURLs(`fetch("/api/status"); const x = "https://evil.test/js";`, base)
	if !contains(got, "https://app.test/api/status") {
		t.Fatalf("missing api: %v", got)
	}
}

func TestJSURLsSPAJSON(t *testing.T) {
	base, _ := url.Parse("https://app.test/")
	got := JSURLs(`{"page":"/dashboard","buildId":"x"} fetch(`+"`/api/me`"+`)`, base)
	if !contains(got, "https://app.test/dashboard") || !contains(got, "https://app.test/api/me") {
		t.Fatalf("spa paths missing: %v", got)
	}
}

func TestLinksSkipsPOSTForm(t *testing.T) {
	base, _ := url.Parse("https://app.test/")
	html := []byte(`<form method="post" action="/auth"></form><form method="get" action="/search"></form><form action="/bare"></form>`)
	got := Links(html, base)
	if contains(got, "https://app.test/auth") {
		t.Fatalf("POST action should not be a link: %v", got)
	}
	if !contains(got, "https://app.test/search") || !contains(got, "https://app.test/bare") {
		t.Fatalf("GET/default forms should be links: %v", got)
	}
}

func TestCollapseAndClassify(t *testing.T) {
	got := CollapseURLs([]string{
		"https://app.test/api/Users?x=1",
		"https://app.test/api/Users",
		"https://app.test/login",
	})
	if len(got) != 2 {
		t.Fatalf("%v", got)
	}
	if ClassifyURL("https://app.test/rest/user/login") != "api" {
		t.Fatal("api")
	}
	if ClassifyURL("https://app.test/home") != "page" {
		t.Fatal("page")
	}
	if ClassifyURL("https://app.test/login") != "page" {
		t.Fatal("login is a page")
	}
	if ClassifyURL("https://app.test/") != "page" {
		t.Fatal("root is a page")
	}
	if Hintable("https://app.test/chunk-abc.js") {
		t.Fatal("js is not a crawl hint")
	}
	if RouteKey("https://app.test/api/Users?x=1") != "https://app.test/api/Users" &&
		RouteKey("https://app.test/api/Users?x=1") != "https://app.test/api/Users/" {
		t.Fatalf("route %q", RouteKey("https://app.test/api/Users?x=1"))
	}
}

func TestFormsAndGenerator(t *testing.T) {
	base, _ := url.Parse("https://app.test/")
	html := []byte(`<meta name="generator" content="AzhaqCMS">
<form id="signin" name="login" method="post" action="/login"><input name="user"><input name="pass"></form>`)
	if Generator(html) != "AzhaqCMS" {
		t.Fatalf("generator %q", Generator(html))
	}
	fs := Forms(html, base)
	if len(fs) != 1 || fs[0].Method != "POST" || fs[0].ID != "signin" || fs[0].Name != "login" || !contains(fs[0].Fields, "user") {
		t.Fatalf("forms %+v", fs)
	}
}

func TestFormSubmittingToItsPage(t *testing.T) {
	// DVWA's forms: action="#" and no action submit to the page itself,
	// its query kept, its fragment dropped.
	base, _ := url.Parse("http://dvwa.test/vulnerabilities/sqli/?id=1&Submit=Submit#top")
	page := []byte(`<form action="#" method="GET"><input type="text" name="id"><input type="submit" name="Submit"></form>
<form enctype="multipart/form-data" method="POST"><input type="hidden" name="MAX_FILE_SIZE"><input name="uploaded" type="FILE"><input type="submit" name="Upload"></form>
<form action="" method="post" enctype="bogus"><input name="security"></form>
<form action="/login.php" method="post"><input name="username"></form>`)
	fs := Forms(page, base)
	if len(fs) != 4 {
		t.Fatalf("forms %+v", fs)
	}
	self := "http://dvwa.test/vulnerabilities/sqli/?id=1&Submit=Submit"
	for i, want := range []Form{
		{Method: "GET", Action: self},
		{Method: "POST", Action: self, Enctype: "multipart/form-data", Files: []string{"uploaded"}},
		{Method: "POST", Action: self, Enctype: "application/x-www-form-urlencoded"},
		{Method: "POST", Action: "http://dvwa.test/login.php", Enctype: "application/x-www-form-urlencoded"},
	} {
		f := fs[i]
		if f.Method != want.Method || f.Action != want.Action || f.Enctype != want.Enctype || strings.Join(f.Files, ",") != strings.Join(want.Files, ",") {
			t.Errorf("form %d: %+v, want %+v", i, f, want)
		}
	}
}

// A <base href> moves what the page's relative URLs resolve against, as
// browsers take it: the first one with an href, for the whole page. A
// form with no action still submits to the page; action="#" to the base.
func TestBaseHref(t *testing.T) {
	page, _ := url.Parse("http://app.test/shop/item.php?id=2")
	body := []byte(`<html><head><base href="/app/"><base href="/other/"><script src="main.js"></script></head><body>
<a href="list.php">list</a> <a href="/abs">abs</a> <iframe src="frame.html"></iframe>
<form action="search.php"><input name="q"></form>
<form method="post"><input name="note"></form>
<form action="#top" method="post"><input name="x"></form></body></html>`)
	links := Links(body, page)
	for _, want := range []string{"http://app.test/app/list.php", "http://app.test/abs", "http://app.test/app/frame.html", "http://app.test/app/search.php"} {
		if !contains(links, want) {
			t.Errorf("links %v lack %s", links, want)
		}
	}
	if src := ScriptSrcs(body, page); len(src) != 1 || src[0] != "http://app.test/app/main.js" {
		t.Errorf("scripts %v", src)
	}
	fs := Forms(body, page)
	var actions []string
	for _, f := range fs {
		actions = append(actions, f.Action)
	}
	if want := "http://app.test/app/search.php http://app.test/shop/item.php?id=2 http://app.test/app/"; strings.Join(actions, " ") != want {
		t.Errorf("actions %q, want %q", actions, want)
	}
	// Not a web URL: the page's own.
	if got := Links([]byte(`<base href="javascript:alert(1)"><a href="x">x</a>`), page); len(got) != 1 || got[0] != "http://app.test/shop/x" {
		t.Errorf("links %v", got)
	}
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

// Pages a tag's scripts open are links: the URL-like strings of a
// javascript: href and of an inline handler, and a data-* attribute that
// is one, resolved against the page; nothing that is not one, and
// nothing on another site.
func TestLinksFromHandlers(t *testing.T) {
	base, _ := url.Parse("http://app.test/vulnerabilities/xss_r/")
	page := []byte(`<a href="javascript:popUp('../../vulnerabilities/view_source.php?id=xss_r&amp;security=low')">src</a>
<input type="button" onclick="popUp('view_help.php?id=xss_r'); track('click', 'help')" data-help-url='../view_help.php?id=brute&security=low'>
<li onclick="location.href='/admin/'" data-id="42" data-page="home" data-target="#modal" data-path="/orders">a</li>
<a href="javascript:void(0)" onclick="window.open('https://twitter.com/share?u=1')">t</a>
<a href="javascript:go('api/items')">i</a>`)
	got := Links(page, base)
	want := []string{
		"http://app.test/vulnerabilities/view_source.php?id=xss_r&security=low",
		"http://app.test/vulnerabilities/xss_r/view_help.php?id=xss_r",
		"http://app.test/vulnerabilities/view_help.php?id=brute&security=low",
		"http://app.test/admin/",
	}
	for _, w := range want {
		if !contains(got, w) {
			t.Errorf("%s missing from %q", w, got)
		}
	}
	if len(got) != len(want) {
		t.Errorf("got %q, want %d links", got, len(want))
	}
}
