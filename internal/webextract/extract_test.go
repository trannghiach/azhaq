package webextract

import (
	"net/url"
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

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}
