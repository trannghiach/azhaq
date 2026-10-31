package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

// A page that loads two scripts, a stylesheet, an image and an icon, and a
// script that imports a chunk.
func assetsSite(t *testing.T) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		js := func(body string) {
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprint(w, body)
		}
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><head><link rel="stylesheet" href="/styles.css"><link rel="icon" href="/favicon.ico"><script src="/main.js"></script><script src="/polyfills.js"></script></head><body><img src="/logo.png"><a href="/about">about</a></body></html>`)
		case "/main.js":
			js(`import("./chunk-abc.js").then(function (m) { m.go(); });`)
		case "/polyfills.js":
			js(`window.polyfilled = true;`)
		case "/chunk-abc.js":
			js(`export function go() {}`)
		case "/styles.css":
			w.Header().Set("Content-Type", "text/css")
			fmt.Fprint(w, `body { margin: 0 }`)
		case "/about":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><body>about</body></html>`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func crawlLines(t *testing.T, srv *httptest.Server, args ...string) map[string]bool {
	t.Helper()
	out, _, err := captureBoth(t, func() error {
		return cmdCrawl(append([]string{"-u", srv.URL + "/", "-allow", "127.0.0.1", "-db", filepath.Join(t.TempDir(), "w.db")}, args...))
	})
	if err != nil && exitCode(err) != exitPartial {
		t.Fatal(err)
	}
	lines := map[string]bool{}
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		lines[strings.TrimPrefix(l, srv.URL)] = true
	}
	return lines
}

// crawl lists the scripts and stylesheets of the pages it reads by default,
// as katana does, and keeps images, fonts and media for -assets.
func TestCrawlListsScriptsAndStylesByDefault(t *testing.T) {
	srv := assetsSite(t)
	lines := crawlLines(t, srv)
	for _, want := range []string{"/", "/about", "/main.js", "/polyfills.js", "/chunk-abc.js", "/styles.css"} {
		if !lines[want] {
			t.Errorf("crawl does not list %s: %v", want, lines)
		}
	}
	for _, not := range []string{"/logo.png", "/favicon.ico"} {
		if lines[not] {
			t.Errorf("crawl lists %s without -assets", not)
		}
	}
	all := crawlLines(t, srv, "-assets")
	for _, want := range []string{"/main.js", "/styles.css", "/logo.png", "/favicon.ico"} {
		if !all[want] {
			t.Errorf("crawl -assets does not list %s: %v", want, all)
		}
	}
	rows := urlRows(t, func() string {
		out, _, _ := captureBoth(t, func() error {
			return cmdCrawl([]string{"-u", srv.URL + "/", "-allow", "127.0.0.1", "-json", "-db", filepath.Join(t.TempDir(), "w.db")})
		})
		return out
	}())
	for _, want := range []string{"/main.js", "/chunk-abc.js", "/styles.css"} {
		if rows[srv.URL+want] == nil {
			t.Errorf("crawl -json has no row for %s", want)
		}
	}
	if rows[srv.URL+"/logo.png"] != nil {
		t.Error("crawl -json lists an image without -assets")
	}
}
