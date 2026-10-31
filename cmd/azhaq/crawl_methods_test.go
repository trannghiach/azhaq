package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A page whose script calls /snippets/fixes and /logger with POST (a GET
// answers 404), /catalog/subscribe with POST (a GET answers 405) and
// /rest/items with both GET and POST.
func postRoutesSite(t *testing.T) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><body><a href="/about">about</a><script src="/app.js"></script></body></html>`)
		case r.URL.Path == "/app.js":
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprint(w, `
fetch("/snippets/fixes", {method: "POST", body: JSON.stringify({key: 1})});
fetch("/logger", {method: "POST", body: JSON.stringify({q: 1})});
var x = new XMLHttpRequest(); x.open("POST", "/catalog/subscribe");
fetch("/rest/items"); fetch("/rest/items", {method: "POST", body: JSON.stringify({name: "a"})});
`)
		case r.URL.Path == "/about":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><body>about</body></html>`)
		case r.URL.Path == "/catalog/subscribe":
			w.Header().Set("Allow", "POST")
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		case r.URL.Path == "/rest/items" && r.Method == http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `[]`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func crawlOut(t *testing.T, srv *httptest.Server, args ...string) (string, string) {
	t.Helper()
	out, errOut, err := captureBoth(t, func() error {
		return cmdCrawl(append([]string{"-u", srv.URL + "/", "-allow", "127.0.0.1", "-db", filepath.Join(t.TempDir(), "w.db")}, args...))
	})
	if err != nil && exitCode(err) != exitPartial {
		t.Fatal(err)
	}
	return out, errOut
}

// Plain crawl lists the routes a script calls with POST, and says so: -ot
// with {{method}} prints the method of each, the summary counts them, and
// -json rows carry methods.
func TestCrawlShowsTheMethodOfScriptCalledRoutes(t *testing.T) {
	srv := postRoutesSite(t)
	plain, errOut := crawlOut(t, srv)
	for _, p := range []string{"/snippets/fixes", "/logger", "/catalog/subscribe"} {
		if !strings.Contains(plain, srv.URL+p+"\n") {
			t.Errorf("plain crawl does not list %s:\n%s", p, plain)
		}
	}
	if !strings.Contains(errOut, "3 listed URLs are routes scripts call with a method other than GET") ||
		!strings.Contains(errOut, "{{method}}") {
		t.Errorf("the summary does not say that plain output lists routes with other methods:\n%s", errOut)
	}

	withMethod, _ := crawlOut(t, srv, "-ot", "{{method}} {{url}}")
	lines := map[string]bool{}
	for _, l := range strings.Split(strings.TrimSpace(withMethod), "\n") {
		lines[strings.TrimPrefix(l, "")] = true
	}
	for _, want := range []string{
		"GET " + srv.URL + "/", "GET " + srv.URL + "/about", "GET " + srv.URL + "/app.js",
		"POST " + srv.URL + "/snippets/fixes", "POST " + srv.URL + "/logger", "POST " + srv.URL + "/catalog/subscribe",
		"GET " + srv.URL + "/rest/items", "POST " + srv.URL + "/rest/items",
	} {
		if !lines[want] {
			t.Errorf("-ot '{{method}} {{url}}' has no line %q:\n%s", want, withMethod)
		}
	}

	fields, _ := crawlOut(t, srv, "-f", "method,path", "-mr", "/logger")
	if strings.TrimSpace(fields) != "POST\n/logger" {
		t.Errorf("-f method,path for /logger: %q", fields)
	}

	dir := t.TempDir()
	crawlOut(t, srv, "-sf", "method", "-sfd", dir)
	files, _ := filepath.Glob(filepath.Join(dir, "*_method.txt"))
	if len(files) != 1 {
		t.Fatalf("-sf method wrote %v", files)
	}
	if b, _ := os.ReadFile(files[0]); !strings.Contains(string(b), "POST\n") || !strings.Contains(string(b), "GET\n") {
		t.Errorf("-sf method file: %q", b)
	}

	rows := urlRows(t, func() string { out, _ := crawlOut(t, srv, "-json"); return out }())
	if m, _ := rows[srv.URL+"/snippets/fixes"]["methods"].([]any); len(m) != 1 || m[0] != "POST" {
		t.Errorf("-json methods of /snippets/fixes: %v", rows[srv.URL+"/snippets/fixes"])
	}
}
