package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/trannghiach/azhaq/internal/browser"
)

// A page with a link to another site, a link of its own and a button that
// calls an API route nothing else names.
func offsiteLinkServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><title>home</title><body><a href="http://203.0.113.9/elsewhere">Docs</a> <a href="/about">About</a> <a href="/team">Team</a>
<button onclick="fetch('/api/' + ['cli', 'cked'].join(''))">Load</button><script src="/app.js"></script></body></html>`)
		case "/app.js":
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprint(w, `fetch('/api/' + ['lo', 'aded'].join(''));`)
		case "/about", "/team":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, `<html><title>%s</title><body><a href="/">Home</a></body></html>`, r.URL.Path)
		default:
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"ok":true}`)
		}
	}))
}

// -interact adds what clicks find to the ordinary crawl. A click on a link
// to another site leaves the scope and is refused; the page keeps its rows.
func TestInteractAddsToTheCrawlWhenAClickLeavesTheScope(t *testing.T) {
	if _, err := browser.Find(); err != nil {
		t.Skip(err)
	}
	srv := offsiteLinkServer()
	defer srv.Close()
	t.Chdir(t.TempDir())
	rows := func(extra ...string) (map[string]bool, string) {
		args := append([]string{"crawl", "-u", srv.URL + "/", "-d", "1", "-browser", "-allow", "127.0.0.1", "-json", "-db", fmt.Sprintf("c%d.db", len(extra))}, extra...)
		out, errOut, code := cli(t, args...)
		if code != exitOK {
			t.Fatalf("%v: exit %d\n%s", extra, code, errOut)
		}
		got := map[string]bool{}
		for _, r := range jsonRows(t, out) {
			got[r["url"].(string)] = true
		}
		return got, errOut
	}
	plain, _ := rows()
	clicked, errOut := rows("-interact", "-interact-clicks", "4")
	for u := range plain {
		if !clicked[u] {
			t.Errorf("-interact lost %s, which the crawl without it has", u)
		}
	}
	for _, route := range []string{"/api/loaded", "/api/clicked"} {
		if !clicked[srv.URL+route] {
			t.Errorf("%s is not among the rows with -interact: %v", route, clicked)
		}
	}
	if !strings.Contains(errOut, "-interact: 6 clicks") && !strings.Contains(errOut, "-interact: 7 clicks") {
		t.Errorf("the summary's -interact note is missing or counts too few clicks:\n%s", errOut)
	}
}
