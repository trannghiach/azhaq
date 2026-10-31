package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// A page with a link, a script, an image, a script that calls a route with
// POST, names a route with a placeholder and holds strings that are no URL.
func kindsSite(t *testing.T) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><body><a href="/about">about</a><img src="/logo.png"><script src="/app.js"></script></body></html>`)
		case "/app.js":
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprint(w, `
fetch("/snippets/fixes", {method: "POST", body: JSON.stringify({key: 1})});
fetch("/rest/items/" + id + "/detail");
var a = "text/plain", b = "application/json", c = "5 items", d = "foo/bar baz";
`)
		case "/about":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><body>about</body></html>`)
		case "/logo.png":
			w.Header().Set("Content-Type", "image/png")
			fmt.Fprint(w, "png")
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// The summary sorts the rows into what a reader compares: the URLs the crawl
// requested and got an answer for (what katana lists), the routes found and
// not requested, the templates, the assets and the strings kept out.
func TestCrawlSummaryCountsEachKindOfRow(t *testing.T) {
	srv := kindsSite(t)
	_, errOut := crawlOut(t, srv, "-json", "-assets")
	sum := sumMap(t, errOut)
	counts, _ := sum["counts"].(map[string]any)
	want := map[string]float64{"requested": 4, "answered": 4, "not requested": 1, "templates": 1, "assets": 1, "rejected strings": 1}
	for k, v := range want {
		if counts[k] != v {
			t.Errorf("%s = %v, want %v (counts %v)", k, counts[k], v, counts)
		}
	}
	// Every URL row is one of requested, not requested or a template.
	if got := counts["requested"].(float64) + counts["not requested"].(float64) + counts["templates"].(float64); got != counts["visited"].(float64)+counts["hint"].(float64) {
		t.Errorf("the kinds add up to %v rows, the coverage counts to %v", got, counts)
	}
}
