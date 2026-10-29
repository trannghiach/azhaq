package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/trannghiach/azhaq/engine"
	"github.com/trannghiach/azhaq/internal/webextract"
	"github.com/trannghiach/azhaq/types"
)

func routeRow(url, tmpl string, methods []string, ops ...engine.Op) engine.MapEntry {
	return engine.MapEntry{
		Entity: types.Entity{Type: types.TypeURL, Key: url}, Role: "api", Template: tmpl, Methods: methods, Ops: ops,
		Found: []webextract.Site{{Script: "http://h/main.js"}},
	}
}

func js(method string, query, body []string) engine.Op {
	return engine.Op{Method: method, Query: query, Body: body, Source: "js-call"}
}

func changesOf(old, neu []engine.MapEntry) []routeChange {
	o, _ := routesOf(old)
	n, all := routesOf(neu)
	return compareRoutes(o, n, all)
}

func TestRouteChangeRules(t *testing.T) {
	base := []engine.MapEntry{
		routeRow("http://h/api/orders/{id}", "http://h/api/orders/{id}", []string{"GET"}, js("GET", nil, nil)),
		routeRow("http://h/api/profile", "", []string{"PUT"}, js("PUT", nil, []string{"name", "email"})),
		routeRow("http://h/api/legacy/report", "", []string{"GET"}, js("GET", nil, nil)),
	}
	next := []engine.MapEntry{
		routeRow("http://h/api/orders/{id}", "http://h/api/orders/{id}", []string{"DELETE", "GET"}, js("GET", nil, nil), js("DELETE", nil, nil)),
		routeRow("http://h/api/profile", "", []string{"PUT"}, js("PUT", nil, []string{"name", "email", "role"})),
		routeRow("http://h/api/v2/export", "", []string{"POST"}, js("POST", nil, []string{"userId", "format"})),
	}
	got := changesOf(base, next)
	lines := routeLines(got)
	want := []string{
		"+ POST /api/v2/export {format, userId}  (main.js)",
		"~ /api/orders/{id}: +DELETE  (main.js)",
		"~ PUT /api/profile: +role  (main.js)",
		"- /api/legacy/report  (main.js)",
	}
	if strings.Join(lines, "\n") != strings.Join(want, "\n") {
		t.Fatalf("got\n%s\nwant\n%s", strings.Join(lines, "\n"), strings.Join(want, "\n"))
	}
	if got[0].Script != "http://h/main.js" || got[2].Method != "PUT" {
		t.Errorf("the script URL and the method are kept: %+v", got)
	}
}

func TestRouteRemovedFieldsAndMethods(t *testing.T) {
	old := []engine.MapEntry{routeRow("http://h/api/p", "", []string{"GET", "PUT"}, js("PUT", []string{"q"}, []string{"a", "b"}))}
	neu := []engine.MapEntry{routeRow("http://h/api/p", "", []string{"PUT"}, js("PUT", []string{"q"}, []string{"a"}))}
	got := routeLines(changesOf(old, neu))
	if len(got) != 2 || got[0] != "~ /api/p: -GET  (main.js)" || got[1] != "~ PUT /api/p: -b  (main.js)" {
		t.Fatalf("%q", got)
	}
}

func TestRouteNoNoise(t *testing.T) {
	old := []engine.MapEntry{
		routeRow("http://H/api/orders/{id}", "http://H/api/orders/{id}", []string{"GET", "DELETE"}, js("GET", []string{"x", "y"}, nil), js("DELETE", nil, []string{"Reason"})),
		routeRow("http://h/api/users/7", "http://h/api/users/{n}", []string{"GET"}, js("GET", nil, nil)),
	}
	// Another placeholder name, a trailing slash, case, ordering.
	neu := []engine.MapEntry{
		routeRow("http://h/api/users/9", "http://h/api/users/{n}", []string{"GET"}, js("GET", nil, nil)),
		routeRow("http://h/API/Orders/{orderId}/", "http://h/API/Orders/{orderId}/", []string{"DELETE", "GET"}, js("DELETE", nil, []string{"reason"}), js("GET", []string{"y", "x"}, nil)),
	}
	if got := changesOf(old, neu); len(got) != 0 {
		t.Fatalf("identifiers, ordering and case are not changes: %+v", got)
	}
}

func TestRouteGoneNeedsAScriptAndNoOtherSource(t *testing.T) {
	archived := engine.MapEntry{Entity: types.Entity{Type: types.TypeURL, Key: "http://h/api/old"}, Role: "api"}
	old := []engine.MapEntry{archived, routeRow("http://h/api/a", "", []string{"GET"}, js("GET", nil, nil)), routeRow("http://h/api/b", "", []string{"GET"}, js("GET", nil, nil))}
	// /api/b is still on a page the crawl found, with no script naming it.
	crawled := engine.MapEntry{Entity: types.Entity{Type: types.TypeURL, Key: "http://h/api/b"}, Role: "page"}
	got := changesOf(old, []engine.MapEntry{crawled})
	if len(got) != 1 || got[0].Kind != "gone" || got[0].Route != "/api/a" {
		t.Fatalf("only the scripted route that nothing holds is gone: %+v", got)
	}
}

func TestRouteGuessedIsNotNew(t *testing.T) {
	guessed := engine.MapEntry{Entity: types.Entity{Type: types.TypeURL, Key: "http://h/api/swagger.json"}, Role: "api", Status: 200}
	if got := changesOf(nil, []engine.MapEntry{guessed}); len(got) != 0 {
		t.Fatalf("a route no script names is not a deploy: %+v", got)
	}
}

func TestRouteAnswerChangeIsNotARouteChange(t *testing.T) {
	a := routeRow("http://h/api/x", "", []string{"GET"}, js("GET", nil, nil))
	b := a
	b.Status, b.Title = 403, "forbidden"
	if got := changesOf([]engine.MapEntry{a}, []engine.MapEntry{b}); len(got) != 0 {
		t.Fatalf("%+v", got)
	}
}

func TestRoutesTextSection(t *testing.T) {
	c := changes{DB: "w.db", Routes: []routeChange{{Kind: "gone", Host: "h", Route: "/api/legacy/report"}}}
	if !c.any() || !strings.Contains(c.text(), "~ 1 API routes\n    - /api/legacy/report\n") {
		t.Fatalf("%q", c.text())
	}
	two := routeLines([]routeChange{{Kind: "gone", Host: "a", Route: "/x"}, {Kind: "gone", Host: "b", Route: "/y"}})
	if two[0] != "- a/x" || two[1] != "- b/y" {
		t.Fatalf("%q", two)
	}
}

// A deploy that changes the bundle reaches a JSON hook and the text of
// the notification, and an unchanged run reports no route.
func TestWatchRoutesReachTheHook(t *testing.T) {
	var mu sync.Mutex
	v2 := false
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.URL.Path == "/":
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<html><title>app</title><script src="/main.js"></script></html>`))
		case r.URL.Path == "/main.js":
			w.Header().Set("Content-Type", "application/javascript")
			if v2 {
				w.Write([]byte(`fetch("/api/v2/export", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({userId: 1, format: "csv"})});`))
			} else {
				w.Write([]byte(`fetch("/api/legacy/report");`))
			}
		case strings.HasPrefix(r.URL.Path, "/api/"):
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"ok":true}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer site.Close()
	type post struct {
		Text string `json:"text"`
		Data struct {
			Routes []routeChange `json:"routes"`
		} `json:"data"`
	}
	var posts []post
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var p post
		_ = json.NewDecoder(r.Body).Decode(&p)
		mu.Lock()
		posts = append(posts, p)
		mu.Unlock()
	}))
	defer hook.Close()
	db := filepath.Join(t.TempDir(), "ws.db")
	watch := func() changes {
		out := capture(t, func() error {
			return cmdWatch([]string{"-db", db, "-json", "-notify", hook.URL, "--", "-url", site.URL + "/", "-skip", "azhaq-paths"})
		})
		var ch changes
		if err := json.Unmarshal([]byte(out), &ch); err != nil {
			t.Fatalf("%v: %q", err, out)
		}
		return ch
	}
	if first := watch(); len(first.Routes) != 0 {
		t.Fatalf("the first run has nothing to compare: %+v", first.Routes)
	}
	mu.Lock()
	v2 = true
	mu.Unlock()
	ch := watch()
	if len(ch.Routes) != 2 || ch.Routes[0].Kind != "new" || ch.Routes[0].Route != "/api/v2/export" || ch.Routes[1].Kind != "gone" || ch.Routes[1].Route != "/api/legacy/report" {
		t.Fatalf("routes %+v", ch.Routes)
	}
	if len(ch.URLs)+len(ch.GoneURLs) != 0 {
		t.Errorf("the routes are not repeated as URLs: %v %v", ch.URLs, ch.GoneURLs)
	}
	if again := watch(); again.any() {
		t.Fatalf("an unchanged run reported %+v", again)
	}
	mu.Lock()
	defer mu.Unlock()
	last := posts[len(posts)-1]
	if len(posts) != 2 || len(last.Data.Routes) != 2 || last.Data.Routes[0].Script != site.URL+"/main.js" ||
		!strings.Contains(last.Text, "+ POST /api/v2/export {format, userId}  (main.js)") || !strings.Contains(last.Text, "- /api/legacy/report") {
		t.Errorf("hook posts %+v", posts)
	}
}
