package jscol

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/trannghiach/azhaq/internal/egress"
	"github.com/trannghiach/azhaq/internal/fetch"
	"github.com/trannghiach/azhaq/internal/webextract"
	"github.com/trannghiach/azhaq/types"
)

// served is a test server that counts what is asked of it; every path it
// does not know is the app's shell, as a single-page app's server does.
type served struct {
	*httptest.Server
	mu   sync.Mutex
	hits map[string]int
}

func serve(t *testing.T, files map[string]string, headers map[string]http.Header) *served {
	t.Helper()
	s := &served{hits: map[string]int{}}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.hits[r.URL.Path]++
		s.mu.Unlock()
		for k, vs := range headers[r.URL.Path] {
			w.Header()[k] = vs
		}
		body, ok := files[r.URL.Path]
		switch {
		case !ok && strings.HasPrefix(r.URL.Path, "/api/"):
			http.NotFound(w, r)
			return
		case !ok:
			body = `<!doctype html><title>Shop</title><div id="app"></div>`
			w.Header().Set("Content-Type", "text/html")
		case strings.HasSuffix(r.URL.Path, ".js"):
			w.Header().Set("Content-Type", "application/javascript")
		case strings.HasSuffix(r.URL.Path, ".json"), strings.HasSuffix(r.URL.Path, ".map"):
			w.Header().Set("Content-Type", "application/json")
		default:
			w.Header().Set("Content-Type", "text/html")
		}
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *served) asked(path string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hits[path]
}

// askedSuffix counts the requests for paths that end in suffix.
func (s *served) askedSuffix(suffix string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for p, c := range s.hits {
		if strings.HasSuffix(p, suffix) {
			n += c
		}
	}
	return n
}

// observe runs the collector on raw: its url rows by URL, and the URLs it
// hints.
func observe(t *testing.T, col *Collector, raw string) (map[string]map[string]any, []string) {
	t.Helper()
	out := map[string]map[string]any{}
	meta, err := col.Run(context.Background(), types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": raw}}, func(o types.Observation) error {
		var p map[string]any
		_ = json.Unmarshal(o.Payload, &p)
		if u, ok := p["url"].(string); ok && o.Kind == "url" {
			if old, ok := out[u]; ok && old["via"] == "js-call" {
				return nil // the call's row says more than the string's
			}
			out[u] = p
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var hints []string
	for _, h := range meta.NextHints {
		hints = append(hints, h.Keys["url"])
	}
	return out, hints
}

// A page on one host whose bundle and API live on another: the bundle is
// read when the run may request its host, and the routes it calls there
// are rows of that host, found in the bundle. A script on a host the run
// may not request is left alone.
func TestScriptsOnOtherHosts(t *testing.T) {
	fetch.Reset()
	t.Cleanup(fetch.Reset)
	api := serve(t, map[string]string{
		"/api/v2/profile": `{"ok":1}`,
	}, nil)
	third := serve(t, map[string]string{"/widget.js": `fetch("/api/track")`}, nil)
	thirdURL := strings.Replace(third.URL, "127.0.0.1", "localhost", 1) // another site
	api.Config.Handler = withFile(api.Config.Handler, "/static/app.js",
		`var API="`+api.URL+`/api/v2";fetch(API+"/orders",{method:"POST",body:JSON.stringify({sku:1,qty:2})});`+
			`fetch("`+api.URL+`/api/v2/users/"+id);var cfg={docs:"`+api.URL+`/about/team"};`)
	page := serve(t, map[string]string{
		"/": `<!doctype html><title>app</title><script src="` + api.URL + `/static/app.js"></script>` +
			`<script src="` + thirdURL + `/widget.js"></script><script>fetch("` + api.URL + `/api/v2/profile")</script>`,
	}, nil)
	col := New(page.Client())
	got, hints := observe(t, col, page.URL+"/")

	orders := got[api.URL+"/api/v2/orders"]
	if orders == nil || orders["via"] != "js-call" || orders["from"] != api.URL+"/static/app.js" {
		t.Fatalf("orders %v (rows %v)", orders, keys(got))
	}
	if at := orders["found_in"].([]any)[0].(map[string]any); at["script"] != api.URL+"/static/app.js" {
		t.Errorf("found in %v", at)
	}
	if got[api.URL+"/api/v2/users/{id}"] == nil {
		t.Errorf("users: %v", keys(got))
	}
	if p := got[api.URL+"/api/v2/profile"]; p == nil || p["from"] != nil {
		t.Errorf("an inline call is the page's: %v", p)
	}
	if !contains(hints, api.URL+"/api/v2/profile") || contains(hints, api.URL+"/api/v2/orders") {
		t.Errorf("hints %v", hints)
	}
	if got[api.URL+"/about/team"] != nil {
		t.Errorf("a page of another host named in a string is its own: %v", keys(got))
	}
	if third.asked("/widget.js") != 0 {
		t.Error("a script of another site was fetched")
	}

	// With a scope, its hosts are the site.
	fetch.Reset()
	egress.SetScope(func(h string) bool { return h == "127.0.0.1" || h == "localhost" })
	col = New(page.Client())
	got, _ = observe(t, col, page.URL+"/")
	if third.asked("/widget.js") != 1 || got[thirdURL+"/widget.js"] == nil {
		t.Errorf("a script in the scope was not read: %v", keys(got))
	}
}

// withFile serves body at path, the rest from h.
func withFile(h http.Handler, path, body string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == path {
			w.Header().Set("Content-Type", "application/javascript")
			_, _ = w.Write([]byte(body))
			return
		}
		h.ServeHTTP(w, r)
	})
}

func keys(m map[string]map[string]any) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// juiceMain is shaped like Juice Shop's main.js: the router's table with
// guards, hash routing, router links in templates, and socket.io's client
// called by a minified name.
const juiceMain = "var Hw=[{path:`administration`,component:Su,canActivate:[cs]},{path:`accounting`,component:Vg,canActivate:[ds]}," +
	"{path:`basket`,component:Bk},{path:`order-completion/:id`,component:Oc},{path:`**`,component:Nf}];Ro.forRoot(Hw,{useHash:!0});" +
	"var t1=[[`mat-menu-item`,``,`routerLink`,`/accounting`,`aria-label`,`Go to accounting page`]];" +
	"this.router.navigate([`/order-completion`,e.orderId]);" +
	"this.http.get(this.host+`/rest/products/search?q=`+e);" +
	"t.path=t.path||`/socket.io`,this.opts=t;this.opts=Object.assign({path:`/engine.io`,agent:!1},a);" +
	"this._socket=Xa(window.location.origin,{path:window.location.pathname+`socket.io`});"

func TestClientRoutesAndSockets(t *testing.T) {
	fetch.Reset()
	t.Cleanup(fetch.Reset)
	srv := serve(t, map[string]string{
		"/":        `<!doctype html><html><head><base href="/"></head><body><app-root></app-root><script src="main.js" type="module"></script></body></html>`,
		"/main.js": juiceMain,
	}, nil)
	col := New(srv.Client())
	got, hints := observe(t, col, srv.URL+"/")

	admin := got[srv.URL+"/#/administration"]
	if admin == nil || admin["role"] != "client-route" || admin["guard"] != "canActivate" {
		t.Fatalf("administration %v (rows %v)", admin, keys(got))
	}
	acc := got[srv.URL+"/#/accounting"]
	if acc == nil || len(acc["found_in"].([]any)) != 2 {
		t.Errorf("accounting: the table and the router link: %v", acc)
	}
	if got[srv.URL+"/#/order-completion/{id}"] == nil || got[srv.URL+"/#/basket"]["guard"] != nil {
		t.Errorf("rows %v", keys(got))
	}
	if oc := got[srv.URL+"/#/order-completion/{id}"]; oc == nil || len(oc["found_in"].([]any)) != 2 {
		t.Errorf("order-completion: the table and the navigation: %v", oc)
	}
	for _, p := range []string{"/accounting", "/order-completion", "/socket.io", "/engine.io"} {
		if got[srv.URL+p] != nil || contains(hints, srv.URL+p) {
			t.Errorf("%s is no page of its own", p)
		}
	}
	for _, h := range hints {
		if strings.Contains(h, "#") {
			t.Errorf("a view was hinted: %s", h)
		}
	}
	ws := got["ws://"+strings.TrimPrefix(srv.URL, "http://")+"/socket.io"]
	if ws == nil || ws["role"] != "websocket" || ws["protocol"] != "socket.io" {
		t.Errorf("socket %v (rows %v)", ws, keys(got))
	}
	if got[srv.URL+"/rest/products/search"] == nil {
		t.Errorf("the API call: %v", keys(got))
	}
}

// A router that keeps its views in the path: the views are rows of their
// own path, with their guard, and asked for once with a GET (the server
// may answer them itself), a template left as a row. A link to a view is
// the view's, not a page of its own.
func TestClientRoutesInThePath(t *testing.T) {
	fetch.Reset()
	t.Cleanup(fetch.Reset)
	srv := serve(t, map[string]string{
		"/": `<!doctype html><div id="root"></div><script src="/app.js"></script>`,
		"/app.js": `(0,o.jsx)(Me,{path:"/admin",element:(0,o.jsx)(RequireAuth,{children:(0,o.jsx)(Admin,{})})});var l=(0,o.jsx)(Link,{to:"/admin"});` +
			`const routes=[{path:"/reports",component:Reports},{path:"/reports/:id",component:Report}];createRouter({history:createWebHistory(),routes});`,
	}, nil)
	col := New(srv.Client())
	got, hints := observe(t, col, srv.URL+"/")
	if r := got[srv.URL+"/admin"]; r == nil || r["role"] != "client-route" || r["guard"] != "RequireAuth" || len(r["found_in"].([]any)) != 2 {
		t.Fatalf("admin %v", r)
	}
	for _, p := range []string{"/admin", "/reports"} {
		if !contains(hints, srv.URL+p) {
			t.Errorf("%s not hinted: %v", p, hints)
		}
	}
	if r := got[srv.URL+"/reports/{id}"]; r == nil || r["role"] != "client-route" {
		t.Errorf("reports/{id} %v", r)
	}
	for _, h := range hints {
		if strings.Contains(h, "{") {
			t.Errorf("a template was hinted: %s", h)
		}
	}
}

// A Create React App manifest that lists a map for every chunk of a
// build that left none behind: the maps are asked for out of the
// origin's budget for maps no script named, not one GET each.
func TestAssetManifestMapsCapped(t *testing.T) {
	fetch.Reset()
	t.Cleanup(fetch.Reset)
	files := `"main.js":"/static/js/main.0123abcd.js","main.js.map":"/static/js/main.0123abcd.js.map"`
	for i := 0; i < 40; i++ {
		files += fmt.Sprintf(`,"static/js/%d.chunk.js.map":"/static/js/%d.abcd%04d.chunk.js.map"`, i, i, i)
	}
	srv := serve(t, map[string]string{
		"/":                           `<!doctype html><div id="root"></div><script src="/static/js/main.0123abcd.js"></script>`,
		"/static/js/main.0123abcd.js": `fetch("/api/v1/cra")`,
		"/asset-manifest.json":        `{"files":{` + files + `},"entrypoints":["static/js/main.0123abcd.js"]}`,
	}, nil)
	col := New(srv.Client())
	got, _ := observe(t, col, srv.URL+"/")
	if m := got[srv.URL+"/asset-manifest.json"]; m == nil || m["role"] != "manifest" {
		t.Errorf("manifest %v", m)
	}
	if n := srv.askedSuffix(".map"); n > maxGuessedMaps {
		t.Errorf("%d maps asked for, the budget is %d", n, maxGuessedMaps)
	}
}

// A call whose URL a script builds from a port it only knows at run time
// ('http://127.0.0.1:' + PORT + '/x') is worked out as far as its
// authority: that is no route of any host.
func TestPartialOrigin(t *testing.T) {
	fetch.Reset()
	t.Cleanup(fetch.Reset)
	srv := serve(t, map[string]string{
		"/": `<!doctype html><script>const PORT=window.__p;fetch('http://127.0.0.1:' + PORT + '/other-post', {method:'POST', body:'q=1'});` +
			`fetch('http://127.0.0.1:' + PORT + '/other-cors', {method:'PUT'});fetch('/api/items', {method:'POST', body:'q=1'});</script>`,
	}, nil)
	col := New(srv.Client())
	got, hints := observe(t, col, srv.URL+"/")
	for u := range got {
		if strings.Contains(u, "127.0.0.1:/") || strings.HasSuffix(u, ":") {
			t.Errorf("a route of no host: %s", u)
		}
	}
	for _, h := range hints {
		if strings.Contains(h, "127.0.0.1:/") {
			t.Errorf("hinted: %s", h)
		}
	}
	if got[srv.URL+"/api/items"] == nil {
		t.Errorf("the page's own call: %v", keys(got))
	}
	for _, p := range []string{"http://127.0.0.1:", "https://api.", "https://api.example.com:", "http://:8080/x"} {
		if _, ok := callRoute(webextract.Call{Path: p, Method: "POST"}, srv.URL, srv.URL+"/"); ok {
			t.Errorf("%q taken as a route", p)
		}
		if keepString(srv.URL+"/", p) {
			t.Errorf("%q kept", p)
		}
	}
}

// Next.js: the build manifest at its known place for the page's build,
// its pages (dynamic ones as templates, its own left out) and the page
// chunks, named from the asset root.
func TestNextManifests(t *testing.T) {
	fetch.Reset()
	t.Cleanup(fetch.Reset)
	srv := serve(t, map[string]string{
		"/": `<!doctype html><div id="__next"></div><script src="/_next/static/chunks/main-1111.js" defer></script>` +
			`<script id="__NEXT_DATA__" type="application/json">{"props":{"pageProps":{}},"page":"/","query":{},"buildId":"abc123"}</script>`,
		"/_next/static/chunks/main-1111.js": `fetch("/api/me")`,
		"/_next/static/abc123/_buildManifest.js": `self.__BUILD_MANIFEST=function(s){return{"/":[s,"static/chunks/pages/index-1a2b.js"],` +
			`"/admin/users/[userId]":["static/chunks/pages/admin/users/[userId]-9f8e.js"],sortedPages:["/","/_app","/_error","/admin/users/[userId]"]}}("static/chunks/1-abc.js");`,
		"/_next/static/abc123/_ssgManifest.js":                    `self.__SSG_MANIFEST=new Set(["/blog/hidden-post"]);`,
		"/_next/static/chunks/pages/admin/users/[userId]-9f8e.js": `fetch("/api/admin/users/"+e+"/permissions",{method:"PUT"})`,
	}, nil)
	col := New(srv.Client())
	got, hints := observe(t, col, srv.URL+"/")
	for _, want := range []string{"/admin/users/{userId}", "/blog/hidden-post", "/api/admin/users/{id}/permissions"} {
		if got[srv.URL+want] == nil {
			t.Errorf("missing %s in %v", want, keys(got))
		}
	}
	for _, p := range []string{"/_app", "/_error"} {
		if got[srv.URL+p] != nil || contains(hints, srv.URL+p) {
			t.Errorf("%s is Next.js's own", p)
		}
	}
	if srv.asked("/_next/static/abc123/static/chunks/pages/index-1a2b.js") != 0 || srv.asked("/_next/static/chunks/pages/index-1a2b.js") != 1 {
		t.Error("chunks are named from /_next/")
	}
}

// Source maps no comment names: the SourceMap header's, and a guess next
// to the bundle, kept only when it is one, a few per origin.
func TestSourceMapsWithoutAComment(t *testing.T) {
	fetch.Reset()
	t.Cleanup(fetch.Reset)
	files := map[string]string{
		"/hdr.js":     `fetch("/api/a")`,
		"/maps/h.map": `{"version":3,"sources":["webpack://app/./src/admin.ts"],"sourcesContent":["fetch(\"/api/internal/debug\")"],"mappings":"AAAA"}`,
		"/main.js":    `fetch("/api/b")`,
		"/main.js.map": `{"version":3,"sources":["webpack://app/./src/main.ts","webpack://app/node_modules/x/index.js"],` +
			`"sourcesContent":["fetch(\"/api/hidden\")",null],"mappings":"AAAA"}`,
		"/other.js":     `fetch("/api/c")`,
		"/other.js.map": `{"sources":["a.ts"]}`, // no mappings: no map
	}
	page := `<!doctype html><script src="/hdr.js"></script><script src="/main.js"></script><script src="/other.js"></script>`
	for i := range 12 {
		name := "/c" + string(rune('a'+i)) + ".js"
		files[name] = `var x=1`
		page += `<script src="` + name + `"></script>`
	}
	files["/"] = page
	srv := serve(t, files, map[string]http.Header{"/hdr.js": {"Sourcemap": {"/maps/h.map"}}})
	col := New(srv.Client())
	got, _ := observe(t, col, srv.URL+"/")
	if m := got[srv.URL+"/maps/h.map"]; m == nil || m["role"] != "sourcemap" || m["guessed"] != nil {
		t.Errorf("header map %v", m)
	}
	if m := got[srv.URL+"/main.js.map"]; m == nil || m["guessed"] != true {
		t.Errorf("guessed map %v", m)
	}
	if got[srv.URL+"/other.js.map"] != nil {
		t.Error("JSON that is no map kept as one")
	}
	for _, p := range []string{"/api/internal/debug", "/api/hidden"} {
		if got[srv.URL+p] == nil {
			t.Errorf("missing %s from a map's sources", p)
		}
	}
	if srv.asked("/hdr.js.map") != 0 {
		t.Error("a map guessed for a script whose header named one")
	}
	guesses := 0
	for p, n := range srv.hits {
		if strings.HasSuffix(p, ".js.map") {
			guesses += n
		}
	}
	if guesses != maxGuessedMaps {
		t.Errorf("%d maps guessed on one origin", guesses)
	}
}

// Create React App's asset manifest lists every chunk, those no script
// names by a string too.
func TestAssetManifest(t *testing.T) {
	fetch.Reset()
	t.Cleanup(fetch.Reset)
	srv := serve(t, map[string]string{
		"/":                            `<!doctype html><div id="root"></div><script defer src="/static/js/main.8e2b9c1d.js"></script>`,
		"/static/js/main.8e2b9c1d.js":  `fetch("/api/me")`,
		"/asset-manifest.json":         `{"files":{"main.js":"/static/js/main.8e2b9c1d.js","static/js/787.1c2d.chunk.js":"/static/js/787.1c2d.chunk.js","index.html":"/index.html"},"entrypoints":["static/js/main.8e2b9c1d.js"]}`,
		"/static/js/787.1c2d.chunk.js": `axios.post("/api/admin/export",{format:f})`,
	}, nil)
	col := New(srv.Client())
	got, _ := observe(t, col, srv.URL+"/")
	if m := got[srv.URL+"/asset-manifest.json"]; m == nil || m["role"] != "manifest" || m["framework"] != "cra" {
		t.Errorf("manifest %v", m)
	}
	if got[srv.URL+"/api/admin/export"] == nil {
		t.Errorf("the chunk only the manifest lists: %v", keys(got))
	}
}

// A socket at the address the server listens on (DVGA's
// ws://0.0.0.0:5013/subscriptions) is the page's server's.
func TestSocketOnTheListeningAddress(t *testing.T) {
	fetch.Reset()
	t.Cleanup(fetch.Reset)
	srv := serve(t, map[string]string{}, nil)
	port := srv.URL[strings.LastIndex(srv.URL, ":")+1:]
	srv.Config.Handler = withFile(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<!doctype html><script>function sub(){var s=new WebSocket("ws://0.0.0.0:` + port + `/subscriptions");` +
			`var o=new WebSocket("ws://0.0.0.0:1/other")}</script>`))
	}), "/none.js", "")
	got, _ := observe(t, New(srv.Client()), srv.URL+"/")
	if got["ws://"+strings.TrimPrefix(srv.URL, "http://")+"/subscriptions"] == nil || len(got) != 1 {
		t.Errorf("rows %v", keys(got))
	}
}
