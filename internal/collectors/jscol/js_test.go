package jscol

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/trannghiach/azhaq/internal/fetch"
	"github.com/trannghiach/azhaq/types"
)

func jsServer(t *testing.T, hits map[string]*atomic.Int32) *httptest.Server {
	t.Helper()
	html := func(body string) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(body))
		}
	}
	js := func(name, body string) http.HandlerFunc {
		hits[name] = &atomic.Int32{}
		return func(w http.ResponseWriter, _ *http.Request) {
			hits[name].Add(1)
			w.Header().Set("Content-Type", "application/javascript")
			_, _ = w.Write([]byte(body))
		}
	}
	mux := http.NewServeMux()
	shell := `<!doctype html><title>Shop</title><script src="/main.js" type="module"></script><script>var cfg = {"api": "/api/config"}</script>`
	mux.HandleFunc("/blog", html(`<!doctype html><title>Blog</title><script src="/main.js"></script><script src="/searchLogger.js"></script>`))
	mux.HandleFunc("/main.js", js("main", `fetch("/api/Users"); import("./chunk-AB12.js"); const w = "/160";`))
	mux.HandleFunc("/chunk-AB12.js", js("chunk", `fetch("/rest/lazy")`))
	mux.HandleFunc("/searchLogger.js", js("search", `logQuery('/logger', params)`))
	mux.HandleFunc("/api/Challenges", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"description":"<a href=\"/ftp/legal.md\">x</a>","js":"fetch('/api/never')"}`))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		html(shell)(w, r) // every unknown path is the SPA shell
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func run(t *testing.T, col *Collector, raw string) []string {
	t.Helper()
	var urls []string
	emit := func(o types.Observation) error {
		var p struct {
			URL string `json:"url"`
		}
		_ = json.Unmarshal(o.Payload, &p)
		urls = append(urls, strings.TrimPrefix(p.URL, "http://"+strings.Split(strings.TrimPrefix(raw, "http://"), "/")[0]))
		return nil
	}
	if _, err := col.Run(context.Background(), types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": raw}}, emit); err != nil {
		t.Fatal(err)
	}
	return urls
}

func has(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func TestScriptsPerPage(t *testing.T) {
	fetch.Reset()
	hits := map[string]*atomic.Int32{}
	srv := jsServer(t, hits)
	col := New(srv.Client())

	root := run(t, col, srv.URL+"/")
	for _, want := range []string{"/api/Users", "/rest/lazy", "/api/config", "/main.js", "/chunk-AB12.js"} {
		if !has(root, want) {
			t.Errorf("root: missing %s in %v", want, root)
		}
	}
	if has(root, "/160") {
		t.Errorf("root: numeric path kept: %v", root)
	}

	blog := run(t, col, srv.URL+"/blog")
	if !has(blog, "/logger") {
		t.Errorf("blog: page script not parsed: %v", blog)
	}
	if has(blog, "/api/Users") {
		t.Errorf("blog: main.js parsed twice: %v", blog)
	}
	for name, n := range hits {
		if n.Load() != 1 {
			t.Errorf("%s fetched %d times", name, n.Load())
		}
	}
}

func TestSkipsShellAndJSON(t *testing.T) {
	fetch.Reset()
	hits := map[string]*atomic.Int32{}
	srv := jsServer(t, hits)
	col := New(srv.Client())

	if got := run(t, col, srv.URL+"/admin"); len(got) != 0 {
		t.Errorf("catch-all shell parsed: %v", got)
	}
	if got := run(t, col, srv.URL+"/api/Challenges"); len(got) != 0 {
		t.Errorf("JSON parsed as a script: %v", got)
	}
	if !col.Skip(types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": srv.URL + "/api/Users"}}) {
		t.Error("API route not skipped at plan time")
	}
	run(t, col, srv.URL+"/")
	if !col.Skip(types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": srv.URL + "/main.js"}}) {
		t.Error("parsed script not skipped at plan time")
	}
}

func TestVendorScripts(t *testing.T) {
	for p, want := range map[string]bool{
		"/resources/js/react-dom.development.js": true,
		"/static/jquery-3.6.0.min.js":            true,
		"/js/bootstrap.bundle.min.js":            true,
		"/api-docs/swagger-ui-bundle.js":         true,
		"/api-docs/swagger-ui-init.js":           false,
		"/static/js/main.8c78208c.js":            false,
		"/resources/js/stockCheck.js":            false,
		"/js/vuex-store.js":                      false,
	} {
		if got := vendorScript.MatchString(p); got != want {
			t.Errorf("%s: %v", p, got)
		}
	}
}
