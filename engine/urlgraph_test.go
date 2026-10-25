package engine_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/trannghiach/azhaq/catalog"
	"github.com/trannghiach/azhaq/collectors"
	"github.com/trannghiach/azhaq/engine"
	"github.com/trannghiach/azhaq/store"
	"github.com/trannghiach/azhaq/types"
)

func TestFixtureURLGraph(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<!doctype html><title>Home</title>
<a href="/login">login</a>
<a href="https://evil.test/out">out</a>
<script src="/app.js"></script>`))
	})
	mux.HandleFunc("/login", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`<title>Login</title><form action="/auth"></form>`))
	})
	mux.HandleFunc("/app.js", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = w.Write([]byte(`fetch("/api/status")`))
	})
	mux.HandleFunc("/api/status", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	mux.HandleFunc("/auth", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`<title>Auth</title>`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	cat := catalog.New()
	collectors.RegisterAll(cat, srv.Client())
	eng := &engine.Engine{Cat: cat, Store: st}
	seed := types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": srv.URL + "/"}}
	if err := eng.RunLocal(context.Background(), []types.Seed{seed}, engine.DefaultBudgets()); err != nil {
		t.Fatal(err)
	}

	ents, err := st.Entities()
	if err != nil {
		t.Fatal(err)
	}
	var urls []string
	for _, e := range ents {
		if e.Type == types.TypeURL {
			urls = append(urls, e.Key)
		}
		if strings.Contains(e.Key, "evil.test") {
			t.Fatalf("external URL leaked into graph: %s", e.Key)
		}
	}
	need := []string{"/login", "/api/status", "/auth"}
	for _, frag := range need {
		if !hasSuffixURL(urls, frag) {
			t.Fatalf("missing %s in %v", frag, urls)
		}
	}
	if len(urls) < 4 {
		t.Fatalf("want a URL graph, got %v", urls)
	}
}

func hasSuffixURL(urls []string, frag string) bool {
	for _, u := range urls {
		if strings.HasSuffix(u, frag) || strings.HasSuffix(u, frag+"/") {
			return true
		}
	}
	return false
}
