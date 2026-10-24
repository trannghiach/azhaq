package engine_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"azhaq/internal/catalog"
	"azhaq/internal/collectors/httpcol"
	"azhaq/internal/collectors/pathscol"
	"azhaq/internal/engine"
	"azhaq/internal/fetch"
	"azhaq/internal/store"
	"azhaq/internal/types"
)

func TestRedirectTruthAndCookieNames(t *testing.T) {
	fetch.Reset()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`<title>Home</title>`))
	})
	mux.HandleFunc("/admin", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", "/login")
		w.Header().Set("Set-Cookie", "session=supersecret; HttpOnly; SameSite=Lax")
		w.Header().Set("X-Team-Id", "9")
		w.WriteHeader(http.StatusSeeOther)
	})
	mux.HandleFunc("/login", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<title>Login</title>`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	cat := catalog.New()
	httpcol.Register(cat, srv.Client())
	cat.MustRegister(&pathscol.Collector{Client: srv.Client(), Wordlist: []string{"admin"}})
	eng := &engine.Engine{Cat: cat, Store: st}
	seed := types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": srv.URL + "/"}}
	if err := eng.RunLocal(context.Background(), []types.Seed{seed}, engine.Budgets{MaxDepth: 2, MaxItems: 32}); err != nil {
		t.Fatal(err)
	}

	obs, _ := st.Observations()
	var sawAdmin, sawCookieName, sawSecret, sawXTeam bool
	for _, o := range obs {
		var p map[string]any
		_ = json.Unmarshal(o.Payload, &p)
		raw, _ := json.Marshal(p)
		if strings.Contains(string(raw), "supersecret") {
			sawSecret = true
		}
		path, _ := p["path"].(string)
		status, _ := p["status"].(float64)
		if path == "/admin" && int(status) == 303 {
			sawAdmin = true
		}
		if cookies, ok := p["cookies"].([]any); ok {
			for _, c := range cookies {
				m, _ := c.(map[string]any)
				if m["name"] == "session" {
					sawCookieName = true
				}
			}
		}
		if h, ok := p["headers"].(map[string]any); ok && h["x-team-id"] == "9" {
			sawXTeam = true
		}
	}
	if !sawAdmin {
		t.Fatalf("want path=/admin status=303, got %+v", obs)
	}
	if !sawCookieName {
		t.Fatal("want cookie name session")
	}
	if sawSecret {
		t.Fatal("cookie value leaked")
	}
	if !sawXTeam {
		t.Fatal("want x-team-id")
	}
}
