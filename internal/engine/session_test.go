package engine_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/trannghiach/azhaq/internal/catalog"
	"github.com/trannghiach/azhaq/internal/collectors/httpcol"
	"github.com/trannghiach/azhaq/internal/collectors/pathscol"
	"github.com/trannghiach/azhaq/internal/engine"
	"github.com/trannghiach/azhaq/internal/fetch"
	"github.com/trannghiach/azhaq/internal/store"
	"github.com/trannghiach/azhaq/internal/types"
)

func TestCookieReachesDashboard(t *testing.T) {
	fetch.Reset()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`<title>Home</title>`))
	})
	mux.HandleFunc("/dashboard", func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("session"); err != nil || c.Value != "test" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`<title>Dash</title>`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	run := func(withCookie bool) bool {
		fetch.Reset()
		if withCookie {
			h := make(http.Header)
			h.Set("Cookie", "session=test")
			fetch.Extra = h
		}
		st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = st.Close() })
		cat := catalog.New()
		httpcol.Register(cat, srv.Client())
		cat.MustRegister(&pathscol.Collector{Client: srv.Client(), Wordlist: []string{"dashboard"}})
		eng := &engine.Engine{Cat: cat, Store: st}
		seed := types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": srv.URL + "/"}}
		if err := eng.RunLocal(context.Background(), []types.Seed{seed}, engine.Budgets{MaxDepth: 2, MaxItems: 16}); err != nil {
			t.Fatal(err)
		}
		return hasSuffixURL(entityURLs(st), "/dashboard")
	}

	if run(false) {
		t.Fatal("dashboard should be missing without cookie")
	}
	if !run(true) {
		t.Fatal("dashboard should appear with -cookie")
	}
}

func entityURLs(st *store.Store) []string {
	ents, _ := st.Entities()
	var urls []string
	for _, e := range ents {
		if e.Type == types.TypeURL {
			urls = append(urls, e.Key)
		}
	}
	return urls
}
