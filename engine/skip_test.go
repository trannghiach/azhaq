package engine_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/trannghiach/azhaq/catalog"
	"github.com/trannghiach/azhaq/engine"
	"github.com/trannghiach/azhaq/internal/collectors/apicol"
	"github.com/trannghiach/azhaq/internal/collectors/crawlcol"
	"github.com/trannghiach/azhaq/internal/collectors/httpcol"
	"github.com/trannghiach/azhaq/internal/fetch"
	"github.com/trannghiach/azhaq/store"
	"github.com/trannghiach/azhaq/types"
)

// A GET that would change something is left alone, and listed the same
// way, whether an API description or a link named it.
func TestStateChangingGetsAreSkippedWhateverFoundThem(t *testing.T) {
	fetch.Reset()
	var mu sync.Mutex
	asked := map[string]bool{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		asked[r.URL.Path] = true
		mu.Unlock()
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<title>VAmPI</title><a href="/openapi.json">spec</a> <a href="/logout">out</a>`))
		case "/openapi.json":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"openapi":"3.0.1","info":{"title":"VAmPI","version":"1"},"paths":{"/users/v1":{"get":{}},"/createdb":{"get":{}}}}`))
		case "/users/v1":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"users":[]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	cat := catalog.New()
	httpcol.Register(cat, srv.Client())
	crawlcol.Register(cat, srv.Client())
	apicol.Register(cat, srv.Client())
	eng := &engine.Engine{Cat: cat, Store: st}
	seed := types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": srv.URL + "/"}}
	if err := eng.RunLocal(context.Background(), []types.Seed{seed}, engine.Budgets{MaxDepth: 3, MaxItems: 64}); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	if asked["/createdb"] || asked["/logout"] {
		t.Fatalf("requested: %v", asked)
	}
	mu.Unlock()
	ents, _ := st.Entities()
	obs, _ := st.Observations()
	coverage := map[string]string{}
	for _, r := range engine.BuildMap(ents, []types.Seed{seed}, obs, nil, false) {
		coverage[strings.TrimPrefix(r.Entity.Key, srv.URL)] = r.Coverage
	}
	if coverage["/createdb"] != "skipped" || coverage["/logout"] != "skipped" || coverage["/users/v1"] != "visited" {
		t.Errorf("coverage %v", coverage)
	}
	left := map[string]string{}
	for _, s := range engine.Skips(ents, obs) {
		left[strings.TrimPrefix(s.Target, srv.URL)] = s.Reason
	}
	if left["/createdb"] != engine.SkipStateChanging || left["/logout"] != engine.SkipStateChanging {
		t.Errorf("left alone %v", left)
	}
}
