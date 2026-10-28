package engine_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sort"
	"sync"
	"testing"

	"github.com/trannghiach/azhaq/catalog"
	"github.com/trannghiach/azhaq/engine"
	"github.com/trannghiach/azhaq/internal/collectors/httpcol"
	"github.com/trannghiach/azhaq/internal/fetch"
	"github.com/trannghiach/azhaq/store"
	"github.com/trannghiach/azhaq/types"
)

// archive stands for azhaq-urls: it hands on what an archive lists,
// archived URLs first, before the application's own pages.
type fakeArchive struct{ base string }

func (a *fakeArchive) Name() string              { return "azhaq-fake-archive" }
func (a *fakeArchive) Info() catalog.Info        { return catalog.Info{Kind: catalog.Passive} }
func (a *fakeArchive) Inputs() []types.SeedType  { return []types.SeedType{types.TypeURL} }
func (a *fakeArchive) Outputs() []string         { return []string{"url"} }
func (a *fakeArchive) Skip(seed types.Seed) bool { return seed.Key() != a.base+"/" }
func (a *fakeArchive) Run(_ context.Context, _ types.Seed, _ func(types.Observation) error) (types.RunMeta, error) {
	hint := func(p, via string) types.Seed {
		keys := map[string]string{"url": a.base + p}
		if via != "" {
			keys[types.ViaKey] = via
		}
		return types.Seed{Type: types.TypeURL, Keys: keys}
	}
	return types.RunMeta{Status: types.StatusOK, NextHints: []types.Seed{
		hint("/old/1", types.ViaArchive), hint("/old/2", types.ViaArchive), hint("/old/3", types.ViaArchive),
		hint("/page", ""), hint("/api/users", ""),
	}}, nil
}

// Under a budget, the front page and the API paths go before the pages
// links name, and what only an archive lists goes last.
func TestBudgetGoesToFrontPagesAndAPIFirst(t *testing.T) {
	fetch.Reset()
	t.Cleanup(fetch.Reset)
	var mu sync.Mutex
	var asked []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		asked = append(asked, r.URL.Path)
		mu.Unlock()
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<title>ok</title>"))
	}))
	t.Cleanup(srv.Close)
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	cat := catalog.New()
	cat.MustRegister(&httpcol.Collector{Client: srv.Client(), Probe: true, NoFavicon: true})
	cat.MustRegister(&fakeArchive{base: srv.URL})
	eng := &engine.Engine{Cat: cat, Store: st}
	fetch.MaxRequests = 3
	seed := types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": srv.URL + "/"}}
	if err := eng.RunLocal(context.Background(), []types.Seed{seed}, engine.Budgets{MaxDepth: 2, MaxItems: 64, Parallel: 1}); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	sort.Strings(asked)
	want := []string{"/", "/api/users", "/page"}
	if len(asked) != len(want) {
		t.Fatalf("asked %v, want %v", asked, want)
	}
	for i := range want {
		if asked[i] != want[i] {
			t.Fatalf("asked %v, want %v", asked, want)
		}
	}
}
