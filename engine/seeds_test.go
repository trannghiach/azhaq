package engine_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/trannghiach/azhaq/catalog"
	"github.com/trannghiach/azhaq/engine"
	"github.com/trannghiach/azhaq/internal/collectors/fake"
	"github.com/trannghiach/azhaq/internal/collectors/rdapcol"
	"github.com/trannghiach/azhaq/store"
	"github.com/trannghiach/azhaq/types"
)

func TestOrgBecomesDomain(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/entities" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"domains":["app.example.test"]}`))
	}))
	t.Cleanup(srv.Close)

	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	cat := catalog.New()
	cat.MustRegister(&rdapcol.Collector{Client: srv.Client(), BaseURL: srv.URL})
	fake.Register(cat, "www.app.example.test")
	eng := &engine.Engine{Cat: cat, Store: st}
	seed := types.Seed{Type: types.TypeOrganization, Keys: map[string]string{"name": "Example Org"}}
	if err := eng.RunLocal(context.Background(), []types.Seed{seed}, engine.Budgets{MaxDepth: 2, MaxItems: 16}); err != nil {
		t.Fatal(err)
	}
	if !hasTypeKey(st, types.TypeDomain, "app.example.test") {
		ents, _ := st.Entities()
		t.Fatalf("org domain missing: %+v", ents)
	}
}

func hasTypeKey(st *store.Store, t types.SeedType, key string) bool {
	ents, _ := st.Entities()
	for _, e := range ents {
		if e.Type == t && e.Key == key {
			return true
		}
	}
	return false
}
