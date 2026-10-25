package engine_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/trannghiach/azhaq/catalog"
	"github.com/trannghiach/azhaq/engine"
	"github.com/trannghiach/azhaq/internal/collectors/httpcol"
	"github.com/trannghiach/azhaq/internal/collectors/pathscol"
	"github.com/trannghiach/azhaq/store"
	"github.com/trannghiach/azhaq/types"
)

// archive stands in for azhaq-urls: a domain collector that reports a
// URL it did not fetch.
type archive struct{}

func (archive) Name() string             { return "azhaq-archive-test" }
func (archive) Inputs() []types.SeedType { return []types.SeedType{types.TypeDomain} }
func (archive) Outputs() []string        { return []string{"url"} }
func (archive) Info() catalog.Info       { return catalog.Info{Kind: catalog.Passive} }
func (archive) Run(_ context.Context, _ types.Seed, emit func(types.Observation) error) (types.RunMeta, error) {
	return types.RunMeta{Status: types.StatusOK, EmitCount: 1}, emit(types.Observation{
		Kind: "url", Source: "archive", Payload: []byte(`{"url":"https://app.example.test/old","via":"archive"}`),
	})
}

func TestArchiveAndPaths(t *testing.T) {
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/", "/login":
			_, _ = w.Write([]byte(`<title>ok</title>`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(app.Close)

	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	cat := catalog.New()
	cat.MustRegister(archive{})
	cat.MustRegister(&pathscol.Collector{Client: app.Client(), Wordlist: []string{"login", "nope"}})
	httpcol.Register(cat, app.Client())

	eng := &engine.Engine{Cat: cat, Store: st}
	seeds := []types.Seed{
		{Type: types.TypeDomain, Keys: map[string]string{"domain": "example.test"}},
		{Type: types.TypeURL, Keys: map[string]string{"url": app.URL + "/"}},
	}
	if err := eng.RunLocal(context.Background(), seeds, engine.Budgets{MaxDepth: 2, MaxItems: 32}); err != nil {
		t.Fatal(err)
	}

	ents, _ := st.Entities()
	var haveOld, haveLogin bool
	for _, e := range ents {
		if e.Type == types.TypeURL && e.Key == "https://app.example.test/old" {
			haveOld = true
		}
		if e.Type == types.TypeURL && hasSuffixURL([]string{e.Key}, "/login") {
			haveLogin = true
		}
	}
	if !haveOld {
		t.Fatalf("archived url missing: %+v", ents)
	}
	if !haveLogin {
		t.Fatalf("paths login missing: %+v", ents)
	}
}
