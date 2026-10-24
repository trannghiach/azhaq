package engine_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"azhaq/internal/catalog"
	"azhaq/internal/collectors/cdxcol"
	"azhaq/internal/collectors/httpcol"
	"azhaq/internal/collectors/pathscol"
	"azhaq/internal/engine"
	"azhaq/internal/store"
	"azhaq/internal/types"
)

func TestCDXAndPaths(t *testing.T) {
	cdx := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[
			["original","statuscode","mimetype","timestamp"],
			["https://app.example.test/old","200","text/html","20200101120000"]
		]`))
	}))
	t.Cleanup(cdx.Close)

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
	cat.MustRegister(&cdxcol.Collector{Client: cdx.Client(), BaseURL: cdx.URL})
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
		t.Fatalf("cdx url missing: %+v", ents)
	}
	if !haveLogin {
		t.Fatalf("paths login missing: %+v", ents)
	}
}
