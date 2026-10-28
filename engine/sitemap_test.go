package engine_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/trannghiach/azhaq/catalog"
	"github.com/trannghiach/azhaq/engine"
	"github.com/trannghiach/azhaq/internal/collectors/crawlcol"
	"github.com/trannghiach/azhaq/internal/collectors/httpcol"
	"github.com/trannghiach/azhaq/internal/collectors/pathscol"
	"github.com/trannghiach/azhaq/internal/fetch"
	"github.com/trannghiach/azhaq/store"
	"github.com/trannghiach/azhaq/types"
)

func TestSitemapAndParams(t *testing.T) {
	fetch.Reset()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<title>Home</title>
<form method="get" action="/search"><input name="q"></form>
<a href="/search?q=test">s</a>`))
	})
	mux.HandleFunc("/sitemap.xml", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		_, _ = w.Write([]byte(`<urlset><url><loc>http://` + r.Host + `/from-map</loc></url></urlset>`))
	})
	mux.HandleFunc("/from-map", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`<title>Mapped</title>`))
	})
	mux.HandleFunc("/search", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`<title>Search</title>`))
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
	crawlcol.Register(cat, srv.Client())
	cat.MustRegister(&pathscol.Collector{Client: srv.Client(), Wordlist: []string{"sitemap.xml"}})
	eng := &engine.Engine{Cat: cat, Store: st}
	seed := types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": srv.URL + "/"}}
	if err := eng.RunLocal(context.Background(), []types.Seed{seed}, engine.Budgets{MaxDepth: 2, MaxItems: 32}); err != nil {
		t.Fatal(err)
	}
	if !hasSuffixURL(entityURLs(st), "/from-map") {
		t.Fatalf("sitemap loc missing: %v", entityURLs(st))
	}
	// q is the link's parameter and the form's field, not the home page's.
	ents, _ := st.Entities()
	obs, _ := st.Observations()
	var sawQ bool
	for _, r := range engine.BuildMap(ents, []types.Seed{seed}, obs, nil, false) {
		switch strings.TrimPrefix(r.Entity.Key, srv.URL) {
		case "/":
			if len(r.Params) > 0 {
				t.Errorf("the home page takes the params of its links: %v", r.Params)
			}
			if len(r.Forms) != 1 || r.Forms[0].Action != srv.URL+"/search" || strings.Join(r.Forms[0].Fields, ",") != "q" {
				t.Errorf("forms of /: %+v", r.Forms)
			}
		case "/search?q=test":
			sawQ = strings.Join(r.Params, ",") == "q"
		}
	}
	if !sawQ {
		t.Fatal("param q missing on /search?q=test")
	}
}
