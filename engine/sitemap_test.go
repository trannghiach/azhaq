package engine_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
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
	obs, _ := st.Observations()
	var sawQ bool
	for _, o := range obs {
		if o.Kind != "param" {
			continue
		}
		var p struct {
			Params []string `json:"params"`
		}
		_ = json.Unmarshal(o.Payload, &p)
		for _, n := range p.Params {
			if n == "q" {
				sawQ = true
			}
		}
	}
	if !sawQ {
		t.Fatalf("param q missing: %+v", obs)
	}
}
