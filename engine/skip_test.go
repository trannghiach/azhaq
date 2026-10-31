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
	"github.com/trannghiach/azhaq/scope"
	"github.com/trannghiach/azhaq/store"
	"github.com/trannghiach/azhaq/types"
)

// What a link is called says nothing about what a GET there does: every
// URL found in scope is requested, whatever found it. A -deny-path rule is
// the user's own: the URL stays in the map, listed with the rule, and is
// never requested.
func TestEveryFoundGetIsRequestedAndDenyPathIsListed(t *testing.T) {
	for _, tc := range []struct {
		name string
		deny []string
	}{{"no rule", nil}, {"deny-path", []string{`^/(createdb|logout)$`}}} {
		t.Run(tc.name, func(t *testing.T) {
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
				case "/users/v1", "/createdb", "/logout":
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
			rules := scope.Rules{DenyPath: tc.deny}.Compile()
			if len(tc.deny) > 0 {
				fetch.DenyPath = rules.DeniedPath
			}
			if err := eng.RunLocal(context.Background(), []types.Seed{seed}, engine.Budgets{MaxDepth: 3, MaxItems: 64, Scope: rules}); err != nil {
				t.Fatal(err)
			}
			mu.Lock()
			got := asked["/createdb"] && asked["/logout"]
			none := !asked["/createdb"] && !asked["/logout"]
			mu.Unlock()
			ents, _ := st.Entities()
			obs, _ := st.Observations()
			coverage := map[string]string{}
			for _, r := range engine.BuildMap(ents, []types.Seed{seed}, obs, nil, false) {
				coverage[strings.TrimPrefix(r.Entity.Key, srv.URL)] = r.Coverage
			}
			left := map[string]string{}
			for _, s := range engine.Skips(ents, obs) {
				left[strings.TrimPrefix(s.Target, srv.URL)] = s.Reason
			}
			if len(tc.deny) == 0 {
				if !got || coverage["/createdb"] != "visited" || coverage["/logout"] != "visited" || len(left) != 0 {
					t.Errorf("requested both: %v; coverage %v; not requested %v", got, coverage, left)
				}
				return
			}
			want := "-deny-path " + tc.deny[0]
			if !none || coverage["/createdb"] != "skipped" || coverage["/logout"] != "skipped" || coverage["/users/v1"] != "visited" ||
				left["/createdb"] != want || left["/logout"] != want {
				t.Errorf("requested none: %v; coverage %v; not requested %v", none, coverage, left)
			}
		})
	}
}
