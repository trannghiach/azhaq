package engine_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"azhaq/internal/catalog"
	"azhaq/internal/collectors/crawlcol"
	"azhaq/internal/collectors/fake"
	"azhaq/internal/collectors/httpcol"
	"azhaq/internal/engine"
	"azhaq/internal/scope"
	"azhaq/internal/store"
	"azhaq/internal/types"
)

func TestPlanLocatesFromCatalog(t *testing.T) {
	cat := catalog.New()
	httpcol.Register(cat, nil)
	fake.Register(cat, "www.example.test")
	eng := &engine.Engine{Cat: cat}

	items := eng.Plan([]types.Seed{
		{Type: types.TypeURL, Keys: map[string]string{"url": "https://Example.test/a"}},
		{Type: types.TypeDomain, Keys: map[string]string{"domain": "example.test"}},
	})
	if len(items) != 2 {
		t.Fatalf("want 2 work items, got %d", len(items))
	}
	byCol := map[string]types.WorkItem{}
	for _, it := range items {
		byCol[it.Collector] = it
	}
	if byCol["azhaq-http"].Seed.Keys["url"] != "https://example.test/a" {
		t.Fatalf("url not normalized: %+v", byCol["azhaq-http"].Seed)
	}
	if byCol["azhaq-fake"].Seed.Type != types.TypeDomain {
		t.Fatal("fake should run on domain")
	}
}

func TestFakeRecurseThenHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<title>From fake</title>`))
	}))
	t.Cleanup(srv.Close)

	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	cat := catalog.New()
	fake.Register(cat, srv.Listener.Addr().String())
	httpcol.Register(cat, srv.Client())
	eng := &engine.Engine{Cat: cat, Store: st}

	// Domain → fake hostname (the httptest host) → http
	seeds := []types.Seed{{Type: types.TypeDomain, Keys: map[string]string{"domain": "example.test"}}}
	if err := eng.RunLocal(context.Background(), seeds, engine.Budgets{MaxDepth: 3, MaxItems: 16}); err != nil {
		t.Fatal(err)
	}
	obs, err := st.Observations()
	if err != nil {
		t.Fatal(err)
	}
	var sawFake, sawHTTP bool
	for _, o := range obs {
		switch o.Collector {
		case "azhaq-fake":
			sawFake = true
		case "azhaq-http":
			sawHTTP = true
			var p map[string]any
			if err := json.Unmarshal(o.Payload, &p); err != nil {
				t.Fatal(err)
			}
			if p["title"] != "From fake" {
				t.Fatalf("title %v", p["title"])
			}
		}
	}
	if !sawFake || !sawHTTP {
		t.Fatalf("want fake+http observations, got %+v", obs)
	}
}

func TestDerivedSeedsJoinFirstWave(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	cat := catalog.New()
	fake.Register(cat, "www.example.test")
	eng := &engine.Engine{Cat: cat, Store: st}
	seed := types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": "https://app.example.test/"}}
	if err := eng.RunLocal(context.Background(), []types.Seed{seed}, engine.Budgets{MaxDepth: 1, MaxItems: 16}); err != nil {
		t.Fatal(err)
	}
	obs, _ := st.Observations()
	for _, o := range obs {
		if o.Collector == "azhaq-fake" {
			return
		}
	}
	t.Fatalf("domain collector should run in wave 0 from a URL seed, got %+v", obs)
}

func TestHTTPIdempotent(t *testing.T) {
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n++
		_, _ = w.Write([]byte(`<title>x</title>`))
	}))
	t.Cleanup(srv.Close)

	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	cat := catalog.New()
	httpcol.Register(cat, srv.Client())
	eng := &engine.Engine{Cat: cat, Store: st}
	seed := types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": srv.URL + "/"}}
	if err := eng.RunLocal(context.Background(), []types.Seed{seed}, engine.DefaultBudgets()); err != nil {
		t.Fatal(err)
	}
	if err := eng.RunLocal(context.Background(), []types.Seed{seed}, engine.DefaultBudgets()); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("collector ran %d times, want 1", n)
	}
}

func TestNoteExternalErrorCounted(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	eng := &engine.Engine{Store: st}
	seed := types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": "https://example.test/"}}
	if err := eng.NoteExternalError([]types.Seed{seed}, "connector", fmt.Errorf("exit status 1")); err != nil {
		t.Fatal(err)
	}
	obs, _ := st.Observations()
	n, _ := store.CountIssues(obs)
	if n != 1 {
		t.Fatalf("errors=%d obs=%+v", n, obs)
	}
	sum, _ := st.Summary()
	if !strings.Contains(sum, "errors=1") {
		t.Fatalf("summary %q", sum)
	}
}

func TestScopeDropsOutOfAllowHints(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	cat := catalog.New()
	fake.Register(cat, "www.other.test")
	eng := &engine.Engine{Cat: cat, Store: st}
	seeds := []types.Seed{{Type: types.TypeDomain, Keys: map[string]string{"domain": "example.test"}}}
	err = eng.RunLocal(context.Background(), seeds, engine.Budgets{
		MaxDepth: 3, MaxItems: 16,
		Scope: scope.Rules{Allow: []string{"example.test"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	ents, _ := st.Entities()
	for _, e := range ents {
		if strings.Contains(e.Key, "other.test") {
			t.Fatalf("out-of-scope hint leaked: %+v", ents)
		}
	}
}

func TestDepthZeroDoesNotFollowCrawlHints(t *testing.T) {
	loginHits := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<title>Home</title><a href="/login">login</a>`))
	})
	mux.HandleFunc("/login", func(w http.ResponseWriter, _ *http.Request) {
		loginHits++
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
	crawlcol.Register(cat, srv.Client())
	eng := &engine.Engine{Cat: cat, Store: st}
	seed := types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": srv.URL + "/"}}
	if err := eng.RunLocal(context.Background(), []types.Seed{seed}, engine.Budgets{MaxDepth: 1, MaxItems: 32}); err != nil {
		t.Fatal(err)
	}
	if loginHits != 0 {
		t.Fatalf("seed wave fetched /login %d times", loginHits)
	}
}

func TestPassiveSkipsHTTP(t *testing.T) {
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		_, _ = w.Write([]byte(`<title>x</title>`))
	}))
	t.Cleanup(srv.Close)

	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	cat := catalog.New()
	fake.Register(cat, srv.Listener.Addr().String())
	httpcol.Register(cat, srv.Client())
	eng := &engine.Engine{Cat: cat, Store: st}
	seeds := []types.Seed{{Type: types.TypeDomain, Keys: map[string]string{"domain": "example.test"}}}
	if err := eng.RunLocal(context.Background(), seeds, engine.Budgets{
		MaxDepth: 3, MaxItems: 16, Passive: true,
	}); err != nil {
		t.Fatal(err)
	}
	if hits != 0 {
		t.Fatalf("passive run fetched HTTP %d times", hits)
	}
}

func TestPassiveURLSeedNotCapped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("passive must not fetch")
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
	eng := &engine.Engine{Cat: cat, Store: st}
	seed := types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": srv.URL + "/"}}
	if err := eng.RunLocal(context.Background(), []types.Seed{seed}, engine.Budgets{
		MaxDepth: 3, MaxItems: 32, Passive: true,
	}); err != nil {
		t.Fatal(err)
	}
	ents, _ := st.Entities()
	if len(ents) == 0 {
		t.Fatal("seed entities should still be stored")
	}
	sum, err := st.Summary()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(sum, "capped=1") {
		t.Fatalf("empty passive plan is not a cap: %q", sum)
	}
}

func TestSeedHTTPBeforeDomainFanout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`<title>SeedApp</title>`))
	}))
	t.Cleanup(srv.Close)
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	cat := catalog.New()
	httpcol.Register(cat, srv.Client())
	fake.Register(cat, "www.other.test")
	eng := &engine.Engine{Cat: cat, Store: st}
	seeds := []types.Seed{
		{Type: types.TypeURL, Keys: map[string]string{"url": srv.URL + "/"}},
		{Type: types.TypeDomain, Keys: map[string]string{"domain": "example.test"}},
	}
	if err := eng.RunLocal(context.Background(), seeds, engine.Budgets{MaxDepth: 2, MaxItems: 1}); err != nil {
		t.Fatal(err)
	}
	obs, _ := st.Observations()
	var sawHTTP bool
	for _, o := range obs {
		if o.Collector == "azhaq-http" {
			sawHTTP = true
		}
		if o.Collector == "azhaq-fake" {
			t.Fatal("domain collector ran before seed HTTP budget was spent")
		}
	}
	if !sawHTTP {
		t.Fatal("seed HTTP should consume the only item")
	}
}

func TestMapVisitedBeforeHint(t *testing.T) {
	ents := []types.Entity{
		{ID: "h", Type: types.TypeHostname, Key: "app.example.test"},
		{ID: "v", Type: types.TypeURL, Key: "https://app.example.test/"},
		{ID: "a", Type: types.TypeURL, Key: "https://app.example.test/api/Users"},
		{ID: "x", Type: types.TypeURL, Key: "https://app.example.test/ghost"},
		{ID: "f", Type: types.TypeHostname, Key: "cdn.other.test"},
	}
	seeds := []types.Seed{{Type: types.TypeURL, Keys: map[string]string{"url": "https://app.example.test/"}}}
	obs := []types.StoredObservation{
		{EntityID: "v", Observation: types.Observation{Collector: "azhaq-http", Kind: "application", Payload: json.RawMessage(`{"status":200,"title":"Home"}`)}},
		{EntityID: "a", Observation: types.Observation{Collector: "azhaq-js", Kind: "url", Payload: json.RawMessage(`{"url":"https://app.example.test/api/Users","role":"api"}`)}},
	}
	got := engine.BuildMap(ents, seeds, obs, []types.Seed{{Type: types.TypeURL, Keys: map[string]string{"url": "https://app.example.test/ghost"}}}, true)
	if got[0].Entity.Key != "app.example.test" || got[0].Role != "live" {
		t.Fatalf("first %+v", got[0])
	}
	var cov []string
	for _, e := range got {
		if e.Entity.Type == types.TypeURL {
			cov = append(cov, e.Coverage+"/"+e.Role)
		}
	}
	if len(cov) != 3 || cov[0] != "visited/app" || cov[1] != "hint/api" || cov[2] != "capped/page" {
		t.Fatalf("coverage %v", cov)
	}
}

func TestMapHomepageNotAPI(t *testing.T) {
	ents := []types.Entity{
		{ID: "v", Type: types.TypeURL, Key: "https://app.example.test/"},
		{ID: "l", Type: types.TypeURL, Key: "https://app.example.test/login"},
	}
	seeds := []types.Seed{{Type: types.TypeURL, Keys: map[string]string{"url": "https://app.example.test/"}}}
	obs := []types.StoredObservation{
		{EntityID: "v", Observation: types.Observation{Collector: "azhaq-http", Kind: "application", Payload: json.RawMessage(`{"status":200,"title":"Home","url":"https://app.example.test/"}`)}},
		{EntityID: "v", Observation: types.Observation{Collector: "azhaq-js", Kind: "url", Payload: json.RawMessage(`{"url":"https://app.example.test/api/status","role":"api"}`)}},
		{EntityID: "v", Observation: types.Observation{Collector: "azhaq-paths", Kind: "url", Payload: json.RawMessage(`{"url":"https://app.example.test/admin","status":403}`)}},
		{EntityID: "l", Observation: types.Observation{Collector: "azhaq-http", Kind: "application", Payload: json.RawMessage(`{"status":200,"url":"https://app.example.test/login"}`)}},
	}
	got := engine.BuildMap(ents, seeds, obs, nil, false)
	byKey := map[string]engine.MapEntry{}
	for _, e := range got {
		byKey[e.Entity.Key] = e
	}
	home := byKey["https://app.example.test/"]
	if home.Coverage != "visited" || home.Role != "app" {
		t.Fatalf("homepage %+v", home)
	}
	login := byKey["https://app.example.test/login"]
	if login.Role != "page" {
		t.Fatalf("login %+v", login)
	}
}

func TestMapLeftoverWithoutCapIsHint(t *testing.T) {
	ents := []types.Entity{{ID: "v", Type: types.TypeURL, Key: "https://demo.test/"}}
	seeds := []types.Seed{{Type: types.TypeURL, Keys: map[string]string{"url": "https://demo.test/"}}}
	left := []types.Seed{{Type: types.TypeURL, Keys: map[string]string{"url": "https://demo.test/"}}}
	got := engine.BuildMap(ents, seeds, nil, left, false)
	if len(got) != 1 || got[0].Coverage != "hint" {
		t.Fatalf("%+v", got)
	}
}

func TestFanReserveRunsDomain(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`<title>SeedApp</title>`))
	}))
	t.Cleanup(srv.Close)
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	cat := catalog.New()
	httpcol.Register(cat, srv.Client())
	fake.Register(cat, "www.other.test")
	eng := &engine.Engine{Cat: cat, Store: st}
	seeds := []types.Seed{
		{Type: types.TypeURL, Keys: map[string]string{"url": srv.URL + "/"}},
		{Type: types.TypeDomain, Keys: map[string]string{"domain": "example.test"}},
	}
	if err := eng.RunLocal(context.Background(), seeds, engine.Budgets{MaxDepth: 2, MaxItems: 8}); err != nil {
		t.Fatal(err)
	}
	obs, _ := st.Observations()
	var sawHTTP, sawFake bool
	for _, o := range obs {
		if o.Collector == "azhaq-http" {
			sawHTTP = true
		}
		if o.Collector == "azhaq-fake" {
			sawFake = true
		}
	}
	if !sawHTTP || !sawFake {
		t.Fatalf("want seed HTTP and domain fake, obs=%+v", obs)
	}
}

func TestMaxItemsMarksCapped(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	cat := catalog.New()
	fake.Register(cat, "www.example.test")
	eng := &engine.Engine{Cat: cat, Store: st}
	seeds := []types.Seed{
		{Type: types.TypeDomain, Keys: map[string]string{"domain": "a.test"}},
		{Type: types.TypeDomain, Keys: map[string]string{"domain": "b.test"}},
	}
	if err := eng.RunLocal(context.Background(), seeds, engine.Budgets{MaxDepth: 1, MaxItems: 1}); err != nil {
		t.Fatal(err)
	}
	sum, err := st.Summary()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(sum, "capped=1") {
		t.Fatalf("summary %q", sum)
	}
}
