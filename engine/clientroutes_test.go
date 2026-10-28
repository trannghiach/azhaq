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
	"github.com/trannghiach/azhaq/collectors"
	"github.com/trannghiach/azhaq/engine"
	"github.com/trannghiach/azhaq/internal/fetch"
	"github.com/trannghiach/azhaq/store"
	"github.com/trannghiach/azhaq/types"
)

// A single-page app whose bundle and API live on another host of its
// site: the API's routes are rows of that host, found by the bundle; the
// router's views are rows of their own, with their guards, never
// requested; the socket is a row, not a page.
func TestSPAOnTwoHosts(t *testing.T) {
	fetch.Reset()
	t.Cleanup(fetch.Reset)
	var mu sync.Mutex
	asked := map[string]bool{}
	note := func(r *http.Request) {
		mu.Lock()
		asked[r.Host+r.URL.Path] = true
		mu.Unlock()
	}
	api := httptest.NewServer(nil)
	t.Cleanup(api.Close)
	api.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		note(r)
		switch r.URL.Path {
		case "/static/main.js":
			w.Header().Set("Content-Type", "application/javascript")
			_, _ = w.Write([]byte("var R=[{path:`administration`,component:Su,canActivate:[cs]},{path:`order-history`,component:Db}];" +
				"Ro.forRoot(R,{useHash:!0});var B=`" + api.URL + "/api/v2`;" +
				"this.http.post(B+`/orders`,{sku:s});this.http.get(B+`/profile`);" +
				"t.path=t.path||`/socket.io`;"))
		case "/api/v2/profile":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"name":"x"}`))
		default:
			http.NotFound(w, r)
		}
	})
	page := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		note(r)
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<!doctype html><title>Shop</title><app-root></app-root><script src="` + api.URL + `/static/main.js"></script>`))
	}))
	t.Cleanup(page.Close)

	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	cat := catalog.New()
	collectors.RegisterAll(cat, page.Client())
	eng := &engine.Engine{Cat: cat, Store: st}
	seeds := []types.Seed{{Type: types.TypeURL, Keys: map[string]string{"url": page.URL + "/"}}}
	if err := eng.RunLocal(context.Background(), seeds, engine.DefaultBudgets()); err != nil {
		t.Fatal(err)
	}
	ents, _ := st.Entities()
	obs, _ := st.Observations()
	edges, _ := st.Edges()
	rows := map[string]engine.MapEntry{}
	for _, r := range engine.BuildMap(ents, seeds, obs, nil, false) {
		rows[r.Entity.Key] = r
	}
	orders := rows[api.URL+"/api/v2/orders"]
	if orders.Role != "api" || len(orders.Found) == 0 || orders.Found[0].Script != api.URL+"/static/main.js" {
		t.Fatalf("orders %+v", orders)
	}
	if p := rows[api.URL+"/api/v2/profile"]; p.Coverage != "visited" {
		t.Errorf("profile %+v", p)
	}
	admin := rows[page.URL+"/#/administration"]
	if admin.Role != "client-route" || admin.Coverage != "hint" || admin.Guard != "canActivate" || admin.Proof != "guard=canActivate" {
		t.Errorf("administration %+v", admin)
	}
	if d := rows[page.URL+"/#/order-history"]; d.Role != "client-route" || d.Guard != "" {
		t.Errorf("order-history %+v", d)
	}
	sock := rows["ws://"+strings.TrimPrefix(page.URL, "http://")+"/socket.io"]
	if sock.Role != "websocket" || sock.Protocol != "socket.io" {
		t.Errorf("socket %+v", sock)
	}
	mu.Lock()
	for _, p := range []string{"/socket.io", "/administration", "/order-history"} {
		if asked[strings.TrimPrefix(page.URL, "http://")+p] {
			t.Errorf("%s was requested", p)
		}
	}
	mu.Unlock()
	// The bundle found the API's routes; the page found the bundle.
	byID := map[string]string{}
	for _, e := range ents {
		byID[e.ID] = e.Key
	}
	var fromScript, fromPage bool
	for _, e := range edges {
		if e.Type != "FOUND" {
			continue
		}
		if byID[e.From] == api.URL+"/static/main.js" && byID[e.To] == api.URL+"/api/v2/orders" {
			fromScript = true
		}
		if byID[e.From] == page.URL+"/" && byID[e.To] == api.URL+"/static/main.js" {
			fromPage = true
		}
	}
	if !fromScript || !fromPage {
		t.Errorf("edges: script → route %v, page → script %v", fromScript, fromPage)
	}
}

// A router that keeps its views in the path (Vue's createWebHistory):
// each view is asked for once, and what the server says of it stands.
// A sign-in's 401 is auth, a page the server renders is a page, the
// router's guard noted beside them; a view the shell answers stays a
// client route; a template is not requested.
func TestPathRoutedViews(t *testing.T) {
	fetch.Reset()
	t.Cleanup(fetch.Reset)
	var mu sync.Mutex
	asked := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		asked[r.URL.Path]++
		mu.Unlock()
		switch r.URL.Path {
		case "/app.js":
			w.Header().Set("Content-Type", "application/javascript")
			_, _ = w.Write([]byte(`const routes=[{path:"/admin-console",component:Admin,meta:{requiresAuth:true}},{path:"/reports",component:Reports},` +
				`{path:"/reports/:id",component:Report},{path:"/settings",component:Settings}];const router=createRouter({history:createWebHistory(),routes});fetch("/api/v1/items");`))
		case "/admin-console":
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("sign in first"))
		case "/reports":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<html><head><title>Reports</title></head><body>server rendered reports</body></html>`))
		case "/api/v1/items":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[]`))
		default:
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<!doctype html><html><head><title>SPA</title></head><body><div id="app"></div><script src="/app.js"></script></body></html>`))
		}
	}))
	t.Cleanup(srv.Close)

	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	cat := catalog.New()
	collectors.RegisterAll(cat, srv.Client())
	eng := &engine.Engine{Cat: cat, Store: st}
	seeds := []types.Seed{{Type: types.TypeURL, Keys: map[string]string{"url": srv.URL + "/"}}}
	if err := eng.RunLocal(context.Background(), seeds, engine.DefaultBudgets()); err != nil {
		t.Fatal(err)
	}
	ents, _ := st.Entities()
	obs, _ := st.Observations()
	rows := map[string]engine.MapEntry{}
	for _, r := range engine.BuildMap(ents, seeds, obs, nil, false) {
		rows[r.Entity.Key] = r
	}
	if a := rows[srv.URL+"/admin-console"]; a.Coverage != "visited" || a.Role != "auth" || a.Guard != "meta.requiresAuth" || !strings.Contains(a.Proof, "status=401") || !strings.Contains(a.Proof, "guard=meta.requiresAuth") {
		t.Errorf("admin-console %+v", a)
	}
	if r := rows[srv.URL+"/reports"]; r.Coverage != "visited" || r.Role != "page" || r.Status != 200 {
		t.Errorf("reports %+v", r)
	}
	if s := rows[srv.URL+"/settings"]; s.Role != "client-route" || s.Coverage != "catchall" {
		t.Errorf("settings %+v", s)
	}
	if r := rows[srv.URL+"/reports/{id}"]; r.Role != "client-route" || r.Coverage != "hint" {
		t.Errorf("reports/{id} %+v", r)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, p := range []string{"/admin-console", "/reports", "/settings"} {
		if asked[p] == 0 {
			t.Errorf("%s was not requested", p)
		}
	}
	for p := range asked {
		if strings.HasPrefix(p, "/reports/") {
			t.Errorf("%s was requested", p)
		}
	}
}
