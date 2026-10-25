package engine_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/trannghiach/azhaq/internal/catalog"
	"github.com/trannghiach/azhaq/internal/collectors/dnscol"
	"github.com/trannghiach/azhaq/internal/collectors/jscol"
	"github.com/trannghiach/azhaq/internal/connector"
	"github.com/trannghiach/azhaq/internal/engine"
	"github.com/trannghiach/azhaq/internal/store"
	"github.com/trannghiach/azhaq/internal/types"
)

func TestSameHostOneNode(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	eng := &engine.Engine{Store: st}
	payload, _ := json.Marshal(map[string]string{"fqdn": "api.example.test"})
	facts := []connector.Fact{
		{Kind: "observation", EntityType: types.TypeHostname, EntityKey: "api.example.test", Collector: "azhaq-ct", ObsKind: "hostname", Payload: payload},
		{Kind: "observation", EntityType: types.TypeHostname, EntityKey: "API.example.test", Collector: "azhaq-dns", ObsKind: "hostname", Payload: payload},
	}
	if _, err := eng.Ingest(context.Background(), facts); err != nil {
		t.Fatal(err)
	}
	ents, _ := st.Entities()
	var hosts int
	for _, e := range ents {
		if e.Type == types.TypeHostname {
			hosts++
			if e.Key != "api.example.test" {
				t.Fatalf("key %q", e.Key)
			}
		}
	}
	if hosts != 1 {
		t.Fatalf("want 1 hostname, got %+v", ents)
	}
}

func TestSharedIPNotMerged(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	eng := &engine.Engine{Store: st}
	a, _ := json.Marshal(map[string]any{"fqdn": "a.example.test", "ips": []string{"203.0.113.9"}})
	b, _ := json.Marshal(map[string]any{"fqdn": "b.example.test", "ips": []string{"203.0.113.9"}})
	facts := []connector.Fact{
		{Kind: "observation", EntityType: types.TypeHostname, EntityKey: "a.example.test", Collector: "azhaq-dns", ObsKind: "dns", Payload: a},
		{Kind: "observation", EntityType: types.TypeHostname, EntityKey: "b.example.test", Collector: "azhaq-dns", ObsKind: "dns", Payload: b},
	}
	if _, err := eng.Ingest(context.Background(), facts); err != nil {
		t.Fatal(err)
	}
	if !hasTypeKey(st, types.TypeHostname, "a.example.test") || !hasTypeKey(st, types.TypeHostname, "b.example.test") {
		ents, _ := st.Entities()
		t.Fatalf("hosts missing: %+v", ents)
	}
	if !hasTypeKey(st, types.TypeIPAddress, "203.0.113.9") {
		ents, _ := st.Entities()
		t.Fatalf("ip missing: %+v", ents)
	}
	ip := store.EntityID(types.TypeIPAddress, "203.0.113.9")
	n := 0
	edges, _ := st.Edges()
	for _, e := range edges {
		if e.Type == "RESOLVES_TO" && e.To == ip {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("want 2 RESOLVES_TO, got %+v", edges)
	}
}

func TestDNSResolvesTo(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	cat := catalog.New()
	cat.MustRegister(dnscol.New())
	eng := &engine.Engine{Cat: cat, Store: st}
	seed := types.Seed{Type: types.TypeHostname, Keys: map[string]string{"fqdn": "localhost"}}
	if err := eng.RunLocal(context.Background(), []types.Seed{seed}, engine.Budgets{MaxDepth: 1, MaxItems: 4}); err != nil {
		t.Fatal(err)
	}
	ents, _ := st.Entities()
	var ip bool
	for _, e := range ents {
		if e.Type == types.TypeIPAddress {
			ip = true
		}
	}
	if !ip {
		t.Fatalf("localhost should RESOLVES_TO an IP: %+v", ents)
	}
}

func TestSPAJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<!doctype html><title>spa</title>
<script type="application/json" id="__NEXT_DATA__">{"page":"/dashboard","buildId":"x"}</script>`))
	}))
	t.Cleanup(srv.Close)

	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	cat := catalog.New()
	jscol.Register(cat, srv.Client())
	eng := &engine.Engine{Cat: cat, Store: st}
	seed := types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": srv.URL + "/"}}
	if err := eng.RunLocal(context.Background(), []types.Seed{seed}, engine.Budgets{MaxDepth: 1, MaxItems: 8}); err != nil {
		t.Fatal(err)
	}
	ents, _ := st.Entities()
	var urls []string
	for _, e := range ents {
		if e.Type == types.TypeURL {
			urls = append(urls, e.Key)
		}
	}
	if !hasSuffixURL(urls, "/dashboard") {
		t.Fatalf("spa route missing: %v", urls)
	}
}
