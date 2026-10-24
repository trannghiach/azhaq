package engine_test

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"azhaq/internal/catalog"
	"azhaq/internal/collectors/ctcol"
	"azhaq/internal/collectors/dnscol"
	"azhaq/internal/collectors/tlscol"
	"azhaq/internal/engine"
	"azhaq/internal/store"
	"azhaq/internal/types"
)

func TestCTHintsBecomeHosts(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[{"name_value":"api.example.test"}]`))
	}))
	t.Cleanup(srv.Close)

	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	cat := catalog.New()
	cat.MustRegister(&ctcol.Collector{Client: srv.Client(), BaseURL: srv.URL})
	cat.MustRegister(dnscol.New())
	eng := &engine.Engine{Cat: cat, Store: st}
	seed := types.Seed{Type: types.TypeDomain, Keys: map[string]string{"domain": "example.test"}}
	if err := eng.RunLocal(context.Background(), []types.Seed{seed}, engine.Budgets{MaxDepth: 2, MaxItems: 16}); err != nil {
		t.Fatal(err)
	}
	ents, _ := st.Entities()
	found := false
	for _, e := range ents {
		if e.Type == types.TypeHostname && e.Key == "api.example.test" {
			found = true
		}
		if e.Key == "other.test" {
			t.Fatal("out of suffix")
		}
	}
	if !found {
		t.Fatalf("api.example.test missing: %+v", ents)
	}
}

func TestTLSFixture(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(srv.Close)

	_, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	col := &tlscol.Collector{
		Port: port,
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return tls.Dial(network, srv.Listener.Addr().String(), &tls.Config{InsecureSkipVerify: true})
		},
	}

	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	cat := catalog.New()
	cat.MustRegister(col)
	eng := &engine.Engine{Cat: cat, Store: st}
	seed := types.Seed{Type: types.TypeHostname, Keys: map[string]string{"fqdn": "example.com"}}
	if err := eng.RunLocal(context.Background(), []types.Seed{seed}, engine.Budgets{MaxDepth: 1, MaxItems: 4}); err != nil {
		t.Fatal(err)
	}
	obs, _ := st.Observations()
	if len(obs) != 1 || obs[0].Kind != "certificate" {
		t.Fatalf("obs %+v", obs)
	}
}

func TestDNSLocalhost(t *testing.T) {
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
	obs, _ := st.Observations()
	if len(obs) != 1 || obs[0].Collector != "azhaq-dns" {
		t.Fatalf("obs %+v", obs)
	}
}
