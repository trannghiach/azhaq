package engine_test

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/trannghiach/azhaq/internal/catalog"
	"github.com/trannghiach/azhaq/internal/collectors/dnscol"
	"github.com/trannghiach/azhaq/internal/collectors/httpcol"
	"github.com/trannghiach/azhaq/internal/dnsr"
	"github.com/trannghiach/azhaq/internal/engine"
	"github.com/trannghiach/azhaq/internal/fetch"
	"github.com/trannghiach/azhaq/internal/store"
	"github.com/trannghiach/azhaq/internal/types"
)

// namesCollector turns a domain into a fixed list of hostnames, like a
// subdomain source.
type namesCollector struct{ names []string }

func (namesCollector) Name() string             { return "test-names" }
func (namesCollector) Info() catalog.Info       { return catalog.Info{Kind: catalog.Passive} }
func (namesCollector) Inputs() []types.SeedType { return []types.SeedType{types.TypeDomain} }
func (namesCollector) Outputs() []string        { return []string{"hostname"} }
func (c namesCollector) Run(_ context.Context, _ types.Seed, emit func(types.Observation) error) (types.RunMeta, error) {
	var hints []types.Seed
	for _, n := range c.names {
		hints = append(hints, types.Seed{Type: types.TypeHostname, Keys: map[string]string{"fqdn": n}})
	}
	payload, _ := json.Marshal(map[string]any{"names": c.names})
	return types.RunMeta{Status: types.StatusOK, NextHints: hints}, emit(types.Observation{Kind: "names", Payload: payload})
}

func TestHTTPWaitsForDNS(t *testing.T) {
	fetch.Reset()
	var mu sync.Mutex
	hosts := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hosts[strings.Split(r.Host, ":")[0]]++
		mu.Unlock()
		_, _ = w.Write([]byte("<title>ok</title>"))
	}))
	t.Cleanup(srv.Close)
	// Every hostname dials the test server; DNS decides which are probed.
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, srv.Listener.Addr().String())
		},
	}}

	pool := dnsr.New(dnsr.Options{Resolvers: []string{"192.0.2.53"}, PerSecond: -1})
	pool.Exchange = func(_ context.Context, q *dns.Msg, _ string) (*dns.Msg, error) {
		m := new(dns.Msg)
		m.SetReply(q)
		name := strings.TrimSuffix(q.Question[0].Name, ".")
		if name == "live.example.org" && q.Question[0].Qtype == dns.TypeA {
			rr, _ := dns.NewRR("live.example.org. 60 IN A 127.0.0.1")
			m.Answer = append(m.Answer, rr)
		} else if name != "live.example.org" {
			m.Rcode = dns.RcodeNameError
		}
		return m, nil
	}

	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	cat := catalog.New()
	cat.MustRegister(namesCollector{names: []string{"live.example.org", "dead.example.org"}})
	cat.MustRegister(dnscol.New(pool))
	httpcol.Register(cat, client)
	eng := &engine.Engine{Cat: cat, Store: st}
	seeds := []types.Seed{{Type: types.TypeDomain, Keys: map[string]string{"domain": "example.org"}}}
	if err := eng.RunLocal(context.Background(), seeds, engine.Budgets{MaxDepth: 3, MaxItems: 32}); err != nil {
		t.Fatal(err)
	}
	if hosts["live.example.org"] == 0 {
		t.Fatalf("live host never probed: %v", hosts)
	}
	if hosts["dead.example.org"] != 0 {
		t.Fatalf("dead host probed: %v", hosts)
	}
	sum, _ := st.Summary()
	if strings.Contains(sum, "capped=1") {
		t.Fatalf("dropped work is not a cap: %s", sum)
	}
}
