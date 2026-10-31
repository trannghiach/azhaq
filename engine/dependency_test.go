package engine_test

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/trannghiach/azhaq/catalog"
	"github.com/trannghiach/azhaq/engine"
	"github.com/trannghiach/azhaq/internal/collectors/dnscol"
	"github.com/trannghiach/azhaq/internal/collectors/httpcol"
	"github.com/trannghiach/azhaq/internal/dnsr"
	"github.com/trannghiach/azhaq/internal/egress"
	"github.com/trannghiach/azhaq/internal/fetch"
	"github.com/trannghiach/azhaq/internal/neterr"
	"github.com/trannghiach/azhaq/store"
	"github.com/trannghiach/azhaq/types"
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

// gate drops every seed; follower runs after it.
type gate struct{}

func (gate) Name() string             { return "test-gate" }
func (gate) Info() catalog.Info       { return catalog.Info{Kind: catalog.Passive} }
func (gate) Inputs() []types.SeedType { return []types.SeedType{types.TypeDomain} }
func (gate) Outputs() []string        { return nil }
func (gate) Run(context.Context, types.Seed, func(types.Observation) error) (types.RunMeta, error) {
	return types.RunMeta{Status: types.StatusOK, Drop: true}, nil
}

type follower struct{ ran *int }

func (follower) Name() string             { return "test-follower" }
func (follower) Info() catalog.Info       { return catalog.Info{Kind: catalog.Passive, After: "test-gate"} }
func (follower) Inputs() []types.SeedType { return []types.SeedType{types.TypeDomain} }
func (follower) Outputs() []string        { return nil }
func (f follower) Run(context.Context, types.Seed, func(types.Observation) error) (types.RunMeta, error) {
	*f.ran++
	return types.RunMeta{Status: types.StatusOK}, nil
}

func TestDropStopsWaitingCollectors(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ran := 0
	cat := catalog.New()
	cat.MustRegister(gate{})
	cat.MustRegister(follower{&ran})
	eng := &engine.Engine{Cat: cat, Store: st}
	seeds := []types.Seed{{Type: types.TypeDomain, Keys: map[string]string{"domain": "example.org"}}}
	if err := eng.RunLocal(context.Background(), seeds, engine.DefaultBudgets()); err != nil {
		t.Fatal(err)
	}
	if ran != 0 {
		t.Errorf("a dropped seed's follower ran %d times", ran)
	}
}

type second struct{ ran *int }

func (second) Name() string             { return "test-second" }
func (second) Info() catalog.Info       { return catalog.Info{Kind: catalog.Passive, After: "test-follower"} }
func (second) Inputs() []types.SeedType { return []types.SeedType{types.TypeDomain} }
func (second) Outputs() []string        { return nil }
func (s second) Run(context.Context, types.Seed, func(types.Observation) error) (types.RunMeta, error) {
	*s.ran++
	return types.RunMeta{Status: types.StatusOK}, nil
}

func TestDropReachesTheWholeChain(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ran := 0
	cat := catalog.New()
	cat.MustRegister(gate{})
	cat.MustRegister(follower{&ran})
	cat.MustRegister(second{&ran})
	eng := &engine.Engine{Cat: cat, Store: st}
	seeds := []types.Seed{{Type: types.TypeDomain, Keys: map[string]string{"domain": "example.org"}}}
	if err := eng.RunLocal(context.Background(), seeds, engine.DefaultBudgets()); err != nil {
		t.Fatal(err)
	}
	stats, _ := st.Stats()
	if ran != 0 || stats.Capped {
		t.Errorf("ran %d, capped %v: a task two links behind a drop must be dropped too", ran, stats.Capped)
	}
}

// spender stands for a collector whose request the budget refused.
type spender struct{ ran *int }

func (spender) Name() string             { return "test-gate" }
func (spender) Info() catalog.Info       { return catalog.Info{Kind: catalog.Passive} }
func (spender) Inputs() []types.SeedType { return []types.SeedType{types.TypeDomain} }
func (spender) Outputs() []string        { return nil }
func (s spender) Run(context.Context, types.Seed, func(types.Observation) error) (types.RunMeta, error) {
	*s.ran++
	return types.RunMeta{Status: types.StatusError, Drop: true}, neterr.ErrBudget
}

func TestSpentBudgetLeavesWorkUndone(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.BeginRun("r1", 4, 0); err != nil {
		t.Fatal(err)
	}
	ran, followed := 0, 0
	cat := catalog.New()
	cat.MustRegister(spender{&ran})
	cat.MustRegister(follower{&followed})
	eng := &engine.Engine{Cat: cat, Store: st}
	seed := types.Seed{Type: types.TypeDomain, Keys: map[string]string{"domain": "example.org"}}
	meta, err := eng.Run(context.Background(), types.WorkItem{Collector: "test-gate", Seed: seed})
	if !errors.Is(err, neterr.ErrBudget) || meta.Status != types.StatusCapped || meta.Drop {
		t.Fatalf("status %q drop %v err %v", meta.Status, meta.Drop, err)
	}
	if _, _ = eng.Run(context.Background(), types.WorkItem{Collector: "test-gate", Seed: seed}); ran != 2 {
		t.Error("work the budget stopped is marked done: it did not run again")
	}
	stats, _ := st.Stats()
	if !stats.Capped || stats.Errors != 0 {
		t.Errorf("capped %v errors %d: a spent budget caps the run and is not an error", stats.Capped, stats.Errors)
	}
}

// swallower asks for a request and takes the refusal for a missing page.
type swallower struct{ ran *int }

func (swallower) Name() string             { return "test-gate" }
func (swallower) Info() catalog.Info       { return catalog.Info{Kind: catalog.Passive} }
func (swallower) Inputs() []types.SeedType { return []types.SeedType{types.TypeDomain} }
func (swallower) Outputs() []string        { return nil }
func (s swallower) Run(ctx context.Context, _ types.Seed, _ func(types.Observation) error) (types.RunMeta, error) {
	*s.ran++
	_ = egress.Spend(ctx)
	return types.RunMeta{Status: types.StatusOK}, nil
}

func TestRefusedRequestLeavesWorkUndone(t *testing.T) {
	fetch.Reset()
	defer fetch.Reset()
	egress.SetMaxRequests(1)
	egress.Count(1)
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ran := 0
	cat := catalog.New()
	cat.MustRegister(swallower{&ran})
	eng := &engine.Engine{Cat: cat, Store: st}
	seed := types.Seed{Type: types.TypeDomain, Keys: map[string]string{"domain": "example.org"}}
	for i := 0; i < 2; i++ {
		if meta, _ := eng.Run(context.Background(), types.WorkItem{Collector: "test-gate", Seed: seed}); meta.Status != types.StatusCapped {
			t.Fatalf("status %q", meta.Status)
		}
	}
	if ran != 2 {
		t.Errorf("ran %d times: work whose request was refused must stay undone", ran)
	}
}
