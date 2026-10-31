package engine_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/trannghiach/azhaq/catalog"
	"github.com/trannghiach/azhaq/engine"
	"github.com/trannghiach/azhaq/internal/collectors/dnscol"
	"github.com/trannghiach/azhaq/internal/dnsr"
	"github.com/trannghiach/azhaq/store"
	"github.com/trannghiach/azhaq/types"
)

// A run stopped while a DNS batch waits for its resolvers leaves the batch's
// tasks undone: azhaq resume asks the names again, and the run is not done.
func TestStoppedDNSBatchLeavesTasksUndone(t *testing.T) {
	pool := dnsr.New(dnsr.Options{Resolvers: []string{"192.0.2.53"}, PerSecond: -1})
	asked := make(chan struct{}, 1)
	pool.Exchange = func(ctx context.Context, q *dns.Msg, _ string) (*dns.Msg, error) {
		select {
		case asked <- struct{}{}:
		default:
		}
		<-ctx.Done() // a resolver that never answers
		return nil, ctx.Err()
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.BeginRun("r1", 0, 0); err != nil {
		t.Fatal(err)
	}
	cat := catalog.New()
	cat.MustRegister(namesCollector{names: []string{"a.example.org", "b.example.org", "c.example.org"}})
	cat.MustRegister(dnscol.New(pool))
	eng := &engine.Engine{Cat: cat, Store: st}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		select {
		case <-asked:
		case <-time.After(5 * time.Second):
		}
		cancel()
	}()
	seeds := []types.Seed{{Type: types.TypeDomain, Keys: map[string]string{"domain": "example.org"}}}
	if err := eng.RunLocal(ctx, seeds, engine.Budgets{MaxDepth: 3, MaxItems: 32}); err == nil {
		t.Fatal("RunLocal returned no error after the stop")
	}
	if left := st.TasksLeft(); left == 0 {
		t.Fatal("the stopped DNS batch is marked done: the run would report itself complete")
	}
}
