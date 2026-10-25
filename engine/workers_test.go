package engine_test

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/trannghiach/azhaq/catalog"
	"github.com/trannghiach/azhaq/engine"
	"github.com/trannghiach/azhaq/store"
	"github.com/trannghiach/azhaq/types"
)

// pages is a Touch collector: a domain has hosts, a host has pages. It
// notes which process ran each seed.
type pages struct {
	who  string
	mu   *sync.Mutex
	ran  map[string]string
	slow time.Duration
}

func (pages) Name() string       { return "test-pages" }
func (pages) Info() catalog.Info { return catalog.Info{Kind: catalog.Touch} }
func (pages) Inputs() []types.SeedType {
	return []types.SeedType{types.TypeDomain, types.TypeHostname, types.TypeURL}
}
func (pages) Outputs() []string { return nil }
func (c pages) Run(_ context.Context, seed types.Seed, emit func(types.Observation) error) (types.RunMeta, error) {
	time.Sleep(c.slow)
	c.mu.Lock()
	c.ran[seed.Key()] += c.who
	c.mu.Unlock()
	var hints []types.Seed
	switch seed.Type {
	case types.TypeDomain:
		for i := 0; i < 5; i++ {
			hints = append(hints, types.Seed{Type: types.TypeHostname, Keys: map[string]string{"fqdn": fmt.Sprintf("h%d.example.org", i)}})
		}
	case types.TypeHostname:
		for i := 0; i < 4; i++ {
			hints = append(hints, types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": fmt.Sprintf("https://%s/p%d", seed.Key(), i)}})
		}
	}
	return types.RunMeta{Status: types.StatusOK, NextHints: hints}, emit(types.Observation{Kind: "page", Payload: []byte(`{"ok":true}`)})
}

func TestWorkersShareARun(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	_ = st.BeginRun("r", 4, 0)
	var mu sync.Mutex
	ran := map[string]string{}
	cat := catalog.New()
	cat.MustRegister(pages{who: "L", mu: &mu, ran: ran, slow: 20 * time.Millisecond})
	w := engine.NewWorkers()
	eng := &engine.Engine{Cat: cat, Store: st, Workers: w}

	// Two workers with their own catalog, as another process has.
	remote := catalog.New()
	remote.MustRegister(pages{who: "W", mu: &mu, ran: ran, slow: 20 * time.Millisecond})
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				task, err := w.Claim(context.Background(), time.Second)
				if err != nil {
					return
				}
				if task != nil {
					w.Done(context.Background(), task.ID, engine.Execute(context.Background(), remote, task.Item))
				}
			}
		}()
	}
	b := engine.DefaultBudgets()
	b.Parallel = 1
	seeds := []types.Seed{{Type: types.TypeDomain, Keys: map[string]string{"domain": "example.org"}}}
	if err := eng.RunLocal(context.Background(), seeds, b); err != nil {
		t.Fatal(err)
	}
	wg.Wait() // the workers stop once the run is over

	byWorker := 0
	for k, who := range ran {
		if len(who) != 1 {
			t.Errorf("%s ran %q", k, who)
		}
		if who == "W" {
			byWorker++
		}
	}
	if len(ran) != 1+5+20 || byWorker == 0 {
		t.Errorf("%d seeds ran, %d by workers", len(ran), byWorker)
	}
	if st.TasksLeft() != 0 {
		t.Errorf("%d tasks left", st.TasksLeft())
	}
	stats, _ := st.Stats()
	if stats.Observations != 26 {
		t.Errorf("%d observations, want one per seed", stats.Observations)
	}
}
