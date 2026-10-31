package engine_test

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/trannghiach/azhaq/catalog"
	"github.com/trannghiach/azhaq/engine"
	"github.com/trannghiach/azhaq/internal/collectors/httpcol"
	"github.com/trannghiach/azhaq/internal/fetch"
	"github.com/trannghiach/azhaq/store"
	"github.com/trannghiach/azhaq/types"
)

// An origin that accepts connections and never answers gets
// fetch.OriginTrips requests, no more: the rest of its work ends capped,
// listed as skipped with the reason, and waits for azhaq resume.
func TestDeadOriginStopsTheRun(t *testing.T) {
	fetch.Reset()
	t.Cleanup(fetch.Reset)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var accepted atomic.Int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			defer c.Close()
		}
	}()
	t.Cleanup(func() { ln.Close() })
	base := "http://" + ln.Addr().String()

	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	_ = st.BeginRun("dead", 1, 0)
	cat := catalog.New()
	cat.MustRegister(&httpcol.Collector{Client: &http.Client{Timeout: 150 * time.Millisecond}, Probe: true, NoFavicon: true})
	eng := &engine.Engine{Cat: cat, Store: st}
	var seeds []types.Seed
	for i := 0; i < 12; i++ {
		seeds = append(seeds, types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": fmt.Sprintf("%s/p%d", base, i)}})
	}
	// One at a time: the count of connections is then exact.
	if err := eng.RunLocal(context.Background(), seeds, engine.Budgets{MaxDepth: 1, MaxItems: 64, Parallel: 1}); err != nil {
		t.Fatal(err)
	}
	if n := int(accepted.Load()); n != fetch.OriginTrips {
		t.Errorf("connections %d, want %d", n, fetch.OriginTrips)
	}
	if left := st.TasksLeft(); left != len(seeds)-fetch.OriginTrips {
		t.Errorf("tasks left %d, want %d", left, len(seeds)-fetch.OriginTrips)
	}
	ents, _ := st.Entities()
	obs, _ := st.Observations()
	reason := fmt.Sprintf("%s stopped answering after %d timeouts", base, fetch.OriginTrips)
	var left []string
	for _, s := range engine.Skips(ents, obs) {
		if s.Reason == reason {
			left = append(left, strings.TrimPrefix(s.Target, base))
		}
	}
	if len(left) != len(seeds)-fetch.OriginTrips {
		t.Errorf("not requested for the origin: %v", left)
	}
	failed := 0
	for _, f := range engine.Failures(ents, obs) {
		if f.Collector == httpcol.Name {
			failed += f.Count
		}
	}
	if failed != fetch.OriginTrips {
		t.Errorf("failures %d, want the %d timeouts only", failed, fetch.OriginTrips)
	}
}
