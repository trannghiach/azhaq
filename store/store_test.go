package store

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/trannghiach/azhaq/types"
)

func TestWorkspaceRuns(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ws.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now()
	if err := s.BeginRun("run-1", 4, 10); err != nil {
		t.Fatal(err)
	}
	a, _ := s.UpsertEntity(types.TypeHostname, "a.example.org", now)
	_ = s.MarkSeen("work")
	if err := s.BeginRun("run-2", 4, 10); err != nil {
		t.Fatal(err)
	}
	if seen, _ := s.Seen("work"); seen {
		t.Fatal("a new run must redo the work")
	}
	_, _ = s.UpsertEntity(types.TypeHostname, "a.example.org", now.Add(time.Hour))
	_, _ = s.UpsertEntity(types.TypeHostname, "b.example.org", now.Add(time.Hour))
	ents, _ := s.Entities()
	if len(ents) != 2 {
		t.Fatalf("run 2 sees %d entities", len(ents))
	}
	s.UseRun("run-1")
	if ents, _ = s.Entities(); len(ents) != 1 || ents[0].ID != a.ID {
		t.Fatalf("run 1 sees %+v", ents)
	}
	runs, _ := s.Runs()
	if len(runs) != 2 || runs[0].ID != "run-1" {
		t.Fatalf("runs %+v", runs)
	}
	s.UseRun("")
	all, _ := s.Entities()
	for _, e := range all {
		if e.Key == "a.example.org" && !e.LastSeen.After(e.FirstSeen) {
			t.Errorf("last_seen not moved: %+v", e)
		}
	}
}

// Many rows written together read back as the same rows written one by one,
// and a Batch holds writes other goroutines make meanwhile in one
// transaction.
func TestBatchAndBulkWritesMatchSingleWrites(t *testing.T) {
	write := func(bulk bool) ([]types.Entity, []types.Edge, int) {
		s, err := Open(filepath.Join(t.TempDir(), "x.db"))
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		if err := s.BeginRun("r", 1, 1); err != nil {
			t.Fatal(err)
		}
		now := time.Now()
		src, _ := s.UpsertEntity(types.TypeURL, "http://h/", now)
		var keys []string
		var obs []types.Observation
		var edges []Edge
		for i := 0; i < 130; i++ { // more than one statement's rows
			k := "http://h/p" + string(rune('a'+i%26)) + string(rune('a'+i/26))
			keys = append(keys, k)
			obs = append(obs, types.Observation{Collector: "c", Kind: "url", Payload: []byte(`{"url":"` + k + `"}`), ObservedAt: now})
			edges = append(edges, Edge{src.ID, EntityID(types.TypeURL, k), "FOUND"})
		}
		done := make(chan struct{})
		s.Batch(func() {
			if bulk {
				if err := s.AddObservations(src.ID, obs); err != nil {
					t.Fatal(err)
				}
				if err := s.UpsertEntities(types.TypeURL, keys, now); err != nil {
					t.Fatal(err)
				}
				if err := s.AddEdges(edges, now); err != nil {
					t.Fatal(err)
				}
			} else {
				for i, o := range obs {
					_, _ = s.AddObservation(src.ID, o)
					_, _ = s.UpsertEntity(types.TypeURL, keys[i], now)
					_ = s.AddEdge(edges[i].From, edges[i].To, edges[i].Type, now)
				}
			}
			go func() { // another goroutine's write waits for the batch's, then goes through
				_, _ = s.UpsertEntity(types.TypeHostname, "h", now)
				close(done)
			}()
		})
		<-done
		ents, _ := s.Entities()
		es, _ := s.Edges()
		all, _ := s.Observations()
		return ents, es, len(all)
	}
	e1, g1, o1 := write(false)
	e2, g2, o2 := write(true)
	if len(e1) != 132 || len(e1) != len(e2) || len(g1) != 130 || len(g1) != len(g2) || o1 != 130 || o1 != o2 {
		t.Errorf("single: %d entities %d edges %d observations; bulk: %d %d %d", len(e1), len(g1), o1, len(e2), len(g2), o2)
	}
}
