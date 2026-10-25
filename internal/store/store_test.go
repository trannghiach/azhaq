package store

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/trannghiach/azhaq/internal/types"
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
