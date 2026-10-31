package egress

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/trannghiach/azhaq/internal/neterr"
)

func TestKillFileStopsSpendAndTake(t *testing.T) {
	Reset()
	defer Reset()
	path := filepath.Join(t.TempDir(), "run.stop")
	stop := SetKill(path)
	defer stop()
	if err := Spend(context.Background()); err != nil || Take() != nil || Spent() {
		t.Fatal("refused before the file exists")
	}
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * KillCheck)
	for Killed() == nil && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	for _, err := range []error{Spend(context.Background()), Take()} {
		if !errors.Is(err, neterr.ErrKilled) || !errors.Is(err, neterr.ErrBudget) || err.Error() != "stopped: kill file "+path+" exists" {
			t.Fatalf("after the file exists: %v", err)
		}
	}
	if !Spent() {
		t.Error("Spent is false with the kill file there")
	}
	stop()
	if Killed() != nil {
		t.Error("still killed after the watch ended")
	}
	// A file there at the start refuses at once.
	defer SetKill("")
	SetKill(path)
	if Take() == nil {
		t.Error("a kill file that was there at the start did not refuse")
	}
}
