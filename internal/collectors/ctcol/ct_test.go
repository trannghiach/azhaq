package ctcol

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"azhaq/internal/types"
)

func TestFirstNonEmptyTakesFastSource(t *testing.T) {
	slow := func(ctx context.Context, _ string) ([]string, string, error) {
		select {
		case <-ctx.Done():
			return nil, "slow", ctx.Err()
		case <-time.After(2 * time.Second):
			return []string{"late.example.test"}, "slow", nil
		}
	}
	fast := func(context.Context, string) ([]string, string, error) {
		return []string{"early.example.test"}, "fast", nil
	}
	t0 := time.Now()
	names, src, err := firstNonEmpty(context.Background(), "example.test", slow, fast)
	if err != nil {
		t.Fatal(err)
	}
	if src != "fast" || len(names) != 1 || names[0] != "early.example.test" {
		t.Fatalf("got %s %v", src, names)
	}
	if time.Since(t0) > 500*time.Millisecond {
		t.Fatalf("waited for slow source: %s", time.Since(t0))
	}
}

func TestFirstNonEmptySkipsEmpty(t *testing.T) {
	empty := func(context.Context, string) ([]string, string, error) {
		return nil, "empty", nil
	}
	next := func(context.Context, string) ([]string, string, error) {
		return []string{"ok.example.test"}, "next", nil
	}
	names, src, err := firstNonEmpty(context.Background(), "example.test", empty, next)
	if err != nil || src != "next" || len(names) != 1 {
		t.Fatalf("got %s %v %v", src, names, err)
	}
}

func TestSkipReservedLive(t *testing.T) {
	c := New(nil)
	var n int
	var skipped string
	meta, err := c.Run(context.Background(), types.Seed{
		Type: types.TypeDomain,
		Keys: map[string]string{"domain": "example.test"},
	}, func(o types.Observation) error {
		n++
		var p struct {
			Skipped string `json:"skipped"`
		}
		_ = json.Unmarshal(o.Payload, &p)
		skipped = p.Skipped
		return nil
	})
	if err != nil || meta.EmitCount != 1 || n != 1 || skipped != "reserved" {
		t.Fatalf("meta %+v n=%d skipped=%q err=%v", meta, n, skipped, err)
	}
}

func TestFirstNonEmptyAllFail(t *testing.T) {
	fail := func(context.Context, string) ([]string, string, error) {
		return nil, "x", errors.New("down")
	}
	_, _, err := firstNonEmpty(context.Background(), "example.test", fail, fail)
	if err == nil {
		t.Fatal("expected error")
	}
}
