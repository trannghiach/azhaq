package limit

import (
	"context"
	"testing"
	"time"
)

func TestPerKeyRate(t *testing.T) {
	l := New(20, 1)
	ctx := context.Background()
	t0 := time.Now()
	for i := 0; i < 5; i++ {
		if err := l.Wait(ctx, "a"); err != nil {
			t.Fatal(err)
		}
	}
	if d := time.Since(t0); d < 150*time.Millisecond {
		t.Fatalf("5 requests at 20/s took %s", d)
	}
	t1 := time.Now()
	if err := l.Wait(ctx, "b"); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(t1); d > 20*time.Millisecond {
		t.Fatalf("another key waited %s", d)
	}
}

func TestUnlimitedAndOverride(t *testing.T) {
	l := New(0, 1)
	l.Set("slow", 10)
	ctx := context.Background()
	t0 := time.Now()
	for i := 0; i < 50; i++ {
		_ = l.Wait(ctx, "fast")
	}
	if d := time.Since(t0); d > 50*time.Millisecond {
		t.Fatalf("unlimited key waited %s", d)
	}
	t1 := time.Now()
	for i := 0; i < 3; i++ {
		_ = l.Wait(ctx, "slow")
	}
	if d := time.Since(t1); d < 150*time.Millisecond {
		t.Fatalf("override ignored: %s", d)
	}
}

func TestWaitHonoursContext(t *testing.T) {
	l := New(1, 1)
	_ = l.Wait(context.Background(), "k")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := l.Wait(ctx, "k"); err == nil {
		t.Fatal("want a context error")
	}
}
