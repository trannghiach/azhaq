package egress

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/trannghiach/azhaq/internal/neterr"
)

func TestRatePacesRequests(t *testing.T) {
	Reset()
	defer Reset()
	SetRate(50) // a burst of 10, then one every 20 ms
	t0 := time.Now()
	for i := 0; i < 20; i++ {
		if err := Spend(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if d := time.Since(t0); d < 150*time.Millisecond {
		t.Errorf("20 requests at 50/s took %s", d)
	}
}

func TestSpendStopsAtTheBudgetAndRefundGivesBack(t *testing.T) {
	Reset()
	defer Reset()
	SetMaxRequests(3)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if err := Spend(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if err := Spend(ctx); !errors.Is(err, neterr.ErrBudget) || Take() == nil || !Spent() {
		t.Fatalf("over the budget: %v", err)
	}
	Refund()
	if Take() != nil || Sent() != 3 {
		t.Errorf("a refunded request is not given back: sent %d", Sent())
	}
	Count(5)
	if Sent() != 8 {
		t.Errorf("counted %d after 5 sent outside, want 8", Sent())
	}
}

func TestWatchBudgetSeesARefusal(t *testing.T) {
	Reset()
	defer Reset()
	SetMaxRequests(1)
	ctx, refused, used := WatchBudget(context.Background())
	if err := Spend(ctx); err != nil || used() != 1 || refused() {
		t.Fatalf("first request: %v used %d", err, used())
	}
	if err := Spend(ctx); err == nil || !refused() || used() != 1 {
		t.Fatalf("second request: %v refused %v used %d", err, refused(), used())
	}
}

func TestSessionTickRefusalIsRefunded(t *testing.T) {
	Reset()
	defer Reset()
	SessionTick = func(context.Context) error { return neterr.ErrBudget }
	defer func() { SessionTick = nil }()
	if err := Spend(context.Background()); err == nil || Sent() != 0 {
		t.Fatalf("a request the session check refused stays counted: %v sent %d", err, Sent())
	}
}

func TestSpendIsSafeUnderConcurrency(t *testing.T) {
	Reset()
	defer Reset()
	SetMaxRequests(50)
	var wg sync.WaitGroup
	var ok sync.Map
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if Spend(context.Background()) == nil {
				ok.Store(i, true)
			}
		}()
	}
	wg.Wait()
	n := 0
	ok.Range(func(_, _ any) bool { n++; return true })
	if n != 50 || Sent() != 50 {
		t.Errorf("%d allowed, %d counted, want 50", n, Sent())
	}
}
