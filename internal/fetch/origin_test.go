package fetch

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/trannghiach/azhaq/internal/neterr"
)

// blackhole accepts connections and never answers them.
func blackhole(t *testing.T) (string, *atomic.Int32) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var accepted atomic.Int32
	var conns []net.Conn
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			conns = append(conns, c)
		}
	}()
	t.Cleanup(func() {
		ln.Close()
		for _, c := range conns {
			c.Close()
		}
	})
	return "http://" + ln.Addr().String(), &accepted
}

func slowClient() *http.Client {
	return &http.Client{Timeout: 150 * time.Millisecond}
}

// An origin that times out OriginTrips times in a row is not asked again:
// the rest is refused at once, as capped work for azhaq resume.
func TestOriginStopsAfterTimeouts(t *testing.T) {
	Reset()
	t.Cleanup(Reset)
	base, accepted := blackhole(t)
	ctx, stopped, _ := WatchBudget(context.Background())
	for i := 0; i < OriginTrips; i++ {
		_, _, err := Do(ctx, slowClient(), fmt.Sprintf("%s/p%d", base, i))
		if err == nil || !neterr.Unanswered(err) {
			t.Fatalf("request %d: %v", i, err)
		}
	}
	if Stopped(ctx) != nil {
		t.Fatal("refused before the origin tripped")
	}
	_, _, err := Do(ctx, slowClient(), base+"/after")
	if !errors.Is(err, neterr.ErrOriginDown) {
		t.Fatalf("after %d timeouts: %v", OriginTrips, err)
	}
	if err.Error() != fmt.Sprintf("not requested: %s stopped answering after %d timeouts", base, OriginTrips) {
		t.Errorf("reason %q", err)
	}
	if n := accepted.Load(); int(n) != OriginTrips {
		t.Errorf("connections %d, want %d", n, OriginTrips)
	}
	if Stopped(ctx) == nil || stopped() {
		t.Error("the refusal is noted on the context as the origin's, not the budget's")
	}
	if got := OriginsDown(); len(got) != 1 || got[0] != base {
		t.Errorf("origins down %v", got)
	}
	// Another origin on the same host is not held to it.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(srv.Close)
	if _, _, err := Do(ctx, srv.Client(), srv.URL+"/"); err != nil {
		t.Errorf("a live origin: %v", err)
	}
}

// An answer starts the count over, and a run that is itself ending does
// not count its cancelled requests against the origin.
func TestOriginAnswerResetsCount(t *testing.T) {
	Reset()
	t.Cleanup(Reset)
	var slow atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if slow.Load() {
			time.Sleep(400 * time.Millisecond)
		}
	}))
	t.Cleanup(srv.Close)
	ctx := context.Background()
	c := &http.Client{Timeout: 100 * time.Millisecond}
	slow.Store(true)
	for i := 0; i < OriginTrips-1; i++ {
		if _, _, err := Do(ctx, c, fmt.Sprintf("%s/slow%d", srv.URL, i)); err == nil {
			t.Fatal("expected a timeout")
		}
	}
	slow.Store(false)
	if _, _, err := Do(ctx, c, srv.URL+"/quick"); err != nil {
		t.Fatalf("an answer: %v", err)
	}
	slow.Store(true)
	for i := 0; i < OriginTrips-1; i++ {
		if _, _, err := Do(ctx, c, fmt.Sprintf("%s/again%d", srv.URL, i)); errors.Is(err, neterr.ErrOriginDown) {
			t.Fatalf("request %d after an answer refused: %v", i, err)
		}
	}
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	_, _, _ = Do(cctx, c, srv.URL+"/cancelled")
	if len(OriginsDown()) != 0 {
		t.Errorf("a cancelled request counted: %v", OriginsDown())
	}
}
