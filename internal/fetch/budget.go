package fetch

import (
	"context"
	"sync"
	"sync/atomic"

	"golang.org/x/time/rate"

	"github.com/trannghiach/azhaq/internal/neterr"
)

// MaxRequests caps the requests a run sends to its targets (-max-requests,
// or what is left of a program's daily budget); zero is no cap.
var MaxRequests int64

var (
	sent   atomic.Int64
	paceMu sync.Mutex
	pace   *rate.Limiter
)

// SetRate paces the requests to targets: perSecond over all hosts (-rate);
// zero is no pace.
func SetRate(perSecond float64) {
	paceMu.Lock()
	defer paceMu.Unlock()
	pace = nil
	if perSecond > 0 {
		pace = rate.NewLimiter(rate.Limit(perSecond), max(1, int(perSecond/5)))
	}
}

// Spend accounts for one request to a target before it is sent: it waits
// for the run's pace, and refuses with neterr.ErrBudget once the budget is
// spent. Every request to a target goes through it (GETs, path and
// parameter guesses, GraphQL, pages loaded in Chrome).
func Spend(ctx context.Context) error {
	for {
		n := sent.Load()
		if MaxRequests > 0 && n >= MaxRequests {
			if b, ok := ctx.Value(refusedKey{}).(*atomic.Bool); ok {
				b.Store(true)
			}
			return neterr.ErrBudget
		}
		if sent.CompareAndSwap(n, n+1) {
			break
		}
	}
	paceMu.Lock()
	p := pace
	paceMu.Unlock()
	if p != nil {
		return p.Wait(ctx)
	}
	return ctx.Err()
}

type refusedKey struct{}

// WatchBudget marks ctx so that refused reports whether the budget refused
// a request made with it: a collector may take a refused request for a
// path that does not exist, and its work is then not done.
func WatchBudget(ctx context.Context) (_ context.Context, refused func() bool) {
	b := new(atomic.Bool)
	return context.WithValue(ctx, refusedKey{}, b), b.Load
}

// Count accounts for requests already sent without asking (the
// subresources a page loaded in Chrome fetched): they count against the
// budget, which may then be spent.
func Count(n int) { sent.Add(int64(n)) }

// Sent is how many requests the run has sent to its targets.
func Sent() int64 { return sent.Load() }

func resetBudget() {
	MaxRequests = 0
	sent.Store(0)
	SetRate(0)
}
