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
	paceR  float64
)

// SetRate paces the requests to targets: perSecond over all hosts (-rate);
// zero is no pace.
func SetRate(perSecond float64) {
	paceMu.Lock()
	defer paceMu.Unlock()
	pace, paceR = nil, 0
	if perSecond > 0 {
		pace, paceR = rate.NewLimiter(rate.Limit(perSecond), max(1, int(perSecond/5))), perSecond
	}
}

// Rate is the pace in requests per second (-rate), or 0 without one.
func Rate() float64 {
	paceMu.Lock()
	defer paceMu.Unlock()
	return paceR
}

// Spend accounts for one request to a target before it is sent: it waits
// for the run's pace, and refuses with neterr.ErrBudget once the budget is
// spent, and with neterr.ErrKilled once the kill file exists. Every request to a target goes through it (GETs, path and
// parameter guesses, GraphQL, pages loaded in Chrome).
func Spend(ctx context.Context) error { return spend(ctx, true) }

// SpendUnpaced is Spend without the wait for the pace: for a request
// whose sender waits for it itself, when it is sent (Chrome's pages),
// not when it is counted, so that no number of them is let go at once.
func SpendUnpaced(ctx context.Context) error { return spend(ctx, false) }

func spend(ctx context.Context, paced bool) error {
	w, _ := ctx.Value(refusedKey{}).(*watch)
	if err := Killed(); err != nil {
		if w != nil {
			w.refused.Store(true)
		}
		return err
	}
	for {
		n := sent.Load()
		if MaxRequests > 0 && n >= MaxRequests {
			if w != nil {
				w.refused.Store(true)
			}
			return neterr.ErrBudget
		}
		if sent.CompareAndSwap(n, n+1) {
			break
		}
	}
	if w != nil {
		w.used.Add(1)
	}
	if !paced {
		return nil
	}
	if err := Pace(ctx); err != nil {
		Refund() // never sent
		if w != nil {
			w.used.Add(-1)
		}
		return err
	}
	return nil
}

// Pace waits for the run's pace (-rate) without counting a request: for
// one counted with Take that is sent as a run's own request would be (a
// request of Chrome's).
//
// The kill file ends the wait: a request counted before it appeared and
// still waiting its turn is not sent after it.
func Pace(ctx context.Context) error {
	paceMu.Lock()
	p := pace
	paceMu.Unlock()
	wake := killWake()
	if p != nil {
		wctx, stop := ctx, func() {}
		if wake != nil {
			var cancel context.CancelFunc
			wctx, cancel = context.WithCancel(ctx)
			go func() {
				select {
				case <-wake:
					cancel()
				case <-wctx.Done():
				}
			}()
			stop = cancel
		}
		err := p.Wait(wctx)
		stop()
		if k := Killed(); k != nil {
			return k
		}
		if err != nil {
			if ctx.Err() == nil {
				// Too little time left to keep the pace: the work stops at
				// the deadline, as a run's -timeout stops it, and is not
				// a failure of the target.
				select {
				case <-ctx.Done():
				case <-wake:
					return Killed()
				}
				return ctx.Err()
			}
			return err
		}
		return nil
	}
	if k := Killed(); k != nil {
		return k
	}
	return ctx.Err()
}

type refusedKey struct{}

type watch struct {
	refused atomic.Bool
	used    atomic.Int64

	mu   sync.Mutex
	down error // the first request refused for an origin that stopped answering
}

// Stopped is the refusal a request made with ctx (marked by WatchBudget)
// got because its origin stopped answering, or nil: the task is not done,
// and azhaq resume runs it again.
func Stopped(ctx context.Context) error {
	w, _ := ctx.Value(refusedKey{}).(*watch)
	if w == nil {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.down
}

// WatchBudget marks ctx so that refused reports whether the budget refused
// a request made with it (a collector may take a refused request for a
// path that does not exist, and its work is then not done), and used how
// many it allowed.
func WatchBudget(ctx context.Context) (_ context.Context, refused func() bool, used func() int) {
	w := new(watch)
	return context.WithValue(ctx, refusedKey{}, w), w.refused.Load, func() int { return int(w.used.Load()) }
}

// Take accounts for one connection to a target that is not an HTTP
// request (a port scan's connect): it counts against the budget, which
// may refuse it with neterr.ErrBudget, and is paced by its caller.
func Take() error {
	if err := Killed(); err != nil {
		return err
	}
	for {
		n := sent.Load()
		if MaxRequests > 0 && n >= MaxRequests {
			return neterr.ErrBudget
		}
		if sent.CompareAndSwap(n, n+1) {
			return nil
		}
	}
}

// Refund gives back one request counted with Take or Spend that was not
// sent after all (the page closed while it waited for the pace).
func Refund() {
	for {
		n := sent.Load()
		if n <= 0 || sent.CompareAndSwap(n, n-1) {
			return
		}
	}
}

// Count accounts for requests already sent without asking (a worker
// process's): they count against the budget, which may then be spent.
func Count(n int) { sent.Add(int64(n)) }

// Spent says nothing more is sent: the budget is spent or a kill file exists.
func Spent() bool { return MaxRequests > 0 && sent.Load() >= MaxRequests || Killed() != nil }

// Sent is how many requests the run has sent to its targets.
func Sent() int64 { return sent.Load() }

func resetBudget() {
	MaxRequests = 0
	sent.Store(0)
	SetRate(0)
}
