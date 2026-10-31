package egress

import (
	"context"
	"sync"
	"sync/atomic"

	"golang.org/x/time/rate"

	"github.com/trannghiach/azhaq/internal/neterr"
)

// SessionTick, when set, is asked about each request counted with Spend:
// a signed-in run checks that its session lives, and an error refuses the
// request (fetch sets it).
var SessionTick func(ctx context.Context) error

// SetMaxRequests caps the requests a run sends to its targets (-max-requests,
// or what is left of a program's daily budget); zero is no cap.
func (p *Policy) SetMaxRequests(n int64) { p.maxReq.Store(n) }

// MaxRequests is the cap, zero for none.
func (p *Policy) MaxRequests() int64 { return p.maxReq.Load() }

// SetRate paces the requests to targets: perSecond over all hosts (-rate);
// zero is no pace.
func (p *Policy) SetRate(perSecond float64) {
	p.paceMu.Lock()
	defer p.paceMu.Unlock()
	p.pace, p.paceR = nil, 0
	if perSecond > 0 {
		p.pace, p.paceR = rate.NewLimiter(rate.Limit(perSecond), max(1, int(perSecond/5))), perSecond
	}
}

// Rate is the pace in requests per second (-rate), or 0 without one.
func (p *Policy) Rate() float64 {
	p.paceMu.Lock()
	defer p.paceMu.Unlock()
	return p.paceR
}

// Spend accounts for one request to a target before it is sent: it waits
// for the run's pace, and refuses with neterr.ErrBudget once the budget is
// spent, and with neterr.ErrKilled once the kill file exists. Every request
// to a target goes through it (GETs, path and parameter guesses, GraphQL,
// pages loaded in Chrome).
func (p *Policy) Spend(ctx context.Context) error { return p.spend(ctx, true) }

// SpendUnpaced is Spend without the wait for the pace: for a request
// whose sender waits for it itself, when it is sent (Chrome's pages),
// not when it is counted, so that no number of them is let go at once.
func (p *Policy) SpendUnpaced(ctx context.Context) error { return p.spend(ctx, false) }

func (p *Policy) spend(ctx context.Context, paced bool) error {
	if err := p.SpendCounted(ctx, paced); err != nil {
		return err
	}
	if f := SessionTick; f != nil {
		if err := f(ctx); err != nil {
			p.Refund() // never sent: the session ended
			if w, _ := ctx.Value(refusedKey{}).(*watch); w != nil {
				w.used.Add(-1)
			}
			return err
		}
	}
	return nil
}

// SpendCounted is Spend without the session check: for the check's own
// requests.
func (p *Policy) SpendCounted(ctx context.Context, paced bool) error {
	w, _ := ctx.Value(refusedKey{}).(*watch)
	if err := p.Killed(); err != nil {
		if w != nil {
			w.refused.Store(true)
		}
		return err
	}
	for {
		n := p.sent.Load()
		if m := p.maxReq.Load(); m > 0 && n >= m {
			if w != nil {
				w.refused.Store(true)
			}
			return neterr.ErrBudget
		}
		if p.sent.CompareAndSwap(n, n+1) {
			break
		}
	}
	if w != nil {
		w.used.Add(1)
	}
	if !paced {
		return nil
	}
	if err := p.Pace(ctx); err != nil {
		p.Refund() // never sent
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
func (p *Policy) Pace(ctx context.Context) error {
	p.paceMu.Lock()
	lim := p.pace
	p.paceMu.Unlock()
	wake := p.killWake()
	if lim != nil {
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
		err := lim.Wait(wctx)
		stop()
		if k := p.Killed(); k != nil {
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
					return p.Killed()
				}
				return ctx.Err()
			}
			return err
		}
		return nil
	}
	if k := p.Killed(); k != nil {
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

// MarkStopped notes on ctx (marked by WatchBudget) that a request was
// refused because its origin stopped answering. Harmless without a mark.
func MarkStopped(ctx context.Context, err error) {
	if w, _ := ctx.Value(refusedKey{}).(*watch); w != nil {
		w.mu.Lock()
		if w.down == nil {
			w.down = err
		}
		w.mu.Unlock()
	}
}

// MarkRefused notes on ctx that the budget refused a request made with it.
func MarkRefused(ctx context.Context) {
	if w, _ := ctx.Value(refusedKey{}).(*watch); w != nil {
		w.refused.Store(true)
	}
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
func (p *Policy) Take() error {
	if err := p.Killed(); err != nil {
		return err
	}
	for {
		n := p.sent.Load()
		if m := p.maxReq.Load(); m > 0 && n >= m {
			return neterr.ErrBudget
		}
		if p.sent.CompareAndSwap(n, n+1) {
			return nil
		}
	}
}

// Refund gives back one request counted with Take or Spend that was not
// sent after all (the page closed while it waited for the pace).
func (p *Policy) Refund() {
	for {
		n := p.sent.Load()
		if n <= 0 || p.sent.CompareAndSwap(n, n-1) {
			return
		}
	}
}

// Count accounts for requests already sent without asking (a worker
// process's): they count against the budget, which may then be spent.
func (p *Policy) Count(n int) { p.sent.Add(int64(n)) }

// Spent says nothing more is sent: the budget is spent or a kill file exists.
func (p *Policy) Spent() bool {
	m := p.maxReq.Load()
	return m > 0 && p.sent.Load() >= m || p.Killed() != nil
}

// Sent is how many requests the run has sent to its targets.
func (p *Policy) Sent() int64 { return p.sent.Load() }

// Package-level forms for the policy in use.

func SetMaxRequests(n int64)                             { Current().SetMaxRequests(n) }
func MaxRequests() int64                                 { return Current().MaxRequests() }
func SetRate(perSecond float64)                          { Current().SetRate(perSecond) }
func Rate() float64                                      { return Current().Rate() }
func Spend(ctx context.Context) error                    { return Current().Spend(ctx) }
func SpendUnpaced(ctx context.Context) error             { return Current().SpendUnpaced(ctx) }
func SpendCounted(ctx context.Context, paced bool) error { return Current().SpendCounted(ctx, paced) }
func Pace(ctx context.Context) error                     { return Current().Pace(ctx) }
func Take() error                                        { return Current().Take() }
func Refund()                                            { Current().Refund() }
func Count(n int)                                        { Current().Count(n) }
func Spent() bool                                        { return Current().Spent() }
func Sent() int64                                        { return Current().Sent() }
