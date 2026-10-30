package browser

import (
	"context"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/chromedp/cdproto/network"

	"github.com/trannghiach/azhaq/internal/fetch"
)

// With a pace set (-rate), a page's requests wait their turn, so the
// seconds a page has taken say nothing of whether it is stuck: a page of
// 42 requests at 2 a second needs 21 s however well it loads. Its
// deadlines then run from the last time it moved (a request of it let go,
// an answer heard), and a page is slow only when nothing moved for a
// while. Without a pace the deadlines stay wall-clock.

// progress is when a page last moved.
type progress struct{ at atomic.Int64 }

func newProgress() *progress {
	p := new(progress)
	p.touch()
	return p
}

// touch notes that the page moved; it is safe on a nil progress.
func (p *progress) touch() {
	if p != nil {
		p.at.Store(time.Now().UnixNano())
	}
}

func (p *progress) idle() time.Duration {
	return time.Since(time.Unix(0, p.at.Load()))
}

// deadline is ctx ending with context.DeadlineExceeded after d, or, when
// p is set, once p has not moved for d (plus the time two requests take at
// the pace) or hard has passed in all.
func deadline(parent context.Context, p *progress, d, hard time.Duration) (context.Context, context.CancelFunc) {
	if p == nil {
		return context.WithTimeout(parent, d)
	}
	ctx, cancel := context.WithCancelCause(parent)
	if r := fetch.Rate(); r > 0 {
		d += time.Duration(2 * float64(time.Second) / r)
	}
	start := time.Now()
	go func() {
		tick := time.NewTicker(100 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
			}
			if p.idle() > d || time.Since(start) > hard {
				cancel(context.DeadlineExceeded)
				return
			}
		}
	}()
	return ctx, func() { cancel(context.Canceled) }
}

// pageWeights is how many requests the pages taken lately made: the
// pace funds a page's tab for as long as it takes to send them.
const pageWeights = 9

// gate lets pages open one at a time per what the pace can fund: a pace
// of 2 a second sends about 60 requests in a page's 30 s, so one page of
// 40 requests at a time is complete, where four at once are all half
// drawn when their time is up. Without a pace it is Tabs.
type gate struct {
	mu      sync.Mutex
	active  int
	wake    chan struct{}
	weights []int
}

// limit is how many pages may be open now.
func (g *gate) limit(tabs int, timeout time.Duration) int {
	r := fetch.Rate()
	if r <= 0 {
		return tabs
	}
	w := 40
	if len(g.weights) > 0 {
		s := slices.Clone(g.weights)
		slices.Sort(s)
		w = max(s[len(s)/2], 1)
	}
	return min(max(int(r*timeout.Seconds()/float64(w)), 1), tabs)
}

// enter waits for a free place, or ctx ending.
func (g *gate) enter(ctx context.Context, tabs int, timeout time.Duration) error {
	for {
		g.mu.Lock()
		if g.active < g.limit(tabs, timeout) {
			g.active++
			g.mu.Unlock()
			return nil
		}
		if g.wake == nil {
			g.wake = make(chan struct{})
		}
		w := g.wake
		g.mu.Unlock()
		select {
		case <-w:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// leave gives the place back; asked is how many requests the page made
// (0: unknown).
func (g *gate) leave(asked int) {
	g.mu.Lock()
	g.active--
	if asked > 0 {
		g.weights = append(g.weights, asked)
		if len(g.weights) > pageWeights {
			g.weights = g.weights[1:]
		}
	}
	if g.wake != nil {
		close(g.wake)
		g.wake = nil
	}
	g.mu.Unlock()
}

// counted says whether a request of this type is part of what a
// screenshot shows, so that one still on its way when the page is
// captured leaves the picture short.
func counted(rt network.ResourceType) bool {
	switch rt {
	case network.ResourceTypeImage, network.ResourceTypeStylesheet, network.ResourceTypeScript,
		network.ResourceTypeFont, network.ResourceTypeMedia:
		return true
	}
	return false
}
