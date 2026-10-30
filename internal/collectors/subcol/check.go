package subcol

import (
	"context"
	"sync"
	"time"

	"github.com/trannghiach/azhaq/catalog"
	"github.com/trannghiach/azhaq/types"
)

// What a checked name came to.
const (
	nameLive      = 1 // resolves, not to a wildcard
	nameDead      = 2 // does not resolve
	nameUnchecked = 3 // the resolvers failed, or the run ended first
)

type checkerKey struct{}

// checker resolves the names a padding source guessed, each once, as the
// source's rounds arrive: the next round is asked only after this one's
// names are known to resolve or not. It works on the run's context, not
// the source's: DNS is paced by -dns-rate, and -source-timeout is for
// asking the source.
type checker struct {
	ctx    context.Context
	domain string
	verify func(ctx context.Context, domain string, names []string) (live, failed []string)
	hint   func(names []string) // live names go on to DNS at once

	mu     sync.Mutex
	state  map[string]int8
	known  map[string]bool // given by a source that is not a padding one
	closed bool            // Run has stopped waiting: nothing more is asked
	asked  int             // names sent to the resolvers
	took   time.Duration   // time spent in them
	// paced: DNS has a -dns-rate, so a guess costs time and guessing is
	// bounded by what the real names cost.
	paced bool
}

func newChecker(ctx context.Context, domain string, verify func(context.Context, string, []string) ([]string, []string), hint func([]string)) *checker {
	return &checker{ctx: ctx, domain: domain, verify: verify, hint: hint, state: map[string]int8{}, known: map[string]bool{}}
}

// know records names a real source gave: they are resolved with the rest
// of the names, and are not guesses to check here.
func (k *checker) know(names []string) {
	if k == nil {
		return
	}
	k.mu.Lock()
	for _, n := range names {
		k.known[n] = true
	}
	k.mu.Unlock()
}

func (k *checker) close() {
	if k == nil {
		return
	}
	k.mu.Lock()
	k.closed = true
	k.mu.Unlock()
}

// check resolves the names it has not checked, bar the ones a real source
// gave, and returns how many of them are new live names.
func (k *checker) check(names []string) int { return k.checkWith(k.ctx, names) }

// checkWith is check on ctx.
func (k *checker) checkWith(ctx context.Context, names []string) int {
	k.mu.Lock()
	var ask []string
	for _, n := range names {
		if _, done := k.state[n]; !done && !k.known[n] && !k.closed {
			k.state[n] = nameUnchecked // taken: no one else asks it
			ask = append(ask, n)
		}
	}
	k.mu.Unlock()
	if len(ask) == 0 {
		return 0
	}
	t0 := time.Now()
	live, failed := k.verify(ctx, k.domain, ask)
	took := time.Since(t0)
	k.mu.Lock()
	k.asked += len(ask)
	k.took += took
	for _, n := range ask {
		k.state[n] = nameDead
	}
	for _, n := range failed {
		k.state[n] = nameUnchecked
	}
	for _, n := range live {
		k.state[n] = nameLive
	}
	k.mu.Unlock()
	if k.hint != nil && len(live) > 0 {
		k.hint(live)
	}
	return len(live)
}

// verdict is what became of a name: 0 when it was never asked.
func (k *checker) verdict(n string) int8 {
	if k == nil {
		return 0
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.state[n]
}

// hinter hands names to DNS as soon as they are known, once each.
type hinter struct {
	ctx    context.Context
	domain string
	max    int

	mu       sync.Mutex
	hinted   map[string]bool
	early    bool
	finished bool // set once Run stops waiting; late sources are ignored
}

func newHinter(ctx context.Context, domain string, max int) *hinter {
	return &hinter{ctx: ctx, domain: domain, max: max, hinted: map[string]bool{}, early: true}
}

func (h *hinter) pass(names []string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.finished || !h.early {
		return // nothing listens: the names go in NextHints at the end
	}
	var seeds []types.Seed
	for _, raw := range names {
		if n := clean(raw, h.domain); n != "" && !h.hinted[n] && len(h.hinted) < h.max {
			h.hinted[n] = true
			seeds = append(seeds, types.Seed{Type: types.TypeHostname, Keys: map[string]string{"fqdn": n}})
		}
	}
	if h.early && !catalog.Hint(h.ctx, seeds...) {
		h.early = false
		for _, s := range seeds {
			delete(h.hinted, s.Keys["fqdn"])
		}
	}
}

func (h *hinter) stop() {
	h.mu.Lock()
	h.finished = true
	h.mu.Unlock()
}

func (h *hinter) was(n string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.hinted[n]
}

// guessFloor is how many guesses a paced run may always check: two of
// subdomain.center's rounds.
const guessFloor = 1000

// room says whether another round of guesses may be checked. With no DNS
// pace it always may (the run's time is the bound); with one, the guesses
// may cost at most half what the real names reported cost, and not less
// than guessFloor.
func (k *checker) room() bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	return !k.paced || k.asked < max(guessFloor, len(k.known)/2)
}
