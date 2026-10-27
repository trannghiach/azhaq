package engine

import (
	"context"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/trannghiach/azhaq/internal/neterr"
	"github.com/trannghiach/azhaq/internal/normalize"
	"github.com/trannghiach/azhaq/scope"
	"github.com/trannghiach/azhaq/types"
)

type Budgets struct {
	MaxDepth     int
	MaxItems     int
	Parallel     int
	FailOnErrors bool
	FailOnCapped bool
	Passive      bool
	Scope        scope.Rules
	// Active lists the flags of enabled active techniques ("dns-brute").
	Active map[string]bool
	// MaxNames caps the seeds handed to batch collectors (DNS) per run.
	MaxNames int
	// Skip names collectors that must not run.
	Skip map[string]bool
	// Resume continues the store's current run from its recorded tasks
	// instead of starting from the seeds.
	Resume bool
	// AllGets also requests found URLs that look like they change state
	// (logout, delete, save…); by default they are listed, not requested.
	AllGets bool
	// PerTemplate is how many URLs of one template (/product?id={n}) are
	// requested; the rest are listed. Zero is the default, 3.
	PerTemplate int
}

type quietKey struct{}

func WithQuiet(ctx context.Context) context.Context {
	return context.WithValue(ctx, quietKey{}, true)
}

func isQuiet(ctx context.Context) bool {
	v, _ := ctx.Value(quietKey{}).(bool)
	return v
}

func DefaultBudgets() Budgets {
	return Budgets{MaxDepth: 4, MaxItems: 2048, Parallel: 16, MaxNames: 20000}
}

// ExpandSeeds returns seeds plus URL→host→eTLD+1 so connectors see wave-0 types.
func ExpandSeeds(seeds []types.Seed) []types.Seed {
	return expandDerived(seeds, map[string]bool{})
}

type originSet struct {
	hosts map[string]bool
	ips   map[string]bool
}

func seedOrigin(seeds []types.Seed) originSet {
	o := originSet{hosts: map[string]bool{}, ips: map[string]bool{}}
	for _, raw := range seeds {
		s := normalize.Seed(raw)
		switch s.Type {
		case types.TypeURL:
			h := normalize.HostFromURL(s.Key())
			if ip := net.ParseIP(h); ip != nil {
				o.ips[ip.String()] = true
			} else if h != "" {
				o.hosts[h] = true
			}
		case types.TypeHostname:
			if s.Key() != "" {
				o.hosts[s.Key()] = true
			}
		case types.TypeIPAddress:
			if s.Key() != "" {
				o.ips[s.Key()] = true
			}
		}
	}
	return o
}

func (o originSet) owns(s types.Seed) bool {
	s = normalize.Seed(s)
	switch s.Type {
	case types.TypeURL:
		h := normalize.HostFromURL(s.Key())
		if ip := net.ParseIP(h); ip != nil {
			return o.ips[ip.String()]
		}
		return o.hosts[h]
	case types.TypeHostname:
		return o.hosts[s.Key()]
	case types.TypeIPAddress:
		return o.ips[s.Key()]
	default:
		return false
	}
}

// fanReserve keeps CT/CDX/RDAP (and sibling DNS) from being cut to zero
// when the seed app is chatty. Small test budgets keep a 1/8 slice only;
// runs of 48+ items hold at least 24 for the domain half.
func fanReserve(b Budgets) int {
	if b.Passive || b.MaxItems <= 1 {
		return 0
	}
	n := b.MaxItems / 8
	if n < 1 {
		n = 1
	}
	if b.MaxItems >= 48 && n < 24 {
		n = 24
	}
	if n > b.MaxItems/2 {
		n = b.MaxItems / 2
	}
	return n
}

func (e *Engine) persistSeeds(seeds []types.Seed) {
	if e == nil || e.Store == nil {
		return
	}
	now := time.Now().UTC()
	for _, s := range seeds {
		s = normalize.Seed(s)
		if s.Key() == "" {
			continue
		}
		ent, err := e.Store.UpsertEntity(s.Type, s.Key(), now)
		if err != nil {
			continue
		}
		e.linkSeed(s, ent, now)
		e.linkInDomain(s, ent, now)
	}
}

func (e *Engine) markCapped() {
	if e == nil || e.Store == nil {
		return
	}
	_ = e.Store.MarkCapped()
}

// progress is how much a run says on stderr while it works.
type progress struct {
	verbose bool
	mu      sync.Mutex
	errs    map[string]int
}

type progressKey struct{}

// WithVerbose makes the run print a line for every finished task, not
// only for failures.
func WithVerbose(ctx context.Context) context.Context {
	return context.WithValue(ctx, progressKey{}, &progress{verbose: true, errs: map[string]int{}})
}

// errorLines caps the lines one kind of failure prints while a run works;
// the summary counts all of them.
const errorLines = 3

func printItem(ctx context.Context, item types.WorkItem, d time.Duration, meta types.RunMeta, err error) {
	if isQuiet(ctx) || meta.Status == types.StatusCapped {
		return
	}
	p, _ := ctx.Value(progressKey{}).(*progress)
	if err != nil {
		if meta.Status == types.StatusCancelled || neterr.Quiet(err) {
			return
		}
		short := ShortError(err.Error())
		if p == nil {
			fmt.Fprintf(os.Stderr, "  ! %s %s: %s\n", item.Collector, item.Seed.Key(), short)
			return
		}
		p.mu.Lock()
		k := item.Collector + "\x00" + short
		p.errs[k]++
		n := p.errs[k]
		p.mu.Unlock()
		switch {
		case p.verbose || n <= errorLines:
			fmt.Fprintf(os.Stderr, "  ! %s %s: %s\n", item.Collector, item.Seed.Key(), short)
		case n == errorLines+1:
			fmt.Fprintf(os.Stderr, "  ! %s: more %q failures; the summary counts them\n", item.Collector, short)
		}
		return
	}
	if p == nil || !p.verbose {
		return
	}
	mark := "."
	if meta.Status == types.StatusDegraded {
		mark = "~"
	}
	fmt.Fprintf(os.Stderr, "  %s %s %s  %s\n", mark, item.Collector, item.Seed.Key(), d.Round(time.Millisecond))
}

// WithProgress counts failures for printItem without printing every task.
func WithProgress(ctx context.Context) context.Context {
	if _, ok := ctx.Value(progressKey{}).(*progress); ok {
		return ctx
	}
	return context.WithValue(ctx, progressKey{}, &progress{errs: map[string]int{}})
}

func seedKey(s types.Seed) string {
	return string(s.Type) + "\x00" + s.Key()
}

// expandDerived folds URL → host → eTLD+1 into the same wave so CT/DNS/TLS
// start with the first page fetch instead of waiting a full depth.
func expandDerived(seeds []types.Seed, seen map[string]bool) []types.Seed {
	var out []types.Seed
	q := append([]types.Seed(nil), seeds...)
	for len(q) > 0 {
		s := normalize.Seed(q[0])
		q = q[1:]
		if s.Key() == "" {
			continue
		}
		k := seedKey(s)
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, s)
		q = append(q, derivedSeeds(s)...)
	}
	return out
}
