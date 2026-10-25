package engine

import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/trannghiach/azhaq/internal/normalize"
	"github.com/trannghiach/azhaq/internal/scope"
	"github.com/trannghiach/azhaq/internal/timing"
	"github.com/trannghiach/azhaq/internal/types"
)

type Budgets struct {
	MaxDepth     int
	MaxItems     int
	Parallel     int
	FailOnErrors bool
	FailOnCapped bool
	Passive      bool
	Scope        scope.Rules
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
	return Budgets{MaxDepth: 4, MaxItems: 512, Parallel: 8}
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

// RunLocal is the optional in-process scheduler: seed-origin HTTP first, then fan-out.
func (e *Engine) RunLocal(ctx context.Context, seeds []types.Seed, b Budgets) error {
	if b.MaxDepth <= 0 {
		b.MaxDepth = 1
	}
	if b.MaxItems <= 0 {
		b.MaxItems = 512
	}
	if b.Parallel <= 0 {
		b.Parallel = 8
	}
	seen := map[string]bool{}
	expanded := expandDerived(seeds, seen)
	e.persistSeeds(expanded)
	origin := seedOrigin(seeds)

	var app, held []types.Seed
	for _, s := range expanded {
		if s.Type == types.TypeDomain {
			held = append(held, s)
			continue
		}
		app = append(app, s)
	}

	appBudget := b
	if reserve := fanReserve(b); reserve > 0 && !b.Passive {
		appBudget.MaxItems = max(1, b.MaxItems-reserve)
	}
	leftover, ran, capped := e.drive(ctx, app, appBudget, origin, seen, 0, true)
	var originLeft, fan []types.Seed
	for _, s := range leftover {
		if origin.owns(s) {
			originLeft = append(originLeft, s)
			continue
		}
		fan = append(fan, s)
	}
	fanLeft, ran, capped2 := e.drive(ctx, append(fan, held...), b, origin, seen, ran, false)
	leftover = append(originLeft, fanLeft...)
	if (capped || capped2 || len(originLeft) > 0 || len(fanLeft) > 0) && ran > 0 {
		e.markCapped()
	}
	if e.Store != nil {
		_ = e.Store.SaveLeftover(leftover)
	}
	return ctx.Err()
}

func (e *Engine) drive(ctx context.Context, frontier []types.Seed, b Budgets, origin originSet, seen map[string]bool, ran int, seedOnly bool) ([]types.Seed, int, bool) {
	capped := false
	var deferred []types.Seed
	for depth := 0; depth < b.MaxDepth && len(frontier) > 0; depth++ {
		if ctx.Err() != nil {
			return append(frontier, deferred...), ran, capped
		}
		waveDone := timing.Start(ctx, "wave", strconv.Itoa(depth))
		items := e.plan(frontier, b)
		if ran+len(items) > b.MaxItems {
			cut := max(0, b.MaxItems-ran)
			if cut < len(items) {
				e.markCapped()
				capped = true
			}
			items = items[:cut]
		}
		if len(items) == 0 {
			waveDone()
			break
		}
		ran += len(items)

		type outcome struct {
			item types.WorkItem
			meta types.RunMeta
			err  error
		}
		outc := make(chan outcome, len(items))
		sem := make(chan struct{}, b.Parallel)
		var wg sync.WaitGroup
		for _, item := range items {
			wg.Add(1)
			go func(item types.WorkItem) {
				defer wg.Done()
				select {
				case <-ctx.Done():
					outc <- outcome{item: item, err: ctx.Err()}
					return
				case sem <- struct{}{}:
				}
				defer func() { <-sem }()
				t0 := time.Now()
				meta, err := e.Run(ctx, item)
				printItem(ctx, item, time.Since(t0), meta, err)
				outc <- outcome{item: item, meta: meta, err: err}
			}(item)
		}
		go func() {
			wg.Wait()
			close(outc)
		}()

		frontier = nil
		for o := range outc {
			if o.err != nil && o.meta.Status != types.StatusCancelled {
				continue
			}
			for _, h := range o.meta.NextHints {
				h = normalize.Seed(h)
				k := seedKey(h)
				if h.Key() == "" || seen[k] || !b.Scope.AllowsSeed(h) {
					continue
				}
				seen[k] = true
				if seedOnly && !origin.owns(h) {
					deferred = append(deferred, h)
					continue
				}
				frontier = append(frontier, h)
			}
		}
		waveDone()
	}
	return append(frontier, deferred...), ran, capped
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

func (e *Engine) plan(seeds []types.Seed, b Budgets) []types.WorkItem {
	items := e.Plan(seeds)
	if !b.Passive {
		return items
	}
	var out []types.WorkItem
	for _, it := range items {
		if activeCollector(it.Collector) {
			continue
		}
		out = append(out, it)
	}
	return out
}

func activeCollector(name string) bool {
	switch name {
	case "azhaq-http", "azhaq-crawl", "azhaq-js", "azhaq-paths", "azhaq-tls":
		return true
	default:
		return false
	}
}

func (e *Engine) markCapped() {
	if e == nil || e.Store == nil {
		return
	}
	_ = e.Store.MarkCapped()
}

func printItem(ctx context.Context, item types.WorkItem, d time.Duration, meta types.RunMeta, err error) {
	if isQuiet(ctx) {
		return
	}
	if timing.From(ctx) == nil {
		if err != nil && meta.Status != types.StatusCancelled {
			fmt.Fprintf(os.Stderr, "  ! %s %s: %s\n", item.Collector, item.Seed.Key(), err)
		}
		return
	}
	if err != nil && meta.Status != types.StatusCancelled {
		fmt.Fprintf(os.Stderr, "  ! %s %s: %s  %s\n", item.Collector, item.Seed.Key(), err, d.Round(time.Millisecond))
		return
	}
	if err != nil {
		return
	}
	mark := "."
	if meta.Status == types.StatusDegraded {
		mark = "~"
	}
	fmt.Fprintf(os.Stderr, "  %s %s %s  %s\n", mark, item.Collector, item.Seed.Key(), d.Round(time.Millisecond))
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
