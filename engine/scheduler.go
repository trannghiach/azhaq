package engine

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/trannghiach/azhaq/catalog"
	"github.com/trannghiach/azhaq/internal/normalize"
	"github.com/trannghiach/azhaq/internal/timing"
	"github.com/trannghiach/azhaq/internal/webextract"
	"github.com/trannghiach/azhaq/types"
)

// batchesInFlight is how many batches one collector may run at once.
const batchesInFlight = 4

// perTemplate is how many URLs of one template (/product?id={n}) are
// fetched; the rest stay in the graph as found, not visited.
const perTemplate = 3

// RunLocal is the built-in scheduler. Work flows: a seed's items start as
// soon as a worker is free, and the hints they return are queued at once,
// so a slow item (a CT log taking 25 s) never holds back the rest.
//
// Items on the seed's own host run before fan-out items, but a reserve of
// the item budget is kept for fan-out so a chatty application cannot starve
// domain-level collectors. Batch collectors (DNS) take many seeds per call
// and have their own budget, MaxNames.
func (e *Engine) RunLocal(ctx context.Context, seeds []types.Seed, b Budgets) error {
	if b.MaxDepth <= 0 {
		b.MaxDepth = 1
	}
	if b.MaxItems <= 0 {
		b.MaxItems = DefaultBudgets().MaxItems
	}
	if b.Parallel <= 0 {
		b.Parallel = DefaultBudgets().Parallel
	}
	if b.MaxNames <= 0 {
		b.MaxNames = DefaultBudgets().MaxNames
	}
	s := &scheduler{
		e:         e,
		b:         b,
		origin:    seedOrigin(seeds),
		seen:      map[string]bool{},
		tmpl:      map[string]int{},
		batch:     map[string][]task{},
		batchBusy: map[string]int{},
		parked:    map[string][]task{},
		results:   make(chan finished, b.Parallel),
	}
	if !b.Passive {
		s.reserve = fanReserve(b)
	}
	expanded := expandDerived(seeds, map[string]bool{})
	e.persistSeeds(expanded)
	for _, seed := range expanded {
		s.add(seed, 0, false)
	}
	s.loop(ctx)
	leftover := s.leftover()
	if len(leftover) > 0 && s.ran+s.names > 0 {
		e.markCapped()
	}
	if e.Store != nil {
		_ = e.Store.SaveLeftover(leftover)
	}
	return ctx.Err()
}

type task struct {
	col   string
	seed  types.Seed
	depth int
	prio  int // 0: the seed's own host or IP; 1: fan-out
}

type finished struct {
	batch   string
	tasks   []task
	metas   []types.RunMeta
	errs    []error
	partial bool // early hints from a task still running
}

type scheduler struct {
	e      *Engine
	b      Budgets
	origin originSet

	seen  map[string]bool // seeds queued at some depth
	tmpl  map[string]int  // URLs queued per template
	queue [2][]task

	batch     map[string][]task // seeds waiting for a batch collector
	batchBusy map[string]int    // batches in flight per collector
	parked    map[string][]task // seedKey + "\x00" + collector it waits for

	ran, originRan, reserve int
	names                   int // seeds handed to batch collectors
	inflight                int
	beyond                  []types.Seed // hints past MaxDepth
	results                 chan finished
}

// add queues every allowed collector for a seed. Hints are checked against
// the scope; the run's own seeds are not.
func (s *scheduler) add(raw types.Seed, depth int, hint bool) {
	seed := normalize.Seed(raw)
	if seed.Key() == "" {
		return
	}
	if hint && !s.b.Scope.AllowsSeed(seed) {
		return
	}
	k := seedKey(seed)
	if s.seen[k] {
		return
	}
	if depth >= s.b.MaxDepth {
		s.beyond = append(s.beyond, seed)
		return
	}
	s.seen[k] = true
	if hint && seed.Type == types.TypeURL && webextract.Templated(seed.Key()) {
		t := webextract.Template(seed.Key())
		if s.tmpl[t] >= perTemplate {
			return
		}
		s.tmpl[t]++
	}
	prio := 1
	if s.origin.owns(seed) {
		prio = 0
	}
	cols := s.e.Cat.Where(seed.Type)
	planned := map[string]bool{}
	for _, col := range cols {
		if s.allowed(col, seed) {
			planned[col.Name()] = true
		}
	}
	for _, col := range cols {
		if !planned[col.Name()] {
			continue
		}
		t := task{col: col.Name(), seed: seed, depth: depth, prio: prio}
		if after := catalog.InfoOf(col).After; after != "" && planned[after] {
			pk := k + "\x00" + after
			s.parked[pk] = append(s.parked[pk], t)
			continue
		}
		s.enqueue(t)
	}
}

// drop discards the tasks that waited for col on a seed, and the tasks
// that waited for those, down the chain.
func (s *scheduler) drop(seedK, col string) {
	pk := seedK + "\x00" + col
	waiting := s.parked[pk]
	delete(s.parked, pk)
	for _, w := range waiting {
		s.drop(seedK, w.col)
	}
}

// unpark queues the tasks that waited for t.
func (s *scheduler) unpark(t task) {
	pk := seedKey(t.seed) + "\x00" + t.col
	for _, w := range s.parked[pk] {
		s.enqueue(w)
	}
	delete(s.parked, pk)
}

func (s *scheduler) enqueue(t task) {
	col, _ := s.e.Cat.Get(t.col)
	if _, ok := col.(catalog.Batcher); ok {
		s.batch[t.col] = append(s.batch[t.col], t)
		return
	}
	s.queue[t.prio] = append(s.queue[t.prio], t)
}

// allowed applies the run's policy: -passive keeps only collectors that do
// not contact the target, and an active technique needs its flag, an
// -allow scope, and a seed inside it.
func (s *scheduler) allowed(col catalog.Collector, seed types.Seed) bool {
	if s.b.Skip[col.Name()] {
		return false
	}
	in := catalog.InfoOf(col)
	switch in.Kind {
	case catalog.Passive:
		return true
	case catalog.Active:
		return in.Flag != "" && s.b.Active[in.Flag] && len(s.b.Scope.Allow) > 0 && s.b.Scope.AllowsSeed(seed)
	default:
		return !s.b.Passive
	}
}

func (s *scheduler) skip(t task) bool {
	col, ok := s.e.Cat.Get(t.col)
	if !ok {
		return true
	}
	sk, ok := col.(catalog.Skipper)
	return ok && sk.Skip(t.seed)
}

func (s *scheduler) loop(ctx context.Context) {
	for {
		if ctx.Err() == nil {
			s.dispatch(ctx)
		}
		if s.inflight == 0 {
			return
		}
		s.handle(<-s.results)
	}
}

func (s *scheduler) dispatch(ctx context.Context) {
	for s.inflight < s.b.Parallel {
		if s.startBatch(ctx) {
			continue
		}
		t, ok := s.next()
		if !ok {
			return
		}
		s.start(ctx, t)
	}
}

// next pops the next runnable task: seed-origin work first while it is
// within its share of the budget, then fan-out.
func (s *scheduler) next() (task, bool) {
	for p := 0; p < 2; p++ {
		for len(s.queue[p]) > 0 {
			t := s.queue[p][0]
			if s.skip(t) {
				s.queue[p] = s.queue[p][1:]
				s.unpark(t) // nothing to wait for
				continue
			}
			if s.ran >= s.b.MaxItems {
				return task{}, false
			}
			if p == 0 && s.originRan >= s.b.MaxItems-s.reserve {
				break
			}
			s.queue[p] = s.queue[p][1:]
			s.ran++
			if p == 0 {
				s.originRan++
			}
			return t, true
		}
	}
	return task{}, false
}

func (s *scheduler) start(ctx context.Context, t task) {
	s.inflight++
	item := types.WorkItem{ID: workID(t.col, t.seed), Collector: t.col, Seed: t.seed}
	go func() {
		t0 := time.Now()
		ctx := catalog.WithHints(ctx, func(seeds []types.Seed) {
			s.results <- finished{tasks: []task{t}, metas: []types.RunMeta{{NextHints: seeds}}, errs: []error{nil}, partial: true}
		})
		meta, err := s.e.Run(ctx, item)
		printItem(ctx, item, time.Since(t0), meta, err)
		s.results <- finished{tasks: []task{t}, metas: []types.RunMeta{meta}, errs: []error{err}}
	}()
}

// startBatch hands waiting seeds to one idle batch collector.
func (s *scheduler) startBatch(ctx context.Context) bool {
	for name, waiting := range s.batch {
		if len(waiting) == 0 || s.batchBusy[name] >= batchesInFlight {
			continue
		}
		col, _ := s.e.Cat.Get(name)
		size := col.(catalog.Batcher).BatchSize()
		if size <= 0 {
			size = 1
		}
		n := min(len(waiting), size, s.b.MaxNames-s.names)
		if n <= 0 {
			continue
		}
		tasks := append([]task(nil), waiting[:n]...)
		s.batch[name] = waiting[n:]
		s.batchBusy[name]++
		s.names += n
		s.inflight++
		go func() {
			seeds := make([]types.Seed, len(tasks))
			for i, t := range tasks {
				seeds[i] = t.seed
			}
			t0 := time.Now()
			res, err := s.e.RunBatch(ctx, name, seeds)
			printBatch(ctx, name, len(seeds), time.Since(t0), err)
			byKey := map[string]types.RunMeta{}
			for _, r := range res {
				byKey[seedKey(r.Seed)] = r.Meta
			}
			f := finished{batch: name}
			for _, t := range tasks {
				m, ok := byKey[seedKey(t.seed)]
				if !ok {
					// Already ran in an earlier run on this database, or the
					// batch failed: release whatever waits on it.
					m = types.RunMeta{Status: types.StatusOK}
					if err != nil {
						m.Status = types.StatusError
					}
				}
				f.tasks = append(f.tasks, t)
				f.metas = append(f.metas, m)
				f.errs = append(f.errs, nil)
			}
			s.results <- f
		}()
		return true
	}
	return false
}

func (s *scheduler) handle(f finished) {
	if f.partial {
		for i, t := range f.tasks {
			for _, h := range f.metas[i].NextHints {
				s.add(h, t.depth+1, true)
			}
		}
		return
	}
	s.inflight--
	if f.batch != "" {
		s.batchBusy[f.batch]--
	}
	for i, t := range f.tasks {
		meta, err := f.metas[i], f.errs[i]
		if meta.Drop {
			s.drop(seedKey(t.seed), t.col)
		} else {
			s.unpark(t)
		}
		if err != nil && meta.Status != types.StatusCancelled {
			continue
		}
		for _, h := range meta.NextHints {
			s.add(h, t.depth+1, true)
		}
	}
}

// leftover is every seed with work that did not run: over budget, or
// found past the depth limit.
func (s *scheduler) leftover() []types.Seed {
	var out []types.Seed
	seen := map[string]bool{}
	put := func(seed types.Seed) {
		k := seedKey(seed)
		if !seen[k] {
			seen[k] = true
			out = append(out, seed)
		}
	}
	for p := range s.queue {
		for _, t := range s.queue[p] {
			if !s.skip(t) {
				put(t.seed)
			}
		}
	}
	for _, waiting := range s.batch {
		for _, t := range waiting {
			put(t.seed)
		}
	}
	for _, waiting := range s.parked {
		for _, t := range waiting {
			put(t.seed)
		}
	}
	for _, seed := range s.beyond {
		if !s.seen[seedKey(seed)] {
			put(seed)
		}
	}
	return out
}

func printBatch(ctx context.Context, name string, n int, d time.Duration, err error) {
	if isQuiet(ctx) || timing.From(ctx) == nil {
		if err != nil && !isQuiet(ctx) {
			fmt.Fprintf(os.Stderr, "  ! %s %d seeds: %s\n", name, n, err)
		}
		return
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "  ! %s %d seeds: %s  %s\n", name, n, err, d.Round(time.Millisecond))
		return
	}
	fmt.Fprintf(os.Stderr, "  . %s %d seeds  %s\n", name, n, d.Round(time.Millisecond))
}
