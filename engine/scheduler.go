package engine

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"time"

	"github.com/trannghiach/azhaq/catalog"
	"github.com/trannghiach/azhaq/internal/fetch"
	"github.com/trannghiach/azhaq/internal/normalize"
	"github.com/trannghiach/azhaq/internal/webextract"
	"github.com/trannghiach/azhaq/store"
	"github.com/trannghiach/azhaq/types"
)

// batchesInFlight is how many batches one collector may run at once.
const batchesInFlight = 4

// perTemplate is how many URLs of one template (/product?id={n}) are
// fetched by default; the rest stay in the graph as found, not visited.
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
		ctx:       ctx,
		secure:    givenHTTPS(seeds),
		schemes:   map[string]bool{},
		asked:     map[string]bool{},
		waiting:   map[string][]heldHint{},
	}
	if !b.Passive {
		s.reserve = fanReserve(b)
	}
	if e.Store != nil {
		catalog.Claim = e.Store.Claim
		defer func() { catalog.Claim = nil }()
		fetch.OnDenied = e.noteDenied
		defer func() { fetch.OnDenied = nil }()
	}
	if b.Resume && e.Store != nil {
		if err := s.restore(); err != nil {
			return err
		}
	} else {
		expanded := expandDerived(seeds, map[string]bool{})
		e.persistSeeds(expanded)
		for _, seed := range expanded {
			s.add(seed, 0, false)
		}
	}
	s.flush()
	s.loop(ctx)
	s.flush()
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
	tier  int // within a prio, what it is worth under a budget (tierOf)
}

type finished struct {
	batch   string
	tasks   []task
	metas   []types.RunMeta
	errs    []error
	partial bool // early hints from a task still running

	scheme string // the host whose http://host/ was asked (scheme.go)
	same   bool   // and whether it is the https site
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

	// The frontier as the store records it (see store.Task): tasks
	// planned and tasks done since the last flush.
	planned []store.Task
	done    []string
	stopped []store.Stopped
	held    []task // work that contacts targets, kept back once the budget is spent
	retry   []task // work the budget stopped before, cheapest first: one at a time

	// Tasks lent to remote workers (Engine.Workers).
	leases  map[string]lease
	remote  int // of inflight, the leased ones
	leaseNo int

	// http://host/ hints on a host given as https://host/ (scheme.go).
	ctx     context.Context
	secure  httpsGiven            // where the run was given https
	schemes map[string]bool       // host → its http URLs are the https site's
	asked   map[string]bool       // hosts whose http://host/ was asked
	waiting map[string][]heldHint // hints held for that answer
}

type lease struct {
	t     task
	until time.Time
}

// record notes a planned task for the store.
func (s *scheduler) record(t task) {
	if s.e.Store != nil {
		s.planned = append(s.planned, store.Task{ID: workID(t.col, t.seed), Collector: t.col, Seed: t.seed, Depth: t.depth, Prio: t.prio})
	}
}

// finish notes a task that will not run again in this run.
func (s *scheduler) finish(t task) {
	if s.e.Store != nil {
		s.done = append(s.done, workID(t.col, t.seed))
	}
}

// flush writes the noted tasks in one transaction.
func (s *scheduler) flush() {
	if s.e.Store == nil || len(s.planned)+len(s.done)+len(s.stopped) == 0 {
		return
	}
	if err := s.e.Store.SaveTasks(s.planned, s.done, s.stopped); err != nil {
		fmt.Fprintf(os.Stderr, "azhaq: recording tasks: %v\n", err)
	}
	s.planned, s.done, s.stopped = s.planned[:0], s.done[:0], s.stopped[:0]
}

// restore rebuilds the queues from the run's recorded tasks: done ones
// count against the budgets, the rest are queued again (behind the task
// they wait for, when that is not done either).
func (s *scheduler) restore() error {
	rows, err := s.e.Store.Tasks()
	if err != nil {
		return err
	}
	open := map[string]map[string]bool{} // seed → collectors not done
	for _, r := range rows {
		seed := normalize.Seed(r.Seed)
		k := seedKey(seed)
		if !s.seen[k] {
			s.seen[k] = true
			if seed.Type == types.TypeURL && webextract.Templated(seed.Key()) {
				s.tmpl[webextract.Template(seed.Key())]++
			}
		}
		if open[k] == nil {
			open[k] = map[string]bool{}
		}
		if !r.Done {
			open[k][r.Collector] = true
			continue
		}
		col, ok := s.e.Cat.Get(r.Collector)
		if _, batch := col.(catalog.Batcher); ok && batch {
			s.names++
		} else {
			s.ran++
			if r.Prio == 0 {
				s.originRan++
			}
		}
	}
	var again []string
	for _, r := range rows {
		col, ok := s.e.Cat.Get(r.Collector)
		if r.Done || !ok {
			continue
		}
		seed := normalize.Seed(r.Seed)
		k := seedKey(seed)
		t := task{col: r.Collector, seed: seed, depth: r.Depth, prio: r.Prio}
		again = append(again, r.ID)
		if after := catalog.InfoOf(col).After; after != "" && open[k][after] {
			pk := k + "\x00" + after
			s.parked[pk] = append(s.parked[pk], t)
			continue
		}
		if _, batch := col.(catalog.Batcher); r.Tries > 0 && !batch {
			// Run alone, it gets the whole budget: a sweep started next to
			// it cannot take the requests a cheap task needs.
			s.retry = append(s.retry, t)
			continue
		}
		s.enqueue(t)
	}
	// A task that ran but whose end was not recorded runs again whole.
	return s.e.Store.Forget(again)
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
	if hint {
		var held bool
		if seed, held = s.scheme(seed, depth); held {
			return
		}
	}
	k := seedKey(seed)
	if s.seen[k] {
		return
	}
	if seed.Type == types.TypeURL {
		// The user's own rule (-deny-path): the URL stays in the map, listed
		// as not requested.
		if rule := s.b.Scope.DeniedPath(seed.Key()); rule != "" {
			s.seen[k] = true
			s.e.noteDenied(seed.Key(), rule)
			return
		}
	}
	if depth >= s.b.MaxDepth {
		s.beyond = append(s.beyond, seed)
		return
	}
	s.seen[k] = true
	if hint && seed.Type == types.TypeURL && webextract.Templated(seed.Key()) {
		t := webextract.Template(seed.Key())
		if s.tmpl[t] >= s.perTemplate() {
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
		s.record(t)
		if after := catalog.InfoOf(col).After; after != "" && planned[after] {
			pk := k + "\x00" + after
			s.parked[pk] = append(s.parked[pk], t)
			continue
		}
		s.enqueue(t)
	}
}

func (s *scheduler) perTemplate() int {
	if s.b.PerTemplate > 0 {
		return s.b.PerTemplate
	}
	return perTemplate
}

// drop discards the tasks that waited for col on a seed, and the tasks
// that waited for those, down the chain.
func (s *scheduler) drop(seedK, col string) {
	pk := seedK + "\x00" + col
	waiting := s.parked[pk]
	delete(s.parked, pk)
	for _, w := range waiting {
		s.finish(w)
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
	// Worth first, arrival order within a tier: a front page found late
	// goes ahead of the archived URLs an archive listed before it, so a
	// budget is spent on what the application serves before on what it
	// once served.
	t.tier = tierOf(t.seed)
	q := s.queue[t.prio]
	i := len(q)
	for i > 0 && q[i-1].tier > t.tier {
		i--
	}
	q = append(q, task{})
	copy(q[i+1:], q[i:])
	q[i] = t
	s.queue[t.prio] = q
}

// tierOf orders a host's work by what it is worth under a budget: a
// service and its front page first, then its API and description paths,
// then the pages links and scripts name, and what only an archive lists
// last. An archive's static assets are never hints (urlcol lists them).
func tierOf(seed types.Seed) int {
	if seed.Type != types.TypeURL {
		return 0
	}
	if seed.Keys[types.ViaKey] == types.ViaArchive {
		return 3
	}
	u, err := url.Parse(seed.Key())
	if err != nil {
		return 2
	}
	switch {
	case u.Path == "" || u.Path == "/":
		return 0
	case webextract.ClassifyURL(seed.Key()) == "api":
		return 1
	default:
		return 2
	}
}

// allowed applies the run's policy: -passive keeps only collectors that do
// not contact the target, and an active technique needs its flag, an
// -allow scope, and a seed inside it.
func (s *scheduler) allowed(col catalog.Collector, seed types.Seed) bool {
	return s.b.Allows(col, seed)
}

// Allows applies the run's policy to one collector on one seed.
func (b Budgets) Allows(col catalog.Collector, seed types.Seed) bool {
	if b.Skip[col.Name()] {
		return false
	}
	in := catalog.InfoOf(col)
	switch in.Kind {
	case catalog.Passive:
		return true
	case catalog.Active:
		return in.Flag != "" && b.Active[in.Flag] && len(b.Scope.Allow) > 0 && b.Scope.AllowsSeed(seed)
	default:
		return !b.Passive
	}
}

// contacts says whether a task's collector sends requests to targets.
func (s *scheduler) contacts(t task) bool {
	col, ok := s.e.Cat.Get(t.col)
	return ok && catalog.InfoOf(col).Kind != catalog.Passive
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
	w := s.e.Workers
	var claims chan claim
	var dones chan remoteDone
	var tick <-chan time.Time
	if w != nil {
		defer w.finish()
		claims, dones = w.claims, w.done
		t := time.NewTicker(5 * time.Second)
		defer t.Stop()
		tick = t.C
		s.leases = map[string]lease{}
	}
	for {
		if ctx.Err() == nil {
			s.redoSession()
			s.dispatch(ctx)
		} else {
			s.release()
		}
		s.flush()
		if s.inflight == 0 {
			if ctx.Err() == nil {
				// The requests since the last check are checked too.
				fetch.EndCheck(ctx)
				s.redoSession()
				s.dispatch(ctx)
				s.flush()
			}
			if s.inflight == 0 {
				return
			}
		}
		select {
		case f := <-s.results:
			s.handle(f)
		case c := <-claims:
			s.lend(ctx, c)
		case d := <-dones:
			s.giveBack(ctx, d)
		case <-tick:
			s.expire()
		}
	}
}

// redoSession asks again the pages whose answers a session that ended gave
// without it (fetch.TakeRedo): what the collectors reported of them is
// dropped, and their tasks run again.
func (s *scheduler) redoSession() {
	urls := fetch.TakeRedo()
	if len(urls) == 0 || s.e.Store == nil {
		return
	}
	var touch []catalog.Collector
	for _, col := range s.e.Cat.Where(types.TypeURL) {
		if catalog.InfoOf(col).Kind == catalog.Touch {
			touch = append(touch, col)
		}
	}
	names := make([]string, len(touch))
	for i, col := range touch {
		names[i] = col.Name()
	}
	for _, raw := range urls {
		seed := normalize.Seed(types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": raw}})
		if seed.Key() == "" || !s.seen[seedKey(seed)] {
			continue
		}
		var keys []string
		for _, col := range touch {
			keys = append(keys, workID(col.Name(), seed))
		}
		for _, col := range touch {
			if f, ok := col.(catalog.Forgetter); ok {
				f.Forget(seed.Key())
			}
		}
		_ = s.e.Store.Unsee(keys)
		if ent, err := s.e.Store.UpsertEntity(seed.Type, seed.Key(), time.Now().UTC()); err == nil {
			_ = s.e.Store.DropObservations(ent.ID, names)
		}
		delete(s.seen, seedKey(seed))
		s.add(seed, 0, true)
	}
}

// lend hands a worker the next task it may run: one that contacts
// targets, is not Local, and is not a batch.
func (s *scheduler) lend(ctx context.Context, c claim) {
	if ctx.Err() != nil {
		c.reply <- nil
		return
	}
	for p := 0; p < 2; p++ {
		for i := 0; i < len(s.queue[p]); i++ {
			t := s.queue[p][i]
			col, ok := s.e.Cat.Get(t.col)
			if !ok || !s.contacts(t) || catalog.InfoOf(col).Local {
				continue
			}
			if s.ran >= s.b.MaxItems || fetch.Spent() || (p == 0 && s.originRan >= s.b.MaxItems-s.reserve) {
				break
			}
			s.queue[p] = append(s.queue[p][:i:i], s.queue[p][i+1:]...)
			if s.skip(t) {
				s.finish(t)
				s.unpark(t)
				i--
				continue
			}
			s.ran++
			if p == 0 {
				s.originRan++
			}
			s.inflight++
			s.remote++
			s.leaseNo++
			id := fmt.Sprintf("%s-%d", workID(t.col, t.seed), s.leaseNo)
			hold := s.e.Workers.Lease
			if hold <= 0 {
				hold = 15 * time.Minute
			}
			s.leases[id] = lease{t: t, until: time.Now().Add(hold)}
			c.reply <- &Task{ID: id, Item: types.WorkItem{ID: workID(t.col, t.seed), Collector: t.col, Seed: t.seed}}
			return
		}
	}
	c.reply <- nil
}

// giveBack records what a worker sent for a lent task.
func (s *scheduler) giveBack(ctx context.Context, d remoteDone) {
	l, ok := s.leases[d.id]
	if !ok {
		d.ok <- false
		return
	}
	delete(s.leases, d.id)
	s.remote--
	d.ok <- true
	item := types.WorkItem{ID: workID(l.t.col, l.t.seed), Collector: l.t.col, Seed: l.t.seed}
	meta, err := s.e.Record(item, d.out)
	printItem(ctx, item, 0, meta, err)
	s.handle(finished{tasks: []task{l.t}, metas: []types.RunMeta{meta}, errs: []error{err}})
}

// expire queues again the tasks whose worker went silent.
func (s *scheduler) expire() {
	now := time.Now()
	for id, l := range s.leases {
		if now.After(l.until) {
			delete(s.leases, id)
			s.remote--
			s.inflight--
			s.ran--
			s.enqueue(l.t)
		}
	}
}

// release gives up on lent tasks once the run is stopping: they are not
// done, and azhaq resume runs them.
func (s *scheduler) release() {
	for id := range s.leases {
		delete(s.leases, id)
		s.remote--
		s.inflight--
	}
}

func (s *scheduler) dispatch(ctx context.Context) {
	for s.inflight-s.remote < s.b.Parallel {
		if s.startBatch(ctx) {
			continue
		}
		t, ok := s.next()
		if !ok {
			s.startRetry(ctx)
			return
		}
		s.start(ctx, t)
	}
}

// startRetry runs the cheapest task the budget stopped before, when
// nothing else runs.
func (s *scheduler) startRetry(ctx context.Context) {
	for s.inflight-s.remote == 0 && len(s.retry) > 0 && !fetch.Spent() && s.ran < s.b.MaxItems {
		t := s.retry[0]
		s.retry = s.retry[1:]
		if s.skip(t) {
			s.finish(t)
			s.unpark(t)
			continue
		}
		s.ran++
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
				s.finish(t)
				s.unpark(t) // nothing to wait for
				continue
			}
			if fetch.Spent() && s.contacts(t) {
				// It would only be refused: it waits for azhaq resume.
				s.queue[p] = s.queue[p][1:]
				s.held = append(s.held, t)
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
	if f.scheme != "" {
		s.schemeAnswered(f.scheme, f.same)
		return
	}
	if f.partial {
		for i, t := range f.tasks {
			for _, h := range f.metas[i].NextHints {
				s.add(h, t.depth+hintStep(h), true)
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
		switch {
		case meta.Status == types.StatusCapped:
			// Not done, nor what waits on it: azhaq resume runs them,
			// after the work the budget has not stopped yet.
			if s.e.Store != nil {
				s.stopped = append(s.stopped, store.Stopped{ID: workID(t.col, t.seed), Used: meta.Requests})
			}
		case meta.Status == types.StatusCancelled:
			// Not done, nor what waits on it: azhaq resume runs them.
		case meta.Drop:
			s.finish(t)
			s.drop(seedKey(t.seed), t.col)
		default:
			s.finish(t)
			s.unpark(t)
		}
		if err != nil && meta.Status != types.StatusCancelled {
			continue
		}
		for _, h := range meta.NextHints {
			s.add(h, t.depth+hintStep(h), true)
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
	for _, t := range append(s.held, s.retry...) {
		put(t.seed)
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
	for _, held := range s.waiting {
		for _, h := range held {
			put(h.seed)
		}
	}
	return out
}

func printBatch(ctx context.Context, name string, n int, d time.Duration, err error) {
	if isQuiet(ctx) {
		return
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "  ! %s %d seeds: %s\n", name, n, ShortError(err.Error()))
		return
	}
	if p, _ := ctx.Value(progressKey{}).(*progress); p != nil && p.verbose {
		fmt.Fprintf(os.Stderr, "  . %s %d seeds  %s\n", name, n, d.Round(time.Millisecond))
	}
}

// hintStep is how much deeper a hint goes: none for the same target under
// another scheme (types.SameTargetKey), one otherwise.
func hintStep(h types.Seed) int {
	if h.Keys[types.SameTargetKey] != "" {
		return 0
	}
	return 1
}
