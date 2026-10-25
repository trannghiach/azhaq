package engine

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/trannghiach/azhaq/catalog"
	"github.com/trannghiach/azhaq/internal/fetch"
	"github.com/trannghiach/azhaq/internal/neterr"
	"github.com/trannghiach/azhaq/internal/normalize"
	"github.com/trannghiach/azhaq/types"
)

// Outcome is what running one work item gave, without a store: what a
// remote worker sends back to the run (see Workers).
type Outcome struct {
	Observations []types.Observation `json:"observations,omitempty"`
	Meta         types.RunMeta       `json:"meta"`
	Error        string              `json:"error,omitempty"`
	Refused      bool                `json:"refused,omitempty"` // a request was refused by the budget
	Requests     int                 `json:"requests"`          // requests to targets it sent
	Cancelled    bool                `json:"cancelled,omitempty"`
}

// Execute runs one work item with the collectors of cat and keeps what it
// reports; nothing is stored. Hints sent while it runs are added to the
// end result.
func Execute(ctx context.Context, cat *catalog.Catalog, item types.WorkItem) Outcome {
	col, ok := cat.Get(item.Collector)
	if !ok {
		return Outcome{Error: "unknown collector " + item.Collector}
	}
	seed := normalize.Seed(item.Seed)
	var mu sync.Mutex
	var out Outcome
	var early []types.Seed
	ctx = catalog.WithHints(ctx, func(seeds []types.Seed) {
		mu.Lock()
		early = append(early, seeds...)
		mu.Unlock()
	})
	ctx, refused, used := fetch.WatchBudget(ctx)
	got, err := col.Run(ctx, seed, func(o types.Observation) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if o.ObservedAt.IsZero() {
			o.ObservedAt = time.Now().UTC()
		}
		if o.Collector == "" {
			o.Collector = col.Name()
		}
		mu.Lock()
		out.Observations = append(out.Observations, o)
		mu.Unlock()
		return nil
	})
	mu.Lock()
	defer mu.Unlock()
	got.NextHints = append(early, got.NextHints...)
	out.Meta = got
	out.Requests = used()
	out.Refused = refused() || errors.Is(err, neterr.ErrBudget)
	out.Cancelled = ctx.Err() != nil
	if err != nil {
		out.Error = err.Error()
	}
	return out
}

// Record stores the outcome of a work item another process ran, as Run
// would have stored it, and returns the item's meta for the scheduler.
func (e *Engine) Record(item types.WorkItem, o Outcome) (types.RunMeta, error) {
	col, ok := e.Cat.Get(item.Collector)
	if !ok {
		return types.RunMeta{ItemID: item.ID, Status: types.StatusError, Error: "unknown collector"}, errors.New("unknown collector " + item.Collector)
	}
	seed := normalize.Seed(item.Seed)
	idKey := workID(col.Name(), seed)
	meta := types.RunMeta{ItemID: item.ID, Status: types.StatusOK}
	fetch.Count(o.Requests) // the run's budget counts every process's requests
	if o.Refused {
		meta.Status, meta.Error, meta.Requests = types.StatusCapped, neterr.ErrBudget.Error(), o.Requests
		e.markCapped()
		return meta, neterr.ErrBudget
	}
	if o.Cancelled {
		meta.Status, meta.Error = types.StatusCancelled, "cancelled"
		return meta, context.Canceled
	}
	if seen, err := e.Store.Seen(idKey); err != nil || seen {
		return meta, err // another process got there first
	}
	now := time.Now().UTC()
	ent, err := e.Store.UpsertEntity(seed.Type, seed.Key(), now)
	if err != nil {
		return types.RunMeta{ItemID: item.ID, Status: types.StatusError, Error: err.Error()}, err
	}
	e.linkSeed(seed, ent, now)
	e.linkInDomain(seed, ent, now)
	for _, ob := range o.Observations {
		if _, err := e.Store.AddObservation(ent.ID, ob); err != nil {
			return types.RunMeta{ItemID: item.ID, Status: types.StatusError, Error: err.Error()}, err
		}
		e.linkFacts(ent, ob, time.Now().UTC())
		meta.EmitCount++
	}
	meta.Drop = o.Meta.Drop
	if o.Error != "" {
		err := errors.New(o.Error)
		meta.Status, meta.Error = types.StatusError, o.Error
		e.noteError(ent.ID, col.Name(), err)
		_ = e.Store.MarkSeen(idKey)
		return meta, err
	}
	if o.Meta.Status != "" {
		meta.Status = o.Meta.Status
	}
	meta.NextHints = append(o.Meta.NextHints, derivedSeeds(seed)...)
	return meta, e.Store.MarkSeen(idKey)
}

// Workers lets other processes take a run's work (azhaq worker): tasks
// that contact targets, apart from batch collectors and Local ones, are
// handed to whichever process claims them, and their outcomes come back
// through Done. The run's own process keeps working too (-parallel).
type Workers struct {
	// Lease is how long a worker may hold a task; after it the task is
	// queued again. Default 15 minutes.
	Lease time.Duration

	claims chan claim
	done   chan remoteDone
	over   chan struct{}
	once   sync.Once
}

// Task is a unit of work as a worker receives it.
type Task struct {
	ID   string         `json:"id"`
	Item types.WorkItem `json:"item"`
}

type claim struct {
	reply chan *Task
}

type remoteDone struct {
	id  string
	out Outcome
	ok  chan bool
}

// NewWorkers prepares a run to take workers.
func NewWorkers() *Workers {
	return &Workers{claims: make(chan claim), done: make(chan remoteDone), over: make(chan struct{})}
}

// ErrRunOver is returned to workers once the run has finished.
var ErrRunOver = errors.New("the run is over")

// Claim waits up to wait for a task. It returns nil with no error when
// none came, and ErrRunOver once the run has finished.
func (w *Workers) Claim(ctx context.Context, wait time.Duration) (*Task, error) {
	c := claim{reply: make(chan *Task, 1)}
	t := time.NewTimer(wait)
	defer t.Stop()
	for {
		select {
		case w.claims <- c:
			select {
			case task := <-c.reply:
				if task != nil {
					return task, nil
				}
			case <-w.over:
				return nil, ErrRunOver
			}
			// Nothing to hand out now: ask again shortly, until wait ends.
			select {
			case <-time.After(250 * time.Millisecond):
				continue
			case <-t.C:
				return nil, nil
			case <-w.over:
				return nil, ErrRunOver
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		case <-w.over:
			return nil, ErrRunOver
		case <-t.C:
			return nil, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// Done hands back the outcome of a claimed task; false means the run no
// longer expected it (its lease ran out, or the run is over).
func (w *Workers) Done(ctx context.Context, id string, out Outcome) bool {
	d := remoteDone{id: id, out: out, ok: make(chan bool, 1)}
	select {
	case w.done <- d:
		return <-d.ok
	case <-w.over:
		return false
	case <-ctx.Done():
		return false
	}
}

func (w *Workers) finish() { w.once.Do(func() { close(w.over) }) }
