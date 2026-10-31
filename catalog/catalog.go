// Package catalog is the registry of collectors and the interfaces a
// collector implements: Collector, and optionally Informer (kind and
// dependencies), Batcher (many seeds per call), Skipper (decline a seed
// at plan time) and Asker (the third parties it would ask).
package catalog

import (
	"context"
	"fmt"
	"sort"
	"sync"

	"github.com/trannghiach/azhaq/types"
)

// Collector is the only plugin shape in Azhaq.
type Collector interface {
	Name() string
	Inputs() []types.SeedType
	Outputs() []string
	Run(ctx context.Context, seed types.Seed, emit func(types.Observation) error) (types.RunMeta, error)
}

// Kind says what a collector contacts. The engine applies -passive and the
// flags for active techniques from it, so collectors need no policy code.
type Kind int

const (
	// Touch collectors send requests to the target itself (HTTP, TLS).
	// Collectors that do not say otherwise are Touch.
	Touch Kind = iota
	// Passive collectors only ask third parties and DNS resolvers.
	Passive
	// Active collectors send traffic nothing on the target linked to:
	// brute force, permutations, port scans. Each runs only when its flag
	// is set and the run has an -allow scope.
	Active
)

// Info describes a collector to the engine.
type Info struct {
	Kind Kind
	// Flag is the CLI flag that enables an Active collector.
	Flag string
	// After names a collector that must finish with the same seed first.
	// When it returns RunMeta.Drop, this collector skips the seed. If that
	// collector is not planned for the seed, this one runs at once.
	After string
	// Local keeps the collector in the process that holds the database
	// (it writes files there, or drives its browser): remote workers never
	// run it.
	Local bool
}

// Claim, when set, records owner as the one collector run that does a
// piece of work once per run (key: what is done, such as a sweep of an
// origin) and returns the owner recorded first. The engine keeps claims
// in the run's workspace, so a resumed run gives the work to the same
// task, which runs it again only if it had not finished.
var Claim func(key, owner string) string

// Informer is optional; a collector without it is Touch.
type Informer interface {
	Info() Info
}

// InfoOf returns a collector's Info, defaulting to Touch.
func InfoOf(c Collector) Info {
	if in, ok := c.(Informer); ok {
		return in.Info()
	}
	return Info{Kind: Touch}
}

// Batcher is optional: a collector that is much cheaper per seed when it
// gets many at once, such as DNS resolution. The engine hands it up to
// BatchSize seeds per call; emit names the seed each observation belongs
// to, and RunBatch returns one RunMeta per seed, in order.
type Batcher interface {
	BatchSize() int
	RunBatch(ctx context.Context, seeds []types.Seed, emit func(types.Seed, types.Observation) error) ([]types.RunMeta, error)
}

type hintKey struct{}

// WithHints returns a context through which a collector can hand over
// seeds before it finishes (see Hint). The engine sets it.
func WithHints(ctx context.Context, fn func([]types.Seed)) context.Context {
	return context.WithValue(ctx, hintKey{}, fn)
}

// Hint passes seeds to the scheduler while the collector is still running,
// so a slow source does not hold back names the fast ones found. It
// reports false when nothing is listening; the collector then returns the
// seeds in RunMeta.NextHints as usual.
func Hint(ctx context.Context, seeds ...types.Seed) bool {
	fn, ok := ctx.Value(hintKey{}).(func([]types.Seed))
	if !ok || fn == nil {
		return false
	}
	if len(seeds) > 0 {
		fn(seeds)
	}
	return true
}

// Skipper is optional. A collector that would return at once for a seed
// (already done this run, wrong kind of URL) says so at plan time, so the
// seed does not spend the run's item budget.
type Skipper interface {
	Skip(seed types.Seed) bool
}

// Forgetter is optional. A collector that remembers the URLs it has
// reported, to report each once, forgets one when the page is asked again
// because the session its first answer came with had ended.
type Forgetter interface {
	Forget(url string)
}

// Asker is optional. A passive collector says, without asking anything,
// which third parties it would ask about a seed, one query each (a source
// may page through its answer), so azhaq plan can count them.
type Asker interface {
	Asks(seed types.Seed) []string
}

// Standing is optional. Its reports stand on their own when the request
// budget stops it midway, each checked before it was made (a path guess
// against the directory's answer to paths that cannot exist): they are
// kept as they come, where other collectors' are held until the task ends.
type Standing interface {
	Standing() bool
}

type Catalog struct {
	mu sync.RWMutex
	by map[string]Collector
}

func New() *Catalog {
	return &Catalog{by: make(map[string]Collector)}
}

func (c *Catalog) Register(col Collector) error {
	if col == nil || col.Name() == "" {
		return fmt.Errorf("catalog: collector needs a name")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.by[col.Name()]; ok {
		return fmt.Errorf("catalog: duplicate %q", col.Name())
	}
	c.by[col.Name()] = col
	return nil
}

func (c *Catalog) MustRegister(col Collector) {
	if err := c.Register(col); err != nil {
		panic(err)
	}
}

func (c *Catalog) Get(name string) (Collector, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	col, ok := c.by[name]
	return col, ok
}

// Where returns every collector that accepts t, sorted by name.
func (c *Catalog) Where(t types.SeedType) []Collector {
	c.mu.RLock()
	defer c.mu.RUnlock()
	var out []Collector
	for _, col := range c.by {
		for _, in := range col.Inputs() {
			if in == t {
				out = append(out, col)
				break
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out
}

func (c *Catalog) Names() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	names := make([]string, 0, len(c.by))
	for n := range c.by {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}
