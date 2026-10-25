package catalog

import (
	"context"
	"fmt"
	"sort"
	"sync"

	"github.com/trannghiach/azhaq/internal/types"
)

// Collector is the only plugin shape in Azhaq.
type Collector interface {
	Name() string
	Inputs() []types.SeedType
	Outputs() []string
	Run(ctx context.Context, seed types.Seed, emit func(types.Observation) error) (types.RunMeta, error)
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
