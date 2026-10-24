package catalog

import (
	"context"
	"testing"

	"azhaq/internal/types"
)

type stub struct {
	name   string
	inputs []types.SeedType
}

func (s stub) Name() string             { return s.name }
func (s stub) Inputs() []types.SeedType { return s.inputs }
func (s stub) Outputs() []string        { return nil }
func (s stub) Run(context.Context, types.Seed, func(types.Observation) error) (types.RunMeta, error) {
	return types.RunMeta{Status: types.StatusOK}, nil
}

func TestWhere(t *testing.T) {
	c := New()
	c.MustRegister(stub{name: "azhaq-http", inputs: []types.SeedType{types.TypeURL, types.TypeHostname}})
	c.MustRegister(stub{name: "azhaq-ct", inputs: []types.SeedType{types.TypeDomain}})

	got := c.Where(types.TypeURL)
	if len(got) != 1 || got[0].Name() != "azhaq-http" {
		t.Fatalf("URL -> %v", names(got))
	}
	if n := c.Where(types.TypeDomain); len(n) != 1 || n[0].Name() != "azhaq-ct" {
		t.Fatalf("Domain -> %v", names(n))
	}
	if n := c.Where(types.TypeEmail); len(n) != 0 {
		t.Fatalf("Email should be empty, got %v", names(n))
	}
}

func TestDuplicate(t *testing.T) {
	c := New()
	c.MustRegister(stub{name: "x", inputs: []types.SeedType{types.TypeURL}})
	if err := c.Register(stub{name: "x", inputs: []types.SeedType{types.TypeURL}}); err == nil {
		t.Fatal("expected duplicate error")
	}
}

func names(cols []Collector) []string {
	out := make([]string, len(cols))
	for i, c := range cols {
		out[i] = c.Name()
	}
	return out
}
