package fake

import (
	"context"
	"encoding/json"
	"time"

	"azhaq/internal/catalog"
	"azhaq/internal/normalize"
	"azhaq/internal/types"
)

const Name = "azhaq-fake"

// Collector emits a fixed hostname for a domain. Tests only — not registered in the CLI.
type Collector struct {
	Host string
}

func (c *Collector) Name() string { return Name }

func (c *Collector) Inputs() []types.SeedType { return []types.SeedType{types.TypeDomain} }

func (c *Collector) Outputs() []string { return []string{"hostname"} }

func (c *Collector) Run(_ context.Context, seed types.Seed, emit func(types.Observation) error) (types.RunMeta, error) {
	host := c.Host
	if host == "" {
		host = "www." + normalize.Hostname(seed.Keys["domain"])
	}
	payload, _ := json.Marshal(map[string]string{"fqdn": host})
	err := emit(types.Observation{
		Collector:  Name,
		Source:     "fixture",
		Kind:       "hostname",
		Payload:    payload,
		Confidence: 1,
		ObservedAt: time.Now().UTC(),
	})
	return types.RunMeta{
		Status:    types.StatusOK,
		EmitCount: 1,
		NextHints: []types.Seed{{Type: types.TypeHostname, Keys: map[string]string{"fqdn": host}}},
	}, err
}

func Register(cat *catalog.Catalog, host string) {
	cat.MustRegister(&Collector{Host: host})
}
