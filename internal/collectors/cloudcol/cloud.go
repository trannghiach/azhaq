package cloudcol

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/trannghiach/azhaq/internal/catalog"
	"github.com/trannghiach/azhaq/internal/normalize"
	"github.com/trannghiach/azhaq/internal/types"
)

const Name = "azhaq-cloud"

// inventory is a customer-supplied export (from their CLI/SDK), not a scrape.
type inventory struct {
	Domains []string `json:"domains"`
	Hosts   []string `json:"hosts"`
	URLs    []string `json:"urls"`
}

type Collector struct{}

func New() *Collector { return &Collector{} }

func Register(cat *catalog.Catalog) {
	cat.MustRegister(New())
}

func (c *Collector) Name() string { return Name }

// Info: this collector only asks third parties or DNS resolvers.
func (c *Collector) Info() catalog.Info { return catalog.Info{Kind: catalog.Passive} }

func (c *Collector) Inputs() []types.SeedType { return []types.SeedType{types.TypeCloudAccount} }

func (c *Collector) Outputs() []string { return []string{"domain", "hostname", "url"} }

func (c *Collector) Run(_ context.Context, seed types.Seed, emit func(types.Observation) error) (types.RunMeta, error) {
	path := seed.Keys["path"]
	if path == "" {
		return types.RunMeta{Status: types.StatusOK}, nil
	}
	if strings.Contains(path, "://") {
		return types.RunMeta{Status: types.StatusError, Error: "cloud inventory must be a local file"}, fmt.Errorf("remote inventory path")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		err = fmt.Errorf("%w (need a local JSON file, e.g. fixtures/inventory.json)", err)
		return types.RunMeta{Status: types.StatusError, Error: err.Error()}, err
	}
	var inv inventory
	if err := json.Unmarshal(raw, &inv); err != nil {
		return types.RunMeta{Status: types.StatusError, Error: err.Error()}, err
	}
	var rawObj map[string]json.RawMessage
	_ = json.Unmarshal(raw, &rawObj)
	known := 0
	for _, k := range []string{"domains", "hosts", "urls"} {
		if _, ok := rawObj[k]; ok {
			known++
		}
	}
	var extraKeys []string
	for k := range rawObj {
		switch k {
		case "domains", "hosts", "urls":
		default:
			extraKeys = append(extraKeys, k)
		}
	}

	id := seed.Key()
	if id == "" {
		id = filepath.Base(path)
	}
	extracted := len(inv.Domains) + len(inv.Hosts) + len(inv.URLs)
	row := map[string]any{
		"id":        id,
		"path":      path,
		"domains":   len(inv.Domains),
		"hosts":     len(inv.Hosts),
		"urls":      len(inv.URLs),
		"extracted": extracted,
	}
	if known == 0 {
		row["warning"] = "no domains/hosts/urls keys (need {\"domains\":[],\"hosts\":[],\"urls\":[]})"
	} else if extracted == 0 {
		row["warning"] = "inventory extracted 0 assets"
	}
	if len(extraKeys) > 0 && known == 0 {
		sort.Strings(extraKeys)
		row["keys"] = extraKeys
	}
	summary, _ := json.Marshal(row)
	if err := emit(types.Observation{
		Collector:  Name,
		Source:     path,
		Kind:       "cloud",
		Payload:    summary,
		Confidence: 0.9,
		ObservedAt: time.Now().UTC(),
	}); err != nil {
		return types.RunMeta{}, err
	}
	meta := types.RunMeta{Status: types.StatusOK, EmitCount: 1}

	for _, d := range inv.Domains {
		d = normalize.Hostname(d)
		if d == "" {
			continue
		}
		p, _ := json.Marshal(map[string]any{"domain": d, "via": "cloud"})
		if err := emit(types.Observation{
			Collector: Name, Source: path, Kind: "domain", Payload: p,
			Confidence: 0.9, ObservedAt: time.Now().UTC(),
		}); err != nil {
			return meta, err
		}
		meta.EmitCount++
		meta.NextHints = append(meta.NextHints, types.Seed{
			Type: types.TypeDomain, Keys: map[string]string{"domain": d},
		})
	}
	for _, h := range inv.Hosts {
		h = normalize.Hostname(h)
		if h == "" {
			continue
		}
		p, _ := json.Marshal(map[string]any{"fqdn": h, "via": "cloud"})
		if err := emit(types.Observation{
			Collector: Name, Source: path, Kind: "hostname", Payload: p,
			Confidence: 0.9, ObservedAt: time.Now().UTC(),
		}); err != nil {
			return meta, err
		}
		meta.EmitCount++
		meta.NextHints = append(meta.NextHints, types.Seed{
			Type: types.TypeHostname, Keys: map[string]string{"fqdn": h},
		})
	}
	for _, u := range inv.URLs {
		u, err := normalize.URL(u)
		if err != nil {
			continue
		}
		p, _ := json.Marshal(map[string]any{"url": u, "via": "cloud"})
		if err := emit(types.Observation{
			Collector: Name, Source: path, Kind: "url", Payload: p,
			Confidence: 0.9, ObservedAt: time.Now().UTC(),
		}); err != nil {
			return meta, err
		}
		meta.EmitCount++
		meta.NextHints = append(meta.NextHints, types.Seed{
			Type: types.TypeURL, Keys: map[string]string{"url": u},
		})
	}
	return meta, nil
}
