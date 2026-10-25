package connector

import (
	"encoding/json"
	"os"

	"github.com/trannghiach/azhaq/internal/normalize"
	"github.com/trannghiach/azhaq/types"
)

// HostIndex is a local stand-in for a paid hostname index.
type HostIndex struct {
	Hosts map[string][]string `json:"hosts"`
}

func LoadHostIndex(path string) (HostIndex, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return HostIndex{}, err
	}
	var idx HostIndex
	if err := json.Unmarshal(raw, &idx); err != nil {
		return HostIndex{}, err
	}
	return idx, nil
}

// FactsFor emits observation + hint lines for each seed domain found in the index.
func (idx HostIndex) FactsFor(seeds []types.Seed, source string) []Fact {
	var out []Fact
	seen := map[string]bool{}
	for _, raw := range seeds {
		s := normalize.Seed(raw)
		domain := domainOf(s)
		if domain == "" {
			continue
		}
		for _, host := range idx.Hosts[domain] {
			host = normalize.Hostname(host)
			if host == "" || seen[host] {
				continue
			}
			seen[host] = true
			payload, _ := json.Marshal(map[string]string{"fqdn": host, "via": "index-fixture"})
			seed := types.Seed{Type: types.TypeHostname, Keys: map[string]string{"fqdn": host}}
			out = append(out, Fact{
				Kind:       "observation",
				EntityType: types.TypeHostname,
				EntityKey:  host,
				Collector:  "index-fixture",
				Source:     source,
				ObsKind:    "hostname",
				Payload:    payload,
			})
			out = append(out, Fact{Kind: "hint", Seed: &seed})
		}
	}
	return out
}

func domainOf(s types.Seed) string {
	switch s.Type {
	case types.TypeDomain:
		return s.Key()
	case types.TypeHostname:
		return normalize.RegistrableDomain(s.Key())
	case types.TypeURL:
		return normalize.RegistrableDomain(normalize.HostFromURL(s.Key()))
	default:
		return ""
	}
}
