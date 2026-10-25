package engine

import (
	"net"
	"sort"

	"github.com/trannghiach/azhaq/internal/normalize"
	"github.com/trannghiach/azhaq/types"
)

// RankEntities puts seed hosts/URLs first, then same-site, then fan-out.
func RankEntities(ents []types.Entity, seeds []types.Seed) []types.Entity {
	hosts, domains, ips := seedScope(seeds)
	out := append([]types.Entity(nil), ents...)
	sort.SliceStable(out, func(i, j int) bool {
		ri, rj := entityRank(out[i], hosts, domains, ips), entityRank(out[j], hosts, domains, ips)
		if ri != rj {
			return ri < rj
		}
		if out[i].Type != out[j].Type {
			return out[i].Type < out[j].Type
		}
		return out[i].Key < out[j].Key
	})
	return out
}

func ScopeLabel(e types.Entity, seeds []types.Seed) string {
	hosts, domains, ips := seedScope(seeds)
	if entityRank(e, hosts, domains, ips) <= 1 {
		return "target"
	}
	return "fanout"
}

// ScopeSeeds expands URL→host→domain and, for a CloudAccount seed, treats
// inventory Domain entities as the target (they would otherwise all be fanout).
func ScopeSeeds(seeds []types.Seed, ents []types.Entity, extra ...[]types.Edge) []types.Seed {
	out := ExpandSeeds(seeds)
	seen := map[string]bool{}
	for _, s := range out {
		seen[seedKey(s)] = true
	}
	add := func(s types.Seed) {
		s = normalize.Seed(s)
		if s.Key() == "" {
			return
		}
		k := seedKey(s)
		if seen[k] {
			return
		}
		seen[k] = true
		out = append(out, s)
	}

	cloud := false
	for _, s := range seeds {
		if s.Type == types.TypeCloudAccount {
			cloud = true
			break
		}
	}
	if cloud {
		for _, e := range ents {
			if e.Type == types.TypeDomain && e.Key != "" {
				add(types.Seed{Type: types.TypeDomain, Keys: map[string]string{"domain": e.Key}})
			}
		}
	}
	var edges []types.Edge
	if len(extra) > 0 {
		edges = extra[0]
	}
	if len(edges) == 0 {
		return out
	}
	byID := map[string]types.Entity{}
	for _, e := range ents {
		byID[e.ID] = e
	}
	targetID := map[string]bool{}
	hosts, domains, ips := seedScope(out)
	for _, e := range ents {
		if entityRank(e, hosts, domains, ips) <= 1 {
			targetID[e.ID] = true
		}
	}
	for _, ed := range edges {
		if ed.Type != "RESOLVES_TO" && ed.Type != "ON_HOST" {
			continue
		}
		if !targetID[ed.From] && !targetID[ed.To] {
			continue
		}
		for _, id := range []string{ed.From, ed.To} {
			e := byID[id]
			if e.Type == types.TypeIPAddress && e.Key != "" {
				add(types.Seed{Type: types.TypeIPAddress, Keys: map[string]string{"ip": e.Key}})
			}
		}
	}
	return out
}

func seedScope(seeds []types.Seed) (hosts, domains, ips map[string]bool) {
	hosts = map[string]bool{}
	domains = map[string]bool{}
	ips = map[string]bool{}
	for _, raw := range seeds {
		s := normalize.Seed(raw)
		switch s.Type {
		case types.TypeURL:
			if h := normalize.HostFromURL(s.Key()); h != "" {
				if ip := net.ParseIP(h); ip != nil {
					ips[ip.String()] = true
				} else {
					hosts[h] = true
					if d := normalize.RegistrableDomain(h); d != "" {
						domains[d] = true
					}
				}
			}
		case types.TypeHostname:
			h := s.Key()
			hosts[h] = true
			if d := normalize.RegistrableDomain(h); d != "" {
				domains[d] = true
			}
		case types.TypeDomain:
			if s.Key() != "" {
				domains[s.Key()] = true
			}
		case types.TypeIPAddress:
			if s.Key() != "" {
				ips[s.Key()] = true
			}
		}
	}
	return hosts, domains, ips
}

func entityRank(e types.Entity, hosts, domains, ips map[string]bool) int {
	switch e.Type {
	case types.TypeURL:
		h := normalize.HostFromURL(e.Key)
		if ip := net.ParseIP(h); ip != nil && ips[ip.String()] {
			return 0
		}
		if hosts[h] {
			return 0
		}
		if d := normalize.RegistrableDomain(h); domains[d] {
			return 1
		}
	case types.TypeHostname:
		if hosts[e.Key] {
			return 0
		}
		if d := normalize.RegistrableDomain(e.Key); domains[d] {
			return 1
		}
	case types.TypeDomain:
		if domains[e.Key] {
			return 1
		}
	case types.TypeIPAddress:
		if ips[e.Key] {
			return 0
		}
	}
	return 2
}
