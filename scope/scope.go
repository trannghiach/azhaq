// Package scope decides which hosts a run may expand to (-allow, -deny).
package scope

import (
	"strings"

	"github.com/trannghiach/azhaq/internal/normalize"
	"github.com/trannghiach/azhaq/types"
)

// Rules is an optional allow/deny list for active fan-out (hosts and URLs).
// Empty Allow means any host is allowed unless it matches Deny.
type Rules struct {
	Allow []string
	Deny  []string
}

func (r Rules) Empty() bool {
	return len(r.Allow) == 0 && len(r.Deny) == 0
}

func (r Rules) Allows(host string) bool {
	host = normalize.Hostname(host)
	if host == "" {
		return true
	}
	for _, d := range r.Deny {
		if hostMatch(host, d) {
			return false
		}
	}
	if len(r.Allow) == 0 {
		return true
	}
	for _, a := range r.Allow {
		if hostMatch(host, a) {
			return true
		}
	}
	return false
}

func (r Rules) AllowsSeed(s types.Seed) bool {
	if r.Empty() {
		return true
	}
	s = normalize.Seed(s)
	switch s.Type {
	case types.TypeURL:
		return r.Allows(normalize.HostFromURL(s.Key()))
	case types.TypeHostname, types.TypeDomain, types.TypeIPAddress:
		return r.Allows(s.Key())
	default:
		return true
	}
}

func hostMatch(host, rule string) bool {
	rule = normalize.Hostname(rule)
	if rule == "" {
		return false
	}
	if host == rule {
		return true
	}
	return strings.HasSuffix(host, "."+rule)
}
