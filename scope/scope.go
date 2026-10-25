// Package scope decides which hosts a run may expand to (-allow, -deny).
package scope

import (
	"net"
	"strings"

	"github.com/trannghiach/azhaq/internal/normalize"
	"github.com/trannghiach/azhaq/types"
)

// Rules is an optional allow/deny list for active fan-out (hosts and URLs).
// Empty Allow means any host is allowed unless it matches Deny. An entry is
//
//	example.com      the domain and its subdomains
//	*.example.com    the same (bug bounty scopes write wildcards this way)
//	=api.example.com that host only
//	10.0.0.0/8       addresses in the range; 192.0.2.7 is one address
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
	rule = strings.TrimSpace(rule)
	if strings.Contains(rule, "/") {
		_, n, err := net.ParseCIDR(rule)
		ip := net.ParseIP(host)
		return err == nil && ip != nil && n.Contains(ip)
	}
	exact := strings.HasPrefix(rule, "=")
	rule = normalize.Hostname(strings.TrimPrefix(strings.TrimPrefix(rule, "="), "*."))
	if rule == "" {
		return false
	}
	if host == rule {
		return true
	}
	if exact || net.ParseIP(rule) != nil {
		return false
	}
	return strings.HasSuffix(host, "."+rule)
}
