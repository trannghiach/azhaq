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
	rule = strings.TrimPrefix(strings.TrimPrefix(rule, "="), "*.")
	// A user often copies a URL's authority into -allow (-allow
	// 127.0.0.1:5013): scope is matched by host, so drop the port. Only a
	// real host:port is split — a bare IPv6 address (::1) and a bare host
	// are left as they are.
	if h, p, err := net.SplitHostPort(rule); err == nil && allDigits(p) {
		rule = h
	}
	rule = normalize.Hostname(rule)
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

// allDigits is true for a non-empty string of ASCII digits (a port number).
func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
