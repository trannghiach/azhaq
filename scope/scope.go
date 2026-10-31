// Package scope decides which hosts a run may expand to (-allow, -deny).
package scope

import (
	"net"
	"net/netip"
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

	idx *index // from Compile: lookups that do not read every rule
}

func (r Rules) Empty() bool {
	return len(r.Allow) == 0 && len(r.Deny) == 0
}

func (r Rules) Allows(host string) bool {
	host = normalize.Hostname(host)
	if host == "" {
		return true
	}
	if r.idx != nil {
		if r.idx.deny.match(host) {
			return false
		}
		return len(r.Allow) == 0 || r.idx.allow.match(host)
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

// Match is the allow rule that lets host through, as it was written, or ""
// when none does: no rules, a host a deny rule excludes, or a host outside
// the allow list.
func (r Rules) Match(host string) string {
	host = normalize.Hostname(host)
	if host == "" || len(r.Allow) == 0 {
		return ""
	}
	if r.idx != nil && !r.idx.allow.match(host) {
		return ""
	}
	for _, d := range r.Deny {
		if hostMatch(host, d) {
			return ""
		}
	}
	for _, a := range r.Allow {
		if hostMatch(host, a) {
			return a
		}
	}
	return ""
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

// AllowsPrefix says whether any address of pf can pass the rules. A range
// no allow rule touches (a domain never matches an address) or one a deny
// range holds whole has no address to ask, and is not a target.
func (r Rules) AllowsPrefix(pf netip.Prefix) bool {
	pf = pf.Masked()
	if r.Empty() {
		return true
	}
	if pf.IsSingleIP() {
		return r.Allows(pf.Addr().String())
	}
	idx := r.idx
	if idx == nil {
		idx = &index{allow: compileSet(r.Allow), deny: compileSet(r.Deny)}
	}
	for _, n := range idx.deny.nets {
		if o, _ := n.Mask.Size(); n.Contains(pf.Addr().AsSlice()) && o <= pf.Bits() && len(n.IP) == pf.Addr().BitLen()/8 {
			return false
		}
	}
	if len(r.Allow) == 0 {
		return true
	}
	for _, n := range idx.allow.nets {
		if n.Contains(pf.Addr().AsSlice()) {
			return true
		}
		if a, ok := netip.AddrFromSlice(n.IP); ok && pf.Contains(a.Unmap()) {
			return true
		}
	}
	// Addresses written out: the smaller of the range and the rules is walked.
	if size := uint64(1) << min(32, pf.Addr().BitLen()-pf.Bits()); size <= uint64(len(idx.allow.exact)) {
		for a := pf.Addr(); pf.Contains(a); a = a.Next() {
			if idx.allow.exact[a.String()] {
				return true
			}
		}
		return false
	}
	for host := range idx.allow.exact {
		if a, err := netip.ParseAddr(host); err == nil && pf.Contains(a) {
			return true
		}
	}
	return false
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

// Compile is r with its rules indexed: a run over tens of thousands of
// targets, each one an allow rule, asks about each host in constant time
// instead of reading every rule. Rules built by hand work as before.
func (r Rules) Compile() Rules {
	r.idx = &index{allow: compileSet(r.Allow), deny: compileSet(r.Deny)}
	return r
}

type index struct{ allow, deny ruleSet }

// ruleSet holds rules by kind, to answer hostMatch for a host without
// reading them all.
type ruleSet struct {
	exact  map[string]bool // a host or address, as written
	suffix map[string]bool // a domain: it and everything under it
	nets   []*net.IPNet
}

func compileSet(rules []string) ruleSet {
	set := ruleSet{exact: map[string]bool{}, suffix: map[string]bool{}}
	for _, rule := range rules {
		rule = strings.TrimSpace(rule)
		if strings.Contains(rule, "/") {
			if _, n, err := net.ParseCIDR(rule); err == nil {
				set.nets = append(set.nets, n)
			}
			continue
		}
		exact := strings.HasPrefix(rule, "=")
		rule = strings.TrimPrefix(strings.TrimPrefix(rule, "="), "*.")
		if h, p, err := net.SplitHostPort(rule); err == nil && allDigits(p) {
			rule = h
		}
		rule = normalize.Hostname(rule)
		if rule == "" {
			continue
		}
		set.exact[rule] = true
		if !exact && net.ParseIP(rule) == nil {
			set.suffix[rule] = true
		}
	}
	return set
}

func (s ruleSet) match(host string) bool {
	if s.exact[host] {
		return true
	}
	for i := 0; i < len(host); i++ {
		if host[i] == '.' && s.suffix[host[i+1:]] {
			return true
		}
	}
	if len(s.nets) > 0 {
		if ip := net.ParseIP(host); ip != nil {
			for _, n := range s.nets {
				if n.Contains(ip) {
					return true
				}
			}
		}
	}
	return false
}
