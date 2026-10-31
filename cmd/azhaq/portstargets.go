package main

import (
	"encoding/binary"
	"net"
	"net/netip"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/trannghiach/azhaq/internal/collectors/asncol"
	"github.com/trannghiach/azhaq/internal/collectors/portcol"
	"github.com/trannghiach/azhaq/internal/normalize"
)

// portTargets are the targets of a port scan sorted by what they are.
// Addresses and ranges are kept as ranges (a /8 costs no memory) and
// handed to the scan in blocks; names are seeds of their own.
type portTargets struct {
	names  []string       // host names
	asns   []string       // AS numbers, still to be looked up
	v4     []ipRange      // IPv4 addresses and ranges
	v6     []netip.Prefix // IPv6 addresses and ranges
	pinned []netip.Prefix // addresses that were given with a port of their own
	ports  map[string][]int
	bare   map[string]bool // names and addresses given with no port
	n      int             // targets given
}

type ipRange struct{ lo, hi uint32 }

// parseTargets reads what the command line and the lists hold: a host, an
// address, host:port, a URL, a CIDR range or an AS number, several to a
// token when separated by commas.
func parseTargets(tokens []string) (portTargets, error) {
	t := portTargets{ports: map[string][]int{}, bare: map[string]bool{}}
	for _, tok := range tokens {
		for _, part := range strings.Split(tok, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			if err := t.add(part); err != nil {
				return t, err
			}
		}
	}
	return t, nil
}

func (t *portTargets) add(tok string) error {
	t.n++
	if strings.Contains(tok, "://") {
		u, err := url.Parse(tok)
		if err != nil || u.Hostname() == "" {
			return usagef("want a host, address, host:port, URL, range or AS number, got %q", tok)
		}
		tok = u.Hostname()
		if u.Port() != "" {
			tok = net.JoinHostPort(tok, u.Port())
		}
	}
	if asn, ok := asncol.NormalizeASN(tok); ok && strings.HasPrefix(strings.ToUpper(tok), "AS") {
		t.asns = append(t.asns, asn)
		return nil
	}
	if strings.Contains(tok, "/") {
		pf, err := netip.ParsePrefix(tok)
		if err != nil {
			return usagef("want a host, address, host:port, URL, range or AS number, got %q", tok)
		}
		t.addPrefix(pf.Masked())
		return nil
	}
	host, port := tok, ""
	if h, p, err := net.SplitHostPort(tok); err == nil {
		host, port = h, p
	} else {
		host = strings.Trim(tok, "[]")
	}
	var only []int
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return usagef("%q: bad port", tok)
		}
		only = []int{n}
	}
	if a, err := netip.ParseAddr(host); err == nil {
		a = a.Unmap()
		key := a.String()
		if only != nil {
			t.ports[key] = appendPort(t.ports[key], only[0])
			t.pinned = append(t.pinned, netip.PrefixFrom(a, a.BitLen()))
			return nil
		}
		t.bare[key] = true
		t.addPrefix(netip.PrefixFrom(a, a.BitLen()))
		return nil
	}
	host = normalize.Hostname(host)
	if host == "" || strings.ContainsAny(host, " /?#@") {
		return usagef("want a host, address, host:port, URL, range or AS number, got %q", tok)
	}
	if only != nil {
		t.ports[host] = appendPort(t.ports[host], only[0])
	} else {
		t.bare[host] = true
	}
	t.names = append(t.names, host)
	return nil
}

// portsOn is the ports each host given with a port of its own is asked:
// its port, plus def when it was also given bare (or lies in a range that
// was given) or when def is the user's own -p, -tp or -pf (own): those
// apply to every target and a host:port never loses its port. Without
// them a host:port is asked that port only.
func (t *portTargets) portsOn(def []int, own bool) map[string][]int {
	out := make(map[string][]int, len(t.ports))
	for h, ps := range t.ports {
		if own || t.asksBare(h) {
			ps = append(append([]int(nil), def...), ps...)
			sort.Ints(ps)
			ps = slices.Compact(ps)
		}
		out[h] = ps
	}
	return out
}

// pinnedOnly are the addresses given only with a port, each once: one that
// is also given bare or in a range is scanned there, with its ports added.
func (t *portTargets) pinnedOnly() []netip.Prefix {
	var out []netip.Prefix
	seen := map[netip.Prefix]bool{}
	for _, pf := range t.pinned {
		if !seen[pf] && !t.asksBare(pf.Addr().String()) {
			seen[pf] = true
			out = append(out, pf)
		}
	}
	return out
}

// asksBare says host was given with no port, or is an address in a range.
func (t *portTargets) asksBare(host string) bool {
	if t.bare[host] {
		return true
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	if a.Is4() {
		n := binary.BigEndian.Uint32(a.AsSlice())
		for _, r := range t.v4 {
			if n >= r.lo && n <= r.hi {
				return true
			}
		}
		return false
	}
	for _, p := range t.v6 {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func appendPort(ports []int, p int) []int {
	for _, q := range ports {
		if q == p {
			return ports
		}
	}
	return append(ports, p)
}

func (t *portTargets) addPrefix(pf netip.Prefix) {
	if pf.Addr().Is4() {
		lo := binary.BigEndian.Uint32(pf.Addr().AsSlice())
		t.v4 = append(t.v4, ipRange{lo, lo + uint32(uint64(1)<<(32-pf.Bits())-1)})
		return
	}
	t.v6 = append(t.v6, pf)
}

// cover is the IPv4 ranges as the fewest CIDR prefixes that hold exactly
// their addresses, overlaps counted once.
func cover(rs []ipRange) []netip.Prefix {
	sort.Slice(rs, func(i, j int) bool { return rs[i].lo < rs[j].lo })
	var merged []ipRange
	for _, r := range rs {
		if n := len(merged); n > 0 && uint64(r.lo) <= uint64(merged[n-1].hi)+1 {
			merged[n-1].hi = max(merged[n-1].hi, r.hi)
			continue
		}
		merged = append(merged, r)
	}
	var out []netip.Prefix
	for _, r := range merged {
		lo := uint64(r.lo)
		hi := uint64(r.hi)
		for lo <= hi {
			// The largest block that starts at lo and ends by hi.
			size := lo & -lo
			if lo == 0 {
				size = 1 << 32
			}
			for lo+size-1 > hi {
				size >>= 1
			}
			bits := 32
			for s := size; s > 1; s >>= 1 {
				bits--
			}
			var b [4]byte
			binary.BigEndian.PutUint32(b[:], uint32(lo))
			out = append(out, netip.PrefixFrom(netip.AddrFrom4(b), bits))
			lo += size
		}
	}
	return out
}

// listLines are the lines of the run's target list: names, and the blocks
// of every range, which the scan takes one task each. The allow rules are
// the targets as given (a range is one rule, not one per block).
func (t *portTargets) listLines() (lines, allow []string, err error) {
	seen := map[string]bool{}
	for _, n := range t.names {
		if !seen[n] {
			seen[n] = true
			lines = append(lines, n)
			allow = append(allow, n)
		}
	}
	var prefixes []netip.Prefix
	prefixes = append(prefixes, cover(t.v4)...)
	prefixes = append(prefixes, t.v6...)
	prefixes = append(prefixes, t.pinnedOnly()...)
	for _, pf := range prefixes {
		bs, err := portcol.Blocks(pf)
		if err != nil {
			return nil, nil, usagef("%v", err)
		}
		allow = append(allow, pf.String())
		for _, b := range bs {
			if k := b.String(); !seen[k] {
				seen[k] = true
				lines = append(lines, k)
			}
		}
	}
	return lines, allow, nil
}

// addresses is how many addresses the ranges hold, for the summary.
func (t *portTargets) addresses() (n float64) {
	for _, r := range cover(append([]ipRange(nil), t.v4...)) {
		n += float64(uint64(1) << (32 - r.Bits()))
	}
	for _, p := range t.v6 {
		n += float64(uint64(1) << min(63, 128-p.Bits()))
	}
	return n + float64(len(t.pinnedOnly()))
}

// addPrefixString adds a range given as text.
func (t *portTargets) addPrefixString(s string) (netip.Prefix, error) {
	pf, err := netip.ParsePrefix(s)
	if err != nil {
		return pf, err
	}
	t.addPrefix(pf.Masked())
	return pf, nil
}
