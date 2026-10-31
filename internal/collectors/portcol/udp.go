package portcol

import (
	"context"
	"fmt"
	"net"
	"slices"
	"sort"
	"strconv"
	"sync"

	"github.com/trannghiach/azhaq/internal/portscan"
)

// udpScan is one address's UDP scan, shared by the names that point to it.
type udpScan struct {
	done chan struct{}
	rep  portscan.UDPReport
	err  error
}

// scanUDPOnce scans an address's UDP ports once, however many names
// point to it.
func (c *Collector) scanUDPOnce(ctx context.Context, host, ip string) (portscan.UDPReport, error) {
	c.mu.Lock()
	if c.udpByIP == nil {
		c.udpByIP = map[string]*udpScan{}
	}
	s, ok := c.udpByIP[ip]
	if !ok {
		s = &udpScan{done: make(chan struct{})}
		c.udpByIP[ip] = s
	}
	c.mu.Unlock()
	if ok {
		select {
		case <-s.done:
			return s.rep, s.err
		case <-ctx.Done():
			return portscan.UDPReport{}, ctx.Err()
		}
	}
	s.rep, s.err = c.Scanner.ScanUDP(ctx, host, ip, c.UDPPorts)
	if s.err != nil {
		recordStops(ip, s.rep.Stopped)
	}
	close(s.done)
	return s.rep, s.err
}

var stops struct {
	sync.Mutex
	byIP map[string][]portscan.UDPStop
}

// recordStops keeps the UDP ports a stopped scan left unfinished: the
// stopped run cannot write a row, so the summary reads them from here.
func recordStops(ip string, list []portscan.UDPStop) {
	if len(list) == 0 {
		return
	}
	stops.Lock()
	defer stops.Unlock()
	if stops.byIP == nil {
		stops.byIP = map[string][]portscan.UDPStop{}
	}
	stops.byIP[ip] = list
}

// StoppedNotes says, for each address whose UDP scan a limit, a signal or
// -timeout stopped, how many of its payloads were asked of each port that
// has not answered. It clears what it read.
func StoppedNotes() []string {
	stops.Lock()
	by := stops.byIP
	stops.byIP = nil
	stops.Unlock()
	ips := make([]string, 0, len(by))
	for ip := range by {
		ips = append(ips, ip)
	}
	sort.Strings(ips)
	var out []string
	for _, ip := range ips {
		var named []string
		untouched := 0
		for _, st := range by[ip] {
			if st.Asked == 0 {
				untouched++
				continue
			}
			named = append(named, fmt.Sprintf("%s/udp: %d of %d payloads asked before the run stopped; no answer yet", net.JoinHostPort(ip, strconv.Itoa(st.Port)), st.Asked, st.Of))
		}
		if len(named) > 3 {
			out = append(out, named[:3]...)
			out = append(out, fmt.Sprintf("%s: %d more UDP ports asked only part of their payloads", ip, len(named)-3))
		} else {
			out = append(out, named...)
		}
		if untouched > 0 {
			out = append(out, fmt.Sprintf("%s: %d UDP %s not asked before the run stopped", ip, untouched, plural(untouched, "port")))
		}
	}
	return out
}

// maxClosedListed: a row names this many of an address's closed UDP ports,
// the count says the rest (a full scan of a host that refuses them all
// would be 65535 numbers).
const maxClosedListed = 16

// addUDP puts what a UDP scan found in a name's row: the ports by state,
// and what each answer said. Silent ports are listed in udp_services (the
// rows a command prints) up to maxListed per address; past it the row's
// udp_open_filtered still has them all, and udp_unlisted says so.
func addUDP(row map[string]any, r portscan.UDPReport, scanned int) {
	open, filtered := []int{}, []int{}
	var services []portscan.UDPPort
	for _, u := range r.Open {
		open = append(open, u.Port)
		services = append(services, u)
	}
	for _, u := range r.OpenFiltered {
		filtered = append(filtered, u.Port)
	}
	if len(r.OpenFiltered) <= maxListed {
		services = append(services, r.OpenFiltered...)
	} else {
		row["udp_unlisted"] = len(r.OpenFiltered)
	}
	row["udp_scanned"] = scanned
	row["udp_open"] = open
	row["udp_open_filtered"] = filtered
	row["udp_closed"] = r.Closed
	if len(r.ClosedPorts) > 0 {
		row["udp_closed_ports"] = r.ClosedPorts[:min(len(r.ClosedPorts), maxClosedListed)]
	}
	if r.Limited > 0 {
		row["udp_limited"] = r.Limited
	}
	if len(services) > 0 {
		row["udp_services"] = services
	}
}

// udpSummary is what the rows of a run say of UDP ports that stayed
// silent, read back for the summary.
type udpSummary struct {
	ports     map[string]map[int]bool // address: open|filtered ports (two rows of an address count once)
	unlisted  []string                // addresses with more silent ports than a row lists
	silentN   int                     // silent ports of range addresses that answered nothing, not listed
	silentIPs int                     // those addresses
	limited   int
	closed    map[string]closedUDP // address: the ports it refused
	// Addresses of the ranges that showed nothing else but refused UDP ports.
	closedN, closedIPs int
}

// closedUDP is how many UDP ports an address refused and the first of them.
type closedUDP struct {
	n     int
	ports []int
}

func (u *udpSummary) add(ip string, filtered []int, unlisted, limited int) {
	if len(filtered) > 0 {
		if u.ports == nil {
			u.ports = map[string]map[int]bool{}
		}
		if u.ports[ip] == nil {
			u.ports[ip] = map[int]bool{}
		}
		for _, p := range filtered {
			u.ports[ip][p] = true
		}
	}
	if unlisted > 0 && !slices.Contains(u.unlisted, ip) {
		u.unlisted = append(u.unlisted, ip)
	}
	u.limited += limited
}

// addClosed notes the UDP ports an address refused (an ICMP port
// unreachable); two rows of an address, one for each name, count once.
func (u *udpSummary) addClosed(ip string, n int, ports []int) {
	if n <= 0 {
		return
	}
	if u.closed == nil {
		u.closed = map[string]closedUDP{}
	}
	if c := u.closed[ip]; n > c.n {
		u.closed[ip] = closedUDP{n, ports}
	}
}

// notes say what open|filtered means, once, how many ports are rows, and
// when a host that refused some ports may have rate-limited its refusals.
func (u *udpSummary) notes() []string {
	var out []string
	rows := 0
	for ip, ps := range u.ports {
		if !slices.Contains(u.unlisted, ip) {
			rows += len(ps)
		}
	}
	if rows > 0 {
		out = append(out, fmt.Sprintf("%d UDP %s open|filtered: no reply and no ICMP port unreachable after every request its protocol has (a silent service or a firewall); a closed port answers with an ICMP error", rows, plural(rows, "port")))
	}
	if n, list := u.closedList(); n > 0 {
		out = append(out, fmt.Sprintf("%d UDP %s closed (ICMP port unreachable): %s", n, plural(n, "port"), list))
	}
	if u.closedIPs > 0 {
		out = append(out, fmt.Sprintf("%d addresses of the ranges refused UDP ports (ICMP port unreachable, %d ports closed in all) and showed nothing else: they are not listed", u.closedIPs, u.closedN))
	}
	if len(u.unlisted) > 0 {
		sort.Strings(u.unlisted)
		var n int
		for _, ip := range u.unlisted {
			n += len(u.ports[ip])
		}
		out = append(out, fmt.Sprintf("%d UDP ports open|filtered on %s are not listed one by one (more than %d on an address: it ignores UDP, or a filter drops it); the workspace row keeps them in udp_open_filtered", n, listOf(u.unlisted, 3), maxListed))
	}
	if u.silentIPs > 0 {
		out = append(out, fmt.Sprintf("%d addresses of the ranges answered no UDP port (no reply, no ICMP port unreachable, %d ports open|filtered in all) and are not listed: a host that is down or drops UDP reads this way; ask one address on its own to list its ports", u.silentIPs, u.silentN))
	}
	if u.limited > 0 {
		out = append(out, fmt.Sprintf("udp: %d silent ports on a host that refused others were not asked again at its ICMP rate limit (about one reply a second; too many for that): some of them may be closed, so scan fewer ports to be sure", u.limited))
	}
	return out
}

// closedList is how many ports were refused, and a few as address:port.
func (u *udpSummary) closedList() (int, string) {
	ips := make([]string, 0, len(u.closed))
	for ip := range u.closed {
		ips = append(ips, ip)
	}
	sort.Strings(ips)
	var all []string
	total := 0
	for _, ip := range ips {
		c := u.closed[ip]
		total += c.n
		for _, p := range c.ports {
			all = append(all, net.JoinHostPort(ip, strconv.Itoa(p)))
		}
	}
	return total, listOfN(all, 3, total)
}

func plural(n int, word string) string {
	if n == 1 {
		return word
	}
	return word + "s"
}
