package portcol

import (
	"context"
	"fmt"

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
	close(s.done)
	return s.rep, s.err
}

// addUDP puts what a UDP scan found in a name's row: the ports by state,
// and what each answer said.
func addUDP(row map[string]any, r portscan.UDPReport, scanned int) {
	open, filtered := []int{}, []int{}
	var services []portscan.UDPPort
	for _, u := range r.Open {
		open = append(open, u.Port)
		services = append(services, u)
	}
	for _, u := range r.OpenFiltered {
		filtered = append(filtered, u.Port)
		services = append(services, u)
	}
	row["udp_scanned"] = scanned
	row["udp_open"] = open
	row["udp_open_filtered"] = filtered
	row["udp_closed"] = r.Closed
	if r.Limited > 0 {
		row["udp_limited"] = r.Limited
	}
	if len(services) > 0 {
		row["udp_services"] = services
	}
}

// udpNotes says what open|filtered means, once, for the summary, and when
// a host that refused some ports may have rate-limited its refusals.
func udpNotes(filtered, limited int) []string {
	var out []string
	if filtered > 0 {
		out = append(out, fmt.Sprintf("udp: %d open|filtered (asked on every way its protocol has, no answer and no ICMP port unreachable): a service that ignores the probe, or a filter; a closed port answers with an ICMP error", filtered))
	}
	if limited > 0 {
		out = append(out, fmt.Sprintf("udp: %d silent ports on a host that refused others were not asked again at its ICMP rate limit (about one reply a second; too many for that): some of them may be closed, so scan fewer ports to be sure", limited))
	}
	return out
}
