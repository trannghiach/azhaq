package portscan

import (
	"context"
	"errors"
	"net"
	"sort"
	"strconv"
	"sync"
	"syscall"
	"time"
)

// UDPTop is the default UDP list: the services that answer a harmless
// request of their own protocol.
const UDPTop = "53,67,69,111,123,137,161,500,514,520,623,1194,1434,1900,3478,4500,5060,5351,5353,5683,10001,11211,27015,47808,51820"

// UDPPorts parses a UDP port spec: a comma-separated list whose parts are
// each a name (top for UDPTop, full), a port or a range, as in Ports:
// "top,5354". "none" alone is no ports; an empty spec is top.
func UDPPorts(spec string) ([]int, error) {
	return parseList(spec, UDPTop, func(w string) (string, bool) {
		switch w {
		case "top", "top-udp":
			return UDPTop, true
		case "full", "all":
			return "1-65535", true
		}
		return "", false
	}, "UDP takes top or full", map[string]string{
		"top-100": "a TCP list", "top100": "a TCP list", "top-1000": "a TCP list", "top1000": "a TCP list",
	})
}

// States of a UDP port. A closed port answers with an ICMP unreachable
// (a connected socket reads it as ECONNREFUSED); an open one may answer
// with data; a silent one is either open and quiet or filtered.
const (
	UDPOpen         = "open"
	UDPOpenFiltered = "open|filtered"
	UDPClosed       = "closed"
)

// UDPPort is one UDP port that was not closed.
type UDPPort struct {
	Port    int    `json:"port"`
	State   string `json:"state"`
	Service string `json:"service,omitempty"`
	Product string `json:"product,omitempty"`
	Version string `json:"version,omitempty"`
	Banner  string `json:"banner,omitempty"`
}

// UDPReport is what one address's UDP scan found.
type UDPReport struct {
	Open         []UDPPort
	OpenFiltered []UDPPort
	// Closed counts the ports the host refused with an ICMP port
	// unreachable; ClosedPorts are those ports, in order.
	Closed      int
	ClosedPorts []int
	// Limited counts the silent ports that were not asked again at the
	// pace of an ICMP rate limit, though other ports of the host were
	// refused: some of them may be closed.
	Limited int
	// Stopped lists, when the scan was stopped (the budget, the kill file,
	// a signal, -timeout), the ports that had not answered or been refused
	// and had payloads left to ask.
	Stopped []UDPStop
}

// UDPStop is a port a stopped scan left with payloads unasked: Asked of the
// Of requests its protocol list has were sent.
type UDPStop struct {
	Port, Asked, Of int
}

// udpPayloads is how many requests a port has in all.
func udpPayloads(port int) int {
	n := 0
	for pass := 0; pass < 8; pass++ {
		if _, ok := udpAsk(port, pass); !ok {
			break
		}
		n++
	}
	return n
}

// ScanUDP sends each port of ip a request of its protocol (where none is
// known: a DNS query, then an SNMP get with the community public, then
// memcached's version, then an empty datagram, as these are what is most
// often moved to an odd port) and sorts the ports by what came back. A port that stayed silent is
// asked again (the second request, or the next of the three) before it is
// called open|filtered. Each datagram counts against the budget, is paced
// and goes in the ledger.
//
// A port is closed only when the kernel read an ICMP port unreachable for
// it; silence is never read as closed. A host that rate-limits those
// replies (Linux sends about one a second) leaves closed ports silent
// too: when some ports were refused and a few silent ones remain, those
// are asked again at the host's pace so each one's reply can arrive, and
// when too many remain for that, they stay open|filtered and Limited says
// so.
func (s *Scanner) ScanUDP(ctx context.Context, host, ip string, ports []int) (UDPReport, error) {
	s.init()
	var r UDPReport
	asked := map[int]int{}
	answered, silent, closed, err := s.udpPass(ctx, host, ip, ports, 0, 0, asked)
	r.Open, r.ClosedPorts = answered, closed
	var spent []int // asked every way their protocol has
	for pass := 1; err == nil && len(silent) > 0 && pass <= 3; pass++ {
		var ask []int
		for _, p := range silent {
			if _, ok := udpAsk(p, pass); ok {
				ask = append(ask, p)
			} else {
				spent = append(spent, p)
			}
		}
		silent = ask
		if len(silent) == 0 {
			break
		}
		var gap time.Duration
		if pass == 1 && len(closed) > 0 && !isLoopback(ip) {
			if len(silent) <= icmpPaceMax {
				gap = icmpGap
			} else {
				r.Limited = len(silent)
			}
		}
		var again []UDPPort
		var more []int
		again, silent, more, err = s.udpPass(ctx, host, ip, silent, pass, gap, asked)
		r.Open = append(r.Open, again...)
		r.ClosedPorts = append(r.ClosedPorts, more...)
	}
	if err != nil {
		r.Stopped = stoppedPorts(ports, r, silent, asked)
	}
	sort.Ints(r.ClosedPorts)
	r.Closed = len(r.ClosedPorts)
	silent = append(silent, spent...)
	for _, p := range silent {
		r.OpenFiltered = append(r.OpenFiltered, UDPPort{Port: p, State: UDPOpenFiltered, Service: udpGuess(p)})
	}
	sort.Slice(r.Open, func(i, j int) bool { return r.Open[i].Port < r.Open[j].Port })
	sort.Slice(r.OpenFiltered, func(i, j int) bool { return r.OpenFiltered[i].Port < r.OpenFiltered[j].Port })
	return r, err
}

var (
	// icmpGap is the time between datagrams to a host whose ICMP replies
	// are rate-limited: Linux's default is one port unreachable a second.
	icmpGap = 1100 * time.Millisecond
	// icmpPaceMax is how many silent ports are asked at that pace (about a
	// minute and a half); more are left open|filtered and counted.
	icmpPaceMax = 80
	// isLoopback: loopback is not rate-limited.
	isLoopback = func(ip string) bool {
		a := net.ParseIP(ip)
		return a != nil && a.IsLoopback()
	}
)

// stoppedPorts are the ports of a stopped scan that neither answered nor
// were refused and still had requests to ask, with what was asked of each.
func stoppedPorts(all []int, r UDPReport, silent []int, asked map[int]int) []UDPStop {
	done := map[int]bool{}
	for _, u := range r.Open {
		done[u.Port] = true
	}
	for _, p := range r.ClosedPorts {
		done[p] = true
	}
	var out []UDPStop
	for _, p := range all {
		if done[p] {
			continue
		}
		if of := udpPayloads(p); asked[p] < of {
			out = append(out, UDPStop{Port: p, Asked: asked[p], Of: of})
		}
	}
	return out
}

func (s *Scanner) udpPass(ctx context.Context, host, ip string, ports []int, pass int, gap time.Duration, asked map[int]int) (open []UDPPort, silent, closed []int, err error) {
	var mu sync.Mutex
	sem := make(chan struct{}, s.udpWorkers)
	var wg sync.WaitGroup
	var stop error
	for i, p := range ports {
		if gap > 0 && i > 0 {
			// A rate-limited host: one datagram at a time, each answered or
			// timed out before the next, so its one reply a second is this port's.
			wg.Wait()
			select {
			case <-ctx.Done():
			case <-time.After(gap):
			}
		}
		if err := s.wait(ctx, ip); err != nil {
			break
		}
		if s.Take != nil {
			if stop = s.Take(); stop != nil {
				break
			}
		}
		select {
		case <-ctx.Done():
		case sem <- struct{}{}:
		}
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		mu.Lock()
		asked[p]++
		mu.Unlock()
		go func(p int) {
			defer wg.Done()
			defer func() { <-sem }()
			u, state := s.udpProbe(ctx, host, ip, p, pass)
			mu.Lock()
			switch state {
			case UDPOpen:
				open = append(open, u)
			case UDPClosed:
				closed = append(closed, p)
			default:
				silent = append(silent, p)
			}
			mu.Unlock()
		}(p)
	}
	wg.Wait()
	if stop != nil {
		return open, silent, closed, stop
	}
	return open, silent, closed, ctx.Err()
}

// udpProbe sends one datagram on a connected socket and waits for the
// answer or the ICMP error the kernel turns into ECONNREFUSED. pass is 0
// for the first ask of a port, up to 3 for the fourth.
func (s *Scanner) udpProbe(ctx context.Context, host, ip string, port, pass int) (UDPPort, string) {
	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	raddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return UDPPort{}, UDPOpenFiltered
	}
	req, _ := udpAsk(port, pass)
	var conn *net.UDPConn
	if req.anySource {
		if conn, err = s.pd.UDPAnySource(ctx, host, raddr); err != nil {
			return UDPPort{}, UDPOpenFiltered
		}
	} else if conn, err = s.pd.UDP(ctx, host, raddr); err != nil {
		return UDPPort{}, UDPOpenFiltered
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(s.Timeout))
	if req.anySource {
		_, err = conn.WriteToUDP(req.payload, raddr)
	} else {
		_, err = conn.Write(req.payload)
	}
	if err != nil {
		return UDPPort{}, udpFailed(err)
	}
	buf := make([]byte, 4096)
	var n int
	for {
		var from *net.UDPAddr
		if req.anySource {
			n, from, err = conn.ReadFromUDP(buf)
			if err == nil && !from.IP.Equal(raddr.IP) {
				continue // not from the host asked
			}
		} else {
			n, err = conn.Read(buf)
		}
		break
	}
	if err != nil {
		return UDPPort{}, udpFailed(err)
	}
	u := UDPPort{Port: port, State: UDPOpen}
	if info, ok := req.parse(buf[:n], req.payload); ok {
		u.Service, u.Product, u.Version, u.Banner = info.service, info.product, info.version, info.banner
	} else {
		// Something answered, but not in the protocol asked for.
		if g := udpGuess(port); g != "" {
			u.Service = g
		}
		u.Banner = printable(buf[:n])
	}
	return u, UDPOpen
}

// udpFailed: nothing listens when the kernel read an ICMP port
// unreachable; any other failure leaves the port undecided.
func udpFailed(err error) string {
	if errors.Is(err, syscall.ECONNREFUSED) {
		return UDPClosed
	}
	return UDPOpenFiltered
}

// udpNames are the services the UDP ports usually carry.
var udpNames = map[int]string{
	53: "dns", 67: "dhcp", 69: "tftp", 111: "rpcbind", 123: "ntp", 137: "netbios-ns", 161: "snmp", 500: "isakmp",
	514: "syslog", 520: "rip", 623: "ipmi", 1194: "openvpn", 1434: "mssql-browser", 1900: "ssdp", 3478: "stun",
	4500: "ipsec-nat-t", 5060: "sip", 5351: "nat-pmp", 5353: "mdns", 5683: "coap", 10001: "ubiquiti-discovery",
	11211: "memcached", 27015: "source-engine", 47808: "bacnet", 51820: "wireguard",
}

// udpGuess names what a silent or unvalidated port usually runs, marked
// as a guess.
func udpGuess(port int) string {
	if n, ok := udpNames[port]; ok {
		return n + "?"
	}
	return ""
}
