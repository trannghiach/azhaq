// Package portcol scans the TCP ports of hosts in scope (-ports, active)
// and hands the ones that may serve HTTP to the HTTP collector.
package portcol

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/trannghiach/azhaq/catalog"
	"github.com/trannghiach/azhaq/internal/collectors/httpcol"
	"github.com/trannghiach/azhaq/internal/dnsr"
	"github.com/trannghiach/azhaq/internal/fetch"
	"github.com/trannghiach/azhaq/internal/fingerprint"
	"github.com/trannghiach/azhaq/internal/neterr"
	"github.com/trannghiach/azhaq/internal/normalize"
	"github.com/trannghiach/azhaq/internal/portscan"
	"github.com/trannghiach/azhaq/types"
)

const Name = "azhaq-ports"

// cdnPorts are the only ports scanned on a CDN or WAF address: the edge
// answers for thousands of customers, so its other ports say nothing about
// the target.
var cdnPorts = []int{80, 443, 8080, 8443}

type Collector struct {
	Pool    *dnsr.Pool
	Scanner *portscan.Scanner
	Ports   []int
	// UDPPorts are the UDP ports to ask on each address; none, no UDP scan.
	UDPPorts []int
	// IPv6 says whether this machine can reach IPv6 addresses; nil is
	// fetch.IPv6Routable.
	IPv6 func() bool

	mu    sync.Mutex
	byIP  map[string]*scan // one scan per address, however many names point to it
	maxIP int              // addresses scanned per name

	udpByIP map[string]*udpScan
}

type scan struct {
	done     chan struct{}
	host     string // the name the services were asked under
	open     []portscan.Open
	silent   []int
	unprobed int
	err      error
}

func New(pool *dnsr.Pool, ports []int, rate float64) *Collector {
	return &Collector{Pool: pool, Ports: ports, Scanner: &portscan.Scanner{Rate: rate, Take: fetch.Take, UserAgent: fetch.UserAgent},
		byIP: map[string]*scan{}, maxIP: 2}
}

func (c *Collector) routable() bool {
	if c.IPv6 != nil {
		return c.IPv6()
	}
	return fetch.IPv6Routable()
}

func (c *Collector) Name() string { return Name }

// Info: connects to every listed port of the target; needs -ports and
// -allow, and waits for DNS so dead names are not scanned.
func (c *Collector) Info() catalog.Info {
	return catalog.Info{Kind: catalog.Active, Flag: "ports", After: "azhaq-dns"}
}

func (c *Collector) Inputs() []types.SeedType {
	return []types.SeedType{types.TypeHostname, types.TypeIPAddress}
}

func (c *Collector) Outputs() []string { return []string{"ports"} }

func (c *Collector) Run(ctx context.Context, seed types.Seed, emit func(types.Observation) error) (types.RunMeta, error) {
	host := normalize.Hostname(seed.Key())
	var ips []string
	// A name behind a CDN or WAF answers on the provider's shared edges:
	// only their web ports are the target's. Any of its addresses or its
	// CNAME says so for all of them (CloudFront's IPv6 ranges read as
	// plain AWS).
	edgeName := ""
	var unrouted []string // IPv6 addresses this machine cannot reach
	if ip := net.ParseIP(host); ip != nil {
		ips = []string{ip.String()}
	} else if c.Pool != nil {
		answer := c.Pool.ResolveBoth(ctx, host)
		if name, kind := fingerprint.NetworkByName(answer.CNAME...); name != "" && kind != "cloud" {
			edgeName = name
		}
		// Both families: a service may listen on one only (naabu -iv 4,6).
		// IPv6 only where this machine can reach it; the summary says
		// when it cannot.
		v4, v6 := 0, 0
		for _, ip := range answer.IPs() {
			switch {
			case net.ParseIP(ip).To4() != nil:
				if v4 < c.maxIP {
					v4++
					ips = append(ips, ip)
				}
			case !c.routable():
				unrouted = append(unrouted, ip)
			case v6 < c.maxIP:
				v6++
				ips = append(ips, ip)
			}
		}
	}
	if len(ips) == 0 && len(unrouted) > 0 {
		// An IPv6-only name: nothing scanned, and the row says why.
		raw, _ := json.Marshal(map[string]any{"host": host, "scanned": 0, "open": []int{}, unroutedKey: unrouted})
		err := emit(types.Observation{Collector: Name, Source: "tcp", Kind: "ports", Payload: raw, Confidence: 0.95, ObservedAt: time.Now().UTC()})
		return types.RunMeta{Status: types.StatusOK, EmitCount: 1}, err
	}
	for _, ip := range ips {
		if name, kind := fingerprint.Network(net.ParseIP(ip)); name != "" && kind != "cloud" && edgeName == "" {
			edgeName = name
		}
	}
	meta := types.RunMeta{Status: types.StatusOK}
	for _, ip := range ips {
		ports := c.Ports
		name := edgeName
		edge := name != ""
		if edge {
			ports = cdnPorts
		}
		open, silent, unprobed, err := c.scanOnce(ctx, host, ip, ports)
		if err != nil && ctx.Err() != nil {
			return types.RunMeta{Status: types.StatusCancelled}, err
		}
		if errors.Is(err, neterr.ErrBudget) {
			// Each connect counts against -max-requests: azhaq resume
			// scans the address again.
			c.forget(ip)
			return types.RunMeta{Status: types.StatusCapped}, err
		}
		var udp portscan.UDPReport
		if len(c.UDPPorts) > 0 && !edge {
			var uerr error
			if udp, uerr = c.scanUDPOnce(ctx, host, ip); uerr != nil {
				if ctx.Err() != nil {
					return types.RunMeta{Status: types.StatusCancelled}, uerr
				}
				if errors.Is(uerr, neterr.ErrBudget) {
					c.forget(ip)
					return types.RunMeta{Status: types.StatusCapped}, uerr
				}
			}
		}
		row := map[string]any{"host": host, "ip": ip, "scanned": len(ports), "open": portsOf(open)}
		if len(c.UDPPorts) > 0 && !edge {
			addUDP(row, udp, len(c.UDPPorts))
		}
		if len(open) > 0 {
			row["services"] = open
		}
		if unprobed > 0 {
			row["unprobed"] = unprobed
		}
		if len(silent) > 0 {
			row["filtered"] = len(silent)
			if len(silent) <= maxListed {
				row["filtered_ports"] = silent
			}
		}
		if edge {
			row["cdn"] = name
			row["note"] = "CDN or WAF address: web ports only"
		}
		if len(unrouted) > 0 {
			row[unroutedKey] = unrouted
		}
		raw, _ := json.Marshal(row)
		if err := emit(types.Observation{
			Collector: Name, Source: "tcp", Kind: "ports", Payload: raw, Confidence: 0.95, ObservedAt: time.Now().UTC(),
		}); err != nil {
			return meta, err
		}
		meta.EmitCount++
		for _, o := range open {
			if !o.Web() || o.Port == 80 || o.Port == 443 {
				continue // the HTTP collector tries 80 and 443 on every name
			}
			hp := net.JoinHostPort(host, strconv.Itoa(o.Port))
			keys := map[string]string{"url": "https://" + hp + "/", httpcol.FallbackKey: "http"}
			switch o.Service {
			case "http", "https": // the probe found out which
				keys = map[string]string{"url": o.Service + "://" + hp + "/"}
			}
			meta.NextHints = append(meta.NextHints, types.Seed{Type: types.TypeURL, Keys: keys})
		}
	}
	return meta, nil
}

// unroutedKey lists, in a name's rows, its IPv6 addresses this machine
// has no route to, which were not scanned.
const unroutedKey = "ipv6_not_scanned"

// Notes are what a run's port scans leave for its summary: how many
// names had IPv6 addresses this machine could not scan.
func Notes(obs []types.StoredObservation) []string {
	names := map[string]bool{}
	var silent []string // address: ports, where a few ports answered neither way, twice
	udpFiltered, udpLimited := 0, 0
	var unprobed []string // address: open ports left without the protocol probes
	for _, o := range obs {
		if o.Collector != Name {
			continue
		}
		var p struct {
			Host     string   `json:"host"`
			IP       string   `json:"ip"`
			Unrouted []string `json:"ipv6_not_scanned"`
			Filtered []int    `json:"filtered_ports"`
			UDPFilt  []int    `json:"udp_open_filtered"`
			UDPLimit int      `json:"udp_limited"`
			Unprobed int      `json:"unprobed"`
		}
		if json.Unmarshal(o.Payload, &p) != nil {
			continue
		}
		if len(p.Unrouted) > 0 {
			names[p.Host] = true
		}
		udpFiltered += len(p.UDPFilt)
		udpLimited += p.UDPLimit
		if p.Unprobed > 0 {
			unprobed = append(unprobed, fmt.Sprintf("%s: %d", p.IP, p.Unprobed))
		}
		if len(p.Filtered) > 0 {
			where := p.Host
			if p.IP != "" && p.IP != p.Host {
				where += " (" + p.IP + ")"
			}
			silent = append(silent, where+" "+portList(p.Filtered, 8))
		}
	}
	var out []string
	switch len(names) {
	case 0:
	case 1:
		out = append(out, "IPv6 addresses of 1 name not scanned: no IPv6 route from this machine")
	default:
		out = append(out, fmt.Sprintf("IPv6 addresses of %d names not scanned: no IPv6 route from this machine", len(names)))
	}
	if len(silent) > 0 {
		sort.Strings(silent)
		more := ""
		if len(silent) > 3 {
			more = fmt.Sprintf(" and %d more addresses", len(silent)-3)
			silent = silent[:3]
		}
		out = append(out, fmt.Sprintf("ports that neither accepted nor refused a connect, asked twice: %s%s; filtered, or the host drops connects: scan them again to be sure (azhaq show -db FILE HOST lists them all)",
			strings.Join(silent, "; "), more))
	}
	if len(unprobed) > 0 {
		sort.Strings(unprobed)
		out = append(out, "open ports whose protocol was not probed, after several others on the same address could not be named (a firewall or tarpit that accepts every connect): "+strings.Join(unprobed, "; "))
	}
	return append(out, udpNotes(udpFiltered, udpLimited)...)
}

// portList is "80, 443" with at most n ports, then how many more.
func portList(ports []int, n int) string {
	var parts []string
	for i, p := range ports {
		if i == n {
			parts = append(parts, fmt.Sprintf("+%d more", len(ports)-n))
			break
		}
		parts = append(parts, strconv.Itoa(p))
	}
	if len(ports) == 1 {
		return "port " + parts[0]
	}
	return "ports " + strings.Join(parts, ", ")
}

// maxListed: a row lists the ports that did not answer when there are
// no more than this; past it, a firewall drops them and the count says
// enough.
const maxListed = 64

func (c *Collector) scanOnce(ctx context.Context, host, ip string, ports []int) ([]portscan.Open, []int, int, error) {
	c.mu.Lock()
	s, ok := c.byIP[ip]
	if !ok {
		s = &scan{done: make(chan struct{}), host: host}
		c.byIP[ip] = s
	}
	c.mu.Unlock()
	if ok {
		select {
		case <-s.done:
		case <-ctx.Done():
			return nil, nil, 0, ctx.Err()
		}
		if s.err != nil || s.host == host {
			return s.open, s.silent, s.unprobed, s.err
		}
		open, err := c.askAgain(ctx, host, ip, s.open)
		return open, s.silent, s.unprobed, err
	}
	r, err := c.Scanner.ScanEach(ctx, host, ip, ports)
	s.open, s.silent, s.unprobed, s.err = r.Open, r.Silent, r.Unprobed, err
	close(s.done)
	return s.open, s.silent, s.unprobed, s.err
}

// askAgain is an address's open ports for another name on it: the
// connects are not repeated, but a web or TLS port is asked again under
// this name (its Host header and SNI), whose site and certificate may be
// its own.
func (c *Collector) askAgain(ctx context.Context, host, ip string, open []portscan.Open) ([]portscan.Open, error) {
	var web []int
	for _, o := range open {
		switch strings.TrimSuffix(o.Service, "?") {
		case "http", "https", "tls":
			web = append(web, o.Port)
		}
	}
	out := append([]portscan.Open(nil), open...)
	if len(web) == 0 {
		return out, nil
	}
	again, err := c.Scanner.Scan(ctx, host, ip, web)
	byPort := map[int]portscan.Open{}
	for _, o := range again {
		byPort[o.Port] = o
	}
	for i, o := range out {
		if n, ok := byPort[o.Port]; ok {
			out[i] = n
		}
	}
	return out, err
}

// forget drops an address's scan so a resumed run scans it again.
func (c *Collector) forget(ip string) {
	c.mu.Lock()
	delete(c.byIP, ip)
	delete(c.udpByIP, ip)
	c.mu.Unlock()
}

func portsOf(open []portscan.Open) []int {
	out := make([]int, 0, len(open))
	for _, o := range open {
		out = append(out, o.Port)
	}
	return out
}
