// Package portcol scans the TCP ports of hosts in scope (-ports, active)
// and hands the ones that may serve HTTP to the HTTP collector.
package portcol

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"slices"
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

// cdnPorts are the only ports scanned on a CDN or WAF address, unless the
// scan is told to scan them all: the edge answers for thousands of
// customers, so its other ports say nothing about the target.
var cdnPorts = []int{80, 443, 8080, 8443}

// Discovery is how a scan tells which addresses are up before it asks
// their ports.
type Discovery int

const (
	// DiscoverOff scans every address, as naabu does.
	DiscoverOff Discovery = iota
	// DiscoverFirst scans only the addresses that answered a connect to
	// 80 or 443 (-wn).
	DiscoverFirst
	// DiscoverOnly lists those addresses and scans nothing (-sn).
	DiscoverOnly
)

type Collector struct {
	// Prior holds, by address, what a scan a limit stopped found and asked.
	Prior   map[string]Prior
	Pool    *dnsr.Pool
	Scanner *portscan.Scanner
	Ports   []int
	// UDPPorts are the UDP ports to ask on each address; none, no UDP scan.
	UDPPorts []int
	// IPv6 says whether this machine can reach IPv6 addresses; nil is
	// fetch.IPv6Routable.
	IPv6 func() bool
	// CDNFull scans CDN and WAF addresses in full, not just their web ports.
	CDNFull bool
	// Discover is how addresses are told up before they are scanned.
	Discover Discovery
	// IPv4Only and IPv6Only keep a name to one family; AllIPs scans every
	// address of a name, not the first two of each family.
	IPv4Only, IPv6Only, AllIPs bool
	// PortsFor gives an address or name ports of its own (host:port given
	// without -p); its key is the host as written, lower case.
	PortsFor map[string][]int
	// Workers is how many addresses of a range are asked at once; 0 is 64.
	Workers int

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
	unprobed int  // open ports left without the protocol probes
	up       bool // answered discovery, or discovery was off
	capped   bool // the threshold of open ports stopped it
	asked    int  // ports asked, in the scanner's order, before it stopped
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
	return []types.SeedType{types.TypeHostname, types.TypeIPAddress, types.TypePrefix}
}

func (c *Collector) Outputs() []string { return []string{"ports"} }

func (c *Collector) portsOf(host string) []int {
	if p, ok := c.PortsFor[host]; ok {
		return p
	}
	return c.Ports
}

func (c *Collector) Run(ctx context.Context, seed types.Seed, emit func(types.Observation) error) (types.RunMeta, error) {
	if seed.Type == types.TypePrefix {
		return c.runPrefix(ctx, seed, emit)
	}
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
		var answer dnsr.Answer
		if c.IPv4Only {
			answer = c.Pool.Resolve(ctx, host)
		} else {
			answer = c.Pool.ResolveBoth(ctx, host)
		}
		if name, kind := fingerprint.NetworkByName(answer.CNAME...); name != "" && kind != "cloud" {
			edgeName = name
		}
		// Both families: a service may listen on one only (naabu -iv 4,6).
		// IPv6 only where this machine can reach it; the summary says
		// when it cannot.
		limit := c.maxIP
		if c.AllIPs {
			limit = 1 << 20
		}
		v4, v6 := 0, 0
		for _, ip := range answer.IPs() {
			switch {
			case net.ParseIP(ip).To4() != nil:
				if v4 < limit && !c.IPv6Only {
					v4++
					ips = append(ips, ip)
				}
			case c.IPv4Only:
			case !c.routable():
				unrouted = append(unrouted, ip)
			case v6 < limit:
				v6++
				ips = append(ips, ip)
			}
		}
		if len(ips) == 0 && len(unrouted) == 0 {
			// Nothing to connect to: no such name, a resolver that did not
			// answer, or no address of the family asked for.
			why := answer.Status
			if answer.Live() {
				why = "no address of the family asked for"
			}
			raw, _ := json.Marshal(map[string]any{"host": host, "scanned": 0, "open": []int{}, "unresolved": why})
			err := emit(types.Observation{Collector: Name, Source: "tcp", Kind: "ports", Payload: raw, Confidence: 0.95, ObservedAt: time.Now().UTC()})
			meta := types.RunMeta{Status: types.StatusOK, EmitCount: 1}
			if answer.Status == dnsr.StatusFailed || answer.Status == dnsr.StatusBroken {
				meta.Status, meta.Error = types.StatusError, "no answer from the DNS resolvers: "+answer.Err
			}
			return meta, err
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
		ports := c.portsOf(host)
		name := edgeName
		edge := name != ""
		if edge && !c.CDNFull {
			ports = cdnPorts
		}
		// A scan an earlier run stopped asks only the ports it had not.
		all := ports
		prior, resumed := c.Prior[ip]
		if resumed {
			ports = without(ports, prior.Asked)
		}
		var s *scan
		var err error
		if c.Discover == DiscoverOff {
			s, err = c.scanOnce(ctx, host, ip, ports)
		} else {
			s, err = c.discoverOnce(ctx, host, ip, ports)
		}
		if err != nil && ctx.Err() != nil {
			return types.RunMeta{Status: types.StatusCancelled}, err
		}
		if stopped(err) {
			// Stopped by -max-requests or the kill file: what it found is
			// kept, with the ports it asked, and azhaq resume asks the rest.
			c.forget(ip)
			if row := c.partialRow(host, ip, all, ports, s, prior, resumed, name, edge); row != nil {
				raw, _ := json.Marshal(row)
				_ = emit(types.Observation{Collector: Name, Source: "tcp", Kind: "ports", Payload: raw, Confidence: 0.95, ObservedAt: time.Now().UTC(), Keep: true})
			}
			return types.RunMeta{Status: types.StatusCapped}, err
		}
		if resumed {
			s, ports = withPrior(s, prior), all
		}
		var udp portscan.UDPReport
		if len(c.UDPPorts) > 0 && !edge && s.up && c.Discover != DiscoverOnly {
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
		row := c.row(host, ip, ports, s, name, edge)
		if len(c.UDPPorts) > 0 && !edge && s.up && c.Discover != DiscoverOnly {
			addUDP(row, udp, len(c.UDPPorts))
		}
		if s.unprobed > 0 {
			row["unprobed"] = s.unprobed
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
		meta.NextHints = append(meta.NextHints, hintsOf(host, s.open)...)
	}
	return meta, nil
}

// row is an address's row: what was asked of it, what answered and what did
// not.
func (c *Collector) row(host, ip string, ports []int, s *scan, edge string, isEdge bool) map[string]any {
	row := map[string]any{"host": host, "ip": ip, "scanned": len(ports), "open": portsOf(s.open)}
	switch {
	case c.Discover != DiscoverOff:
		row["up"] = s.up
		if !s.up || c.Discover == DiscoverOnly {
			row["scanned"] = 0
		}
	}
	if len(s.open) > 0 {
		row["services"] = s.open
	}
	if len(s.silent) > 0 {
		row["filtered"] = len(s.silent)
		if len(s.silent) <= maxListed {
			row["filtered_ports"] = s.silent
		}
	}
	if s.capped {
		row["threshold"] = true
	}
	if isEdge {
		row["cdn"] = edge
		if c.CDNFull {
			row["note"] = "CDN or WAF address: scanned in full"
		} else {
			row["note"] = "CDN or WAF address: web ports only"
		}
	}
	return row
}

// hintsOf are the web ports a name's scan found, as URLs for the HTTP
// collector.
func hintsOf(host string, open []portscan.Open) []types.Seed {
	var out []types.Seed
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
		out = append(out, types.Seed{Type: types.TypeURL, Keys: keys})
	}
	return out
}

// unroutedKey lists, in a name's rows, its IPv6 addresses this machine
// has no route to, which were not scanned.
const unroutedKey = "ipv6_not_scanned"

// Notes are what a run's port scans leave for its summary: names that did
// not resolve, IPv6 addresses this machine could not scan, ports that did
// not answer, addresses left out and why.
func Notes(obs []types.StoredObservation) []string {
	names := map[string]bool{}
	var silent []string // address: ports, where a few ports answered neither way, twice
	var udp udpSummary
	var unprobed []string // address: open ports left without the protocol probes
	var unresolved []string
	var stopped []string // addresses the open-port threshold stopped
	var edges []string
	var down, outside, filtAddrs, addrs, ranges int
	// A row of a scan a limit stopped is read only while nothing came
	// after it: the row that finishes the scan says it all.
	newest := map[string]int{}
	for i, o := range obs {
		if o.Collector == Name {
			var id struct {
				Host string `json:"host"`
				IP   string `json:"ip"`
			}
			if json.Unmarshal(o.Payload, &id) == nil {
				newest[id.Host+"\x00"+id.IP] = i
			}
		}
	}
	for i, o := range obs {
		if o.Collector != Name {
			continue
		}
		var p struct {
			Partial    bool     `json:"partial"`
			Host       string   `json:"host"`
			IP         string   `json:"ip"`
			Unrouted   []string `json:"ipv6_not_scanned"`
			Filtered   []int    `json:"filtered_ports"`
			UDPFilt    []int    `json:"udp_open_filtered"`
			UDPUnlist  int      `json:"udp_unlisted"`
			UDPSilentN int      `json:"udp_silent_ports"`
			UDPSilentA int      `json:"udp_silent_addresses"`
			Unresolved string   `json:"unresolved"`
			Threshold  bool     `json:"threshold"`
			CDN        string   `json:"cdn"`
			Note       string   `json:"note"`
			Up         *bool    `json:"up"`
			Range      bool     `json:"range"`
			Prefix     string   `json:"prefix"`
			Addresses  int      `json:"addresses"`
			Down       int      `json:"down"`
			Outside    int      `json:"outside_scope"`
			FiltAddrs  int      `json:"filtered_addresses"`
			Edges      int      `json:"cdn_addresses"`
			CDNFull    bool     `json:"cdn_full"`
			UDPLimit   int      `json:"udp_limited"`
			Unprobed   int      `json:"unprobed"`
		}
		if json.Unmarshal(o.Payload, &p) != nil || p.Partial && newest[p.Host+"\x00"+p.IP] != i {
			continue
		}
		if p.Range {
			ranges++
			addrs += p.Addresses
			down += p.Down
			outside += p.Outside
			filtAddrs += p.FiltAddrs
			if p.Edges > 0 {
				edges = append(edges, fmt.Sprintf("%d addresses of a range", p.Edges))
			}
			udp.silentN += p.UDPSilentN
			udp.silentIPs += p.UDPSilentA
			continue
		}
		if p.Unresolved != "" {
			unresolved = append(unresolved, p.Host)
		}
		if p.Up != nil && !*p.Up {
			down++
		}
		if p.Threshold {
			stopped = append(stopped, p.IP)
		}
		if p.CDN != "" && p.Prefix == "" && strings.Contains(p.Note, "web ports only") {
			edges = append(edges, p.IP+" ("+p.CDN+")")
		}
		if len(p.Unrouted) > 0 {
			names[p.Host] = true
		}
		who := p.IP
		if who == "" {
			who = p.Host
		}
		udp.add(who, p.UDPFilt, p.UDPUnlist, p.UDPLimit)
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
	if len(unresolved) > 0 {
		sort.Strings(unresolved)
		out = append(out, fmt.Sprintf("%d names did not resolve and were not scanned: %s", len(unresolved), listOf(unresolved, 5)))
	}
	switch len(names) {
	case 0:
	case 1:
		out = append(out, "IPv6 addresses of 1 name not scanned: no IPv6 route from this machine")
	default:
		out = append(out, fmt.Sprintf("IPv6 addresses of %d names not scanned: no IPv6 route from this machine", len(names)))
	}
	if outside > 0 {
		out = append(out, fmt.Sprintf("%d addresses in the ranges are outside the scope (-deny, -allow) and were not scanned", outside))
	}
	if down > 0 {
		out = append(out, fmt.Sprintf("%d addresses answered neither a connect to 80 nor to 443 (asked twice) and were not scanned: a host that drops both is not found this way, scan without -wn to ask it anyway", down))
	}
	if len(edges) > 0 {
		out = append(out, fmt.Sprintf("CDN or WAF addresses were asked only on ports 80, 443, 8080 and 8443, as their other ports belong to the provider's other customers (%s): -cdn-full scans them in full", listOf(edges, 3)))
	}
	if len(stopped) > 0 {
		out = append(out, fmt.Sprintf("reached the open-port threshold (-pts): ports not yet asked were left out, and open ports past it may be missing: %s", listOf(stopped, 3)))
	}
	if filtAddrs > 0 {
		out = append(out, fmt.Sprintf("%d addresses in the ranges had ports that neither accepted nor refused a connect, asked twice: dead, or filtered; they are not listed one by one", filtAddrs))
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
	return append(out, udp.notes()...)
}

// listOf is up to n of items, then how many more.
func listOf(items []string, n int) string {
	if len(items) <= n {
		return strings.Join(items, ", ")
	}
	return fmt.Sprintf("%s and %d more", strings.Join(items[:n], ", "), len(items)-n)
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

// scanOnce asks an address's ports, once however many names point to it.
func (c *Collector) scanOnce(ctx context.Context, host, ip string, ports []int) (*scan, error) {
	return c.once(ctx, host, ip, func() *scan {
		r, err := c.Scanner.ScanEach(ctx, host, ip, ports)
		return &scan{open: r.Open, silent: r.Silent, unprobed: r.Unprobed, up: true, capped: r.Threshold, asked: r.Asked, err: err}
	}, func(s *scan) (*scan, error) {
		open, err := c.askAgain(ctx, host, ip, s.open)
		return &scan{open: open, silent: s.silent, unprobed: s.unprobed, up: s.up, capped: s.capped}, err
	})
}

// discoverOnce is scanOnce for a scan that first asks whether the address
// is up, and stops there when told to (-sn).
func (c *Collector) discoverOnce(ctx context.Context, host, ip string, ports []int) (*scan, error) {
	return c.once(ctx, host, ip, func() *scan {
		up, err := c.Scanner.Up(ctx, host, ip)
		if err != nil || !up || c.Discover == DiscoverOnly {
			return &scan{up: up, err: err}
		}
		r, err := c.Scanner.ScanEach(ctx, host, ip, ports)
		return &scan{open: r.Open, silent: r.Silent, unprobed: r.Unprobed, up: true, capped: r.Threshold, err: err}
	}, func(s *scan) (*scan, error) {
		if !s.up || c.Discover == DiscoverOnly {
			return s, nil
		}
		open, err := c.askAgain(ctx, host, ip, s.open)
		return &scan{open: open, silent: s.silent, unprobed: s.unprobed, up: s.up, capped: s.capped}, err
	})
}

// once runs scan for an address the first time it is asked for and shares
// the answer; another name on it gets again, which asks its web ports
// under that name.
func (c *Collector) once(ctx context.Context, host, ip string, run func() *scan, again func(*scan) (*scan, error)) (*scan, error) {
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
			return &scan{}, ctx.Err()
		}
		if s.err != nil || s.host == host {
			return s, s.err
		}
		return again(s)
	}
	r := run()
	s.open, s.silent, s.unprobed, s.up, s.capped, s.asked, s.err = r.open, r.silent, r.unprobed, r.up, r.capped, r.asked, r.err
	close(s.done)
	return s, s.err
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

// PartialKey marks the row of a scan a limit stopped; AskedKey lists the
// ports it asked (1-1000,8080), which azhaq resume does not ask again.
const (
	PartialKey = "partial"
	AskedKey   = "asked_ports"
)

// Prior is what a stopped scan of an address found and asked.
type Prior struct {
	Asked []int
	Open  []portscan.Open
}

// Priors reads the rows of scans a limit stopped from a workspace: the
// newest for each address.
func Priors(obs []types.StoredObservation) map[string]Prior {
	out := map[string]Prior{}
	for _, o := range obs {
		if o.Collector != Name || o.Kind != "ports" {
			continue
		}
		var row struct {
			IP       string          `json:"ip"`
			Partial  bool            `json:"partial"`
			Asked    string          `json:"asked_ports"`
			Services []portscan.Open `json:"services"`
		}
		if json.Unmarshal(o.Payload, &row) != nil || row.IP == "" {
			continue
		}
		if !row.Partial {
			delete(out, row.IP) // a whole scan came after it
			continue
		}
		asked, err := portscan.Ports(row.Asked)
		if err != nil {
			continue
		}
		out[row.IP] = Prior{Asked: asked, Open: row.Services}
	}
	return out
}

func without(ports, asked []int) []int {
	done := map[int]bool{}
	for _, p := range asked {
		done[p] = true
	}
	var out []int
	for _, p := range ports {
		if !done[p] {
			out = append(out, p)
		}
	}
	return out
}

// stopped: a limit ended the scan, not a failure.
func stopped(err error) bool {
	return errors.Is(err, neterr.ErrBudget) || errors.Is(err, neterr.ErrKilled)
}

// partialRow is the row of a scan a limit stopped: the ports it found and
// the ones it asked, with what an earlier stopped run of it had.
func (c *Collector) partialRow(host, ip string, all, ports []int, s *scan, prior Prior, resumed bool, name string, edge bool) map[string]any {
	if s == nil || (s.asked == 0 && !resumed) {
		return nil
	}
	asked := c.Scanner.Ordered(ip, ports)[:min(s.asked, len(ports))]
	part := s
	if resumed {
		part = withPrior(s, prior)
		asked = append(slices.Clone(prior.Asked), asked...)
	}
	row := c.row(host, ip, all, part, name, edge)
	row["scanned"] = len(asked)
	row[PartialKey] = true
	row[AskedKey] = portscan.Compact(asked)
	return row
}

// withPrior is s with the open ports an earlier stopped scan found.
func withPrior(s *scan, prior Prior) *scan {
	m := *s
	m.open = append(slices.Clone(prior.Open), s.open...)
	sort.Slice(m.open, func(i, j int) bool { return m.open[i].Port < m.open[j].Port })
	return &m
}
