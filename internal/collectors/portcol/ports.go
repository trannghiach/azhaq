// Package portcol scans the TCP ports of hosts in scope (-ports, active)
// and hands the ones that may serve HTTP to the HTTP collector.
package portcol

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strconv"
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

	mu    sync.Mutex
	byIP  map[string]*scan // one scan per address, however many names point to it
	maxIP int              // addresses scanned per name
}

type scan struct {
	done chan struct{}
	open []portscan.Open
	err  error
}

func New(pool *dnsr.Pool, ports []int, rate float64) *Collector {
	return &Collector{Pool: pool, Ports: ports, Scanner: &portscan.Scanner{Rate: rate, Take: fetch.Take}, byIP: map[string]*scan{}, maxIP: 2}
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
	if ip := net.ParseIP(host); ip != nil {
		ips = []string{ip.String()}
	} else if c.Pool != nil {
		answer := c.Pool.ResolveBoth(ctx, host)
		if name, kind := fingerprint.NetworkByName(answer.CNAME...); name != "" && kind != "cloud" {
			edgeName = name
		}
		// Both families: a service may listen on one only (naabu -iv 4,6).
		// IPv6 only where this machine can reach it.
		v4, v6 := 0, 0
		for _, ip := range answer.IPs() {
			switch {
			case net.ParseIP(ip).To4() != nil && v4 < c.maxIP:
				v4++
				ips = append(ips, ip)
			case net.ParseIP(ip).To4() == nil && v6 < c.maxIP && fetch.IPv6Routable():
				v6++
				ips = append(ips, ip)
			}
		}
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
		open, err := c.scanOnce(ctx, ip, ports)
		if err != nil && ctx.Err() != nil {
			return types.RunMeta{Status: types.StatusCancelled}, err
		}
		if errors.Is(err, neterr.ErrBudget) {
			// Each connect counts against -max-requests: azhaq resume
			// scans the address again.
			c.forget(ip)
			return types.RunMeta{Status: types.StatusCapped}, err
		}
		row := map[string]any{"host": host, "ip": ip, "scanned": len(ports), "open": portsOf(open)}
		if len(open) > 0 {
			row["services"] = open
		}
		if edge {
			row["cdn"] = name
			row["note"] = "CDN or WAF address: web ports only"
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
			meta.NextHints = append(meta.NextHints, types.Seed{Type: types.TypeURL, Keys: map[string]string{
				"url": "https://" + hp + "/", httpcol.FallbackKey: "http",
			}})
		}
	}
	return meta, nil
}

func (c *Collector) scanOnce(ctx context.Context, ip string, ports []int) ([]portscan.Open, error) {
	c.mu.Lock()
	s, ok := c.byIP[ip]
	if !ok {
		s = &scan{done: make(chan struct{})}
		c.byIP[ip] = s
	}
	c.mu.Unlock()
	if ok {
		select {
		case <-s.done:
			return s.open, s.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	s.open, s.err = c.Scanner.Scan(ctx, ip, ports)
	close(s.done)
	return s.open, s.err
}

// forget drops an address's scan so a resumed run scans it again.
func (c *Collector) forget(ip string) {
	c.mu.Lock()
	delete(c.byIP, ip)
	c.mu.Unlock()
}

func portsOf(open []portscan.Open) []int {
	out := make([]int, 0, len(open))
	for _, o := range open {
		out = append(out, o.Port)
	}
	return out
}
