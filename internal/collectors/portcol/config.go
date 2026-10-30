package portcol

import (
	"net"
	"time"

	"github.com/trannghiach/azhaq/internal/portscan"
)

// Config holds the knobs of a port scan that the zero value leaves at the
// scanner's defaults.
type Config struct {
	Timeout          time.Duration // per connect
	Retries          int           // portscan.Scanner.Retries
	Workers          int           // connects in flight
	MinRate          float64       // the pace is at least this
	Order            portscan.Order
	Seed             int64
	Threshold        int
	Unnamed          int // see portscan.Scanner.Unnamed
	Detect           portscan.Detect
	SourceIP         net.IP
	Payload          []byte
	Proxy, ProxyAuth string

	CDNFull                    bool
	Discover                   Discovery
	IPv4Only, IPv6Only, AllIPs bool
	PortsFor                   map[string][]int
}

// Apply sets c's knobs from cfg.
func (c *Collector) Apply(cfg Config) {
	s := c.Scanner
	s.Timeout, s.Retries, s.Workers = cfg.Timeout, cfg.Retries, cfg.Workers
	s.Order, s.Seed, s.Threshold, s.Detect, s.Unnamed = cfg.Order, cfg.Seed, cfg.Threshold, cfg.Detect, cfg.Unnamed
	s.SourceIP, s.Payload = cfg.SourceIP, cfg.Payload
	s.Proxy, s.ProxyAuth = cfg.Proxy, cfg.ProxyAuth
	if cfg.MinRate > 0 && s.Rate < cfg.MinRate {
		s.Rate = cfg.MinRate
	}
	c.CDNFull, c.Discover = cfg.CDNFull, cfg.Discover
	c.IPv4Only, c.IPv6Only, c.AllIPs = cfg.IPv4Only, cfg.IPv6Only, cfg.AllIPs
	c.PortsFor = cfg.PortsFor
}
