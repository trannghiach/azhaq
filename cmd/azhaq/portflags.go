package main

import (
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/trannghiach/azhaq/internal/collectors/portcol"
	"github.com/trannghiach/azhaq/internal/portscan"
)

// portFlags are run's -port-* flags as given.
type portFlags struct {
	minRate                                      float64
	timeout                                      time.Duration
	retries, workers, threshold, unnamed         int
	seed                                         int64
	order, detect, discover, ip, source, payload string
	proxy, proxyAuth                             string
	cdnFull, allIPs                              bool
	on                                           []string
}

// portConfig reads the flags into the collector's knobs; a value it does
// not know is a usage error, before anything is sent.
func portConfig(f portFlags) (portcol.Config, error) {
	cfg := portcol.Config{Timeout: f.timeout, Workers: f.workers, MinRate: f.minRate, Seed: f.seed, Threshold: f.threshold, Unnamed: f.unnamed,
		CDNFull: f.cdnFull, AllIPs: f.allIPs}
	switch {
	case f.retries < 0:
	case f.retries == 0:
		cfg.Retries = -1 // none
	default:
		cfg.Retries = f.retries
	}
	switch f.order {
	case "random", "":
		cfg.Order = portscan.OrderTiered
	case "asc", "ascending":
	default:
		return cfg, usagef("-port-order wants random or asc, got %q", f.order)
	}
	switch f.detect {
	case "all", "":
	case "banner":
		cfg.Detect = portscan.DetectBanner
	case "none":
		cfg.Detect = portscan.DetectNone
	default:
		return cfg, usagef("-port-detect wants all, banner or none, got %q", f.detect)
	}
	switch f.discover {
	case "":
	case "first":
		cfg.Discover = portcol.DiscoverFirst
	case "only":
		cfg.Discover = portcol.DiscoverOnly
	default:
		return cfg, usagef("-port-discover wants first or only, got %q", f.discover)
	}
	switch f.ip {
	case "":
	case "4":
		cfg.IPv4Only = true
	case "6":
		cfg.IPv6Only = true
	default:
		return cfg, usagef("-port-ip wants 4 or 6, got %q", f.ip)
	}
	if f.source != "" {
		if cfg.Detect == portscan.DetectAll {
			cfg.Detect = portscan.DetectBanner // the service probes dial from the system's address
		}
		if cfg.SourceIP = net.ParseIP(f.source); cfg.SourceIP == nil {
			return cfg, usagef("-port-source-ip wants an address, got %q", f.source)
		}
	}
	if f.payload != "" {
		cfg.Payload = []byte(strings.NewReplacer(`\r`, "\r", `\n`, "\n", `\t`, "\t").Replace(f.payload))
	}
	if f.proxy != "" {
		cfg.Proxy = strings.TrimPrefix(strings.TrimPrefix(f.proxy, "socks5://"), "socks5h://")
		cfg.ProxyAuth = f.proxyAuth
		if _, _, err := net.SplitHostPort(cfg.Proxy); err != nil {
			return cfg, usagef("-port-proxy wants a SOCKS5 proxy as host:port, got %q", f.proxy)
		}
		// The service probes of -port-detect all dial on their own: through a
		// proxy, a port is asked its banner only.
		if cfg.Detect == portscan.DetectAll {
			cfg.Detect = portscan.DetectBanner
		}
	}
	if f.timeout < 0 || f.workers < 0 || f.threshold < 0 {
		return cfg, usagef("-port-timeout, -port-workers and -port-threshold are not negative")
	}
	for _, o := range f.on {
		host, spec, ok := strings.Cut(o, "=")
		if !ok {
			return cfg, usagef("-ports-on wants HOST=PORTS, got %q", o)
		}
		ports, err := portscan.Ports(spec)
		if err != nil {
			return cfg, usagef("-ports-on %s: %v", host, err)
		}
		if cfg.PortsFor == nil {
			cfg.PortsFor = map[string][]int{}
		}
		cfg.PortsFor[strings.ToLower(strings.Trim(strings.TrimSpace(host), "[]"))] = ports
	}
	return cfg, nil
}

// portsOnFlag is -ports-on HOST=PORTS for a host given with its port.
func portsOnFlag(host string, ports []int) []string {
	parts := make([]string, len(ports))
	for i, p := range ports {
		parts[i] = strconv.Itoa(p)
	}
	return []string{"-ports-on", host + "=" + strings.Join(parts, ",")}
}
