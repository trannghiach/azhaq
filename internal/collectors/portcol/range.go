package portcol

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/trannghiach/azhaq/internal/collectors/asncol"
	"github.com/trannghiach/azhaq/internal/fetch"
	"github.com/trannghiach/azhaq/internal/fingerprint"
	"github.com/trannghiach/azhaq/internal/neterr"
	"github.com/trannghiach/azhaq/internal/portscan"
	"github.com/trannghiach/azhaq/types"
)

// A range is scanned in blocks of 256 addresses, one task each: the run
// records its progress by block, and a range of millions of addresses is
// never held as millions of seeds.
const (
	blockBits4 = 24
	blockBits6 = 120
	// maxBits6: an IPv6 range larger than this has more addresses than any
	// IPv4 range (a /8) and is no scan anyone finishes.
	maxBits6 = 104
)

// Blocks splits pf into the prefixes a range is scanned in. An IPv6 range
// of more than 2^24 addresses is refused rather than cut: nothing finishes it.
func Blocks(pf netip.Prefix) ([]netip.Prefix, error) {
	pf = pf.Masked()
	size := blockBits4
	if pf.Addr().Is6() {
		size = blockBits6
		if pf.Bits() < maxBits6 {
			return nil, fmt.Errorf("%s: an IPv6 range larger than /%d has more addresses than a /8", pf, maxBits6)
		}
	}
	if pf.Bits() >= size {
		return []netip.Prefix{pf}, nil
	}
	n := 1 << (size - pf.Bits())
	out := make([]netip.Prefix, 0, n)
	addr := pf.Addr()
	step := 1 << (pf.Addr().BitLen() - size)
	for i := 0; i < n; i++ {
		out = append(out, netip.PrefixFrom(addr, size))
		for j := 0; j < step; j++ {
			addr = addr.Next()
		}
	}
	return out, nil
}

func (c *Collector) runPrefix(ctx context.Context, seed types.Seed, emit func(types.Observation) error) (types.RunMeta, error) {
	pf, err := netip.ParsePrefix(seed.Key())
	if err != nil {
		return types.RunMeta{Status: types.StatusError, Error: err.Error()}, nil
	}
	pf = pf.Masked()
	blocks, err := Blocks(pf)
	if err != nil {
		return types.RunMeta{Status: types.StatusError, Error: err.Error()}, nil
	}
	if len(blocks) > 1 || blocks[0] != pf {
		// Too big for one task: its blocks are the work (a range met under
		// an AS number, not one the command line split).
		meta := types.RunMeta{Status: types.StatusOK}
		for _, b := range blocks {
			meta.NextHints = append(meta.NextHints, types.Seed{Type: types.TypePrefix, Keys: map[string]string{"prefix": b.String()}})
		}
		return meta, nil
	}

	var addrs []netip.Addr
	for a := pf.Addr(); a.IsValid() && pf.Contains(a); a = a.Next() {
		addrs = append(addrs, a)
	}
	type result struct {
		row    map[string]any
		open   []portscan.Open
		ip     string
		err    error
		follow bool // something answered: the address goes on to the other collectors
	}
	workers := c.Workers
	if workers <= 0 {
		workers = 64
	}
	var (
		mu        sync.Mutex
		wg        sync.WaitGroup
		meta      = types.RunMeta{Status: types.StatusOK}
		first     error
		emitErr   error
		down, out int
		filtAddrs int
		edgeAddrs int
		udpFilt   int
		withOpen  int
	)
	sem := make(chan struct{}, workers)
	record := func(res result) {
		mu.Lock()
		defer mu.Unlock()
		if res.err != nil && first == nil {
			first = res.err
		}
		if res.row == nil {
			return
		}
		raw, _ := json.Marshal(res.row)
		if err := emit(types.Observation{Collector: Name, Source: "tcp", Kind: "ports", Payload: raw, Confidence: 0.95, ObservedAt: time.Now().UTC()}); err != nil && emitErr == nil {
			emitErr = err
			return
		}
		meta.EmitCount++
		if res.follow {
			meta.NextHints = append(meta.NextHints, types.Seed{Type: types.TypeIPAddress, Keys: map[string]string{"ip": res.ip, "from": asncol.FromPrefix}})
			meta.NextHints = append(meta.NextHints, hintsOf(res.ip, res.open)...)
		}
	}
	for _, a := range addrs {
		if ctx.Err() != nil {
			break
		}
		mu.Lock()
		stop := first != nil
		mu.Unlock()
		if stop {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(a netip.Addr) {
			defer wg.Done()
			defer func() { <-sem }()
			ip := a.String()
			if fetch.Allow != nil && !fetch.Allow(ip) {
				mu.Lock()
				out++
				mu.Unlock()
				return
			}
			ports := c.portsOf(ip)
			edge, edgeName := false, ""
			if name, kind := fingerprint.Network(net.ParseIP(ip)); name != "" && kind != "cloud" {
				edge, edgeName = true, name
				if !c.CDNFull {
					ports = cdnPorts
				}
			}
			s := &scan{up: true}
			var uerr error
			switch {
			case c.Discover != DiscoverOff:
				if s.up, s.err = c.Scanner.Up(ctx, ip, ip); s.err == nil && s.up && c.Discover == DiscoverFirst {
					s = c.scanRange(ctx, ip, ports)
				}
			default:
				s = c.scanRange(ctx, ip, ports)
			}
			if s.err != nil {
				record(result{err: s.err})
				return
			}
			var udp portscan.UDPReport
			if len(c.UDPPorts) > 0 && !edge && s.up && c.Discover != DiscoverOnly {
				udp, uerr = c.Scanner.ScanUDP(ctx, ip, ip, c.UDPPorts)
				if uerr != nil {
					record(result{err: uerr})
					return
				}
			}
			mu.Lock()
			switch {
			case !s.up:
				down++
			case len(s.open) > 0 || len(udp.Open) > 0:
				withOpen++
			}
			if len(s.silent) > 0 {
				filtAddrs++
			}
			if edge && !c.CDNFull {
				edgeAddrs++
			}
			udpFilt += len(udp.OpenFiltered)
			mu.Unlock()
			// An address that shows nothing has no row: the range's row counts them.
			if len(s.open) == 0 && len(udp.Open) == 0 && !(c.Discover == DiscoverOnly && s.up) {
				return
			}
			row := c.row(ip, ip, ports, s, edgeName, edge)
			row["prefix"] = pf.String()
			if len(c.UDPPorts) > 0 && !edge && s.up && c.Discover != DiscoverOnly {
				u := udp
				u.OpenFiltered = nil // the range's row counts them
				addUDP(row, u, len(c.UDPPorts))
			}
			follow := len(s.open) > 0 || len(udp.Open) > 0
			if follow {
				// The address seed that follows finds its scan done.
				c.remember(ip, s, udp, len(c.UDPPorts) > 0 && !edge && s.up && c.Discover != DiscoverOnly)
			}
			record(result{row: row, open: s.open, ip: ip, follow: follow})
		}(a)
	}
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return types.RunMeta{Status: types.StatusCancelled}, err
	}
	if emitErr != nil {
		return meta, emitErr
	}
	if errors.Is(first, neterr.ErrBudget) {
		return types.RunMeta{Status: types.StatusCapped}, first
	}
	if first != nil {
		return types.RunMeta{Status: types.StatusError, Error: first.Error()}, nil
	}
	rng := map[string]any{"range": true, "prefix": pf.String(), "addresses": len(addrs) - out, "with_open": withOpen,
		"scanned": len(c.portsOf("")), "down": down, "outside_scope": out, "filtered_addresses": filtAddrs,
		"cdn_addresses": edgeAddrs, "udp_open_filtered_n": udpFilt, "open": []int{}}
	raw, _ := json.Marshal(rng)
	if err := emit(types.Observation{Collector: Name, Source: "tcp", Kind: "ports", Payload: raw, Confidence: 0.95, ObservedAt: time.Now().UTC()}); err != nil {
		return meta, err
	}
	meta.EmitCount++
	sort.Slice(meta.NextHints, func(i, j int) bool { return meta.NextHints[i].Key() < meta.NextHints[j].Key() })
	return meta, nil
}

// scanRange asks one address of a range its ports.
func (c *Collector) scanRange(ctx context.Context, ip string, ports []int) *scan {
	r, err := c.Scanner.ScanEach(ctx, ip, ip, ports)
	return &scan{open: r.Open, silent: r.Silent, up: true, capped: r.Threshold, err: err}
}

// remember keeps the scan of an address that answered, so the seed that
// follows it (a name, an address) is not scanned again.
func (c *Collector) remember(ip string, s *scan, udp portscan.UDPReport, withUDP bool) {
	done := make(chan struct{})
	close(done)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.byIP[ip] = &scan{done: done, host: ip, open: s.open, silent: s.silent, up: s.up, capped: s.capped}
	if withUDP {
		if c.udpByIP == nil {
			c.udpByIP = map[string]*udpScan{}
		}
		c.udpByIP[ip] = &udpScan{done: done, rep: udp}
	}
}
