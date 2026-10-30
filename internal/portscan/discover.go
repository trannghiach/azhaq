package portscan

import (
	"context"
	"net"
	"strconv"
	"sync"

	"github.com/trannghiach/azhaq/internal/ledger"
)

// DiscoveryPorts are the ports a host is asked on to tell it is there: a
// host that accepts or refuses on either is up, as with nmap's connect
// ping as an ordinary user.
var DiscoveryPorts = []int{443, 80}

// Up says whether ip answers a connect on DiscoveryPorts: one that
// accepts or refuses proves a host there, silence on both twice says
// none (or one that drops what it is not meant to answer). Each connect
// is paced, counted and recorded like a scan's.
func (s *Scanner) Up(ctx context.Context, host, ip string) (bool, error) {
	s.init()
	for try := 0; try < 2; try++ {
		var wg sync.WaitGroup
		var mu sync.Mutex
		var up bool
		var stop error
		for _, p := range DiscoveryPorts {
			if err := s.wait(ctx, ip); err != nil {
				return false, err
			}
			if s.Take != nil {
				if stop = s.Take(); stop != nil {
					break
				}
			}
			select {
			case <-ctx.Done():
				wg.Wait()
				return false, ctx.Err()
			case s.conns <- struct{}{}:
			}
			wg.Add(1)
			go func(p int) {
				defer wg.Done()
				defer func() { <-s.conns }()
				addr := net.JoinHostPort(ip, strconv.Itoa(p))
				ledger.TCP(ctx, host, addr)
				c, err := s.dial(ctx, ip, addr)
				self := err == nil && selfConnect(c)
				if err == nil {
					c.Close()
				}
				if err == nil || refused(err) || self {
					mu.Lock()
					up = true
					mu.Unlock()
				}
			}(p)
		}
		wg.Wait()
		if stop != nil {
			return false, stop
		}
		if err := ctx.Err(); err != nil {
			return false, err
		}
		if up {
			return true, nil
		}
	}
	return false, nil
}
