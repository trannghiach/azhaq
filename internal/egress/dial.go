package egress

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/trannghiach/azhaq/internal/ledger"
	"github.com/trannghiach/azhaq/internal/neterr"
)

// DialTarget connects to a target as the run's HTTP client does: a name
// goes to the addresses the run's resolver found for it, IPv6 first where
// the machine has a route and IPv4 after a short head start (RFC 8305).
// It refuses once the kill file exists and for a host outside the scope.
func DialTarget(ctx context.Context, network, addr string) (net.Conn, error) {
	if host, _, err := net.SplitHostPort(addr); err == nil && !Current().Allows(host) {
		return nil, neterr.ErrOutOfScope
	}
	return dialThrough(ctx, network, addr)
}

// DialProxy connects to a proxy the user named (-proxy, -chrome-proxy):
// not a target, so not held to the scope; the kill file still stops it.
func DialProxy(ctx context.Context, network, addr string) (net.Conn, error) {
	return dialThrough(ctx, network, addr)
}

// dialThrough is the dial of a target's transport: the scope is checked
// for each request, not for a connection, which may be to a proxy.
func dialThrough(ctx context.Context, network, addr string) (net.Conn, error) {
	p := Current()
	if err := p.Killed(); err != nil {
		return nil, err
	}
	return dialResolved(ctx, p, network, addr)
}

// DialSource connects to a third-party service (a mail server, a database
// of a source): not the scope's business, the kill file stops it, and the
// connection is recorded as a source's.
func DialSource(ctx context.Context, network, addr string) (net.Conn, error) {
	if err := Current().Killed(); err != nil {
		return nil, err
	}
	ledger.TCPAs(ctx, ledger.ClassSource, "", addr)
	d := &net.Dialer{Timeout: 30 * time.Second}
	return d.DialContext(ctx, network, addr)
}

func pinnedDial(ip string) func(ctx context.Context, network, addr string) (net.Conn, error) {
	d := &net.Dialer{Timeout: 5 * time.Second}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		_, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		if err := Current().Killed(); err != nil {
			return nil, err
		}
		return d.DialContext(ctx, network, net.JoinHostPort(ip, port))
	}
}

// dialResolved connects through the resolver's addresses when it has an
// answer, the way the system would. Some edges answer only one family
// from a given network.
func dialResolved(ctx context.Context, p *Policy, network, addr string) (net.Conn, error) {
	d := &net.Dialer{Timeout: 5 * time.Second}
	host, port, err := net.SplitHostPort(addr)
	if err != nil || net.ParseIP(host) != nil {
		return d.DialContext(ctx, network, addr)
	}
	ips := p.Resolve(ctx, host)
	if len(ips) == 0 {
		return d.DialContext(ctx, network, addr) // /etc/hosts, special-use names
	}
	var v4, v6 []string
	for _, ip := range ips {
		if strings.Contains(ip, ":") {
			v6 = append(v6, ip)
		} else {
			v4 = append(v4, ip)
		}
	}
	primary, fallback := v4, v6
	if ipv6Routable() && len(v6) > 0 {
		primary, fallback = v6, v4
	} else if !ipv6Routable() {
		fallback = nil
	}
	if len(primary) == 0 {
		primary, fallback = fallback, nil
	}
	return dialEither(ctx, d, network, port, primary, fallback)
}

// fallbackDelay is the head start of the preferred address family.
const fallbackDelay = 300 * time.Millisecond

// dialEither tries primary addresses in order and, from fallbackDelay on,
// the fallback ones alongside; the first connection wins.
func dialEither(ctx context.Context, d *net.Dialer, network, port string, primary, fallback []string) (net.Conn, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type result struct {
		c   net.Conn
		err error
	}
	results := make(chan result, 2)
	try := func(ips []string, wait time.Duration) {
		if wait > 0 {
			select {
			case <-ctx.Done():
				results <- result{err: ctx.Err()}
				return
			case <-time.After(wait):
			}
		}
		var last error
		for _, ip := range ips {
			c, err := d.DialContext(ctx, network, net.JoinHostPort(ip, port))
			if err == nil {
				results <- result{c: c}
				return
			}
			last = err
			if ctx.Err() != nil {
				break
			}
		}
		results <- result{err: last}
	}
	n := 1
	go try(primary, 0)
	if len(fallback) > 0 {
		n++
		go try(fallback, fallbackDelay)
	}
	var first error
	for i := 0; i < n; i++ {
		r := <-results
		if r.err == nil {
			cancel()
			// The other attempt may still connect: close what it opens.
			go func(left int) {
				for j := 0; j < left; j++ {
					if r := <-results; r.c != nil {
						r.c.Close()
					}
				}
			}(n - i - 1)
			return r.c, nil
		}
		if first == nil {
			first = r.err
		}
	}
	return nil, first
}

// IPv6Routable says whether this machine can reach IPv6 addresses on the
// internet.
func IPv6Routable() bool { return ipv6Routable() }

var ipv6Routable = sync.OnceValue(func() bool {
	// A UDP "connection" sends nothing; it only asks the kernel for a
	// route and a source address.
	c, err := net.Dial("udp6", "[2001:4860:4860::8888]:53")
	if err != nil {
		return false
	}
	defer c.Close()
	ip := c.LocalAddr().(*net.UDPAddr).IP
	return ip.IsGlobalUnicast() && !ip.IsPrivate()
})
