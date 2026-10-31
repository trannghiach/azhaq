package egress

import (
	"context"
	"crypto/tls"
	"net"
	"strings"
	"time"

	"golang.org/x/net/proxy"

	"github.com/trannghiach/azhaq/internal/ledger"
	"github.com/trannghiach/azhaq/internal/neterr"
)

// PortDialer opens the TCP connections and UDP sockets of a port scan. Each
// one is refused once the kill file exists and for an address, or the name
// it was found under, outside the scope; each is entered in the ledger
// before it is made. The scanner counts them against the budget (Take) and
// paces them: it knows which of its connects are one more port and which
// are the same port asked again.
type PortDialer struct {
	timeout time.Duration
	src     net.IP
	via     proxy.ContextDialer // SOCKS5 for the connects of the scan itself; nil: direct
}

// NewPortDialer is a dialer with a timeout per connect, connecting from
// the local address src (nil: the system's; a target of the other family is
// asked from the system's) and, when socks5 is host:port, through that
// SOCKS5 proxy (auth is "user:password" for it).
func NewPortDialer(timeout time.Duration, src net.IP, socks5, auth string) *PortDialer {
	d := &PortDialer{timeout: timeout, src: src}
	if socks5 != "" {
		var a *proxy.Auth
		if u, p, ok := strings.Cut(auth, ":"); ok || u != "" {
			a = &proxy.Auth{User: u, Password: p}
		}
		if pd, err := proxy.SOCKS5("tcp", socks5, a, &net.Dialer{Timeout: timeout}); err == nil {
			d.via, _ = pd.(proxy.ContextDialer)
		}
	}
	return d
}

// Proxied says the scan's own connects go through a proxy.
func (d *PortDialer) Proxied() bool { return d.via != nil }

// allowed refuses a connect once the kill file exists, or when neither the
// name an address was found under nor the address is in the scope.
func (d *PortDialer) allowed(host, addr string) error {
	p := Current()
	if err := p.Killed(); err != nil {
		return err
	}
	if p.Scope() == nil {
		return nil
	}
	ip, _, err := net.SplitHostPort(addr)
	if err != nil {
		ip = addr
	}
	// A name is in scope by its rule, an address by its own or its range's.
	if p.Allows(ip) || (host != "" && p.Allows(host)) {
		return nil
	}
	return neterr.ErrOutOfScope
}

func (d *PortDialer) netDialer(ip string) net.Dialer {
	nd := net.Dialer{Timeout: d.timeout}
	if d.src != nil {
		if t := net.ParseIP(ip); t != nil && (t.To4() == nil) == (d.src.To4() == nil) {
			nd.LocalAddr = &net.TCPAddr{IP: d.src}
		}
	}
	return nd
}

func hostOfAddr(addr string) string {
	h, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return h
}

// TCP connects to addr (ip:port) of host ("" when only the address is
// known), through the proxy when there is one.
func (d *PortDialer) TCP(ctx context.Context, host, addr string) (net.Conn, error) {
	if err := d.allowed(host, addr); err != nil {
		return nil, err
	}
	ledger.TCP(ctx, host, addr)
	if d.via != nil {
		cctx, cancel := context.WithTimeout(ctx, d.timeout)
		defer cancel()
		return d.via.DialContext(cctx, "tcp", addr)
	}
	nd := d.netDialer(hostOfAddr(addr))
	return nd.DialContext(ctx, "tcp", addr)
}

// TCPDirect is TCP that never goes through the proxy: the service probes
// dial on their own.
func (d *PortDialer) TCPDirect(ctx context.Context, host, addr string) (net.Conn, error) {
	if err := d.allowed(host, addr); err != nil {
		return nil, err
	}
	ledger.TCP(ctx, host, addr)
	nd := d.netDialer(hostOfAddr(addr))
	return nd.DialContext(ctx, "tcp", addr)
}

// TLS is TCPDirect with a TLS handshake that waits at most handshake.
func (d *PortDialer) TLS(ctx context.Context, host, addr string, cfg *tls.Config, handshake time.Duration) (net.Conn, error) {
	if err := d.allowed(host, addr); err != nil {
		return nil, err
	}
	ledger.TCP(ctx, host, addr)
	nd := d.netDialer(hostOfAddr(addr))
	hctx, cancel := context.WithTimeout(ctx, handshake)
	defer cancel()
	return (&tls.Dialer{NetDialer: &nd, Config: cfg}).DialContext(hctx, "tcp", addr)
}

// UDP opens a socket connected to raddr, which is a datagram about to be
// sent to it: the ledger has it first.
func (d *PortDialer) UDP(ctx context.Context, host string, raddr *net.UDPAddr) (*net.UDPConn, error) {
	if err := d.allowed(host, raddr.String()); err != nil {
		return nil, err
	}
	ledger.UDP(ctx, host, raddr.String())
	return net.DialUDP("udp", nil, raddr)
}

// UDPAnySource is UDP for a service that answers from a port of its own: the
// socket is not connected to raddr.
func (d *PortDialer) UDPAnySource(ctx context.Context, host string, raddr *net.UDPAddr) (*net.UDPConn, error) {
	if err := d.allowed(host, raddr.String()); err != nil {
		return nil, err
	}
	ledger.UDP(ctx, host, raddr.String())
	return listenAnySource(raddr)
}

// DialTLS connects to addr (host:port) of a target and runs the TLS
// handshake, observing whatever certificate it presents: one handshake, one
// ledger line, held to the kill file and the scope.
func DialTLS(ctx context.Context, host, addr string, cfg *tls.Config, timeout time.Duration) (net.Conn, error) {
	return (&PortDialer{timeout: timeout}).TLS(ctx, host, addr, cfg, timeout)
}
