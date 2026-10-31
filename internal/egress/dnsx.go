package egress

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/proxy"

	"github.com/trannghiach/azhaq/internal/ledger"
)

// How a resolver is reached.
const (
	DNSUDP = "udp"
	DNSTCP = "tcp"
	DNSDoT = "dot"
	DNSDoH = "doh"
)

// DNSServer is one resolver: how it is reached, its address (the URL for
// DoH) and, for DoH, whether the query goes by GET.
type DNSServer struct {
	Key  string // how the run names it; recorded in the ledger
	Net  string
	Addr string
	GET  bool
}

// DNSExchanger sends DNS messages for a resolver pool: over UDP (and TCP
// again when the answer is cut), TCP, TLS or HTTPS, or through a SOCKS5
// proxy, which carries TCP only. Each query is entered in the ledger as a
// dns line and refused once the kill file exists. The pool paces them.
type DNSExchanger struct {
	timeout time.Duration
	udp     *dns.Client
	tcp     *dns.Client
	dot     *dns.Client
	doh     *http.Client
	via     proxy.ContextDialer // through this, over TCP; nil: direct
}

// NewDNSExchanger is an exchanger with a timeout per query. Proxy is a
// socks5:// or socks5h:// URL every query goes through; "" sends them directly.
func NewDNSExchanger(timeout time.Duration, proxyURL string) *DNSExchanger {
	x := &DNSExchanger{
		timeout: timeout,
		udp:     &dns.Client{Net: "udp", Timeout: timeout},
		tcp:     &dns.Client{Net: "tcp", Timeout: timeout},
		dot:     &dns.Client{Net: "tcp-tls", Timeout: timeout},
		doh:     dohClient(timeout, nil),
	}
	if u, err := url.Parse(proxyURL); err == nil && proxyURL != "" {
		if d, err := proxy.FromURL(u, &net.Dialer{Timeout: timeout}); err == nil {
			if cd, ok := d.(proxy.ContextDialer); ok {
				x.via = cd
			}
		}
	}
	return x
}

// CheckDNSProxy says whether raw is a proxy URL DNS can go through: a
// SOCKS5 proxy.
func CheckDNSProxy(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if u.Scheme != "socks5" && u.Scheme != "socks5h" {
		return fmt.Errorf("%q: DNS goes through a socks5 proxy only (socks5://host:port)", raw)
	}
	_, err = proxy.FromURL(u, proxy.Direct)
	return err
}

func dohClient(timeout time.Duration, via proxy.ContextDialer) *http.Client {
	tr := &http.Transport{}
	if via != nil {
		tr.DialContext = via.DialContext
	}
	return &http.Client{Timeout: timeout, Transport: newGuarded(DNS, tr, "")}
}

func record(ctx context.Context, q *dns.Msg, server string) error {
	if err := Current().Killed(); err != nil {
		return err
	}
	if len(q.Question) > 0 {
		ledger.DNS(ctx, strings.TrimSuffix(q.Question[0].Name, "."), dns.TypeToString[q.Question[0].Qtype], server)
	}
	return nil
}

// Exchange sends q to srv and returns the answer.
func (x *DNSExchanger) Exchange(ctx context.Context, q *dns.Msg, srv DNSServer) (*dns.Msg, error) {
	if err := record(ctx, q, srv.Key); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, x.timeout)
	defer cancel()
	switch {
	case srv.Net == DNSDoH:
		return x.exchangeDoH(ctx, q, srv)
	case x.via != nil:
		// Through a proxy everything is TCP: a SOCKS5 proxy carries no UDP
		// here. DoT keeps its TLS inside the tunnel.
		return x.viaProxy(ctx, q, srv)
	case srv.Net == DNSTCP:
		in, _, err := x.tcp.ExchangeContext(ctx, q, srv.Addr)
		return in, err
	case srv.Net == DNSDoT:
		in, _, err := x.dot.ExchangeContext(ctx, q, srv.Addr)
		return in, err
	}
	in, _, err := x.udp.ExchangeContext(ctx, q, srv.Addr)
	// A reply too big for a plain UDP datagram (a long CNAME chain) is read
	// again over TCP, as a truncated one is.
	if (err == nil && in.Truncated) || errors.Is(err, dns.ErrBuf) {
		in, _, err = x.tcp.ExchangeContext(ctx, q, srv.Addr)
	}
	return in, err
}

// ExchangeAt asks one server directly over UDP, and over TCP when the
// answer is cut: a name server being followed, not one of the pool's.
func (x *DNSExchanger) ExchangeAt(ctx context.Context, q *dns.Msg, server string) (*dns.Msg, error) {
	if err := record(ctx, q, server); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, x.timeout)
	defer cancel()
	in, _, err := x.udp.ExchangeContext(ctx, q, server)
	if err == nil && in.Truncated {
		in, _, err = x.tcp.ExchangeContext(ctx, q, server)
	}
	return in, err
}

// viaProxy asks one resolver over TCP through the proxy.
func (x *DNSExchanger) viaProxy(ctx context.Context, q *dns.Msg, srv DNSServer) (*dns.Msg, error) {
	c, err := x.via.DialContext(ctx, "tcp", srv.Addr)
	if err != nil {
		return nil, err
	}
	conn := &dns.Conn{Conn: c}
	defer conn.Close()
	client := x.tcp
	if srv.Net == DNSDoT {
		client = x.dot
		tc, err := dotConn(ctx, c, srv.Addr, x.dot.TLSConfig)
		if err != nil {
			return nil, err
		}
		conn = &dns.Conn{Conn: tc}
	}
	in, _, err := client.ExchangeWithConnContext(ctx, q, conn)
	return in, err
}

// dotConn wraps c, a connection to a DoT resolver, in TLS.
func dotConn(ctx context.Context, c net.Conn, addr string, cfg *tls.Config) (net.Conn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	var tc *tls.Config
	if cfg != nil {
		tc = cfg.Clone()
	} else {
		tc = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	if tc.ServerName == "" {
		tc.ServerName = host
	}
	conn := tls.Client(c, tc)
	if err := conn.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	return conn, nil
}

// exchangeDoH asks over HTTPS as RFC 8484 says: the wire message in a
// POST body, or base64url in the dns parameter of a GET.
func (x *DNSExchanger) exchangeDoH(ctx context.Context, q *dns.Msg, srv DNSServer) (*dns.Msg, error) {
	wire := q.Copy()
	wire.Id = 0 // RFC 8484: a cache-friendly id
	raw, err := wire.Pack()
	if err != nil {
		return nil, err
	}
	var req *http.Request
	if srv.GET {
		req, err = http.NewRequestWithContext(ctx, http.MethodGet, srv.Addr+queryJoin(srv.Addr)+"dns="+base64.RawURLEncoding.EncodeToString(raw), nil)
	} else {
		req, err = http.NewRequestWithContext(ctx, http.MethodPost, srv.Addr, bytes.NewReader(raw))
		if err == nil {
			req.Header.Set("Content-Type", "application/dns-message")
		}
	}
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-message")
	client := x.doh
	if x.via != nil {
		client = dohClient(x.timeout, x.via)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: HTTP %d", srv.Addr, resp.StatusCode)
	}
	in := new(dns.Msg)
	if err := in.Unpack(body); err != nil {
		return nil, err
	}
	in.Id = q.Id
	return in, nil
}

func queryJoin(u string) string {
	if strings.Contains(u, "?") {
		return "&"
	}
	return "?"
}

// Transfer asks server for the zone domain over TCP (AXFR), through the
// proxy when there is one, and returns its records. The transfer is cut
// when ctx ends.
func (x *DNSExchanger) Transfer(ctx context.Context, domain, server string) ([]dns.RR, error) {
	m := new(dns.Msg)
	m.SetAxfr(dns.Fqdn(domain))
	if err := record(ctx, m, server); err != nil {
		return nil, err
	}
	var c net.Conn
	var err error
	if x.via != nil {
		c, err = x.via.DialContext(ctx, "tcp", server)
	} else {
		var dd net.Dialer
		c, err = dd.DialContext(ctx, "tcp", server)
	}
	if err != nil {
		return nil, err
	}
	defer c.Close()
	go func() { // a transfer that outlasts its time is cut
		<-ctx.Done()
		_ = c.Close()
	}()
	tr := &dns.Transfer{Conn: &dns.Conn{Conn: c}, ReadTimeout: x.timeout}
	ch, err := tr.In(m, server)
	if err != nil {
		return nil, err
	}
	var rrs []dns.RR
	for env := range ch {
		if env.Error != nil {
			return nil, env.Error
		}
		rrs = append(rrs, env.RR...)
	}
	return rrs, nil
}

// SetDoTTLS sets the TLS settings of DoT queries: for a resolver whose
// certificate is not in the system's roots (a test's).
func (x *DNSExchanger) SetDoTTLS(cfg *tls.Config) { x.dot.TLSConfig = cfg }
