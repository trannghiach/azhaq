package egress

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/trannghiach/azhaq/internal/ledger"
	"github.com/trannghiach/azhaq/internal/neterr"
	"github.com/trannghiach/azhaq/scope"
)

// guarded is the transport of every client egress hands out. Before a
// request goes it applies the controls of its class, then the ledger
// records it (and holds back what -deny-path or a killed run's writes say).
type guarded struct {
	class Class
	base  *http.Transport
	sni   string // the server name every handshake asks for, "" for the URL's host
	rt    http.RoundTripper
}

func newGuarded(class Class, base *http.Transport, sni string) *guarded {
	g := &guarded{class: class, base: base, sni: sni}
	if class == Own || class == DNS {
		g.rt = base // the user's own, or a DNS query the exchanger records itself
	} else {
		g.rt = ledger.WrapAs(string(class), base)
	}
	return g
}

func (g *guarded) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := g.check(req); err != nil {
		if req.Body != nil {
			req.Body.Close()
		}
		if g.class == Target {
			Refund() // counted by its sender, never sent
		}
		return nil, err
	}
	return g.rt.RoundTrip(req)
}

// check is what a request is held to before it leaves: the kill file
// for every class but the user's own, and for a target the scope, which
// covers the URL's host, the Host header, every header that names a host
// and the server name the handshake asks for.
func (g *guarded) check(req *http.Request) error {
	if g.class == Own {
		return nil
	}
	p := Current()
	if err := p.Killed(); err != nil {
		return err
	}
	if g.class != Target {
		return nil
	}
	return p.checkRequest(req, g.sni)
}

// checkRequest refuses a request a front end could route to a host outside
// the scope: neterr.ErrOutOfScope. Without a scope it holds nothing back.
func (p *Policy) checkRequest(req *http.Request, sni string) error {
	allow, open := p.scope()
	if allow == nil || req.URL == nil {
		return nil
	}
	if h := req.URL.Hostname(); h != "" && !allow(h) {
		return neterr.ErrOutOfScope
	}
	if req.Host != "" && !open["host"] {
		if h := hostOnly(req.Host); h != "" && !allow(h) {
			return neterr.ErrOutOfScope
		}
	}
	for name, vs := range req.Header {
		if open[strings.ToLower(name)] {
			continue
		}
		for _, v := range vs {
			if scope.HeaderOutsideBy(allow, name, v) != "" {
				return neterr.ErrOutOfScope
			}
		}
	}
	if sni != "" && !open["sni"] && !allow(sni) {
		return neterr.ErrOutOfScope
	}
	return nil
}

func hostOnly(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return strings.Trim(h, "[]")
	}
	return strings.Trim(hostport, "[]")
}

// CloseIdleConnections passes on to the transport, as http.Client looks for it.
func (g *guarded) CloseIdleConnections() { g.base.CloseIdleConnections() }

// Unwrap is the *http.Transport under a client's transport that egress
// made, or rt itself.
func Unwrap(rt http.RoundTripper) http.RoundTripper {
	if g, ok := rt.(*guarded); ok {
		return g.base
	}
	return ledger.Unwrap(rt)
}

// TargetOptions are what a client to targets can be set apart by. Zero
// values are the defaults.
type TargetOptions struct {
	// Timeout is the whole request, HeaderTimeout the wait for the first
	// byte of the answer, HandshakeTimeout the TLS handshake.
	Timeout, HeaderTimeout, HandshakeTimeout time.Duration
	// TLS is the handshake's settings; nil takes any certificate, TLS 1.2 up.
	// Its ServerName is held to the scope like a Host header.
	TLS *tls.Config
	// NoReuse opens a connection for every request.
	NoReuse bool
	// Proxy replaces -proxy (and the environment's) for this client.
	Proxy *url.URL
	// Follow lets the client follow redirects; by default it answers with
	// the redirect itself.
	Follow bool
}

// TargetClient is an HTTP client for requests to targets: the guard checks
// each against the scope and the kill file, the ledger records it, a name
// connects through the run's resolver, and the request goes through -proxy.
// It sends no more than what its caller counts with Spend.
func TargetClient(o TargetOptions) *http.Client {
	cfg := o.TLS
	if cfg == nil {
		cfg = &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}
	}
	proxy := ProxyFor
	if o.Proxy != nil {
		proxy = http.ProxyURL(o.Proxy)
	}
	tr := &http.Transport{
		Proxy:                 proxy,
		DialContext:           dialThrough,
		DisableKeepAlives:     o.NoReuse,
		TLSHandshakeTimeout:   o.HandshakeTimeout,
		ResponseHeaderTimeout: o.HeaderTimeout,
		TLSClientConfig:       cfg,
	}
	c := &http.Client{Timeout: o.Timeout, Transport: newGuarded(Target, tr, cfg.ServerName)}
	if !o.Follow {
		c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	}
	return c
}

// TargetFrom is c, a client someone else made (a test's server client, one
// the run was given), with its requests held to the target controls: c
// itself when it already is.
func TargetFrom(c *http.Client) *http.Client {
	if _, ok := c.Transport.(*guarded); ok {
		return c
	}
	cp := *c
	var base *http.Transport
	switch t := Unwrap(c.Transport).(type) {
	case *http.Transport:
		base = t
	case nil:
		base = http.DefaultTransport.(*http.Transport)
	default:
		cp.Transport = &foreign{rt: ledger.WrapAs(string(Target), t), g: newGuarded(Target, &http.Transport{}, "")}
		return &cp
	}
	cp.Transport = newGuarded(Target, base, "")
	return &cp
}

// foreign holds a transport that is not an *http.Transport to the same
// checks and records.
type foreign struct {
	rt http.RoundTripper
	g  *guarded
}

func (f *foreign) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := f.g.check(req); err != nil {
		if req.Body != nil {
			req.Body.Close()
		}
		Refund()
		return nil, err
	}
	return f.rt.RoundTrip(req)
}

// Tweak is c with its transport copied and changed by f: timeouts, TLS
// settings, connection limits. The copy is held to the same controls; f
// does not decide where a connection goes. c is returned as it is when it
// was not made by egress.
func Tweak(c *http.Client, f func(*http.Transport)) *http.Client {
	g, ok := c.Transport.(*guarded)
	if !ok {
		return c
	}
	t := g.base.Clone()
	f(t)
	cp := *c
	sni := g.sni
	if t.TLSClientConfig != nil {
		sni = t.TLSClientConfig.ServerName
	}
	cp.Transport = newGuarded(g.class, t, sni)
	return &cp
}

// Pinned is c with every connection going to ip, not to a pooled one for
// the name; the request is still the URL's (its Host, its scope).
func Pinned(c *http.Client, ip string) *http.Client {
	return Tweak(c, func(t *http.Transport) {
		t.DisableKeepAlives = true
		t.DialContext = pinnedDial(ip)
	})
}

// SourceOptions are what a client to a third-party source can be set apart by.
type SourceOptions struct {
	Timeout time.Duration
	// Proxy sends the requests through this URL; nil takes the environment's
	// (HTTP_PROXY, HTTPS_PROXY), as the default transport does.
	Proxy *url.URL
}

// SourceClient is an HTTP client for a third party the run asks about its
// targets (archives, RDAP, search engines, a scope platform, a notification
// service): not held to the target scope, held to the kill file, sent
// through the proxy given for it, verified by the system's certificates, and
// recorded in the ledger as a source.
func SourceClient(o SourceOptions) *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if o.Proxy != nil {
		tr.Proxy = http.ProxyURL(o.Proxy)
	}
	return &http.Client{Timeout: o.Timeout, Transport: newGuarded(Source, tr, "")}
}

// SourceFrom is c, a client someone else made, with its requests held to
// the source controls and recorded as a source's; c itself when it
// already is.
func SourceFrom(c *http.Client) *http.Client {
	if g, ok := c.Transport.(*guarded); ok && g.class == Source {
		return c
	}
	cp := *c
	base := http.DefaultTransport.(*http.Transport)
	if t, ok := Unwrap(c.Transport).(*http.Transport); ok {
		base = t
	}
	cp.Transport = newGuarded(Source, base, "")
	return &cp
}

// OwnOptions are what a client to the user's own endpoint can be set apart by.
type OwnOptions struct {
	Timeout time.Duration
	// Proxy sends the requests through this URL; nil: the environment's.
	Proxy *url.URL
	// Insecure takes any certificate: a proxy such as Burp signs its own.
	// TLS, when set, is used as it is instead.
	Insecure bool
	TLS      *tls.Config
	// Follow lets the client follow redirects.
	Follow bool
}

// OwnClient is an HTTP client for an endpoint of the user's own: a replay
// proxy, a worker's link to its run, where -seal-to posts the seal. Nothing
// is held back and nothing is recorded: it is not a request about a target.
func OwnClient(o OwnOptions) *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.ForceAttemptHTTP2 = false
	switch {
	case o.TLS != nil:
		tr.TLSClientConfig = o.TLS
	case o.Insecure:
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10}
	}
	if o.Proxy != nil {
		tr.Proxy = http.ProxyURL(o.Proxy)
	}
	c := &http.Client{Timeout: o.Timeout, Transport: newGuarded(Own, tr, "")}
	if !o.Follow {
		c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	}
	return c
}
