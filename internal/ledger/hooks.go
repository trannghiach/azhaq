package ledger

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/trannghiach/azhaq/internal/neterr"
)

type collectorKey struct{}

// WithCollector marks ctx with the collector whose work it is, for the
// entries made with it.
func WithCollector(ctx context.Context, name string) context.Context {
	return context.WithValue(ctx, collectorKey{}, name)
}

func collectorOf(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	s, _ := ctx.Value(collectorKey{}).(string)
	return s
}

// HTTP records req, about to be sent to a target. It is a no-op without a
// ledger.
func HTTP(req *http.Request) { HTTPAs(ClassTarget, req) }

// HTTPAs is HTTP for a request of another class.
func HTTPAs(class string, req *http.Request) {
	l := Active()
	if l == nil || req == nil || req.URL == nil {
		return
	}
	method := req.Method
	if method == "" {
		method = http.MethodGet
	}
	host := req.URL.Hostname()
	vhost := req.Host
	if vhost == req.URL.Host || vhost == host {
		vhost = ""
	}
	e := Entry{Kind: "http", Class: class, Method: method, Target: req.URL.Redacted(), Host: host, VHost: vhost,
		Body: bodySum(req), Collector: collectorOf(req.Context())}
	if class == ClassTarget {
		e.Rule = l.rule(host)
	}
	l.Record(e)
}

// bodySum is the start of the sha256 of req's body, "" for none; it reads
// a copy (GetBody), never the body being sent.
func bodySum(req *http.Request) string {
	if req.Body == nil || req.Body == http.NoBody || req.GetBody == nil {
		return ""
	}
	rc, err := req.GetBody()
	if err != nil {
		return ""
	}
	defer rc.Close()
	h := sha256.New()
	if _, err := io.Copy(h, rc); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// Deny, when set, is asked about each request before it is sent: an error
// holds it back (a -deny-path rule). Every client of the run sends through
// Transport, so no collector steps round the rule.
var Deny func(raw string) error

// Unsent is called for a request Transport held back after it was counted
// (fetch gives it back to the budget).
var Unsent func()

// Chrome records a request Chrome sent. ctx may be nil.
func Chrome(ctx context.Context, method, raw string) { ChromeAt(ctx, method, raw, time.Time{}) }

// ChromeAt is Chrome for a request sent at a time already past; zero is now.
func ChromeAt(ctx context.Context, method, raw string, at time.Time) {
	l := Active()
	if l == nil {
		return
	}
	var host string
	if u, err := url.Parse(raw); err == nil {
		host = u.Hostname()
		raw = u.Redacted()
	}
	if method == "" {
		method = http.MethodGet
	}
	l.Record(Entry{Time: at, Kind: "chrome", Class: ClassTarget, Method: method, Target: raw, Host: host,
		Rule: l.rule(host), Collector: collectorOf(ctx)})
}

// TCP records a connection about to be made to a target at addr (ip:port).
// host is the name it was found under, "" when only the address is known.
func TCP(ctx context.Context, host, addr string) { TCPAs(ctx, ClassTarget, host, addr) }

// TCPAs is TCP for a connection of another class.
func TCPAs(ctx context.Context, class, host, addr string) {
	l := Active()
	if l == nil {
		return
	}
	ip, _, err := net.SplitHostPort(addr)
	if err != nil {
		ip = addr
	}
	name := host
	if name == "" {
		name = ip
	}
	var rule string
	if class == ClassTarget {
		if rule = l.rule(name); rule == "" && name != ip {
			rule = l.rule(ip)
		}
	}
	l.Record(Entry{Kind: "tcp", Class: class, Target: addr, Host: host, Rule: rule, Collector: collectorOf(ctx)})
}

// DNS records a query about to be sent to a resolver: the name, its type
// ("A") and the resolver's address or URL.
func DNS(ctx context.Context, name, qtype, server string) {
	l := Active()
	if l == nil {
		return
	}
	l.Record(Entry{Kind: "dns", Class: ClassDNS, Method: qtype, Target: server, Host: name, Rule: l.rule(name), Collector: collectorOf(ctx)})
}

// Transport records each request before it goes to Base, so a request
// that fails still appears. Class is what the requests are sent to
// (ClassTarget when empty); only a target's are held by -deny-path and by
// the writes a killed run sent.
type Transport struct {
	Base  http.RoundTripper
	Class string
}

func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	class := t.Class
	if class == "" {
		class = ClassTarget
	}
	if f := Deny; f != nil && req.URL != nil && class == ClassTarget {
		if err := f(req.URL.String()); err != nil {
			if req.Body != nil {
				req.Body.Close()
			}
			if Unsent != nil {
				Unsent()
			}
			return nil, err
		}
	}
	if l := Active(); l != nil && class == ClassTarget && req.URL != nil && !Safe(req.Method) && l.refused(req.Method, req.URL.Redacted(), bodySum(req), false) {
		if req.Body != nil {
			req.Body.Close()
		}
		if Unsent != nil {
			Unsent()
		}
		return nil, neterr.ErrNotRepeated
	}
	HTTPAs(class, req)
	return t.base().RoundTrip(req)
}

func (t *Transport) base() http.RoundTripper {
	if t.Base == nil {
		return noBase{}
	}
	return t.Base
}

// noBase is what a Transport without a Base sends with: an error. Only
// egress makes the transports a run sends with, and gives each a Base.
type noBase struct{}

func (noBase) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("ledger: the transport has no Base to send with")
}

// CloseIdleConnections passes on to Base, as http.Client looks for it.
func (t *Transport) CloseIdleConnections() {
	if c, ok := t.base().(interface{ CloseIdleConnections() }); ok {
		c.CloseIdleConnections()
	}
}

// Wrap is rt with its requests recorded; a
// transport already wrapped is returned as it is.
func Wrap(rt http.RoundTripper) http.RoundTripper { return WrapAs(ClassTarget, rt) }

// WrapAs is Wrap for requests of another class.
func WrapAs(class string, rt http.RoundTripper) http.RoundTripper {
	if t, ok := rt.(*Transport); ok {
		return t
	}
	return &Transport{Base: rt, Class: class}
}

// Unwrap is the transport under Wrap's, or rt itself.
func Unwrap(rt http.RoundTripper) http.RoundTripper {
	if t, ok := rt.(*Transport); ok {
		return t.base()
	}
	return rt
}
