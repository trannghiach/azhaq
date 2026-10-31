package ledger

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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

// HTTP records req, about to be sent. It is a no-op without a ledger.
func HTTP(req *http.Request) {
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
	l.Record(Entry{Kind: "http", Method: method, Target: req.URL.Redacted(), Host: host, VHost: vhost,
		Body: bodySum(req), Rule: l.rule(host), Collector: collectorOf(req.Context())})
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
	l.Record(Entry{Time: at, Kind: "chrome", Method: method, Target: raw, Host: host,
		Rule: l.rule(host), Collector: collectorOf(ctx)})
}

// TCP records a connection about to be made to addr (ip:port). host is the
// name it was found under, "" when only the address is known.
func TCP(ctx context.Context, host, addr string) {
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
	rule := l.rule(name)
	if rule == "" && name != ip {
		rule = l.rule(ip)
	}
	l.Record(Entry{Kind: "tcp", Target: addr, Host: host, Rule: rule, Collector: collectorOf(ctx)})
}

// Transport records each request before it goes to Base, so a request
// that fails still appears.
type Transport struct{ Base http.RoundTripper }

func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if f := Deny; f != nil && req.URL != nil {
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
	if l := Active(); l != nil && req.URL != nil && !Safe(req.Method) && l.refused(req.Method, req.URL.Redacted(), bodySum(req), false) {
		if req.Body != nil {
			req.Body.Close()
		}
		if Unsent != nil {
			Unsent()
		}
		return nil, neterr.ErrNotRepeated
	}
	HTTP(req)
	return t.base().RoundTrip(req)
}

func (t *Transport) base() http.RoundTripper {
	if t.Base == nil {
		return http.DefaultTransport
	}
	return t.Base
}

// CloseIdleConnections passes on to Base, as http.Client looks for it.
func (t *Transport) CloseIdleConnections() {
	if c, ok := t.base().(interface{ CloseIdleConnections() }); ok {
		c.CloseIdleConnections()
	}
}

// Wrap is rt (nil: the default transport) with its requests recorded; a
// transport already wrapped is returned as it is.
func Wrap(rt http.RoundTripper) http.RoundTripper {
	if t, ok := rt.(*Transport); ok {
		return t
	}
	return &Transport{Base: rt}
}

// Unwrap is the transport under Wrap's, or rt itself.
func Unwrap(rt http.RoundTripper) http.RoundTripper {
	if t, ok := rt.(*Transport); ok {
		return t.base()
	}
	return rt
}
