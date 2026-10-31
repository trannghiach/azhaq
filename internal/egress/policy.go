package egress

import (
	"context"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"

	"golang.org/x/time/rate"

	"github.com/trannghiach/azhaq/internal/ledger"
	"github.com/trannghiach/azhaq/internal/neterr"
)

// Class is what a request or connection is sent to.
type Class string

const (
	// Target: a host the run was pointed at. Held to the scope, -deny-path,
	// the budget, the pace and -proxy.
	Target Class = ledger.ClassTarget
	// Source: a third party asked about the targets (archives, RDAP,
	// search, a notification). Not held to the target scope; held to the
	// kill file and its own proxy, and recorded.
	Source Class = ledger.ClassSource
	// DNS: a resolver.
	DNS Class = ledger.ClassDNS
	// Own: an endpoint of the user's own (a replay proxy, a worker's link to
	// its run, where -seal-to posts). Not a target and not recorded: the
	// ledger holds what was sent about targets.
	Own Class = ledger.ClassOwn
)

// Policy is the controls of one run. There is one in use at a time
// (Current); the CLI builds it from the flags before anything is sent.
type Policy struct {
	mu          sync.RWMutex
	allow       func(host string) bool
	openHeaders map[string]bool
	denyPath    func(raw string) string
	onDenied    func(raw, rule string)
	proxy       *url.URL
	resolver    func(ctx context.Context, host string) []string

	maxReq atomic.Int64
	sent   atomic.Int64

	paceMu sync.Mutex
	pace   *rate.Limiter
	paceR  float64

	kill
}

// Config is what a Policy is built from. A zero Config holds nothing back.
type Config struct {
	// Allow says whether a target host is in scope; nil: every host is.
	Allow func(host string) bool
	// OpenHeaders are host-naming headers (lower case) that are not held to
	// Allow: the user typed what they name.
	OpenHeaders map[string]bool
	// DenyPath returns the -deny-path rule a URL matches, or "".
	DenyPath func(raw string) string
	// OnDenied hears of each request DenyPath kept out.
	OnDenied func(raw, rule string)
	// MaxRequests caps the requests to targets; zero is no cap.
	MaxRequests int64
	// Rate paces the requests to targets, per second over all hosts.
	Rate float64
	// TargetProxy is where every request to a target goes (-proxy); nil: the
	// environment's.
	TargetProxy *url.URL
	// Resolver gives the addresses to connect to for a name; nil: the system's.
	Resolver func(ctx context.Context, host string) []string
}

// New is a Policy holding what cfg says.
func New(cfg Config) *Policy {
	p := &Policy{}
	p.allow, p.openHeaders, p.denyPath, p.onDenied = cfg.Allow, cfg.OpenHeaders, cfg.DenyPath, cfg.OnDenied
	p.proxy, p.resolver = cfg.TargetProxy, cfg.Resolver
	p.maxReq.Store(cfg.MaxRequests)
	p.SetRate(cfg.Rate)
	return p
}

var current atomic.Pointer[Policy]

func init() {
	current.Store(New(Config{}))
	ledger.Unsent = Refund
	ledger.Deny = CheckDenied
}

// Use makes p the policy of the run.
func Use(p *Policy) { current.Store(p) }

// Current is the policy in use: never nil.
func Current() *Policy { return current.Load() }

// Reset puts the policy in use back to holding nothing back, as a new run
// (or a test) starts. A kill file being watched stays watched.
func Reset() { Current().Reset() }

// Reset is Reset for p.
func (p *Policy) Reset() {
	p.mu.Lock()
	p.allow, p.openHeaders, p.denyPath, p.onDenied, p.proxy, p.resolver = nil, nil, nil, nil, nil, nil
	p.mu.Unlock()
	p.maxReq.Store(0)
	p.sent.Store(0)
	p.SetRate(0)
}

// SetScope sets which target hosts are in scope; nil lifts the scope.
func (p *Policy) SetScope(allow func(host string) bool, open map[string]bool) {
	p.mu.Lock()
	p.allow, p.openHeaders = allow, open
	p.mu.Unlock()
}

// SetDenyPath sets the user's -deny-path rules; nil lifts them.
func (p *Policy) SetDenyPath(f func(raw string) string) {
	p.mu.Lock()
	p.denyPath = f
	p.mu.Unlock()
}

// SetOnDenied sets who hears of a request -deny-path kept out; nil: the run's notes.
func (p *Policy) SetOnDenied(f func(raw, rule string)) {
	p.mu.Lock()
	p.onDenied = f
	p.mu.Unlock()
}

// SetTargetProxy sets the proxy for every request to a target (-proxy).
func (p *Policy) SetTargetProxy(u *url.URL) {
	p.mu.Lock()
	p.proxy = u
	p.mu.Unlock()
}

// SetResolver sets the run's resolver; nil goes back to the system's. It
// is swapped whole: a request a finished run left behind may still dial
// while the next run sets it.
func (p *Policy) SetResolver(f func(ctx context.Context, host string) []string) {
	p.mu.Lock()
	p.resolver = f
	p.mu.Unlock()
}

func (p *Policy) scope() (func(string) bool, map[string]bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.allow, p.openHeaders
}

// Scope is the run's scope, nil when it has none.
func (p *Policy) Scope() func(host string) bool {
	a, _ := p.scope()
	return a
}

// Allows says whether a target host is in scope: always without a scope.
func (p *Policy) Allows(host string) bool {
	a, _ := p.scope()
	return a == nil || a(host)
}

// TargetProxy is the proxy for requests to targets, nil for none.
func (p *Policy) TargetProxy() *url.URL {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.proxy
}

// ProxyFor sends a request to a target through -proxy, else as the
// environment says.
func (p *Policy) ProxyFor(r *http.Request) (*url.URL, error) {
	if u := p.TargetProxy(); u != nil {
		return u, nil
	}
	return http.ProxyFromEnvironment(r)
}

// Resolve is the run's answer for host, nil without a resolver.
func (p *Policy) Resolve(ctx context.Context, host string) []string {
	p.mu.RLock()
	f := p.resolver
	p.mu.RUnlock()
	if f != nil {
		return f(ctx, host)
	}
	return nil
}

// DeniedBy is the -deny-path rule that keeps raw out, or "".
func (p *Policy) DeniedBy(raw string) string {
	p.mu.RLock()
	f := p.denyPath
	p.mu.RUnlock()
	if f == nil {
		return ""
	}
	return f(raw)
}

// Noter, when set, takes a line for the run's summary: what -deny-path
// kept out when nothing is listening for it.
var Noter func(text string)

// CheckDenied is nil for a URL no -deny-path rule keeps out, else the error
// to refuse it with; it tells OnDenied. Nothing has been spent or sent.
func (p *Policy) CheckDenied(raw string) error {
	rule := p.DeniedBy(raw)
	if rule == "" {
		return nil
	}
	p.mu.RLock()
	f := p.onDenied
	p.mu.RUnlock()
	switch {
	case f != nil:
		f(raw, rule)
	case Noter != nil:
		Noter(raw + " was not requested: " + DenyReason(rule))
	}
	return &neterr.Denied{Rule: rule}
}

// DenyReason is how a rule is named in a list of what was not requested.
func DenyReason(rule string) string { return "-deny-path " + rule }

// Package-level forms for the policy in use.

// SetScope is Current().SetScope with no open headers.
func SetScope(allow func(host string) bool) { Current().SetScope(allow, nil) }

// HasScope says the run has a scope.
func HasScope() bool { return Current().Scope() != nil }

// Allows is Current().Allows.
func Allows(host string) bool { return Current().Allows(host) }

// DeniedBy is Current().DeniedBy.
func DeniedBy(raw string) string { return Current().DeniedBy(raw) }

// CheckDenied is Current().CheckDenied.
func CheckDenied(raw string) error { return Current().CheckDenied(raw) }

// SetOnDenied is Current().SetOnDenied.
func SetOnDenied(f func(raw, rule string)) { Current().SetOnDenied(f) }

// SetDenyPath is Current().SetDenyPath.
func SetDenyPath(f func(raw string) string) { Current().SetDenyPath(f) }

// SetTargetProxy is Current().SetTargetProxy.
func SetTargetProxy(u *url.URL) { Current().SetTargetProxy(u) }

// TargetProxy is Current().TargetProxy.
func TargetProxy() *url.URL { return Current().TargetProxy() }

// ProxyFor is Current().ProxyFor.
func ProxyFor(r *http.Request) (*url.URL, error) { return Current().ProxyFor(r) }

// SetResolver is Current().SetResolver.
func SetResolver(f func(ctx context.Context, host string) []string) { Current().SetResolver(f) }

// Resolve is Current().Resolve.
func Resolve(ctx context.Context, host string) []string { return Current().Resolve(ctx, host) }
