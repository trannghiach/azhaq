// Package dnsr resolves names through a pool of recursive resolvers, with a
// rate limit per resolver, retries on another resolver, and wildcard
// detection per zone.
package dnsr

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"github.com/trannghiach/azhaq/internal/limit"
	"github.com/trannghiach/azhaq/internal/normalize"
)

// DefaultResolvers are used when none are configured.
var DefaultResolvers = []string{
	"1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112",
}

// Status values of an Answer.
const (
	StatusOK       = "ok"       // A or AAAA records
	StatusCNAME    = "cname"    // a CNAME chain that ends without an address
	StatusNoData   = "nodata"   // the name exists but has no address
	StatusNXDomain = "nxdomain" // the name does not exist
	StatusReserved = "reserved" // special-use name (.test, .local, …); not queried
	StatusFailed   = "failed"   // every resolver tried failed or timed out
	// StatusBroken: every attempt, on two passes, was answered SERVFAIL,
	// by two resolvers or more. They answered alike: the name's own DNS
	// is broken (a lame delegation, dead name servers) for everyone. A
	// REFUSED is the resolver refusing this machine, and one resolver
	// alone may be the broken one: both stay failures.
	StatusBroken = "servfail"
)

// errBroken: every attempt was answered SERVFAIL, by two resolvers or
// more.
var errBroken = errors.New("SERVFAIL from every resolver asked")

// Answer is what a name resolved to.
type Answer struct {
	Name   string
	A      []string
	AAAA   []string
	CNAME  []string // the chain, first hop first
	Status string
	Err    string
}

// Live is true when the name has an address.
func (a Answer) Live() bool { return len(a.A)+len(a.AAAA) > 0 }

// IPs are the A and AAAA addresses.
func (a Answer) IPs() []string { return append(append([]string(nil), a.A...), a.AAAA...) }

// Pool resolves names. It is safe for concurrent use and caches each name
// for the life of the pool.
type Pool struct {
	servers []string
	limit   *limit.Limiter
	timeout time.Duration
	retries int
	udp     *dns.Client
	tcp     *dns.Client
	next    atomic.Uint64

	mu    sync.Mutex
	cache map[string]*entry
	six   map[string]*entry // AAAA asked for names that have A records

	// Exchange replaces the network call (tests).
	Exchange func(ctx context.Context, m *dns.Msg, server string) (*dns.Msg, error)
}

type entry struct {
	once sync.Once
	ans  Answer
}

// Options configure a Pool. Zero values take the defaults.
type Options struct {
	Resolvers []string      // host or host:port; default DefaultResolvers
	PerSecond float64       // queries per second per resolver; default 100
	Timeout   time.Duration // per query; default 2s
	Retries   int           // extra attempts on other resolvers; default 2
}

// New returns a Pool.
func New(o Options) *Pool {
	servers := o.Resolvers
	if len(servers) == 0 {
		servers = DefaultResolvers
	}
	var norm []string
	for _, s := range servers {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, _, err := net.SplitHostPort(s); err != nil {
			s = net.JoinHostPort(s, "53")
		}
		norm = append(norm, s)
	}
	if o.PerSecond == 0 {
		o.PerSecond = 100
	}
	if o.Timeout <= 0 {
		o.Timeout = 2 * time.Second
	}
	if o.Retries == 0 {
		o.Retries = 2
	}
	return &Pool{
		servers: norm,
		limit:   limit.New(o.PerSecond, max(1, int(o.PerSecond/5))),
		timeout: o.Timeout,
		retries: o.Retries,
		udp:     &dns.Client{Net: "udp", Timeout: o.Timeout},
		tcp:     &dns.Client{Net: "tcp", Timeout: o.Timeout},
		cache:   map[string]*entry{},
		six:     map[string]*entry{},
	}
}

// Resolvers lists the servers in use.
func (p *Pool) Resolvers() []string { return append([]string(nil), p.servers...) }

// Resolve returns A, AAAA and the CNAME chain of name. AAAA is asked only
// when there is no A record.
func (p *Pool) Resolve(ctx context.Context, name string) Answer {
	name = normalize.Hostname(name)
	p.mu.Lock()
	e, ok := p.cache[name]
	if !ok {
		e = &entry{}
		p.cache[name] = e
	}
	p.mu.Unlock()
	e.once.Do(func() { e.ans = p.resolve(ctx, name) })
	return e.ans
}

// ResolveBoth is Resolve with the AAAA records of names that also have
// A records: what a connection needs on a network that prefers IPv6.
func (p *Pool) ResolveBoth(ctx context.Context, name string) Answer {
	a := p.Resolve(ctx, name)
	if len(a.A) == 0 || len(a.AAAA) > 0 || a.Status != StatusOK {
		return a
	}
	name = normalize.Hostname(name)
	p.mu.Lock()
	e, ok := p.six[name]
	if !ok {
		e = &entry{}
		p.six[name] = e
	}
	p.mu.Unlock()
	e.once.Do(func() {
		if m, err := p.Query(ctx, name, dns.TypeAAAA); err == nil && m.Rcode == dns.RcodeSuccess {
			e.ans.AAAA, _ = records(m, dns.TypeAAAA)
		}
	})
	a.AAAA = e.ans.AAAA
	return a
}

// ResolveMany resolves names with up to workers queries in flight and
// returns answers in the same order. Names whose every attempt failed
// (timeouts, SERVFAIL under load) get a second pass at a quarter of the
// concurrency, so a burst of dropped queries does not lose names.
func (p *Pool) ResolveMany(ctx context.Context, names []string, workers int) []Answer {
	if workers <= 0 {
		workers = 64
	}
	out := p.resolveMany(ctx, names, workers)
	var again []string
	var at []int
	for i, a := range out {
		if (a.Status == StatusFailed || a.Status == StatusBroken) && ctx.Err() == nil {
			p.forget(a.Name)
			again = append(again, names[i])
			at = append(at, i)
		}
	}
	if len(again) > 0 {
		for j, a := range p.resolveMany(ctx, again, max(workers/4, 4)) {
			out[at[j]] = a
		}
	}
	return out
}

// forget drops a cached answer so the next Resolve asks again.
func (p *Pool) forget(name string) {
	p.mu.Lock()
	delete(p.cache, normalize.Hostname(name))
	p.mu.Unlock()
}

func (p *Pool) resolveMany(ctx context.Context, names []string, workers int) []Answer {
	out := make([]Answer, len(names))
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	for i, n := range names {
		wg.Add(1)
		go func(i int, n string) {
			defer wg.Done()
			select {
			case <-ctx.Done():
				out[i] = Answer{Name: n, Status: StatusFailed, Err: ctx.Err().Error()}
				return
			case sem <- struct{}{}:
			}
			defer func() { <-sem }()
			out[i] = p.Resolve(ctx, n)
		}(i, n)
	}
	wg.Wait()
	return out
}

func (p *Pool) resolve(ctx context.Context, name string) Answer {
	a := Answer{Name: name}
	if normalize.SpecialUse(name) || !strings.Contains(name, ".") {
		// localhost, *.test, *.local, single labels: public resolvers do not
		// know them, but /etc/hosts or the local resolver may.
		return p.system(ctx, name)
	}
	m, err := p.Query(ctx, name, dns.TypeA)
	if err != nil {
		a.Status, a.Err = StatusFailed, err.Error()
		if errors.Is(err, errBroken) {
			a.Status = StatusBroken
		}
		return a
	}
	if m.Rcode == dns.RcodeNameError {
		a.Status = StatusNXDomain
		return a
	}
	a.A, a.CNAME = records(m, dns.TypeA)
	if len(a.A) == 0 {
		if m6, err := p.Query(ctx, name, dns.TypeAAAA); err == nil && m6.Rcode == dns.RcodeSuccess {
			var chain []string
			a.AAAA, chain = records(m6, dns.TypeAAAA)
			if len(a.CNAME) == 0 {
				a.CNAME = chain
			}
		}
	}
	switch {
	case a.Live():
		a.Status = StatusOK
	case len(a.CNAME) > 0:
		a.Status = StatusCNAME
	default:
		a.Status = StatusNoData
	}
	return a
}

func (p *Pool) system(ctx context.Context, name string) Answer {
	a := Answer{Name: name, Status: StatusReserved}
	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, name)
	if err != nil || len(ips) == 0 {
		return a
	}
	for _, ip := range ips {
		if v4 := ip.IP.To4(); v4 != nil {
			a.A = append(a.A, v4.String())
		} else {
			a.AAAA = append(a.AAAA, ip.IP.String())
		}
	}
	a.Status = StatusOK
	return a
}

// Query sends one question, moving to another resolver on a timeout,
// SERVFAIL or REFUSED, and retrying over TCP when the answer is truncated.
func (p *Pool) Query(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
	if len(p.servers) == 0 {
		return nil, errors.New("no resolvers")
	}
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(name), qtype)
	q.RecursionDesired = true
	var last error
	servfail := map[string]int{} // resolver → attempts it answered SERVFAIL
	for attempt := 0; attempt <= p.retries; attempt++ {
		server := p.servers[int(p.next.Add(1)-1)%len(p.servers)]
		if err := p.limit.Wait(ctx, server); err != nil {
			return nil, err
		}
		in, err := p.exchange(ctx, q, server)
		if err != nil {
			last = err
			continue
		}
		if in.Rcode == dns.RcodeServerFailure || in.Rcode == dns.RcodeRefused {
			if in.Rcode == dns.RcodeServerFailure {
				servfail[server]++
			}
			last = errors.New(server + ": " + dns.RcodeToString[in.Rcode])
			continue
		}
		return in, nil
	}
	n := 0
	for _, c := range servfail {
		n += c
	}
	if n == p.retries+1 && len(servfail) >= 2 {
		return nil, fmt.Errorf("%w (last %v)", errBroken, last)
	}
	return nil, last
}

func (p *Pool) exchange(ctx context.Context, q *dns.Msg, server string) (*dns.Msg, error) {
	if p.Exchange != nil {
		return p.Exchange(ctx, q, server)
	}
	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	in, _, err := p.udp.ExchangeContext(ctx, q, server)
	if err == nil && in.Truncated {
		in, _, err = p.tcp.ExchangeContext(ctx, q, server)
	}
	return in, err
}

// records returns the addresses of type qtype and the CNAME chain in m.
func records(m *dns.Msg, qtype uint16) (addrs, chain []string) {
	for _, rr := range m.Answer {
		switch r := rr.(type) {
		case *dns.A:
			if qtype == dns.TypeA {
				addrs = append(addrs, r.A.String())
			}
		case *dns.AAAA:
			if qtype == dns.TypeAAAA {
				addrs = append(addrs, r.AAAA.String())
			}
		case *dns.CNAME:
			chain = append(chain, normalize.Hostname(r.Target))
		}
	}
	return addrs, chain
}
