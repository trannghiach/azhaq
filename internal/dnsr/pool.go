// Package dnsr resolves names through a pool of recursive resolvers, with a
// rate limit per resolver, retries on another resolver, and wildcard
// detection per zone.
package dnsr

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/proxy"

	"github.com/trannghiach/azhaq/internal/limit"
	"github.com/trannghiach/azhaq/internal/normalize"
)

// DefaultResolvers are used when none are configured: three operators,
// two addresses each, in pairs (pick asks half the list away for a
// second opinion, so it lands on another operator).
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

// IsBroken says whether err is the SERVFAIL of every attempt, by two
// resolvers or more: the name's own DNS is broken, for everyone.
func IsBroken(err error) bool { return errors.Is(err, errBroken) }

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
	health  map[string]*health // fixed at New: read without p.mu
	limit   *limit.Limiter
	timeout time.Duration
	retries int
	udp     *dns.Client
	tcp     *dns.Client
	dot     *dns.Client
	doh     *http.Client
	proto   map[string]Server   // by key
	named   bool                // the resolvers were given, not the defaults
	dial    proxy.ContextDialer // DNS goes through this (-proxy), over TCP; nil: direct
	next    atomic.Uint64

	// TraceRoots and TracePort replace RootServers and port 53 for Trace
	// (tests, a lab).
	TraceRoots []string
	TracePort  string

	mu    sync.Mutex
	cache map[string]*entry
	six   map[string]*entry // AAAA asked for names that have A records
	wild  map[string]bool   // zones that answer for any label (Wildcards)

	// Exchange replaces the network call (tests).
	Exchange func(ctx context.Context, m *dns.Msg, server string) (*dns.Msg, error)
}

// health counts a resolver's recent attempts and the ones that got no
// answer, halved as they grow so it can recover.
type health struct {
	mu                  sync.Mutex
	tries, fails, skips int
}

func (h *health) note(failed bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.tries++; failed {
		h.fails++
	}
	if h.tries >= 200 {
		h.tries, h.fails = h.tries/2, h.fails/2
	}
}

// sick: a third of its recent queries went unanswered. Quad9 drops about
// half the queries for names a CDN zone serves (2026-10-29), each costing a
// full timeout; the pool stops leaning on it.
func (h *health) sick() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.tries >= 20 && h.fails*3 > h.tries
}

// pass says whether to pass a resolver over: it is sick, and this is not
// the one time in sixteen it is asked anyway, to show it is back.
func (h *health) pass() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.tries < 20 || h.fails*3 <= h.tries {
		return false
	}
	h.skips++
	return h.skips%16 != 0
}

type entry struct {
	once sync.Once
	ans  Answer
}

// Options configure a Pool. Zero values take the defaults.
type Options struct {
	Resolvers []string      // as ParseResolvers gives them; default DefaultResolvers
	PerSecond float64       // queries per second per resolver; 0 is no pace but the callers' workers
	Burst     int           // queries a resolver may be sent at once after a pause; default a fifth of PerSecond, at least 1
	Timeout   time.Duration // per query; default 2s
	Retries   int           // extra attempts on other resolvers; default 2
	Attempts  int           // when set, attempts in all per query (Retries+1), as dnsx -retry
	Proxy     string        // socks5://host:port: every query goes through it, over TCP
}

// New returns a Pool.
func New(o Options) *Pool {
	servers := o.Resolvers
	named := len(servers) > 0
	if !named {
		servers = DefaultResolvers
	}
	var norm []string
	proto := map[string]Server{}
	for _, s := range servers {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		srv, err := ParseResolver(s)
		if err != nil {
			// Not a form ParseResolvers gives: a plain address, as before.
			if _, _, err := net.SplitHostPort(s); err != nil {
				s = net.JoinHostPort(s, "53")
			}
			srv = Server{Key: s, Net: NetUDP, Addr: s}
		}
		if _, dup := proto[srv.Key]; !dup {
			norm = append(norm, srv.Key)
			proto[srv.Key] = srv
		}
	}
	if o.Timeout <= 0 {
		o.Timeout = 2 * time.Second
	}
	if o.Retries == 0 {
		o.Retries = 2
	}
	if o.Attempts > 0 {
		o.Retries = o.Attempts - 1
	}
	hs := map[string]*health{}
	for _, s := range norm {
		hs[s] = &health{}
	}
	p := &Pool{
		servers: norm,
		health:  hs,
		proto:   proto,
		named:   named,
		limit:   limit.New(o.PerSecond, cmpBurst(o)),
		timeout: o.Timeout,
		retries: o.Retries,
		udp:     &dns.Client{Net: "udp", Timeout: o.Timeout},
		tcp:     &dns.Client{Net: "tcp", Timeout: o.Timeout},
		dot:     &dns.Client{Net: "tcp-tls", Timeout: o.Timeout},
		doh:     &http.Client{Timeout: o.Timeout},
		cache:   map[string]*entry{},
		six:     map[string]*entry{},
		wild:    map[string]bool{},
	}
	if u, err := url.Parse(o.Proxy); err == nil && o.Proxy != "" {
		if d, err := proxy.FromURL(u, &net.Dialer{Timeout: o.Timeout}); err == nil {
			if cd, ok := d.(proxy.ContextDialer); ok {
				p.dial = cd
			}
		}
	}
	return p
}

func cmpBurst(o Options) int {
	if o.Burst > 0 {
		return o.Burst
	}
	return max(1, int(o.PerSecond/5))
}

// ProxyError says whether proxy is a URL New can use for DNS.
func ProxyError(raw string) error {
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

// Reserved says whether name is one the pool does not send to its resolvers:
// a special-use name (localhost, *.test, *.local) or a single label, when the
// resolvers are the default public ones. The system's resolver answers
// those, so /etc/hosts and local DNS work and nothing local is asked of a
// public resolver. Resolvers the user named are asked for everything, as
// dnsx does.
func (p *Pool) Reserved(name string) bool {
	name = normalize.Hostname(name)
	return !p.named && net.ParseIP(name) == nil && (normalize.SpecialUse(name) || !strings.Contains(name, "."))
}

// System asks the system's resolver for the addresses of name.
func (p *Pool) System(ctx context.Context, name string) (a, aaaa []string) {
	r := p.system(ctx, normalize.Hostname(name))
	return r.A, r.AAAA
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

// Registered says whether a registrable domain exists in DNS: its SOA is
// answered, or anything but NXDOMAIN is (a failure is taken as existing,
// so nothing is called free that may not be).
func (p *Pool) Registered(ctx context.Context, domain string) bool {
	m, err := p.Query(ctx, domain, dns.TypeSOA)
	return err != nil || m.Rcode != dns.RcodeNameError
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
	q := question(name, dns.TypeA)
	m, from, err := p.query(ctx, q, "")
	if err != nil {
		a.Status, a.Err = StatusFailed, err.Error()
		if errors.Is(err, errBroken) {
			a.Status = StatusBroken
		}
		return a
	}
	// One resolver's NXDOMAIN or empty answer is not the name dead: a
	// public resolver answers NODATA now and then for a name every other
	// one resolves (a stale negative cache, an edge that lost the zone).
	// A second resolver is asked once before the name is called dead, and
	// its addresses win. Names under a wildcard zone and wildcard probes
	// are not worth the query: they answer alike everywhere.
	second := func() bool {
		if !p.confirms(name) {
			return false
		}
		m2, _, err := p.query(ctx, q, from)
		if err != nil || m2.Rcode != dns.RcodeSuccess {
			return false
		}
		if addrs, chain := records(m2, dns.TypeA); len(addrs) > 0 {
			a.A, a.CNAME = addrs, chain
			return true
		}
		return false
	}
	if m.Rcode == dns.RcodeNameError {
		// A generated name (DNS brute force, permutations) that one good
		// resolver says does not exist almost never exists, and confirming
		// every miss would double a wordlist's queries; a NODATA or a
		// dangling CNAME below is still confirmed.
		if !bulk(ctx) && second() {
			a.Status = StatusOK
			return a
		}
		// A CNAME chain the resolver followed to a name that does not exist
		// says where the name points: a dangling one.
		_, a.CNAME = records(m, dns.TypeA)
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
	if !a.Live() {
		second()
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
	m, _, err := p.query(ctx, question(name, qtype), "")
	return m, err
}

// question asks for qtype with EDNS0 and a 4,096-byte buffer, so an answer
// over 512 bytes (a long TXT, many records) arrives over UDP, not after a
// truncation and a second query over TCP.
func question(name string, qtype uint16) *dns.Msg {
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(name), qtype)
	q.RecursionDesired = true
	q.SetEdns0(4096, false)
	return q
}

// query is Query naming the resolver that answered; avoid, when the pool
// has another, is one that is not asked (a second opinion).
func (p *Pool) query(ctx context.Context, q *dns.Msg, avoid string) (*dns.Msg, string, error) {
	if len(p.servers) == 0 {
		return nil, "", errors.New("no resolvers")
	}
	var last error
	var lastMsg *dns.Msg         // the last SERVFAIL or REFUSED, returned with the error
	servfail := map[string]int{} // resolver → attempts it answered SERVFAIL
	for attempt := 0; attempt <= p.retries; attempt++ {
		server := p.pick(attempt, avoid)
		if err := p.limit.Wait(ctx, server); err != nil {
			return nil, "", err
		}
		in, err := p.exchange(ctx, q, server)
		if h := p.health[server]; h != nil && ctx.Err() == nil {
			h.note(err != nil)
		}
		if err != nil {
			last = err
			continue
		}
		if in.Rcode == dns.RcodeServerFailure || in.Rcode == dns.RcodeRefused {
			if in.Rcode == dns.RcodeServerFailure {
				servfail[server]++
			}
			last, lastMsg = errors.New(server+": "+dns.RcodeToString[in.Rcode]), in
			continue
		}
		return in, server, nil
	}
	n := 0
	for _, c := range servfail {
		n += c
	}
	if n == p.retries+1 && len(servfail) >= 2 {
		return lastMsg, "", fmt.Errorf("%w (last %v)", errBroken, last)
	}
	return lastMsg, "", last
}

// pick is the resolver for an attempt: round robin, or, first, for a
// second opinion on what avoid answered, the resolver half the list away
// from it. The list pairs an operator's addresses (1.1.1.1 and 1.0.0.1
// share a cache), so the next one would often answer alike.
func (p *Pool) pick(attempt int, avoid string) string {
	n := len(p.servers)
	if avoid != "" && n > 1 && attempt == 0 {
		for i, s := range p.servers {
			if s == avoid {
				if o := p.servers[(i+n/2)%n]; p.health[o] == nil || !p.health[o].sick() {
					return o
				}
				break
			}
		}
	}
	var first string
	for range n {
		i := p.next.Add(1) - 1
		s := p.servers[int(i)%n]
		if s == avoid && n > 1 {
			continue
		}
		if first == "" {
			first = s
		}
		if h := p.health[s]; h == nil || !h.pass() {
			return s
		}
	}
	if first == "" {
		first = p.servers[0]
	}
	return first
}

type bulkKey struct{}

// Bulk marks ctx as a bulk resolve (DNS brute force, permutations), where
// a plain NXDOMAIN is taken at its word: see resolve. A NODATA answer or a
// dangling CNAME is confirmed either way.
func Bulk(ctx context.Context) context.Context {
	return context.WithValue(ctx, bulkKey{}, true)
}

func bulk(ctx context.Context) bool {
	v, _ := ctx.Value(bulkKey{}).(bool)
	return v
}

// confirms says whether a dead-looking answer for name is worth a second
// resolver's opinion: the pool has one, and the name is neither a
// wildcard probe nor under a zone known to answer for any label.
func (p *Pool) confirms(name string) bool {
	if len(p.servers) < 2 || p.retries < 1 || strings.HasPrefix(name, probePrefix) {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for z := parent(name); z != ""; z = parent(z) {
		if p.wild[z] {
			return false
		}
	}
	return true
}

// wildcard records a zone that answers for any label.
func (p *Pool) wildcard(zone string) {
	p.mu.Lock()
	p.wild[zone] = true
	p.mu.Unlock()
}

func (p *Pool) exchange(ctx context.Context, q *dns.Msg, server string) (*dns.Msg, error) {
	if p.Exchange != nil {
		return p.Exchange(ctx, q, server)
	}
	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	srv, ok := p.proto[server]
	if !ok {
		srv = Server{Key: server, Net: NetUDP, Addr: server}
	}
	switch {
	case srv.Net == NetDoH:
		return p.exchangeDoH(ctx, q, srv)
	case p.dial != nil:
		// Through a proxy everything is TCP: a SOCKS5 proxy carries no UDP
		// here. DoT keeps its TLS inside the tunnel.
		return p.viaProxy(ctx, q, srv)
	case srv.Net == NetTCP:
		in, _, err := p.tcp.ExchangeContext(ctx, q, srv.Addr)
		return in, err
	case srv.Net == NetDoT:
		in, _, err := p.dot.ExchangeContext(ctx, q, srv.Addr)
		return in, err
	}
	in, _, err := p.udp.ExchangeContext(ctx, q, srv.Addr)
	if err == nil && in.Truncated {
		in, _, err = p.tcp.ExchangeContext(ctx, q, srv.Addr)
	}
	return in, err
}

// viaProxy asks one resolver over TCP through the proxy.
func (p *Pool) viaProxy(ctx context.Context, q *dns.Msg, srv Server) (*dns.Msg, error) {
	c, err := p.dial.DialContext(ctx, "tcp", srv.Addr)
	if err != nil {
		return nil, err
	}
	conn := &dns.Conn{Conn: c}
	defer conn.Close()
	client := p.tcp
	if srv.Net == NetDoT {
		client = p.dot
		tc, err := dotConn(ctx, c, srv.Addr, p.dot.TLSConfig)
		if err != nil {
			return nil, err
		}
		conn = &dns.Conn{Conn: tc}
	}
	in, _, err := client.ExchangeWithConnContext(ctx, q, conn)
	return in, err
}

// exchangeDoH asks over HTTPS as RFC 8484 says: the wire message in a
// POST body, or base64url in the dns parameter of a GET.
func (p *Pool) exchangeDoH(ctx context.Context, q *dns.Msg, srv Server) (*dns.Msg, error) {
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
	client := p.doh
	if p.dial != nil {
		client = &http.Client{Timeout: p.timeout, Transport: &http.Transport{DialContext: p.dial.DialContext}}
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
