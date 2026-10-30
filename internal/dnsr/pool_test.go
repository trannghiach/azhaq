package dnsr

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// testZone answers for example.org. *.wild.example.org is a wildcard.
func testZone(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	q := r.Question[0]
	name := strings.TrimSuffix(strings.ToLower(q.Name), ".")
	a := func(n, ip string) dns.RR { rr, _ := dns.NewRR(n + ". 60 IN A " + ip); return rr }
	switch {
	case name == "www.example.org" && q.Qtype == dns.TypeA:
		m.Answer = append(m.Answer, a(name, "192.0.2.10"))
	case name == "api.example.org" && q.Qtype == dns.TypeA:
		cn, _ := dns.NewRR("api.example.org. 60 IN CNAME www.example.org.")
		m.Answer = append(m.Answer, cn, a("www.example.org", "192.0.2.10"))
	case name == "v6.example.org" && q.Qtype == dns.TypeAAAA:
		rr, _ := dns.NewRR("v6.example.org. 60 IN AAAA 2001:db8::1")
		m.Answer = append(m.Answer, rr)
	case name == "v6.example.org":
	case name == "real.wild.example.org" && q.Qtype == dns.TypeA:
		m.Answer = append(m.Answer, a(name, "192.0.2.50"))
	case strings.HasSuffix(name, ".wild.example.org") && q.Qtype == dns.TypeA:
		m.Answer = append(m.Answer, a(name, "192.0.2.99"))
	case strings.HasSuffix(name, ".wild.example.org"):
	default:
		m.Rcode = dns.RcodeNameError
	}
	_ = w.WriteMsg(m)
}

func serve(t *testing.T, h dns.HandlerFunc) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no UDP: %v", err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: h}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String()
}

func TestResolveRecords(t *testing.T) {
	p := New(Options{Resolvers: []string{serve(t, testZone)}, PerSecond: -1})
	ctx := context.Background()
	cases := map[string]string{
		"www.example.org":  "ok",
		"api.example.org":  "ok",
		"v6.example.org":   "ok",
		"dead.example.org": "nxdomain",
		"app.example.test": "reserved",
	}
	for name, want := range cases {
		if a := p.Resolve(ctx, name); a.Status != want {
			t.Errorf("%s: status %s (%+v), want %s", name, a.Status, a, want)
		}
	}
	if a := p.Resolve(ctx, "api.example.org"); len(a.CNAME) != 1 || a.CNAME[0] != "www.example.org" || a.A[0] != "192.0.2.10" {
		t.Errorf("cname chain %+v", a)
	}
	if a := p.Resolve(ctx, "v6.example.org"); len(a.AAAA) != 1 {
		t.Errorf("aaaa %+v", a)
	}
}

func TestRetryOnAnotherResolver(t *testing.T) {
	var bad atomic.Int32
	failing := serve(t, func(w dns.ResponseWriter, r *dns.Msg) {
		bad.Add(1)
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeServerFailure)
		_ = w.WriteMsg(m)
	})
	good := serve(t, testZone)
	p := New(Options{Resolvers: []string{failing, good}, PerSecond: -1, Timeout: time.Second})
	for _, n := range []string{"www.example.org", "api.example.org", "dead.example.org"} {
		if a := p.Resolve(context.Background(), n); a.Status == StatusFailed {
			t.Fatalf("%s failed: %+v", n, a)
		}
	}
	if bad.Load() == 0 {
		t.Fatal("round robin never used the failing resolver")
	}
}

func TestCacheAndMany(t *testing.T) {
	var n atomic.Int32
	addr := serve(t, func(w dns.ResponseWriter, r *dns.Msg) {
		n.Add(1)
		testZone(w, r)
	})
	p := New(Options{Resolvers: []string{addr}, PerSecond: -1})
	names := []string{"www.example.org", "www.example.org", "dead.example.org", "www.example.org"}
	got := p.ResolveMany(context.Background(), names, 8)
	if got[0].Status != StatusOK || got[2].Status != StatusNXDomain || got[3].A[0] != "192.0.2.10" {
		t.Fatalf("answers %+v", got)
	}
	if n.Load() != 2 {
		t.Fatalf("queries %d, want 2 (each name once)", n.Load())
	}
}

func TestWildcard(t *testing.T) {
	p := New(Options{Resolvers: []string{serve(t, testZone)}, PerSecond: -1})
	w := NewWildcards(p)
	ctx := context.Background()
	check := func(name string, want bool) {
		t.Helper()
		if got := w.Match(ctx, name, "example.org", p.Resolve(ctx, name)); got != want {
			t.Errorf("%s: wildcard=%v, want %v", name, got, want)
		}
	}
	check("anything.wild.example.org", true)
	check("deep.er.wild.example.org", true)
	check("real.wild.example.org", false)
	check("www.example.org", false)
	if !w.Zone(ctx, "wild.example.org") || w.Zone(ctx, "example.org") {
		t.Error("zone detection")
	}
}

func TestManyRetriesFailedNames(t *testing.T) {
	// The first three queries for www get SERVFAIL (every attempt of the
	// first pass); the second pass gets an answer.
	var www atomic.Int32
	addr := serve(t, func(w dns.ResponseWriter, r *dns.Msg) {
		if strings.HasPrefix(r.Question[0].Name, "www.") && www.Add(1) <= 3 {
			m := new(dns.Msg)
			m.SetRcode(r, dns.RcodeServerFailure)
			_ = w.WriteMsg(m)
			return
		}
		testZone(w, r)
	})
	p := New(Options{Resolvers: []string{addr}, PerSecond: -1, Timeout: time.Second})
	got := p.ResolveMany(context.Background(), []string{"www.example.org", "dead.example.org"}, 8)
	if got[0].Status != StatusOK || got[1].Status != StatusNXDomain {
		t.Fatalf("answers %+v", got)
	}
}

// Two resolvers answering SERVFAIL, on both passes, is the name's own
// DNS broken: an answer, not a failure of the run. One resolver alone, a
// REFUSED and silence stay failures.
func TestBrokenNameIsNotAFailure(t *testing.T) {
	answer := func(rcode int) string {
		return serve(t, func(w dns.ResponseWriter, r *dns.Msg) {
			m := new(dns.Msg)
			m.SetRcode(r, rcode)
			_ = w.WriteMsg(m)
		})
	}
	sf1, sf2 := answer(dns.RcodeServerFailure), answer(dns.RcodeServerFailure)
	p := New(Options{Resolvers: []string{sf1, sf2}, PerSecond: -1, Timeout: time.Second})
	if got := p.ResolveMany(context.Background(), []string{"lame.example.org"}, 4); got[0].Status != StatusBroken || got[0].Live() {
		t.Fatalf("lame delegation %+v", got[0])
	}
	for name, rs := range map[string][]string{"one resolver": {sf1}, "refused": {answer(dns.RcodeRefused), answer(dns.RcodeRefused)}} {
		p = New(Options{Resolvers: rs, PerSecond: -1, Timeout: time.Second})
		if got := p.ResolveMany(context.Background(), []string{"www.example.org"}, 4); got[0].Status != StatusFailed {
			t.Errorf("%s: %+v", name, got[0])
		}
	}
	silent := serve(t, func(w dns.ResponseWriter, r *dns.Msg) {})
	p = New(Options{Resolvers: []string{silent}, PerSecond: -1, Timeout: 100 * time.Millisecond})
	if got := p.ResolveMany(context.Background(), []string{"www.example.org"}, 4); got[0].Status != StatusFailed {
		t.Fatalf("no answer at all %+v", got[0])
	}
}

// One resolver's NODATA or NXDOMAIN is checked with another before the
// name is called dead: a public resolver answers NODATA now and then for
// a name every other one resolves.
func TestSecondResolverBeforeDead(t *testing.T) {
	var flakyAsked atomic.Int32
	flaky := serve(t, func(w dns.ResponseWriter, r *dns.Msg) {
		flakyAsked.Add(1)
		m := new(dns.Msg)
		m.SetReply(r)
		if strings.HasPrefix(r.Question[0].Name, "api.") {
			m.Rcode = dns.RcodeNameError
		}
		_ = w.WriteMsg(m) // NODATA for everything else
	})
	good := serve(t, testZone)
	p := New(Options{Resolvers: []string{flaky, good}, PerSecond: -1, Timeout: time.Second})
	ctx := context.Background()
	if a := p.Resolve(ctx, "www.example.org"); a.Status != StatusOK || a.A[0] != "192.0.2.10" {
		t.Fatalf("nodata from one resolver: %+v", a)
	}
	if a := p.Resolve(ctx, "api.example.org"); a.Status != StatusOK || len(a.CNAME) != 1 {
		t.Fatalf("nxdomain from one resolver: %+v", a)
	}
	if flakyAsked.Load() == 0 {
		t.Fatal("the flaky resolver was never asked")
	}
}

// Two resolvers agreeing cost one extra query per dead-looking name, and
// a wildcard probe gets none.
func TestDeadNameAgreedByTwo(t *testing.T) {
	var n atomic.Int32
	count := func(w dns.ResponseWriter, r *dns.Msg) { n.Add(1); testZone(w, r) }
	p := New(Options{Resolvers: []string{serve(t, count), serve(t, count)}, PerSecond: -1, Timeout: time.Second})
	ctx := context.Background()
	if a := p.Resolve(ctx, "dead.example.org"); a.Status != StatusNXDomain {
		t.Fatalf("%+v", a)
	}
	if n.Load() != 2 {
		t.Fatalf("queries %d, want 2 (one per resolver)", n.Load())
	}
	n.Store(0)
	if a := p.Resolve(ctx, probePrefix+"abc.example.org"); a.Status != StatusNXDomain || n.Load() != 1 {
		t.Fatalf("probe %+v asked %d resolvers", a, n.Load())
	}
	n.Store(0)
	p.wildcard("example.org")
	if a := p.Resolve(ctx, "gone.example.org"); a.Status != StatusNXDomain || n.Load() != 1 {
		t.Fatalf("under a wildcard zone %+v asked %d resolvers", a, n.Load())
	}
}

// A bulk resolve (DNS brute force) takes a plain NXDOMAIN at its word: one
// query per miss, not two. A NODATA answer is still confirmed.
func TestBulkSkipsNXDOMAINSecondOpinion(t *testing.T) {
	var n atomic.Int32
	count := func(w dns.ResponseWriter, r *dns.Msg) { n.Add(1); testZone(w, r) }
	p := New(Options{Resolvers: []string{serve(t, count), serve(t, count)}, PerSecond: -1, Timeout: time.Second})
	ctx := Bulk(context.Background())
	if a := p.Resolve(ctx, "missing.example.org"); a.Status != StatusNXDomain || n.Load() != 1 {
		t.Fatalf("bulk nxdomain %+v asked %d resolvers, want 1", a, n.Load())
	}
	// A real name still resolves, and a NODATA name is still confirmed.
	n.Store(0)
	if a := p.Resolve(ctx, "www.example.org"); a.Status != StatusOK {
		t.Fatalf("bulk real name %+v", a)
	}
}

func TestSickResolverBenchedAndRecovers(t *testing.T) {
	for _, n := range []int{2, 6} {
		var servers []string
		for i := range n {
			servers = append(servers, fmt.Sprintf("192.0.2.%d:53", i+1))
		}
		bad := servers[n-1] // an odd index: the turn it gets must not hang on it
		var dropped, answered atomic.Int32
		p := New(Options{Resolvers: servers, PerSecond: -1})
		p.Exchange = func(_ context.Context, m *dns.Msg, server string) (*dns.Msg, error) {
			if server == bad {
				if dropped.Load() < 40 {
					dropped.Add(1)
					return nil, errors.New("i/o timeout")
				}
				answered.Add(1)
			}
			r := new(dns.Msg)
			r.SetRcode(m, dns.RcodeNameError)
			return r, nil
		}
		names := make([]string, 4000)
		for i := range names {
			names[i] = fmt.Sprintf("n%d.example.org", i)
		}
		for _, a := range p.ResolveMany(Bulk(context.Background()), names, 1) {
			if a.Status != StatusNXDomain {
				t.Fatalf("%+v", a)
			}
		}
		// Benched after its first drops, yet still asked now and then.
		if a := answered.Load(); a < 20 {
			t.Fatalf("%d resolvers: the one that came back was asked %d times after", n, a)
		}
	}
}

// A resolver whose NXDOMAINs a second resolver has confirmed trustedAfter
// times running is asked about one in auditEvery only; the first one it
// gets wrong brings the second opinions back.
func TestTrustedNXDOMAINIsAuditedNotRepeated(t *testing.T) {
	var asked atomic.Int32
	var lie atomic.Bool
	liar := func(w dns.ResponseWriter, r *dns.Msg) {
		asked.Add(1)
		if lie.Load() && r.Question[0].Qtype == dns.TypeA && strings.HasPrefix(r.Question[0].Name, "www.") {
			m := new(dns.Msg)
			m.SetReply(r)
			m.Rcode = dns.RcodeNameError
			_ = w.WriteMsg(m)
			return
		}
		testZone(w, r)
	}
	honest := func(w dns.ResponseWriter, r *dns.Msg) { asked.Add(1); testZone(w, r) }
	p := New(Options{Resolvers: []string{serve(t, liar), serve(t, honest)}, PerSecond: -1, Timeout: time.Second})
	ctx := context.Background()
	dead := func(n int, prefix string) {
		for i := range n {
			if a := p.Resolve(ctx, fmt.Sprintf("%s%d.example.org", prefix, i)); a.Status != StatusNXDomain {
				t.Fatalf("%+v", a)
			}
		}
	}
	dead(2*trustedAfter+8, "a") // each resolver is confirmed trustedAfter times: two queries a name
	if got, want := int(asked.Load()), 2*(2*trustedAfter+8); got < want-8 {
		t.Fatalf("%d queries before trust, want about %d", got, want)
	}
	asked.Store(0)
	const n = 8 * auditEvery
	dead(n, "b")
	if got := int(asked.Load()); got > n+n/4 {
		t.Fatalf("%d queries for %d trusted names: they are still confirmed one by one", got, n)
	}
	// A name with a CNAME chain is always confirmed.
	if a := p.Resolve(ctx, "api.example.org"); a.Status != StatusOK {
		t.Fatalf("%+v", a)
	}
	// A resolver that now says NXDOMAIN for a name that exists is caught
	// by the audit, and confirmed name by name again.
	lie.Store(true)
	for range 4 * auditEvery {
		p.forget("www.example.org")
		p.Resolve(ctx, "www.example.org")
	}
	h := p.health[p.servers[0]]
	h.mu.Lock()
	agree := h.nxAgree
	h.mu.Unlock()
	if agree >= trustedAfter {
		t.Errorf("a resolver that lied is still trusted (%d)", agree)
	}
}

// An answer too big for 512 bytes (a long CNAME chain, many addresses) is
// asked for with EDNS0 and arrives in one datagram: a name with a big
// answer is not a failed lookup.
func TestBigAnswerFitsWithEDNS0(t *testing.T) {
	big := func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		opt := r.IsEdns0()
		if opt == nil || opt.UDPSize() < 1232 {
			m.Truncated = true // what a real server does to a plain query
			_ = w.WriteMsg(m)
			return
		}
		m.Compress = true
		for i := range 50 {
			rr, _ := dns.NewRR(fmt.Sprintf("big.example.org. 60 IN A 192.0.2.%d", i+1))
			m.Answer = append(m.Answer, rr)
		}
		m.SetEdns0(1232, false)
		_ = w.WriteMsg(m)
	}
	p := New(Options{Resolvers: []string{serve(t, big)}, PerSecond: -1, Timeout: time.Second})
	if a := p.Resolve(context.Background(), "big.example.org"); a.Status != StatusOK || len(a.A) != 50 {
		t.Fatalf("%+v", a)
	}
}
