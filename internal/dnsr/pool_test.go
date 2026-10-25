package dnsr

import (
	"context"
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
