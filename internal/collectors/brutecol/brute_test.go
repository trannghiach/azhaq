package brutecol

import (
	"context"
	"encoding/json"
	"net"
	"sort"
	"strings"
	"testing"

	"github.com/miekg/dns"

	"github.com/trannghiach/azhaq/internal/dnsr"
	"github.com/trannghiach/azhaq/internal/types"
)

// live names in example.org; *.wild.example.org is a wildcard.
var live = map[string]bool{"www.example.org": true, "api.example.org": true, "api2.example.org": true, "dev-api.example.org": true}

func pool(t *testing.T) *dnsr.Pool {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		q := r.Question[0]
		name := strings.TrimSuffix(q.Name, ".")
		switch {
		case (live[name] || strings.HasSuffix(name, ".wild.example.org")) && q.Qtype == dns.TypeA:
			rr, _ := dns.NewRR(q.Name + " 60 IN A 192.0.2.1")
			m.Answer = append(m.Answer, rr)
		case live[name] || strings.HasSuffix(name, ".wild.example.org"):
		default:
			m.Rcode = dns.RcodeNameError
		}
		_ = w.WriteMsg(m)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return dnsr.New(dnsr.Options{Resolvers: []string{pc.LocalAddr().String()}, PerSecond: -1})
}

func names(t *testing.T, o types.Observation) []string {
	t.Helper()
	var p struct {
		Names []string `json:"names"`
	}
	if err := json.Unmarshal(o.Payload, &p); err != nil {
		t.Fatal(err)
	}
	sort.Strings(p.Names)
	return p.Names
}

func TestBrute(t *testing.T) {
	p := pool(t)
	b := &Brute{Pool: p, Wild: dnsr.NewWildcards(p), Words: []string{"www", "api", "nope", "Bad Word", "x.wild", "# comment"}}
	var got types.Observation
	meta, err := b.Run(context.Background(), types.Seed{Type: types.TypeDomain, Keys: map[string]string{"domain": "example.org"}},
		func(o types.Observation) error { got = o; return nil })
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Join(names(t, got), ","); n != "api.example.org,www.example.org" {
		t.Fatalf("found %s (wildcard names must be dropped)", n)
	}
	if len(meta.NextHints) != 2 {
		t.Fatalf("hints %+v", meta.NextHints)
	}
}

func TestPermute(t *testing.T) {
	p := pool(t)
	perm := &Permute{Pool: p, Wild: dnsr.NewWildcards(p), Words: []string{"dev", "test"}}
	var got types.Observation
	_, err := perm.Run(context.Background(), types.Seed{Type: types.TypeHostname, Keys: map[string]string{"fqdn": "api.example.org"}},
		func(o types.Observation) error { got = o; return nil })
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Join(names(t, got), ","); n != "api2.example.org,dev-api.example.org" {
		t.Fatalf("found %s", n)
	}
	// Each candidate is tried once per run.
	var again types.Observation
	_, _ = perm.Run(context.Background(), types.Seed{Type: types.TypeHostname, Keys: map[string]string{"fqdn": "api.example.org"}},
		func(o types.Observation) error { again = o; return nil })
	if again.Payload != nil {
		t.Fatalf("second run retried candidates: %s", again.Payload)
	}
}

func TestVariants(t *testing.T) {
	v := strings.Join(variants("web-01.example.org", []string{"dev"}), " ")
	for _, want := range []string{"web-02.example.org", "web-00.example.org", "dev-web-01.example.org", "dev.example.org", "dev.web-01.example.org"} {
		if !strings.Contains(v, want) {
			t.Errorf("missing %s in %s", want, v)
		}
	}
}
