package dnscol

import (
	"context"
	"encoding/json"
	"net"
	"strings"
	"testing"

	"github.com/miekg/dns"

	"github.com/trannghiach/azhaq/internal/dnsr"
	"github.com/trannghiach/azhaq/internal/types"
)

func zone(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	q := r.Question[0]
	name := strings.TrimSuffix(strings.ToLower(q.Name), ".")
	rr := func(s string) dns.RR { x, _ := dns.NewRR(s); return x }
	switch {
	case name == "example.org" && q.Qtype == dns.TypeA:
		m.Answer = append(m.Answer, rr("example.org. 60 IN A 192.0.2.1"))
	case name == "example.org" && q.Qtype == dns.TypeMX:
		m.Answer = append(m.Answer, rr("example.org. 60 IN MX 10 mail.example.org."))
	case name == "example.org" && q.Qtype == dns.TypeNS:
		m.Answer = append(m.Answer, rr("example.org. 60 IN NS ns1.example.org."))
	case name == "example.org" && q.Qtype == dns.TypeTXT:
		m.Answer = append(m.Answer, rr(`example.org. 60 IN TXT "v=spf1 -all"`))
	case name == "example.org":
	case name == "www.example.org" && q.Qtype == dns.TypeA:
		m.Answer = append(m.Answer, rr("www.example.org. 60 IN CNAME edge.example.org."), rr("edge.example.org. 60 IN A 192.0.2.10"))
	case strings.HasSuffix(name, ".apps.example.org") && q.Qtype == dns.TypeA:
		m.Answer = append(m.Answer, rr(name+". 60 IN A 192.0.2.99"))
	case strings.HasSuffix(name, ".apps.example.org"):
	default:
		m.Rcode = dns.RcodeNameError
	}
	_ = w.WriteMsg(m)
}

func TestBatch(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(zone)}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })

	c := New(dnsr.New(dnsr.Options{Resolvers: []string{pc.LocalAddr().String()}, PerSecond: -1}))
	var seeds []types.Seed
	for _, h := range []string{"example.org", "www.example.org", "gone.example.org", "x1.apps.example.org", "127.0.0.1:8080", "app.example.test"} {
		seeds = append(seeds, types.Seed{Type: types.TypeHostname, Keys: map[string]string{"fqdn": h}})
	}
	got := map[string]map[string]any{}
	metas, err := c.RunBatch(context.Background(), seeds, func(s types.Seed, o types.Observation) error {
		var p map[string]any
		_ = json.Unmarshal(o.Payload, &p)
		got[s.Keys["fqdn"]] = p
		return nil
	})
	if err != nil || len(metas) != len(seeds) {
		t.Fatalf("metas %d err %v", len(metas), err)
	}
	if p := got["example.org"]; p["mx"] == nil || p["ns"] == nil || p["txt"] == nil {
		t.Errorf("apex extras %v", p)
	}
	if p := got["www.example.org"]; p["cname"] != "edge.example.org" || metas[1].Drop || len(metas[1].NextHints) != 1 {
		t.Errorf("www %v meta %+v", p, metas[1])
	}
	if p := got["gone.example.org"]; p["error"] != "nxdomain" || !metas[2].Drop {
		t.Errorf("nxdomain %v %+v", p, metas[2])
	}
	if p := got["x1.apps.example.org"]; p["wildcard"] != true || !metas[3].Drop {
		t.Errorf("wildcard %v %+v", p, metas[3])
	}
	if p := got["127.0.0.1:8080"]; p["ips"] == nil || metas[4].Drop {
		t.Errorf("ip:port %v", p)
	}
	if p := got["app.example.test"]; p["skipped"] != "reserved" || metas[5].Drop {
		t.Errorf("reserved names stay probeable %v %+v", p, metas[5])
	}
}
