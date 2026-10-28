package dnscol

import (
	"context"
	"encoding/json"
	"net"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"github.com/trannghiach/azhaq/internal/dnsr"
	"github.com/trannghiach/azhaq/types"
)

// A name whose CNAME chain ends at a name that does not exist: on a
// service anyone may create names on, or under a domain nobody holds, it
// is a takeover candidate; a CNAME to the owner's own name is not.
func TestDanglingCNAME(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no UDP: %v", err)
	}
	zone := map[string]string{
		"azure.example.org.":  "gone-app.azurewebsites.net.",
		"vendor.example.org.": "cdn.forgotten-vendor-xyz.io.",
		"own.example.org.":    "missing.example.org.",
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		q := r.Question[0]
		if target, ok := zone[q.Name]; ok && q.Qtype == dns.TypeA {
			m.Answer = append(m.Answer, &dns.CNAME{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60}, Target: target})
		}
		if q.Qtype == dns.TypeSOA && strings.HasSuffix(q.Name, "azurewebsites.net.") {
			_ = w.WriteMsg(m)
			return
		}
		m.Rcode = dns.RcodeNameError // every CNAME target, and forgotten-vendor-xyz.io itself, does not exist
		_ = w.WriteMsg(m)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	defer srv.Shutdown()
	c := New(dnsr.New(dnsr.Options{Resolvers: []string{pc.LocalAddr().String()}, PerSecond: -1}))
	got := map[string]map[string]any{}
	for _, host := range []string{"azure.example.org", "vendor.example.org", "own.example.org"} {
		seed := types.Seed{Type: types.TypeHostname, Keys: map[string]string{"fqdn": host}}
		_, err := c.Run(context.Background(), seed, func(o types.Observation) error {
			var p map[string]any
			_ = json.Unmarshal(o.Payload, &p)
			got[host] = p
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if f, _ := got["azure.example.org"]["takeover"].(map[string]any); f["service"] != "Azure" || f["strength"] != "dangling" {
		t.Errorf("azure %v", got["azure.example.org"])
	}
	if f, _ := got["vendor.example.org"]["takeover"].(map[string]any); f["service"] != "domain" || f["strength"] != "strong" {
		t.Errorf("vendor %v", got["vendor.example.org"])
	}
	if got["own.example.org"]["takeover"] != nil {
		t.Errorf("own name %v", got["own.example.org"])
	}
}
