package main

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

const estateZones = `{
  "axfr": false,
  "zones": {
    "northwind.test.": {
      "northwind.test.": ["SOA ns1.northwind.test. hostmaster.northwind.test. 1 3600 600 86400 60", "NS ns1.northwind.test.", "A 127.31.0.5"],
      "ns1.northwind.test.": ["A 127.0.0.1"],
      "ci.northwind.test.": ["A 127.31.0.10"],
      "www.northwind.test.": ["CNAME northwind.test."],
      "*.dev.northwind.test.": ["A 127.31.0.20"],
      "box.dev.northwind.test.": ["A 127.31.0.21"]
    }
  },
  "ptr": {
    "0.31.127.in-addr.arpa.": {
      "@": ["SOA ns1.northwind.test. hostmaster.northwind.test. 1 3600 600 86400 60", "NS ns1.northwind.test."],
      "10": ["ci.northwind.test."]
    }
  }
}`

// serve runs h on loopback and returns its UDP and TCP address.
func serve(t *testing.T, h dns.HandlerFunc) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := pc.LocalAddr().String()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	mux := dns.NewServeMux()
	mux.HandleFunc(".", h)
	started := make(chan struct{}, 2)
	u := &dns.Server{PacketConn: pc, Handler: mux, NotifyStartedFunc: func() { started <- struct{}{} }}
	c := &dns.Server{Listener: ln, Handler: mux, NotifyStartedFunc: func() { started <- struct{}{} }}
	go func() { _ = u.ActivateAndServe() }()
	go func() { _ = c.ActivateAndServe() }()
	<-started
	<-started
	t.Cleanup(func() { _ = u.Shutdown(); _ = c.Shutdown() })
	return addr
}

func ask(t *testing.T, addr, name string, qtype uint16) *dns.Msg {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(name, qtype)
	in, _, err := (&dns.Client{Timeout: 2 * time.Second}).Exchange(m, addr)
	if err != nil {
		t.Fatalf("ask %s: %v", name, err)
	}
	return in
}

func newTestHandler(lab *labData) dns.HandlerFunc {
	// The upstream is a closed port: only names the zones hold may answer.
	return handler(lab, newCounters(), "127.0.0.1:1", 0, false)
}

func TestZoneFileServesItsZones(t *testing.T) {
	lab, err := loadZones([]byte(estateZones))
	if err != nil {
		t.Fatal(err)
	}
	addr := serve(t, newTestHandler(lab))

	if in := ask(t, addr, "ci.northwind.test.", dns.TypeA); len(in.Answer) != 1 || in.Answer[0].(*dns.A).A.String() != "127.31.0.10" || !in.Authoritative {
		t.Fatalf("ci: %v", in)
	}
	if in := ask(t, addr, "www.northwind.test.", dns.TypeA); len(in.Answer) < 1 || in.Answer[0].Header().Rrtype != dns.TypeCNAME {
		t.Fatalf("a CNAME to the apex should be followed: %v", in)
	}
	if in := ask(t, addr, "nope.northwind.test.", dns.TypeA); in.Rcode != dns.RcodeNameError {
		t.Fatalf("a missing name must be NXDOMAIN, got %v", in)
	}
	// A wildcard answers what the zone does not hold; a real name below it wins.
	if in := ask(t, addr, "anything.dev.northwind.test.", dns.TypeA); len(in.Answer) != 1 || in.Answer[0].(*dns.A).A.String() != "127.31.0.20" {
		t.Fatalf("wildcard: %v", in)
	}
	if in := ask(t, addr, "box.dev.northwind.test.", dns.TypeA); len(in.Answer) != 1 || in.Answer[0].(*dns.A).A.String() != "127.31.0.21" {
		t.Fatalf("box: %v", in)
	}
	// The default zone is not served.
	if in := ask(t, addr, "www.azqlab.lan.", dns.TypeA); len(in.Answer) != 0 {
		t.Fatalf("azqlab.lan must not answer in zone mode: %v", in)
	}
	// The reverse zone.
	if in := ask(t, addr, "10.0.31.127.in-addr.arpa.", dns.TypePTR); len(in.Answer) != 1 || in.Answer[0].(*dns.PTR).Ptr != "ci.northwind.test." {
		t.Fatalf("ptr: %v", in)
	}
	if in := ask(t, addr, "99.0.31.127.in-addr.arpa.", dns.TypePTR); in.Rcode != dns.RcodeNameError {
		t.Fatalf("an unknown address must be NXDOMAIN: %v", in)
	}
	if in := ask(t, addr, "0.31.127.in-addr.arpa.", dns.TypeSOA); len(in.Answer) != 1 {
		t.Fatalf("reverse apex SOA: %v", in)
	}
}

func transfer1(t *testing.T, addr, zone string) ([]dns.RR, error) {
	t.Helper()
	m := new(dns.Msg)
	m.SetAxfr(zone)
	ch, err := new(dns.Transfer).In(m, addr)
	if err != nil {
		return nil, err
	}
	var out []dns.RR
	for env := range ch {
		if env.Error != nil {
			return out, env.Error
		}
		out = append(out, env.RR...)
	}
	return out, nil
}

func TestZoneTransferFollowsTheFile(t *testing.T) {
	lab, err := loadZones([]byte(estateZones))
	if err != nil {
		t.Fatal(err)
	}
	addr := serve(t, newTestHandler(lab))
	if rrs, err := transfer1(t, addr, "northwind.test."); err == nil && len(rrs) > 0 {
		t.Fatalf("axfr:false must refuse a transfer, got %d records", len(rrs))
	}
	lab.axfr = true
	rrs, err := transfer1(t, addr, "northwind.test.")
	if err != nil {
		t.Fatal(err)
	}
	if rrs[0].Header().Rrtype != dns.TypeSOA || rrs[len(rrs)-1].Header().Rrtype != dns.TypeSOA {
		t.Fatalf("a transfer starts and ends with the SOA: %v", rrs)
	}
	names := map[string]bool{}
	for _, r := range rrs {
		names[r.Header().Name] = true
	}
	for _, want := range []string{"ci.northwind.test.", "*.dev.northwind.test.", "box.dev.northwind.test."} {
		if !names[want] {
			t.Errorf("transfer lacks %s", want)
		}
	}
}

func TestDefaultLabIsUnchanged(t *testing.T) {
	lab := defaultLab()
	lab.axfr = true
	addr := serve(t, newTestHandler(lab))
	if in := ask(t, addr, "www.azqlab.lan.", dns.TypeA); len(in.Answer) != 1 || in.Answer[0].(*dns.A).A.String() != "127.0.0.1" {
		t.Fatalf("www: %v", in)
	}
	if in := ask(t, addr, "x.wild.azqlab.lan.", dns.TypeA); len(in.Answer) != 1 || in.Answer[0].(*dns.A).A.String() != "127.0.0.2" {
		t.Fatalf("wildcard: %v", in)
	}
	if in := ask(t, addr, "real.wild.azqlab.lan.", dns.TypeA); len(in.Answer) != 1 || in.Answer[0].(*dns.A).A.String() != "127.0.0.3" {
		t.Fatalf("a real name below the wildcard: %v", in)
	}
	if in := ask(t, addr, "servfail.azqlab.lan.", dns.TypeA); in.Rcode != dns.RcodeServerFailure {
		t.Fatalf("servfail: %v", in)
	}
	if in := ask(t, addr, "3.0.0.127.in-addr.arpa.", dns.TypePTR); len(in.Answer) != 1 || in.Answer[0].(*dns.PTR).Ptr != "real.wild.azqlab.lan." {
		t.Fatalf("ptr: %v", in)
	}
	rrs, err := transfer1(t, addr, "azqlab.lan.")
	if err != nil || len(rrs) < 20 {
		t.Fatalf("axfr: %d records, %v", len(rrs), err)
	}
}

func TestLoadZonesRejectsBadFiles(t *testing.T) {
	for name, raw := range map[string]string{
		"not json":    `{`,
		"no zones":    `{"zones": {}}`,
		"outside":     `{"zones": {"a.test.": {"SOA": ["x"], "b.test.": ["A 127.0.0.1"]}}}`,
		"bad record":  `{"zones": {"a.test.": {"a.test.": ["SOA ns.a.test. h.a.test. 1 2 3 4 5"], "x.a.test.": ["A not-an-ip"]}}}`,
		"missing SOA": `{"zones": {"a.test.": {"a.test.": ["A 127.0.0.1"]}}}`,
	} {
		if _, err := loadZones([]byte(raw)); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}
