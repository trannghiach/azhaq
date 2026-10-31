package main

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/miekg/dns"

	"github.com/trannghiach/azhaq/internal/collectors/subcol"
)

// danglingZone answers like a resolver for a zone with one name whose CNAME
// points at an Azure name that no longer exists (NXDOMAIN), and
// one that resolves.
func danglingZone(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no UDP: %v", err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		name := strings.TrimSuffix(strings.ToLower(r.Question[0].Name), ".")
		rr := func(s string) dns.RR { x, _ := dns.NewRR(s); return x }
		switch {
		case name == "shop.example.org" && r.Question[0].Qtype == dns.TypeA:
			m.Answer = []dns.RR{rr("shop.example.org. 60 IN CNAME gone.azurewebsites.net.")}
			m.Rcode = dns.RcodeNameError
		case name == "www.example.org" && r.Question[0].Qtype == dns.TypeA:
			m.Answer = []dns.RR{rr("www.example.org. 60 IN A 192.0.2.1")}
		case name == "shop.example.org" || name == "www.example.org":
		default:
			m.Rcode = dns.RcodeNameError
		}
		_ = w.WriteMsg(m)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	path := filepath.Join(t.TempDir(), "resolvers.txt")
	if err := os.WriteFile(path, []byte(pc.LocalAddr().String()+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

const takeoverLineWant = "[takeover] shop.example.org -> gone.azurewebsites.net (Azure, dangling)"

// A takeover candidate is a finding: on the row in -json, and under -silent
// a [takeover] line on stderr, with stdout still one name per line.
func TestDNSTakeoverIsNotLostUnderSilent(t *testing.T) {
	res := danglingZone(t)
	ls, rep, code := dnsOut(t, "-d", "shop.example.org,www.example.org", "-r", res, "-json")
	rows := dnsRows(t, ls)
	tk, _ := rows["shop.example.org"]["takeover"].(map[string]any)
	if code != exitOK || tk == nil || tk["service"] != "Azure" || tk["target"] != "gone.azurewebsites.net" || tk["strength"] != "dangling" {
		t.Fatalf("exit %d row %v", code, rows["shop.example.org"])
	}
	if rows["www.example.org"]["takeover"] != nil || len(rep.Takeover) != 1 {
		t.Errorf("rows %v takeover %+v", rows, rep.Takeover)
	}
	out, errOut, err := captureBoth(t, func() error {
		return run([]string{"dns", "-d", "shop.example.org,www.example.org", "-r", res, "-silent"})
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(out) != "www.example.org" {
		t.Errorf("stdout %q: -silent keeps one name per line", out)
	}
	if strings.TrimSpace(errOut) != takeoverLineWant {
		t.Errorf("stderr %q", errOut)
	}
	// Without -silent the summary says it as before.
	_, errOut, _ = captureBoth(t, func() error {
		return run([]string{"dns", "-d", "shop.example.org", "-r", res})
	})
	if !strings.Contains(errOut, "! takeover candidate (dangling): shop.example.org") || strings.Contains(errOut, "[takeover]") {
		t.Errorf("plain stderr %q", errOut)
	}
}

// subs -live: the same candidate is on its row, and under -silent on stderr.
func TestSubsTakeoverIsNotLostUnderSilent(t *testing.T) {
	t.Chdir(t.TempDir())
	res := danglingZone(t)
	defer subcol.UseTestSources(subcol.TestSource{Name: "s", Default: true, Names: []string{"shop.example.org", "www.example.org"}})()
	out, rep, code := runContract(t, "subs", "-d", "example.org", "-live", "-resolvers", res, "-no-history")
	if code != exitOK || len(rep.Takeover) != 1 {
		t.Fatalf("exit %d takeover %+v", code, rep.Takeover)
	}
	var found bool
	for _, r := range jsonRows(t, out) {
		if r["host"] == "shop.example.org" {
			tk, _ := r["takeover"].(map[string]any)
			found = tk != nil && tk["service"] == "Azure"
		} else if r["takeover"] != nil {
			t.Errorf("row %v", r)
		}
	}
	if !found {
		t.Errorf("no takeover on the row of shop.example.org:\n%s", out)
	}
	t.Setenv("AZHAQ_DATA_DIR", t.TempDir())
	out, errOut, err := captureBoth(t, func() error {
		return run([]string{"subs", "-d", "example.org", "-live", "-resolvers", res, "-no-history", "-silent"})
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Fields(out); len(got) != 2 || strings.Contains(out, "takeover") {
		t.Errorf("stdout %q", out)
	}
	if strings.TrimSpace(errOut) != takeoverLineWant {
		t.Errorf("stderr %q", errOut)
	}
}
