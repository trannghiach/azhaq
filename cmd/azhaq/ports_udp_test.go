package main

import (
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// -pu alone asks those UDP ports and no TCP port: a DNS server on an odd
// port is found at -rate 5 within -timeout 10s, in one request, where the
// default TCP top-100 would be paced ahead of it and use up the run (50
// requests, exit 4, no result).
func TestPortsUDPAloneFindsDNSOnAnOddPortAtALowRate(t *testing.T) {
	t.Chdir(t.TempDir())
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		_ = w.WriteMsg(m)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	defer srv.Shutdown()
	port := pc.LocalAddr().(*net.UDPAddr).Port
	out, errOut, code := cli(t, "ports", "-pu", fmt.Sprint(port), "-timeout", "10s", "-detect", "banner", "-retries", "0", "-rate", "5", "127.0.0.1", "-json")
	sum := sumMap(t, errOut)
	if code != exitOK || sum["results"] != float64(1) || sum["requests"] != float64(1) {
		t.Fatalf("exit %d, summary %v\n%s", code, sum, out)
	}
	if !strings.Contains(out, `"protocol":"udp"`) || !strings.Contains(out, `"service":"dns"`) || !strings.Contains(out, `"state":"open"`) {
		t.Errorf("row %s", out)
	}
}

// A scan the timeout stops says how many of a port's payloads were asked:
// the port is not called closed or answered for.
func TestPortsUDPStoppedSaysHowManyPayloadsWereAsked(t *testing.T) {
	t.Chdir(t.TempDir())
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 1500)
		for {
			if _, _, err := pc.ReadFrom(buf); err != nil {
				return
			}
		}
	}()
	port := pc.LocalAddr().(*net.UDPAddr).Port
	_, errOut, code := cli(t, "ports", "-pu", fmt.Sprint(port), "-timeout", "1s", "-connect-timeout", "400ms", "-retries", "0", "-rate", "5", "127.0.0.1", "-json")
	sum := sumMap(t, errOut)
	if code != exitLimit || sum["complete"] != false {
		t.Fatalf("exit %d, summary %v", code, sum)
	}
	want := fmt.Sprintf("127.0.0.1:%d/udp: 3 of 4 payloads asked before the run stopped; no answer yet", port)
	if !strings.Contains(fmt.Sprint(sum["notes"]), want) {
		t.Errorf("no %q in notes %v", want, sum["notes"])
	}
}
