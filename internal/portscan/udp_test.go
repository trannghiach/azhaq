package portscan

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"path/filepath"
	"reflect"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/trannghiach/azhaq/internal/ledger"
)

func TestUDPPorts(t *testing.T) {
	top, err := UDPPorts("")
	if err != nil || len(top) != 20 || top[0] != 53 {
		t.Fatalf("default list: %v %v", top, err)
	}
	if p, _ := UDPPorts("top"); !reflect.DeepEqual(p, top) {
		t.Fatal("top is not the default")
	}
	if p, err := UDPPorts("none"); err != nil || len(p) != 0 {
		t.Fatalf("none: %v %v", p, err)
	}
	if p, _ := UDPPorts("123,53-54"); !reflect.DeepEqual(p, []int{53, 54, 123}) {
		t.Fatalf("list: %v", p)
	}
}

func TestUDPPortsCompose(t *testing.T) {
	top, _ := UDPPorts("top")
	got, err := UDPPorts("TOP,5354,53")
	want := append(append([]int{}, top...), 5354)
	slices.Sort(want)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("top,5354: %v %v", got, err)
	}
	if got, err = UDPPorts("full"); err != nil || len(got) != 65535 {
		t.Fatalf("full: %d %v", len(got), err)
	}
	if _, err = UDPPorts("none,53"); err == nil || err.Error() != `bad port "none"` {
		t.Fatalf("none,53: %v", err)
	}
	_, err = UDPPorts("top-100")
	if err == nil || err.Error() != `bad port "top-100": UDP takes top or full (top-100 is a TCP list)` {
		t.Fatalf("top-100 on UDP: %v", err)
	}
}

func udpListener(t *testing.T, reply []byte) (port int, reads *atomic.Int32) {
	t.Helper()
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	reads = new(atomic.Int32)
	go func() {
		buf := make([]byte, 2048)
		for {
			_, from, err := c.ReadFrom(buf)
			if err != nil {
				return
			}
			reads.Add(1)
			if reply != nil {
				c.WriteTo(reply, from)
			}
		}
	}()
	return c.LocalAddr().(*net.UDPAddr).Port, reads
}

// udpResponder runs fn on each datagram and sends back what it returns
// (nothing, when it returns nil).
func udpResponder(t *testing.T, fn func(in []byte) []byte) (port int, reads *atomic.Int32) {
	t.Helper()
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	reads = new(atomic.Int32)
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := c.ReadFrom(buf)
			if err != nil {
				return
			}
			reads.Add(1)
			if out := fn(buf[:n]); out != nil {
				c.WriteTo(out, from)
			}
		}
	}()
	return c.LocalAddr().(*net.UDPAddr).Port, reads
}

func closedUDPPort(t *testing.T) int {
	t.Helper()
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := c.LocalAddr().(*net.UDPAddr).Port
	c.Close()
	return p
}

// A reply is open, an ICMP port unreachable (ECONNREFUSED on the
// connected socket) closed, and neither open|filtered, asked twice.
func TestUDPStates(t *testing.T) {
	answering, _ := udpListener(t, []byte("pong"))
	quiet, quietReads := udpListener(t, nil)
	closed := closedUDPPort(t)

	var takes atomic.Int32
	s := &Scanner{Timeout: 300 * time.Millisecond, Take: func() error { takes.Add(1); return nil }}
	r, err := s.ScanUDP(context.Background(), "localhost", "127.0.0.1", []int{answering, quiet, closed})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Open) != 1 || r.Open[0].Port != answering || r.Open[0].State != UDPOpen || r.Open[0].Banner != "pong" {
		t.Fatalf("open: %+v", r.Open)
	}
	if len(r.OpenFiltered) != 1 || r.OpenFiltered[0].Port != quiet || r.OpenFiltered[0].State != UDPOpenFiltered {
		t.Fatalf("open|filtered: %+v", r.OpenFiltered)
	}
	if r.Closed != 1 {
		t.Fatalf("closed: %d", r.Closed)
	}
	if got := quietReads.Load(); got != 2 {
		t.Fatalf("the silent port was asked %d times, want 2", got)
	}
	if got := takes.Load(); got != 4 { // 3 ports, the silent one twice
		t.Fatalf("%d probes counted against the budget, want 4", got)
	}
}

// DNS moved to a port nobody assigns to it is found by the first ask,
// and a service that answers only an empty datagram by the second: no
// more datagrams than before.
func TestUDPUnknownPortsAskDNSThenEmpty(t *testing.T) {
	dns, dnsReads := udpResponder(t, func(in []byte) []byte {
		if len(in) < 12 {
			return nil // a DNS server ignores an empty datagram
		}
		r := append([]byte{}, in[:12]...)
		r[2], r[3], r[6], r[7] = 0x81, 0x80, 0, 0
		return r
	})
	pong, pongReads := udpResponder(t, func(in []byte) []byte {
		if len(in) == 0 {
			return []byte("pong")
		}
		return nil
	})
	var takes atomic.Int32
	s := &Scanner{Timeout: 300 * time.Millisecond, Take: func() error { takes.Add(1); return nil }}
	r, err := s.ScanUDP(context.Background(), "localhost", "127.0.0.1", []int{dns, pong})
	if err != nil {
		t.Fatal(err)
	}
	got := map[int]UDPPort{}
	for _, u := range r.Open {
		got[u.Port] = u
	}
	if u := got[dns]; u.State != UDPOpen || u.Service != "dns" || u.Banner != "dns answer, rcode 0, 0 records" {
		t.Errorf("dns on an odd port: %+v", u)
	}
	if u := got[pong]; u.State != UDPOpen || u.Banner != "pong" || u.Service != "" {
		t.Errorf("empty-datagram service: %+v", u)
	}
	if len(r.OpenFiltered) != 0 {
		t.Errorf("open|filtered: %+v", r.OpenFiltered)
	}
	if dnsReads.Load() != 1 || pongReads.Load() != 2 || takes.Load() != 3 {
		t.Errorf("datagrams: dns port %d, other %d, %d counted; want 1, 2, 3", dnsReads.Load(), pongReads.Load(), takes.Load())
	}
}

func TestUDPBudgetStopsTheScan(t *testing.T) {
	p, _ := udpListener(t, []byte("x"))
	n := 0
	s := &Scanner{Take: func() error {
		if n++; n > 1 {
			return context.DeadlineExceeded
		}
		return nil
	}}
	if _, err := s.ScanUDP(context.Background(), "", "127.0.0.1", []int{p, p + 1, p + 2}); err == nil {
		t.Fatal("a spent budget did not stop the scan")
	}
}

func TestEveryUDPProbeIsRecorded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "l.jsonl")
	l, err := ledger.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	ledger.Use(l)
	defer ledger.Use(nil)

	answering, _ := udpListener(t, []byte("x"))
	quiet, _ := udpListener(t, nil)
	ports := []int{answering, quiet}
	for i := 0; i < 5; i++ {
		ports = append(ports, closedUDPPort(t))
	}
	var takes atomic.Int32
	s := &Scanner{Timeout: 300 * time.Millisecond, Take: func() error { takes.Add(1); return nil }}
	if _, err := s.ScanUDP(context.Background(), "localhost", "127.0.0.1", ports); err != nil {
		t.Fatal(err)
	}
	l.Close()
	got := 0
	if err := ledger.Read(path, func(e ledger.Entry) error {
		if e.Kind == "udp" && e.Host == "localhost" {
			got++
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if got != int(takes.Load()) || got != len(ports)+1 {
		t.Fatalf("ledger has %d udp entries, %d probes were counted, want %d", got, takes.Load(), len(ports)+1)
	}
}

// reply helpers: what each protocol's server answers, as bytes.
func dnsReply(sent []byte) []byte {
	r := append([]byte{}, sent[:12]...)
	r[2], r[3], r[7] = 0x81, 0x80, 13
	return r
}

func TestUDPParsers(t *testing.T) {
	ntp := make([]byte, 48)
	ntp[0], ntp[1] = 0x1c, 2 // version 3, mode 4, stratum 2

	snmpBody := tlv(0x30, tlv(0x30, tlv(0x06, []byte{0x2b, 6, 1, 2, 1, 1, 1, 0}), tlv(0x04, []byte("Linux box 6.1.0 #1 SMP x86_64"))))
	snmp := tlv(0x30, tlv(0x02, []byte{0}), tlv(0x04, []byte("public")),
		tlv(0xa2, tlv(0x02, []byte{1, 2}), tlv(0x02, []byte{0}), tlv(0x02, []byte{0}), snmpBody))

	nbReply := func(sent []byte) []byte {
		nb := append(append([]byte{}, sent[:2]...), 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0)
		nb = append(nb, 0x20, 'C', 'K')
		nb = append(nb, bytes.Repeat([]byte{'A'}, 30)...)
		nb = append(nb, 0, 0, 0x21, 0, 1, 0, 0, 0, 0, 0, 20, 1)
		nb = append(nb, []byte("FILESRV        ")...)
		return append(nb, 0x00, 0x04, 0x00)
	}
	stunReq := stunBinding()
	stunReply := append([]byte{0x01, 0x01, 0, 16}, stunReq[4:]...)
	sw := "coturn-4.5.2 'dan Eider'"
	stunReply = append(stunReply, 0x80, 0x22, 0, byte(len(sw)))
	stunReply = append(stunReply, sw...)
	for len(stunReply)%4 != 0 {
		stunReply = append(stunReply, 0)
	}
	binary.BigEndian.PutUint16(stunReply[2:], uint16(len(stunReply)-20))
	stunAnswer := func(sent []byte) []byte {
		return append(append([]byte{}, stunReply[:4]...), append(sent[4:20], stunReply[20:]...)...)
	}

	ikeReply := func(sent []byte) []byte {
		r := append([]byte{}, sent...)
		r[len(r)-10] = 34 // exchange type, 10 bytes from the end of the header
		return r
	}
	coapReply := func(sent []byte) []byte {
		return []byte{0x60, 0x45, sent[2], sent[3], 0xff, '<', '/', 'a', '>'}
	}
	mdns := []byte{0, 0, 0x84, 0, 0, 0, 0, 3, 0, 0, 0, 0}

	tests := []struct {
		name  string
		port  int
		reply func(sent []byte) []byte
		want  udpInfo
	}{
		{"dns", 53, dnsReply, udpInfo{service: "dns", banner: "dns answer, rcode 0, 13 records"}},
		{"ntp", 123, func([]byte) []byte { return ntp }, udpInfo{service: "ntp", banner: "ntp v3 stratum 2"}},
		{"snmp", 161, func([]byte) []byte { return snmp }, udpInfo{service: "snmp", banner: "Linux box 6.1.0 #1 SMP x86_64"}},
		{"ssdp", 1900, func([]byte) []byte {
			return []byte("HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=120\r\nSERVER: Linux/5.15 UPnP/1.1 MiniUPnPd/2.3.3\r\nST: ssdp:all\r\n\r\n")
		}, udpInfo{service: "ssdp", product: "MiniUPnPd", version: "2.3.3", banner: "Linux/5.15 UPnP/1.1 MiniUPnPd/2.3.3"}},
		{"mdns", 5353, func([]byte) []byte { return mdns }, udpInfo{service: "mdns", banner: "mdns answer, 3 records"}},
		{"netbios", 137, nbReply, udpInfo{service: "netbios-ns", banner: "netbios name FILESRV"}},
		{"ike", 500, ikeReply, udpInfo{service: "isakmp", banner: "ikev2"}},
		{"ike nat-t", 4500, ikeReply, udpInfo{service: "isakmp", banner: "ikev2"}},
		{"stun", 3478, stunAnswer, udpInfo{service: "stun", product: "coturn", version: "4.5.2", banner: "coturn-4.5.2 'dan Eider'"}},
		{"memcached", 11211, func([]byte) []byte {
			return append([]byte{0, 1, 0, 0, 0, 1, 0, 0}, "VERSION 1.6.21\r\n"...)
		}, udpInfo{service: "memcached", product: "memcached", version: "1.6.21", banner: "VERSION 1.6.21"}},
		{"bacnet", 47808, func([]byte) []byte { return []byte{0x81, 0x0b, 0, 12, 1, 0x20, 0xff, 0xff, 0, 0xff, 0x10, 0} }, udpInfo{service: "bacnet", banner: "bacnet/ip answer"}},
		{"coap", 5683, coapReply, udpInfo{service: "coap", banner: "coap 2.05 </a>"}},
	}
	for _, tt := range tests {
		req := udpRequest(tt.port)
		if len(req.payload) == 0 {
			t.Errorf("%s: no request", tt.name)
			continue
		}
		got, ok := req.parse(tt.reply(req.payload), req.payload)
		if !ok || got != tt.want {
			t.Errorf("%s: got %+v %v, want %+v", tt.name, got, ok, tt.want)
		}
		// Anything else on the port is not that protocol's answer.
		if _, ok := req.parse([]byte("hello"), req.payload); ok {
			t.Errorf("%s: a stray answer was taken for the protocol's", tt.name)
		}
	}
	if r := udpRequest(51820); len(r.payload) != 0 {
		t.Error("a port without a known protocol gets an empty datagram")
	}
}

func TestUDPRequestsAreHarmless(t *testing.T) {
	// The queries named in the spec: the DNS one asks for the root's NS,
	// the SNMP one is a GET of sysDescr.0 with community public, the
	// memcached one the version.
	if q := dnsQuery(); !bytes.HasSuffix(q, []byte{0, 0, 2, 0, 1}) {
		t.Errorf("dns query: % x", q)
	}
	if !bytes.Contains(snmpGet(), []byte("public")) || snmpGet()[0] != 0x30 {
		t.Error("snmp request")
	}
	if !bytes.HasSuffix(udpRequest(11211).payload, []byte("version\r\n")) {
		t.Error("memcached request")
	}
	if !bytes.HasPrefix(udpRequest(1900).payload, []byte("M-SEARCH * HTTP/1.1")) {
		t.Error("ssdp request")
	}
}
