package dnsr

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// recordZone answers every type for rec.test.
func recordZone(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	q := r.Question[0]
	name := strings.ToLower(q.Name)
	add := func(rec string) {
		if rr, err := dns.NewRR(name + " 30 IN " + rec); err == nil && (rr.Header().Rrtype == q.Qtype || q.Qtype == dns.TypeANY) {
			m.Answer = append(m.Answer, rr)
		}
	}
	switch name {
	case "rec.test.":
		for _, rec := range []string{"A 192.0.2.1", "AAAA 2001:db8::1", "MX 10 mail.rec.test.", "NS ns.rec.test.",
			`TXT "a" "b"`, "SRV 1 2 3 srv.rec.test.", `CAA 0 issue "ca.test"`, "SOA ns.rec.test. host.rec.test. 7 1 2 3 4", "A 10.0.0.1"} {
			add(rec)
		}
	case "1.2.0.192.in-addr.arpa.":
		add("PTR rec.test.")
	default:
		m.Rcode = dns.RcodeNameError
	}
	_ = w.WriteMsg(m)
}

func TestLookupReadsEveryTypeAsDnsxDoes(t *testing.T) {
	p := New(Options{Resolvers: []string{serve(t, recordZone)}, PerSecond: -1})
	all := []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeMX, dns.TypeNS, dns.TypeTXT, dns.TypeSRV, dns.TypeCAA, dns.TypeSOA}
	d := p.Lookup(context.Background(), "rec.test", LookupOptions{Types: all})
	if !d.Answered() || d.StatusCode != "NOERROR" || d.TTL != 30 {
		t.Fatalf("answered %v status %q ttl %d", d.Answered(), d.StatusCode, d.TTL)
	}
	for name, got := range map[string][]string{"a": d.A, "aaaa": d.AAAA, "mx": d.MX, "ns": d.NS, "txt": d.TXT, "srv": d.SRV, "caa": d.CAA} {
		want := map[string][]string{"a": {"192.0.2.1", "10.0.0.1"}, "aaaa": {"2001:db8::1"}, "mx": {"mail.rec.test"}, "ns": {"ns.rec.test"},
			"txt": {"ab"}, "srv": {"srv.rec.test"}, "caa": {"ca.test"}}[name]
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s = %v, want %v", name, got, want)
		}
	}
	if len(d.SOA) != 1 || d.SOA[0].Serial != 7 || d.SOA[0].Mbox != "host.rec.test" {
		t.Errorf("soa %+v", d.SOA)
	}
	// dnsx's list holds the documentation ranges too.
	if !d.HasInternalIPs || !reflect.DeepEqual(d.InternalIPs, []string{"192.0.2.1", "10.0.0.1", "2001:db8::1"}) {
		t.Errorf("internal %v %v", d.HasInternalIPs, d.InternalIPs)
	}
	if len(d.AllRecords) < 9 {
		t.Errorf("all = %d records", len(d.AllRecords))
	}
	if len(d.Resolver) != 1 {
		t.Errorf("resolver %v", d.Resolver)
	}
}

func TestLookupGivesTheCodeOfAnAnswerWithNoRecords(t *testing.T) {
	p := New(Options{Resolvers: []string{serve(t, recordZone)}, PerSecond: -1})
	d := p.Lookup(context.Background(), "nope.test", LookupOptions{})
	if !d.Answered() || d.StatusCode != "NXDOMAIN" || d.StatusCodeRaw != dns.RcodeNameError || d.Any() {
		t.Errorf("%+v", d)
	}
	if c, ok := d.Rcode(dns.TypeA); !ok || c != dns.RcodeNameError {
		t.Errorf("rcode %d %v", c, ok)
	}
}

func TestLookupPTRTakesAnAddress(t *testing.T) {
	p := New(Options{Resolvers: []string{serve(t, recordZone)}, PerSecond: -1})
	d := p.Lookup(context.Background(), "192.0.2.1", LookupOptions{Types: []uint16{dns.TypePTR}})
	if !reflect.DeepEqual(d.PTR, []string{"rec.test"}) {
		t.Errorf("ptr %v", d.PTR)
	}
}

func TestLookupSERVFAILIsAnAnswerAndAFailure(t *testing.T) {
	p := New(Options{Resolvers: []string{serve(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeServerFailure)
		_ = w.WriteMsg(m)
	})}, PerSecond: -1, Attempts: 2})
	d := p.Lookup(context.Background(), "sf.test", LookupOptions{})
	if !d.Answered() || d.StatusCodeRaw != dns.RcodeServerFailure || len(d.Failures) != 1 {
		t.Errorf("answered %v code %d failures %v", d.Answered(), d.StatusCodeRaw, d.Failures)
	}
}

func TestAttemptsAreTheQueriesOfAFailingName(t *testing.T) {
	var n atomic.Int64
	addr := serve(t, func(w dns.ResponseWriter, r *dns.Msg) {
		n.Add(1)
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeRefused)
		_ = w.WriteMsg(m)
	})
	for _, attempts := range []int{1, 2, 5} {
		n.Store(0)
		p := New(Options{Resolvers: []string{addr}, PerSecond: -1, Attempts: attempts})
		p.Lookup(context.Background(), "x.test", LookupOptions{})
		if int(n.Load()) != attempts {
			t.Errorf("-retry %d: %d queries", attempts, n.Load())
		}
	}
}

func TestATwoSecondOpinionNeedsMoreThanOneAttempt(t *testing.T) {
	var n atomic.Int64
	h := func(w dns.ResponseWriter, r *dns.Msg) {
		n.Add(1)
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeNameError)
		_ = w.WriteMsg(m)
	}
	a, b := serve(t, h), serve(t, h)
	for attempts, want := range map[int]int64{1: 1, 2: 2} {
		n.Store(0)
		p := New(Options{Resolvers: []string{a, b}, PerSecond: -1, Attempts: attempts})
		p.Lookup(context.Background(), "gone.test", LookupOptions{})
		if n.Load() != want {
			t.Errorf("-retry %d: %d queries, want %d", attempts, n.Load(), want)
		}
	}
}

func TestHostsFileAnswersFirst(t *testing.T) {
	h := ParseHosts("# c\n127.1.2.3 mine.test alias.test\n::1 six.test\n")
	p := New(Options{Resolvers: []string{serve(t, recordZone)}, PerSecond: -1})
	d := p.Lookup(context.Background(), "mine.test", LookupOptions{Types: []uint16{dns.TypeA}, Hosts: h})
	if !d.HostsFile || !reflect.DeepEqual(d.A, []string{"127.1.2.3"}) {
		t.Errorf("%+v", d)
	}
}

func TestQuestionAsksWithEDNS0(t *testing.T) {
	var size atomic.Int64
	addr := serve(t, func(w dns.ResponseWriter, r *dns.Msg) {
		if o := r.IsEdns0(); o != nil {
			size.Store(int64(o.UDPSize()))
		}
		recordZone(w, r)
	})
	New(Options{Resolvers: []string{addr}, PerSecond: -1}).Lookup(context.Background(), "rec.test", LookupOptions{})
	if size.Load() != 4096 {
		t.Errorf("EDNS0 buffer %d", size.Load())
	}
}

func TestParseResolverForms(t *testing.T) {
	ok := map[string]Server{
		"1.1.1.1":                     {Key: "1.1.1.1:53", Net: NetUDP, Addr: "1.1.1.1:53"},
		"1.1.1.1:5353":                {Key: "1.1.1.1:5353", Net: NetUDP, Addr: "1.1.1.1:5353"},
		"udp:9.9.9.9":                 {Key: "9.9.9.9:53", Net: NetUDP, Addr: "9.9.9.9:53"},
		"tcp:9.9.9.9:5300":            {Key: "tcp:9.9.9.9:5300", Net: NetTCP, Addr: "9.9.9.9:5300"},
		"dot:dns.example":             {Key: "dot:dns.example:853", Net: NetDoT, Addr: "dns.example:853"},
		"::1":                         {Key: "[::1]:53", Net: NetUDP, Addr: "[::1]:53"},
		"[::1]:5353":                  {Key: "[::1]:5353", Net: NetUDP, Addr: "[::1]:5353"},
		"dns.example:53":              {Key: "dns.example:53", Net: NetUDP, Addr: "dns.example:53"},
		"doh:https://h.test/dns":      {Key: "doh:https://h.test/dns", Net: NetDoH, Addr: "https://h.test/dns"},
		"doh:https://h.test/dns:get":  {Key: "doh:https://h.test/dns:get", Net: NetDoH, Addr: "https://h.test/dns", GET: true},
		"doh:https://h.test/dns:post": {Key: "doh:https://h.test/dns", Net: NetDoH, Addr: "https://h.test/dns"},
	}
	for in, want := range ok {
		got, err := ParseResolver(in)
		if err != nil || got != want {
			t.Errorf("%q: %+v, %v; want %+v", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "res.txt", "doh:dns.example", "doh:https://h.test/dns:jsonapi", "udp:", "1.1.1.1/24"} {
		if _, err := ParseResolver(bad); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
}

func TestParseResolversTakesAFileOrAList(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "r.txt")
	if err := os.WriteFile(f, []byte("# resolvers\n1.1.1.1\n\ntcp:8.8.8.8\n1.1.1.1:53\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	want := []string{"1.1.1.1:53", "tcp:8.8.8.8:53"}
	for _, spec := range []string{f, "1.1.1.1,tcp:8.8.8.8", "1.1.1.1, tcp:8.8.8.8,1.1.1.1:53"} {
		got, err := ParseResolvers(spec)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("%q: %v, %v", spec, got, err)
		}
	}
	if got, err := ParseResolvers(""); got != nil || err != nil {
		t.Errorf("empty: %v %v", got, err)
	}
	if _, err := ParseResolvers(filepath.Join(dir, "missing.txt")); err == nil {
		t.Error("a missing file was taken for a resolver")
	}
	empty := filepath.Join(dir, "e.txt")
	_ = os.WriteFile(empty, []byte("# nothing\n"), 0o644)
	if _, err := ParseResolvers(empty); err == nil {
		t.Error("an empty file was accepted")
	}
}

// each transport answers the same names.
func TestEveryTransportAnswers(t *testing.T) {
	// UDP, TCP
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	var tcpN, udpN atomic.Int64
	count := func(c *atomic.Int64) dns.HandlerFunc {
		return func(w dns.ResponseWriter, r *dns.Msg) { c.Add(1); recordZone(w, r) }
	}
	us := &dns.Server{PacketConn: pc, Handler: count(&udpN)}
	ts := &dns.Server{Listener: ln, Handler: count(&tcpN)}
	go func() { _ = us.ActivateAndServe() }()
	go func() { _ = ts.ActivateAndServe() }()
	t.Cleanup(func() { _ = us.Shutdown(); _ = ts.Shutdown() })

	// DoT
	cert, pool := selfSigned(t)
	tl, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Skip(err)
	}
	var dotN, dohN atomic.Int64
	ds := &dns.Server{Listener: tl, Handler: count(&dotN)}
	go func() { _ = ds.ActivateAndServe() }()
	t.Cleanup(func() { _ = ds.Shutdown() })

	// DoH, POST and GET
	var methods []string
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		methods = append(methods, r.Method)
		var raw []byte
		if r.Method == http.MethodGet {
			raw, _ = base64.RawURLEncoding.DecodeString(r.URL.Query().Get("dns"))
		} else {
			raw, _ = io.ReadAll(r.Body)
		}
		q := new(dns.Msg)
		if err := q.Unpack(raw); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		dohN.Add(1)
		rec := &memWriter{}
		recordZone(rec, q)
		out, _ := rec.msg.Pack()
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(out)
	}))
	t.Cleanup(hs.Close)

	for _, spec := range []string{
		pc.LocalAddr().String(),
		"udp:" + pc.LocalAddr().String(),
		"tcp:" + ln.Addr().String(),
		"dot:" + tl.Addr().String(),
		"doh:" + hs.URL + "/dns-query",
		"doh:" + hs.URL + "/dns-query:get",
	} {
		keys, err := ParseResolvers(spec)
		if err != nil {
			t.Fatalf("%s: %v", spec, err)
		}
		p := New(Options{Resolvers: keys, PerSecond: -1})
		p.x.SetDoTTLS(&tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12})
		d := p.Lookup(context.Background(), "rec.test", LookupOptions{Types: []uint16{dns.TypeMX}})
		if !reflect.DeepEqual(d.MX, []string{"mail.rec.test"}) || len(d.Failures) > 0 {
			t.Errorf("%s: mx %v failures %v", spec, d.MX, d.Failures)
		}
	}
	if udpN.Load() != 2 || tcpN.Load() != 1 || dotN.Load() != 1 || dohN.Load() != 2 {
		t.Errorf("udp %d tcp %d dot %d doh %d", udpN.Load(), tcpN.Load(), dotN.Load(), dohN.Load())
	}
	if !reflect.DeepEqual(methods, []string{"POST", "GET"}) {
		t.Errorf("doh methods %v", methods)
	}
}

type memWriter struct{ msg *dns.Msg }

func (m *memWriter) LocalAddr() net.Addr         { return &net.UDPAddr{} }
func (m *memWriter) RemoteAddr() net.Addr        { return &net.UDPAddr{} }
func (m *memWriter) WriteMsg(r *dns.Msg) error   { m.msg = r; return nil }
func (m *memWriter) Write(b []byte) (int, error) { return len(b), nil }
func (m *memWriter) Close() error                { return nil }
func (m *memWriter) TsigStatus() error           { return nil }
func (m *memWriter) TsigTimersOnly(bool)         {}
func (m *memWriter) Hijack()                     {}

func selfSigned(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "dot.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pool
}

// a zone transfer over TCP, one server that allows it and one that refuses.
func TestTransferAsksOverTCP(t *testing.T) {
	serveTCP := func(h dns.HandlerFunc) string {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Skip(err)
		}
		s := &dns.Server{Listener: ln, Handler: h}
		go func() { _ = s.ActivateAndServe() }()
		t.Cleanup(func() { _ = s.Shutdown() })
		return ln.Addr().String()
	}
	good := serveTCP(func(w dns.ResponseWriter, r *dns.Msg) {
		soa, _ := dns.NewRR("z.test. 60 IN SOA ns.z.test. h.z.test. 1 2 3 4 5")
		a, _ := dns.NewRR("www.z.test. 60 IN A 192.0.2.9")
		ch := make(chan *dns.Envelope, 1)
		ch <- &dns.Envelope{RR: []dns.RR{soa, a, soa}}
		close(ch)
		_ = new(dns.Transfer).Out(w, r, ch)
	})
	bad := serveTCP(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeRefused)
		_ = w.WriteMsg(m)
	})
	p := New(Options{Resolvers: []string{"127.0.0.1:1"}, PerSecond: -1})
	chain, fails := p.Transfer(context.Background(), "z.test", []string{bad, good})
	if len(chain.Data) != 1 || chain.Data[0].Resolver[0] != good || !reflect.DeepEqual(chain.Data[0].A, []string{"192.0.2.9"}) {
		t.Errorf("chain %+v", chain)
	}
	if len(fails) != 1 || fails[0].Type != bad {
		t.Errorf("failures %+v", fails)
	}
}

func TestTraceFollowsDelegations(t *testing.T) {
	// root → tld → leaf, all on loopback; glue names the next server.
	leaf := serve(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		rr, _ := dns.NewRR("www.t.test. 60 IN A 192.0.2.7")
		m.Answer = append(m.Answer, rr)
		_ = w.WriteMsg(m)
	})
	_, leafPort, _ := net.SplitHostPort(leaf)
	refer := func(zone string) dns.HandlerFunc {
		return func(w dns.ResponseWriter, r *dns.Msg) {
			m := new(dns.Msg)
			m.SetReply(r)
			ns, _ := dns.NewRR(zone + " 60 IN NS ns." + zone)
			glue, _ := dns.NewRR("ns." + zone + " 60 IN A 127.0.0.1")
			m.Ns, m.Extra = append(m.Ns, ns), append(m.Extra, glue)
			_ = w.WriteMsg(m)
		}
	}
	root := serve(t, refer("test."))
	p := New(Options{Resolvers: []string{"127.0.0.1:1"}, PerSecond: -1, Timeout: time.Second})
	p.TraceRoots = []string{root}
	// every referral points at the leaf's port
	p.TracePort = leafPort
	c := p.Trace(context.Background(), "www.t.test", dns.TypeA, 8)
	if len(c.Data) != 2 {
		t.Fatalf("chain %d steps: %+v", len(c.Data), c)
	}
	if !reflect.DeepEqual(c.Data[0].NS, []string{"ns.test"}) || !reflect.DeepEqual(c.Data[1].A, []string{"192.0.2.7"}) {
		t.Errorf("steps %+v %+v", c.Data[0], c.Data[1])
	}
}

// socks5 is a proxy for CONNECT without authentication; it counts the
// connections it carries.
func socks5(t *testing.T) (string, *atomic.Int64) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	t.Cleanup(func() { ln.Close() })
	var n atomic.Int64
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				buf := make([]byte, 262)
				if _, err := io.ReadFull(c, buf[:2]); err != nil {
					return
				}
				_, _ = io.ReadFull(c, buf[:int(buf[1])])
				_, _ = c.Write([]byte{5, 0})
				if _, err := io.ReadFull(c, buf[:4]); err != nil || buf[1] != 1 {
					return
				}
				var host string
				switch buf[3] {
				case 1:
					_, _ = io.ReadFull(c, buf[:4])
					host = net.IP(buf[:4]).String()
				case 3:
					_, _ = io.ReadFull(c, buf[:1])
					l := int(buf[0])
					_, _ = io.ReadFull(c, buf[:l])
					host = string(buf[:l])
				default:
					return
				}
				_, _ = io.ReadFull(c, buf[:2])
				port := int(buf[0])<<8 | int(buf[1])
				up, err := net.Dial("tcp", net.JoinHostPort(host, fmtInt(port)))
				if err != nil {
					_, _ = c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
					return
				}
				defer up.Close()
				n.Add(1)
				_, _ = c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
				go io.Copy(up, c)
				_, _ = io.Copy(c, up)
			}()
		}
	}()
	return ln.Addr().String(), &n
}

func fmtInt(n int) string { return strconv.Itoa(n) }

func TestProxyCarriesDNSOverTCP(t *testing.T) {
	// the resolver listens on TCP as well, on the port its UDP socket has
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	_, port, _ := net.SplitHostPort(pc.LocalAddr().String())
	ln, err := net.Listen("tcp", "127.0.0.1:"+port)
	if err != nil {
		t.Skip(err)
	}
	var udpN, tcpN atomic.Int64
	us := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) { udpN.Add(1); recordZone(w, r) })}
	ts := &dns.Server{Listener: ln, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) { tcpN.Add(1); recordZone(w, r) })}
	go func() { _ = us.ActivateAndServe() }()
	go func() { _ = ts.ActivateAndServe() }()
	t.Cleanup(func() { _ = us.Shutdown(); _ = ts.Shutdown() })
	px, carried := socks5(t)
	p := New(Options{Resolvers: []string{pc.LocalAddr().String()}, PerSecond: -1, Proxy: "socks5://" + px})
	d := p.Lookup(context.Background(), "rec.test", LookupOptions{Types: []uint16{dns.TypeMX}})
	if !reflect.DeepEqual(d.MX, []string{"mail.rec.test"}) {
		t.Fatalf("mx %v failures %v", d.MX, d.Failures)
	}
	if udpN.Load() != 0 || tcpN.Load() != 1 || carried.Load() != 1 {
		t.Errorf("udp %d tcp %d through the proxy %d: want 0, 1, 1", udpN.Load(), tcpN.Load(), carried.Load())
	}
	if err := ProxyError("http://x:1"); err == nil {
		t.Error("an http proxy was accepted for DNS")
	}
}
