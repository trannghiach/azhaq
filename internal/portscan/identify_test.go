package portscan

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/trannghiach/azhaq/internal/ledger"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name+".hex"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// The answers of the services lab's daemons, each read by its protocol.
func TestProtocolReaders(t *testing.T) {
	tests := []struct {
		proto, fixture                  string
		service, product, version, note string
	}{
		{"redis", "redis", "redis", "Redis", "7.4.12", ""},
		{"postgresql", "postgres", "postgresql", "PostgreSQL", "14 - 17", ""},
		{"mongodb", "mongo", "mongodb", "MongoDB", "7.0", ""},
		{"mqtt", "mqtt", "mqtt", "", "", "connack accepted"},
		{"memcached", "memcached", "memcached", "memcached", "1.6.45", ""},
		{"ldap", "ldap", "ldap", "OpenLDAP", "", "dc=example,dc=org"},
		{"smb", "smb", "smb", "Samba smbd", "", "smb 3.1.1"},
		{"dns", "dns", "dns", "", "", "dns answer"},
		{"amqp", "amqp", "amqp", "RabbitMQ", "3.13.7", "amqp 0-9"},
	}
	for _, tt := range tests {
		raw := fixture(t, tt.fixture)
		p := protocolNamed(tt.proto)
		if p == nil {
			t.Fatalf("no protocol %s", tt.proto)
		}
		if p.frame != nil && p.frame(raw) > len(raw) {
			t.Errorf("%s: frame says %d of %d bytes", tt.proto, p.frame(raw), len(raw))
		}
		var o Open
		if !p.read(raw, &o) {
			t.Errorf("%s: answer not recognised", tt.proto)
			continue
		}
		if o.Service == "" {
			o.Service = p.name
		}
		if o.Service != tt.service || o.Product != tt.product || !strings.HasPrefix(o.Version, tt.version) || !strings.Contains(o.Banner, tt.note) {
			t.Errorf("%s: %+v", tt.proto, o)
		}
	}
}

// No reader takes what is not its own: an HTTP answer, a text greeting,
// noise, and nothing.
func TestProtocolReadersRefuseOthers(t *testing.T) {
	others := [][]byte{
		[]byte("HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n"), []byte("HTTP/1.0 400 Bad Request\r\n\r\n"),
		[]byte("hello\r\n"), []byte("SSH-2.0-OpenSSH_9.6\r\n"), []byte("220 mail ESMTP Postfix\r\n"), []byte("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
		[]byte("ERROR\r\n"), []byte("-ERR something\r\n"), []byte("+OK ready\r\n"), []byte("\x15\x03\x01\x00\x02\x02\x28"), {0xff, 0xff, 0xff, 0xff, 0xff}, nil,
	}
	for _, p := range protocols {
		if p.name == "redis" {
			continue // -ERR unknown command is its own answer to the HEAD
		}
		for _, o := range others {
			var got Open
			if p.read(o, &got) {
				t.Errorf("%s took %q: %+v", p.name, o, got)
			}
		}
	}
}

func TestPassiveGreetings(t *testing.T) {
	tests := []struct {
		raw       string
		service   string
		product   string
		version   string
		unchanged bool
	}{
		{"RFB 003.008\n", "vnc", "VNC", "3.8", false},
		{"\xff\xfd\x18\xff\xfd\x20\xff\xfd\x23\xff\xfd\x27login: ", "telnet", "", "", false},
		{":irc.test NOTICE AUTH :*** Looking up your hostname...\r\n", "irc", "", "", false},
		{"PING :1A2B3C4D\r\n", "irc", "", "", false},
		{"200 NNTP Service Ready, posting allowed\r\n", "nntp", "", "", false},
		{"200 InterNetNews NNRP server INN 2.7.1 ready (posting ok)\r\n", "nntp", "INN", "2.7.1", false},
		{"RTSP/1.0 200 OK\r\nCSeq: 1\r\nServer: GStreamer RTSP server 1.22.0\r\n\r\n", "rtsp", "GStreamer RTSP server", "1.22.0", false},
		{"RTSP/1.0 400 Bad Request\r\n\r\n", "rtsp", "", "", false},
		{"SIP/2.0 200 OK\r\nServer: Asterisk PBX 20.5.0\r\n\r\n", "sip", "Asterisk PBX", "20.5.0", false},
		{"\"IMPLEMENTATION\" \"Dovecot Pigeonhole\"\r\n\"SIEVE\" \"fileinto\"\r\nOK\r\n", "sieve", "Dovecot Pigeonhole", "", false},
		{"220 hi there\r\n", "", "", "", true},
	}
	for _, tt := range tests {
		o := Open{Banner: printable([]byte(tt.raw))}
		(&Scanner{}).greeted(&o, []byte(tt.raw))
		if tt.unchanged {
			if o.Service != "" || o.Product != "" {
				t.Errorf("%q: %+v", tt.raw, o)
			}
			continue
		}
		if o.Service != tt.service || o.Product != tt.product || o.Version != tt.version {
			t.Errorf("%q: got %q %q %q, want %q %q %q", tt.raw, o.Service, o.Product, o.Version, tt.service, tt.product, tt.version)
		}
	}
}

// A fake service of a protocol: it answers its own request and closes on
// anything else, as most binary servers do on an HTTP request.
func fakeService(t *testing.T, start []byte, answer []byte) int {
	return listen(t, func(c net.Conn) {
		buf := make([]byte, 4096)
		n, _ := c.Read(buf)
		if bytes.HasPrefix(buf[:n], start) {
			c.Write(answer)
			time.Sleep(50 * time.Millisecond)
		}
	})
}

// An AMQP broker answers the HEAD with its version header and closes; it is
// then asked AMQP, and its Connection.Start names the product.
func TestAMQPOnAnotherPortIsAskedAMQP(t *testing.T) {
	start := fixture(t, "amqp")
	port := listen(t, func(c net.Conn) {
		buf := make([]byte, 4096)
		n, _ := c.Read(buf)
		if bytes.HasPrefix(buf[:n], []byte("AMQP")) {
			c.Write(start)
		} else {
			c.Write([]byte("AMQP\x00\x00\x09\x01"))
		}
		time.Sleep(50 * time.Millisecond)
	})
	s := &Scanner{Banner: 150 * time.Millisecond, Timeout: time.Second, Take: func() error { return nil }}
	r, err := s.ScanEach(context.Background(), "", "127.0.0.1", []int{port})
	if err != nil || len(r.Open) != 1 {
		t.Fatalf("%v %+v", err, r)
	}
	if o := r.Open[0]; o.Service != "amqp" || o.Product != "RabbitMQ" || o.Version != "3.13.7" {
		t.Errorf("%+v", o)
	}
}

func TestLadderFindsServicesOnOtherPorts(t *testing.T) {
	redis := fakeService(t, []byte("INFO"), []byte("$31\r\n# Server\r\nredis_version:6.2.1\r\n\r\n"))
	mc := fakeService(t, []byte("version"), []byte("VERSION 1.6.9\r\n"))
	mqtt := fakeService(t, []byte{0x10}, []byte{0x20, 2, 0, 0})
	pg := fakeService(t, []byte{0, 0, 0, 8, 0, 1, 0, 0}, []byte("EFATAL:  unsupported frontend protocol 1.0: server supports 3.0 to 3.0\n\x00"))
	ldapAnswer := fixture(t, "ldap")
	ldap := listen(t, func(c net.Conn) {
		buf := make([]byte, 4096)
		if n, _ := c.Read(buf); n > 0 && buf[0] == 0x30 {
			c.Write(ldapAnswer)
		}
	})
	var takes atomic.Int32
	s := &Scanner{Banner: 150 * time.Millisecond, Timeout: time.Second, Take: func() error { takes.Add(1); return nil }}
	for _, tt := range []struct {
		port                      int
		service, product, version string
	}{
		{redis, "redis", "Redis", "6.2.1"}, {mc, "memcached", "memcached", "1.6.9"}, {mqtt, "mqtt", "", ""},
		{pg, "postgresql", "PostgreSQL", "14 - 17"}, {ldap, "ldap", "OpenLDAP", ""},
	} {
		takes.Store(0)
		r, err := s.ScanEach(context.Background(), "", "127.0.0.1", []int{tt.port})
		if err != nil || len(r.Open) != 1 {
			t.Fatalf("scan %d: %v %+v", tt.port, err, r)
		}
		if o := r.Open[0]; o.Service != tt.service || o.Product != tt.product || o.Version != tt.version {
			t.Errorf("port %d: %+v", tt.port, o)
		}
		if n := takes.Load(); n > 1+maxProbes {
			t.Errorf("port %d took %d connects, bound %d", tt.port, n, 1+maxProbes)
		}
	}
}

// A port on its usual number is asked its own protocol first.
func TestUsualPortAsksItsOwnProtocolFirst(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	ln.Close()
	var asked atomic.Value
	port := fakeService(t, []byte("INFO"), []byte("+PONG\r\n"))
	saved := protocols
	t.Cleanup(func() { protocols = saved })
	r := protocolNamed("redis")
	cp := *r
	cp.ports = []int{port}
	cp.request = func(target) []byte { asked.Store(true); return []byte("INFO server\r\n") }
	protocols = append([]*protocol{&cp}, saved...)
	var takes atomic.Int32
	s := &Scanner{Banner: 100 * time.Millisecond, Timeout: time.Second, Take: func() error { takes.Add(1); return nil }}
	rep, err := s.ScanEach(context.Background(), "", "127.0.0.1", []int{port})
	if err != nil || len(rep.Open) != 1 || rep.Open[0].Service != "redis" || asked.Load() == nil {
		t.Fatalf("%+v %v", rep, err)
	}
	if takes.Load() != 1 {
		t.Errorf("%d connects: its own protocol is asked on the connection already open", takes.Load())
	}
}

func tlsCert(t *testing.T) []tls.Certificate {
	t.Helper()
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	srv.Close()
	return srv.TLS.Certificates
}

// The greeting inside a TLS tunnel is read before any HEAD.
func TestTLSWrappedGreeting(t *testing.T) {
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: tlsCert(t)})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var heads atomic.Int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				if err := c.(*tls.Conn).Handshake(); err != nil {
					return
				}
				c.Write([]byte("* OK [CAPABILITY IMAP4rev1] Dovecot 2.3.21 ready.\r\n"))
				if line, _ := bufio.NewReader(c).ReadString('\n'); strings.HasPrefix(line, "HEAD") {
					heads.Add(1)
				}
			}()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	o := scanOne(t, port)
	if o.Service != "imap" || !o.TLS || o.Product != "Dovecot" || o.Version != "2.3.21" || heads.Load() != 0 {
		t.Errorf("imaps: %+v (%d HEADs)", o, heads.Load())
	}
}

// A server that refuses HEAD is asked GET / for its page.
func TestHeadRefusedGetsThePage(t *testing.T) {
	mailpit := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "no", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><head><title>Mailpit</title><link rel=stylesheet href="/dist/app.css?v1.20.7"></head></html>`))
	}))
	defer mailpit.Close()
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusNotImplemented)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<title>Our Intranet</title>"))
	}))
	defer plain.Close()
	port := func(s *httptest.Server) int { return s.Listener.Addr().(*net.TCPAddr).Port }
	if o := scanOne(t, port(mailpit)); o.Service != "http" || o.Product != "Mailpit" || o.Version != "1.20.7" || o.Title != "Mailpit" {
		t.Errorf("mailpit: %+v", o)
	}
	if o := scanOne(t, port(plain)); o.Service != "http" || o.Product != "" || o.Title != "Our Intranet" {
		t.Errorf("plain: %+v", o)
	}
}

// ICY is HTTP in all but its name; a binary answer to the HEAD stays a banner.
func TestIcyAndBinaryAnswers(t *testing.T) {
	icy := listen(t, func(c net.Conn) {
		c.Read(make([]byte, 512))
		c.Write([]byte("ICY 200 OK\r\nicy-name: radio\r\nServer: Icecast 2.4.4\r\n\r\n"))
	})
	bin := listen(t, func(c net.Conn) {
		c.Read(make([]byte, 512))
		c.Write([]byte{0x15, 0x03, 0x01, 0x00, 0x02, 0x02, 0x50}) // a TLS alert
	})
	weird := listen(t, func(c net.Conn) {
		c.Read(make([]byte, 512))
		c.Write([]byte{0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x02, 0x03})
	})
	if o := scanOne(t, icy); o.Service != "icy" || o.Product != "Icecast" || o.Version != "2.4.4" {
		t.Errorf("icy: %+v", o)
	}
	if o := scanOne(t, bin); o.Service == "" && o.Banner == "" {
		t.Errorf("tls alert dropped: %+v", o)
	}
	if o := scanOne(t, weird); !strings.HasPrefix(o.Banner, "(binary) deadbeef") {
		t.Errorf("binary answer dropped: %+v", o)
	}
}

func TestTCPWrapped(t *testing.T) {
	port := listen(t, func(c net.Conn) {})
	if o := scanOne(t, port); o.Service != "tcpwrapped" {
		t.Errorf("%+v", o)
	}
}

// Ports that say nothing to anything are run down the ladder until a few
// have failed; the rest are counted, not asked.
func TestLadderLimit(t *testing.T) {
	var ports []int
	for i := 0; i < ladderLimit+3; i++ {
		ports = append(ports, listen(t, func(c net.Conn) { time.Sleep(3 * time.Second) }))
	}
	var takes atomic.Int32
	s := &Scanner{Workers: 1, Banner: 20 * time.Millisecond, Timeout: 20 * time.Millisecond, Take: func() error { takes.Add(1); return nil }}
	r, err := s.ScanEach(context.Background(), "", "127.0.0.1", ports)
	if err != nil || len(r.Open) != len(ports) {
		t.Fatalf("%+v %v", r, err)
	}
	if r.Unprobed != 3 {
		t.Errorf("%d ports left unprobed, want 3", r.Unprobed)
	}
	if max := len(ports) + ladderLimit*maxProbes; int(takes.Load()) > max {
		t.Errorf("%d connects, bound %d", takes.Load(), max)
	}
}

// Every connect of the ladder is a ledger entry and a counted take.
func TestLadderConnectsAreRecorded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "l.jsonl")
	l, err := ledger.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	ledger.Use(l)
	defer ledger.Use(nil)
	port := fakeService(t, []byte("version"), []byte("VERSION 1.6.9\r\n"))
	var takes atomic.Int32
	s := &Scanner{Banner: 150 * time.Millisecond, Timeout: time.Second, Take: func() error { takes.Add(1); return nil }}
	r, err := s.ScanEach(context.Background(), "localhost", "127.0.0.1", []int{port})
	if err != nil || len(r.Open) != 1 || r.Open[0].Service != "memcached" {
		t.Fatalf("%+v %v", r, err)
	}
	l.Close()
	n := 0
	ledger.Read(path, func(e ledger.Entry) error {
		if e.Kind == "tcp" {
			n++
		}
		return nil
	})
	if n != int(takes.Load()) || n < 4 {
		t.Errorf("%d ledger entries, %d takes", n, takes.Load())
	}
}

func TestFramesAndCounts(t *testing.T) {
	smb := fixture(t, "smb")
	if got := nbssFrame(smb); got != len(smb) {
		t.Errorf("nbss frame %d of %d", got, len(smb))
	}
	if got := binary.BigEndian.Uint16(tnsConnect()); int(got) != len(tnsConnect()) {
		t.Errorf("tns length %d of %d", got, len(tnsConnect()))
	}
	hdr := tdsPrelogin()
	if int(binary.BigEndian.Uint16(hdr[2:])) != len(hdr) {
		t.Errorf("tds length %d of %d", binary.BigEndian.Uint16(hdr[2:]), len(hdr))
	}
}

// Orchestrators and key-value stores name themselves in the body of
// GET / or /version.
func TestBodyProductsOfControlPlanes(t *testing.T) {
	for _, tt := range []struct{ body, product, version string }{
		{`{"etcdserver":"3.5.9","etcdcluster":"3.5.0"}`, "etcd", "3.5.9"},
		{`{"major":"1","minor":"29","gitVersion":"v1.29.2","goVersion":"go1.21"}`, "Kubernetes", "1.29.2"},
		{`{"Platform":{"Name":"Docker Engine - Community"},"Version":"24.0.7","ApiVersion":"1.43"}`, "Docker Engine", "24.0.7"},
		{`{"version":{"number":"2.11.0","distribution":"opensearch"}}`, "OpenSearch", "2.11.0"},
		{`{"hello":"world"}`, "", ""},
	} {
		if p, v := bodyProduct([]byte(tt.body)); p != tt.product || v != tt.version {
			t.Errorf("%s: %q %q", tt.body, p, v)
		}
	}
	if !needsVersionPage([]byte(`{"kind":"Status","apiVersion":"v1","status":"Failure","code":403}`)) || !needsVersionPage([]byte("404 page not found\n")) {
		t.Error("an API's plain refusal is not asked /version")
	}
}

// A budget spent while a port is being asked what it serves stops the scan.
func TestBudgetSpentInTheLadderStopsTheScan(t *testing.T) {
	port := fakeService(t, []byte("version"), []byte("VERSION 1.6.9\r\n"))
	var n atomic.Int32
	s := &Scanner{Banner: 100 * time.Millisecond, Timeout: time.Second, Take: func() error {
		if n.Add(1) > 3 {
			return context.DeadlineExceeded
		}
		return nil
	}}
	if _, err := s.ScanEach(context.Background(), "", "127.0.0.1", []int{port}); err == nil {
		t.Fatal("a spent budget in the middle of a port's probes was not reported")
	}
}
