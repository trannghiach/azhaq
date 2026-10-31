package portscan

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestPorts(t *testing.T) {
	got, err := Ports("443,22,8000-8002,22")
	if err != nil || !reflect.DeepEqual(got, []int{22, 443, 8000, 8001, 8002}) {
		t.Fatalf("%v %v", got, err)
	}
	for spec, n := range map[string]int{"top-100": 100, "top-1000": 1000, "full": 65535} {
		if p, err := Ports(spec); err != nil || len(p) != n {
			t.Errorf("%s: %d ports, %v", spec, len(p), err)
		}
	}
	for _, bad := range []string{"0", "70000", "90-80", "x"} {
		if _, err := Ports(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// Names, numbers and ranges mix in one list; a name of the other
// protocol is refused with what to use.
func TestPortsCompose(t *testing.T) {
	got, err := Ports("Top-100,8080-8081")
	if err != nil || !slices.Contains(got, 443) || !slices.Contains(got, 8080) || len(got) != 100 {
		t.Fatalf("Top-100,8080-8081 (both already in the list): %d ports, %v", len(got), err)
	}
	got, err = Ports("top-100,8082-8083")
	if err != nil || len(got) != 102 || !slices.Contains(got, 8083) {
		t.Fatalf("top-100,8082-8083: %d ports, %v", len(got), err)
	}
	if got, err = Ports("22,all"); err != nil || len(got) != 65535 {
		t.Fatalf("22,all: %d %v", len(got), err)
	}
	if got, err = Ports("none"); err != nil || len(got) != 0 {
		t.Fatalf("none: %v %v", got, err)
	}
	if _, err = Ports("none,22"); err == nil || err.Error() != `bad port "none"` {
		t.Fatalf("none,22: %v", err)
	}
	_, err = Ports("22,top")
	if err == nil || err.Error() != `bad port "top": TCP takes top-100, top-1000 or full (top is the UDP list)` {
		t.Fatalf("top on TCP: %v", err)
	}
	if _, err = Ports("22,nope"); err == nil || err.Error() != `bad port "nope"` {
		t.Fatalf("nope: %v", err)
	}
}

func TestScanAndBanner(t *testing.T) {
	ssh, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ssh.Close()
	go func() {
		for {
			c, err := ssh.Accept()
			if err != nil {
				return
			}
			c.Write([]byte("SSH-2.0-OpenSSH_9.6\r\n"))
			c.Close()
		}
	}()
	silent, _ := net.Listen("tcp", "127.0.0.1:0")
	defer silent.Close()
	go func() {
		for {
			c, err := silent.Accept()
			if err != nil {
				return
			}
			time.Sleep(200 * time.Millisecond)
			c.Close()
		}
	}()
	closed, _ := net.Listen("tcp", "127.0.0.1:0")
	closedPort := closed.Addr().(*net.TCPAddr).Port
	closed.Close()
	sshPort := ssh.Addr().(*net.TCPAddr).Port
	silentPort := silent.Addr().(*net.TCPAddr).Port

	s := &Scanner{Rate: 1000, Banner: 100 * time.Millisecond}
	open, err := s.Scan(context.Background(), "", "127.0.0.1", []int{sshPort, silentPort, closedPort})
	if err != nil || len(open) != 2 {
		t.Fatalf("open %+v err %v", open, err)
	}
	for _, o := range open {
		if o.Port == sshPort && (o.Service != "ssh" || o.Banner != "SSH-2.0-OpenSSH_9.6" || o.Web()) {
			t.Errorf("ssh %+v", o)
		}
		if o.Port == silentPort && (o.Banner != "" || !o.Web()) {
			t.Errorf("silent %+v", o)
		}
	}
	if printable([]byte{0x50, 0x3e, 0xfa, 0x01, 0x9c, 0xda, 0x83, 0x40, 0xe0, 0x12}) != "(binary)" {
		t.Error("binary banner shown as text")
	}
}

// A port that says nothing first is asked once: HTTP on the open
// connection, then TLS on a second one, which counts like a connect.
func TestIdentifySilentPorts(t *testing.T) {
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodHead || !strings.HasPrefix(r.Host, "app.test:") || r.UserAgent() != "Mozilla/5.0 test" {
			t.Errorf("probe %s %s Host %s UA %s", r.Method, r.URL, r.Host, r.UserAgent())
		}
		w.Header().Set("Server", "Werkzeug/3.0")
	}))
	defer plain.Close()
	secure := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer secure.Close()
	// A TLS service that is not HTTP: it answers nothing inside.
	quietTLS, _ := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: secure.TLS.Certificates})
	defer quietTLS.Close()
	go func() {
		for {
			c, err := quietTLS.Accept()
			if err != nil {
				return
			}
			go func() {
				_ = c.(*tls.Conn).Handshake()
				time.Sleep(time.Second)
				c.Close()
			}()
		}
	}()
	// Redis answers a command it does not know with -ERR.
	redis, _ := net.Listen("tcp", "127.0.0.1:0")
	defer redis.Close()
	go func() {
		for {
			c, err := redis.Accept()
			if err != nil {
				return
			}
			go func() {
				_, _ = c.Read(make([]byte, 512))
				_, _ = c.Write([]byte("-ERR unknown command 'HEAD'\r\n"))
				c.Close()
			}()
		}
	}()
	port := func(addr string) int {
		_, p, _ := net.SplitHostPort(addr)
		n, _ := strconv.Atoi(p)
		return n
	}
	var taken atomic.Int32
	s := &Scanner{Rate: 1000, Banner: 300 * time.Millisecond, UserAgent: "Mozilla/5.0 test", Take: func() error { taken.Add(1); return nil }}
	ports := []int{port(plain.Listener.Addr().String()), port(secure.Listener.Addr().String()), port(quietTLS.Addr().String()), port(redis.Addr().String())}
	open, err := s.Scan(context.Background(), "app.test", "127.0.0.1", ports)
	if err != nil || len(open) != 4 {
		t.Fatalf("open %+v err %v", open, err)
	}
	got := map[int]Open{}
	for _, o := range open {
		got[o.Port] = o
	}
	if o := got[ports[0]]; o.Service != "http" || o.Banner != "Werkzeug/3.0" || o.TLS || !o.Web() {
		t.Errorf("http %+v", o)
	}
	// Go answers plain HTTP on its TLS port with a 400: still https.
	if o := got[ports[1]]; o.Service != "https" || !o.TLS || o.Banner != "HTTP/1.0 200 OK" || !o.Web() ||
		!slices.Contains(o.SubjectAN, "example.com") || !slices.Contains(o.SubjectAN, "127.0.0.1") {
		t.Errorf("https %+v", o)
	}
	if o := got[ports[2]]; o.Service != "tls" || !o.TLS || !o.Web() || !slices.Contains(o.SubjectAN, "example.com") { // tls: handed on, HTTP inside may be slow
		t.Errorf("tls %+v", o)
	}
	if o := got[ports[3]]; o.Service != "redis" || o.Banner != "-ERR unknown command 'HEAD'" || o.TLS || o.Web() {
		t.Errorf("redis %+v", o)
	}
	// Four connects, and a TLS probe each for the HTTPS and the TLS port.
	if n := taken.Load(); n != 6 {
		t.Errorf("%d connections counted, want 6", n)
	}
}

func TestHTTPAnswer(t *testing.T) {
	for head, want := range map[string]string{
		"HTTP/1.1 200 OK\r\nServer: nginx/1.25\r\nX: y\r\n\r\n": "nginx/1.25",
		"HTTP/1.0 404 Not Found\r\nContent-Length: 0\r\n\r\n":   "HTTP/1.0 404 Not Found",
		"HTTP/1.1 302 Found\r\nserver:  Werkzeug \r\n\r\n":      "Werkzeug",
	} {
		if _, got, ok := httpAnswer([]byte(head)); !ok || got != want {
			t.Errorf("%q: %q", head, got)
		}
	}
	if _, _, ok := httpAnswer([]byte("-ERR unknown")); ok {
		t.Error("not HTTP taken for HTTP")
	}
}

// A port that answers neither way is asked again after the others, and
// stays silent; a refused one is closed and asked once.
func TestSilentPortsAskedTwice(t *testing.T) {
	closed, _ := net.Listen("tcp", "127.0.0.1:0")
	closedPort := closed.Addr().(*net.TCPAddr).Port
	closed.Close()
	var taken atomic.Int32
	s := &Scanner{Rate: 1000, Timeout: 200 * time.Millisecond, Banner: -1, Take: func() error { taken.Add(1); return nil }}
	// TEST-NET-1 has no host: a timeout or an unreachable, never a refusal.
	r, err := s.ScanEach(context.Background(), "", "192.0.2.1", []int{81})
	if err != nil || len(r.Open) != 0 || !reflect.DeepEqual(r.Silent, []int{81}) || taken.Load() != 2 {
		t.Fatalf("silent %+v err %v, %d connects", r, err, taken.Load())
	}
	taken.Store(0)
	r, err = s.ScanEach(context.Background(), "", "127.0.0.1", []int{closedPort})
	if err != nil || len(r.Open)+len(r.Silent) != 0 || taken.Load() != 1 {
		t.Fatalf("closed %+v err %v, %d connects", r, err, taken.Load())
	}
}

// sshd under load greets late: its banner is waited for, not taken for
// a port to ask HTTP.
func TestLateGreeting(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				time.Sleep(300 * time.Millisecond)
				c.Write([]byte("SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13\r\n"))
				time.Sleep(100 * time.Millisecond)
				c.Close()
			}()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	saved := speaksFirst
	defer func() { speaksFirst = saved }()
	speaksFirst = func(p int) bool { return p == port }
	s := &Scanner{Rate: 1000, Timeout: 500 * time.Millisecond, Banner: 200 * time.Millisecond}
	open, err := s.Scan(context.Background(), "", "127.0.0.1", []int{port})
	if err != nil || len(open) != 1 || open[0].Service != "ssh" || open[0].Banner != "SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13" {
		t.Fatalf("late greeting %+v err %v", open, err)
	}
}

// sshd under a burst of connects can hold its greeting back on one
// connection and send it on the next: a server-first port that said
// nothing is connected to once more.
func TestSilentGreeterGetsASecondConnection(t *testing.T) {
	var conns atomic.Int32
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			first := conns.Add(1) == 1
			go func() {
				defer c.Close()
				if first {
					time.Sleep(time.Second) // longer than Timeout + Banner of the scan
					return
				}
				c.Write([]byte("SSH-2.0-OpenSSH_9.6\r\n"))
			}()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	saved := speaksFirst
	t.Cleanup(func() { speaksFirst = saved })
	speaksFirst = func(p int) bool { return p == port }
	var taken atomic.Int32
	s := &Scanner{Rate: 1000, Timeout: 100 * time.Millisecond, Banner: 100 * time.Millisecond, Take: func() error { taken.Add(1); return nil }}
	open, err := s.Scan(context.Background(), "", "127.0.0.1", []int{port})
	if err != nil || len(open) != 1 {
		t.Fatalf("open %+v err %v", open, err)
	}
	if o := open[0]; o.Service != "ssh" || o.Product != "OpenSSH" || o.Version != "9.6" || o.Banner != "SSH-2.0-OpenSSH_9.6" || o.again {
		t.Fatalf("second look %+v", o)
	}
	// The first connect, the TLS probe of the identify and the second look.
	if taken.Load() != 3 || conns.Load() != 3 {
		t.Errorf("%d connects counted, %d made, want 3 and 3", taken.Load(), conns.Load())
	}
}

// A server-first port that never greets keeps today's result, after one
// more connection.
func TestSilentGreeterStaysOpen(t *testing.T) {
	var conns atomic.Int32
	port := listen(t, func(c net.Conn) {
		conns.Add(1)
		time.Sleep(600 * time.Millisecond)
	})
	saved := speaksFirst
	t.Cleanup(func() { speaksFirst = saved })
	speaksFirst = func(p int) bool { return p == port }
	s := &Scanner{Rate: 1000, Timeout: 100 * time.Millisecond, Banner: 100 * time.Millisecond}
	open, err := s.Scan(context.Background(), "", "127.0.0.1", []int{port})
	if err != nil || len(open) != 1 || open[0].Banner != "" || open[0].Service != "" || open[0].again {
		t.Fatalf("open %+v err %v", open, err)
	}
	if conns.Load() != 3 {
		t.Errorf("%d connections, want 3", conns.Load())
	}
}

// A greeting that comes only when the HEAD is sent is not lost.
func TestGreetingInReplyToTheHead(t *testing.T) {
	port := listen(t, func(c net.Conn) {
		_, _ = c.Read(make([]byte, 512))
		c.Write([]byte("SSH-2.0-OpenSSH_9.6\r\nInvalid SSH identification string.\r\n"))
	})
	saved := speaksFirst
	t.Cleanup(func() { speaksFirst = saved })
	speaksFirst = func(p int) bool { return p == port }
	var taken atomic.Int32
	s := &Scanner{Rate: 1000, Timeout: 100 * time.Millisecond, Banner: 100 * time.Millisecond, Take: func() error { taken.Add(1); return nil }}
	open, err := s.Scan(context.Background(), "", "127.0.0.1", []int{port})
	if err != nil || len(open) != 1 {
		t.Fatalf("open %+v err %v", open, err)
	}
	if o := open[0]; o.Service != "ssh" || o.Product != "OpenSSH" || o.Version != "9.6" || o.Banner != "SSH-2.0-OpenSSH_9.6" {
		t.Errorf("greeting in the reply: %+v", o)
	}
	if taken.Load() != 1 {
		t.Errorf("%d connects, want 1: the port was identified", taken.Load())
	}
}

func TestLoopbackUnpacedUnlessRateGiven(t *testing.T) {
	ports := make([]int, 60)
	for i := range ports {
		ports[i] = 1 + i // closed on most machines; refused at once either way
	}
	for _, c := range []struct {
		s    *Scanner
		slow bool
	}{{&Scanner{Banner: -1}, false}, {&Scanner{Rate: 20, Banner: -1}, true}} {
		t0 := time.Now()
		if _, err := c.s.Scan(context.Background(), "127.0.0.1", "127.0.0.1", ports); err != nil {
			t.Fatal(err)
		}
		if took := time.Since(t0); (took > time.Second) != c.slow {
			t.Fatalf("rate %v on loopback took %v", c.s.Rate, took)
		}
	}
}

func TestPortsDashIsAll(t *testing.T) {
	if p, err := Ports("-"); err != nil || len(p) != 65535 {
		t.Fatalf("%d %v", len(p), err)
	}
	p, _ := Ports("top-1000")
	if !slices.Contains(p, 5985) || !slices.Contains(p, 5986) || slices.Contains(p, 3007) || slices.Contains(p, 3013) {
		t.Error("top-1000 is not naabu's list")
	}
}

func TestSpecAndExclude(t *testing.T) {
	if s := Spec([]int{22, 80, 81, 82, 443}); s != "22,80-82,443" {
		t.Error(s)
	}
	got, err := Exclude([]int{22, 80, 81, 443}, "80-81,9")
	if err != nil || !reflect.DeepEqual(got, []int{22, 443}) {
		t.Errorf("%v %v", got, err)
	}
}

func TestTieredOrder(t *testing.T) {
	all, _ := Ports("1-3000")
	a, b := Tiered(all, 1), Tiered(all, 1)
	if !reflect.DeepEqual(a, b) || len(a) != len(all) || reflect.DeepEqual(a, all) {
		t.Fatal("not a repeatable shuffle")
	}
	top, _ := Ports("top-100")
	in := map[int]bool{}
	for _, p := range top {
		in[p] = true
	}
	n := 0
	for _, p := range all {
		if in[p] {
			n++
		}
	}
	for _, p := range a[:n] {
		if !in[p] {
			t.Fatalf("%d before the end of the top 100", p)
		}
	}
}

func listener(t *testing.T) (port int, stop func()) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	return l.Addr().(*net.TCPAddr).Port, func() { l.Close() }
}

// -detect none: one connect per open port, nothing read or sent.
func TestDetectNoneIsOneConnectPerPort(t *testing.T) {
	var n atomic.Int32
	s := &Scanner{Detect: DetectNone, Take: func() error { n.Add(1); return nil }}
	var ports []int
	for i := 0; i < 3; i++ {
		p, stop := listener(t)
		defer stop()
		ports = append(ports, p)
	}
	r, err := s.ScanEach(context.Background(), "", "127.0.0.1", ports)
	if err != nil || len(r.Open) != 3 || n.Load() != 3 {
		t.Fatalf("%d open, %d connects, %v", len(r.Open), n.Load(), err)
	}
}

// A threshold stops asking an address that answers everywhere.
func TestThresholdStopsAHost(t *testing.T) {
	var ports []int
	for i := 0; i < 6; i++ {
		p, stop := listener(t)
		defer stop()
		ports = append(ports, p)
	}
	s := &Scanner{Detect: DetectNone, Threshold: 2, Workers: 1}
	r, _ := s.ScanEach(context.Background(), "", "127.0.0.1", ports)
	if !r.Threshold || len(r.Open) < 2 || len(r.Open) > 3 || r.Asked >= len(ports) {
		t.Fatalf("open %d asked %d threshold %v", len(r.Open), r.Asked, r.Threshold)
	}
}

// Retries: n passes over the silent ports, counted as connects.
func TestRetriesCountedAsConnects(t *testing.T) {
	// 192.0.2.1 is never routed: its connects time out (or are refused on
	// a machine without a route); use loopback closed ports instead and
	// check that refused ports are not retried.
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	p := l.Addr().(*net.TCPAddr).Port
	l.Close()
	var n atomic.Int32
	s := &Scanner{Detect: DetectNone, Retries: 3, Take: func() error { n.Add(1); return nil }}
	r, err := s.ScanEach(context.Background(), "", "127.0.0.1", []int{p})
	if err != nil || len(r.Open) != 0 || len(r.Silent) != 0 || n.Load() != 1 {
		t.Fatalf("%d connects, %+v, %v", n.Load(), r, err)
	}
}

func TestUpAnswersOnRefusal(t *testing.T) {
	s := &Scanner{}
	up, err := s.Up(context.Background(), "127.0.0.1", "127.0.0.1")
	if err != nil || !up {
		t.Fatalf("loopback is up: %v %v", up, err)
	}
}

// A socket that connected to itself is not an open port (a dial from the
// ephemeral range to a closed local port can pick that port as its source).
func TestSelfConnectIsNotOpen(t *testing.T) {
	var conn net.Conn
	for p := 40000; p < 40200 && conn == nil; p++ {
		d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: p}}
		c, err := d.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(p)))
		if err == nil {
			conn = c
		}
	}
	if conn == nil {
		t.Skip("this kernel did not self-connect")
	}
	defer conn.Close()
	if !selfConnect(conn) {
		t.Fatal("a socket connected to itself was not noticed")
	}
	port, stop := listener(t)
	defer stop()
	if c, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port))); err != nil || selfConnect(c) {
		t.Errorf("a connection to a listener is not a self-connect: %v", err)
	} else {
		c.Close()
	}
}

// Scanning the ephemeral range of loopback reports only ports something
// listens on, however many closed ones meet themselves.
func TestEphemeralRangeHasNoPhantomPorts(t *testing.T) {
	listeners := func() map[int]bool {
		m := map[int]bool{}
		for _, file := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
			raw, err := os.ReadFile(file)
			if err != nil {
				t.Skip("no " + file)
			}
			for _, l := range strings.Split(string(raw), "\n")[1:] {
				f := strings.Fields(l)
				if len(f) > 3 && f[3] == "0A" {
					i := strings.LastIndex(f[1], ":")
					if n, err := strconv.ParseInt(f[1][i+1:], 16, 32); err == nil {
						m[int(n)] = true
					}
				}
			}
		}
		return m
	}
	before := listeners()
	var ports []int
	for p := 32768; p <= 60999; p++ {
		ports = append(ports, p)
	}
	s := &Scanner{Detect: DetectNone}
	r, err := s.ScanEach(context.Background(), "", "127.0.0.1", ports)
	if err != nil {
		t.Fatal(err)
	}
	after := listeners()
	selfPorts, reached := tcpPairs()
	for _, o := range r.Open {
		if before[o.Port] || after[o.Port] {
			continue
		}
		if selfPorts[o.Port] {
			t.Errorf("port %d reported open from a connection to itself", o.Port)
			continue
		}
		// Another package's test server may have come and gone during the
		// scan: the scan's closed connection to it, from another local port,
		// is still in TIME_WAIT.
		if reached[o.Port] {
			continue
		}
		c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(o.Port)), time.Second)
		if err == nil {
			self := selfConnect(c)
			c.Close()
			if !self {
				continue
			}
		}
		t.Errorf("port %d reported open and nothing listens on it", o.Port)
	}
}

// tcpPairs reads the loopback TCP entries in every state: the ports a
// socket connected to itself on (local and remote port equal), and the
// remote ports reached from another local port.
func tcpPairs() (self, reached map[int]bool) {
	self, reached = map[int]bool{}, map[int]bool{}
	port := func(addr string) int {
		n, _ := strconv.ParseInt(addr[strings.LastIndex(addr, ":")+1:], 16, 32)
		return int(n)
	}
	for _, file := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		raw, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		for _, l := range strings.Split(string(raw), "\n")[1:] {
			f := strings.Fields(l)
			if len(f) < 4 || f[3] == "0A" {
				continue
			}
			lp, rp := port(f[1]), port(f[2])
			if lp == rp {
				self[lp] = true
			} else {
				reached[rp] = true
			}
		}
	}
	return self, reached
}
