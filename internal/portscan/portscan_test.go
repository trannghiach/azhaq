package portscan

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
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
