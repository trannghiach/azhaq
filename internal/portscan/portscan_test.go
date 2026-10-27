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
