package main

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/trannghiach/azhaq/internal/ledger"
)

func TestDiffMultiset(t *testing.T) {
	a := []string{"GET /a", "GET /a", "GET /b", "POST /c"}
	b := []string{"GET /a", "GET /b", "GET /b", "GET /d"}
	oa, ob := diffMultiset(a, b)
	if strings.Join(oa, "|") != "GET /a x1|POST /c x1" || strings.Join(ob, "|") != "GET /b x1|GET /d x1" {
		t.Fatalf("only a %v, only b %v", oa, ob)
	}
	if oa, ob := diffMultiset(a, []string{"POST /c", "GET /b", "GET /a", "GET /a"}); len(oa)+len(ob) != 0 {
		t.Fatalf("same multiset in another order: %v %v", oa, ob)
	}
}

func TestLedgerKey(t *testing.T) {
	origin := "http://127.0.0.1:4000"
	cases := []struct {
		e    ledger.Entry
		want string
	}{
		{ledger.Entry{Kind: "http", Method: "get", Target: origin + "/rest/products/search?q=a%20b"}, "GET /rest/products/search?q=a%20b"},
		{ledger.Entry{Kind: "chrome", Method: "GET", Target: origin + "/#/login"}, "GET /"},
		{ledger.Entry{Kind: "chrome", Method: "GET", Target: "ws://127.0.0.1:4000/socket.io/?EIO=4"}, "GET /socket.io/?EIO=4"},
		{ledger.Entry{Kind: "http", Method: "GET", Target: "http://127.0.0.1:9/x"}, "GET http://127.0.0.1:9/x"},
		{ledger.Entry{Kind: "tcp", Target: "127.0.0.1:22"}, "tcp 127.0.0.1:22"},
	}
	for _, c := range cases {
		if got := ledgerKey(c.e, origin); got != c.want {
			t.Errorf("%+v: %q, want %q", c.e, got, c.want)
		}
	}
}

func TestSummaryRequests(t *testing.T) {
	stderr := "progress 1\n{\"type\":\"summary\",\"requests\":12}\nnoise\n{\"other\":1}\n"
	if n := summaryRequests(stderr); n != 12 {
		t.Fatalf("got %d", n)
	}
	if n := summaryRequests("no json here\n"); n != -1 {
		t.Fatalf("got %d", n)
	}
}

func TestTallyProblems(t *testing.T) {
	ok := tally{summary: 2, ledger: []string{"GET /a", "GET /b"}, counter: []string{"GET /b", "GET /a"}}
	if p := ok.problems(); len(p) != 0 {
		t.Fatalf("agreeing counts: %v", p)
	}
	bad := tally{summary: 3, ledger: []string{"GET /a", "GET /b"}, counter: []string{"GET /a"}}
	if p := strings.Join(bad.problems(), "|"); !strings.Contains(p, "summary 3 != ledger 2") || !strings.Contains(p, "GET /b x1") {
		t.Fatalf("problems: %s", p)
	}
	if p := (tally{summary: -1}).problems(); len(p) == 0 {
		t.Fatal("no summary is a problem")
	}
	if p := (tally{summary: 0, exit: 2}).problems(); len(p) == 0 {
		t.Fatal("exit 2 is a problem")
	}
}

func TestCountProxyLogs(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/go" {
			w.Header().Set("Location", "http://"+r.Host+"/there")
			w.WriteHeader(http.StatusFound)
			return
		}
		_, _ = io.WriteString(w, "ok")
	}))
	defer up.Close()
	p, err := newCountProxy(up.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer p.close()
	cli := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	before := time.Now()
	for _, r := range []struct{ method, path string }{{"GET", "/a?x=1&y=%20"}, {"POST", "/b"}, {"HEAD", "/c"}} {
		req, _ := http.NewRequest(r.method, p.origin+r.path, nil)
		resp, err := cli.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}
	resp, err := cli.Get(p.origin + "/go")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if loc := resp.Header.Get("Location"); loc != p.origin+"/there" {
		t.Errorf("a redirect to the upstream must lead back to the proxy: %q", loc)
	}
	var keys []string
	for _, s := range p.since(0) {
		keys = append(keys, s.key())
		if s.At.Before(before) {
			t.Errorf("%s logged at %v, before it was sent", s.key(), s.At)
		}
	}
	if got := strings.Join(keys, "|"); got != "GET /a?x=1&y=%20|POST /b|HEAD /c|GET /go" {
		t.Fatalf("logged %s", got)
	}
	if p.n() != 4 || len(p.since(2)) != 2 {
		t.Fatalf("n %d, since(2) %d", p.n(), len(p.since(2)))
	}
}

// A WebSocket upgrade goes through the proxy, and is logged as one when
// its headers arrive.
func TestCountProxyWebSocket(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\nhello")
		_ = rw.Flush()
	})}
	go srv.Serve(ln)
	defer srv.Close()
	p, err := newCountProxy("http://" + ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer p.close()
	conn, err := net.Dial("tcp", strings.TrimPrefix(p.origin, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = io.WriteString(conn, "GET /socket.io/?EIO=4&transport=websocket HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n")
	br := bufio.NewReader(conn)
	status, _ := br.ReadString('\n')
	if !strings.Contains(status, "101") {
		t.Fatalf("status %q", status)
	}
	seen := p.since(0)
	if len(seen) != 1 || !seen[0].Upgrade || seen[0].Target != "/socket.io/?EIO=4&transport=websocket" {
		t.Fatalf("logged %+v", seen)
	}
}

func TestDNSEcho(t *testing.T) {
	u := startUDP(true)
	defer u.pc.Close()
	conn, err := net.Dial("udp", u.pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	q := []byte{0xab, 0xcd, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1}
	_, _ = conn.Write(q)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil || n != len(q) || buf[0] != 0xab || buf[1] != 0xcd || buf[2]&0x80 == 0 {
		t.Fatalf("answer %x, %v", buf[:n], err)
	}
	if u.seen.Load() != 1 {
		t.Fatalf("counted %d", u.seen.Load())
	}
}
