package browser

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/proxy"

	"github.com/trannghiach/azhaq/internal/fetch"
)

// A process other than Chrome cannot use the guard to reach the scope.
func TestGuardOnlyChrome(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the guard tells Chrome's connections apart on Linux only")
	}
	b := startChrome(t)
	target := newRecorder(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "internal") })
	defer target.Close()
	fetch.Reset()
	fetch.Allow = func(h string) bool { return h == "127.0.0.1" }
	d, err := proxy.SOCKS5("tcp", b.guard.addr(), nil, proxy.Direct)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(target.URL)
	if c, err := d.Dial("tcp", u.Host); err == nil {
		c.Close()
		t.Error("the guard relayed for a process other than Chrome")
	}
	if got := target.got(); len(got) > 0 {
		t.Errorf("the server was asked for %q", got)
	}
	// Chrome itself still goes through.
	_ = fetch.Spend(context.Background())
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if _, err := b.Load(ctx, target.URL+"/", false); err != nil || !slices.Contains(target.got(), "/") {
		t.Errorf("Chrome's page: %v, server asked for %q", err, target.got())
	}
}

// wsHandler answers a WebSocket handshake, and anything else with x.
func wsHandler(w http.ResponseWriter, r *http.Request) {
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		fmt.Fprint(w, "x")
		return
	}
	sum := sha1.Sum([]byte(r.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	c, rw, err := w.(http.Hijacker).Hijack()
	if err != nil {
		return
	}
	defer c.Close()
	fmt.Fprintf(rw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", base64.StdEncoding.EncodeToString(sum[:]))
	_ = rw.Flush()
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, _ = io.Copy(io.Discard, c)
}

// The WebSockets a page opens, ws:// and wss://, are counted once each,
// by the guard; the page's other requests, TLS ones too, by the Fetch
// domain only. Once the budget is spent, a WebSocket is refused.
func TestGuardCountsWebSockets(t *testing.T) {
	b := startChrome(t)
	var mu sync.Mutex
	secure := 0
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		secure++
		mu.Unlock()
		wsHandler(w, r)
	}))
	defer tlsSrv.Close()
	page := `<html><body><img src="` + tlsSrv.URL + `/pixel.png"><script>
const open = s => new Promise(ok => { const w = new WebSocket(s); w.onopen = () => ok('open'); w.onerror = () => ok('error'); });
Promise.all([open('ws://' + location.host + '/ws'), open('` + strings.Replace(tlsSrv.URL, "https:", "wss:", 1) + `/wss')]).then(r => document.title = r.join(' '));
</script></body></html>`
	own := newRecorder(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, page)
			return
		}
		wsHandler(w, r)
	})
	defer own.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	fetch.Reset()
	fetch.Allow = func(h string) bool { return h == "127.0.0.1" }
	_ = fetch.Spend(ctx)
	p, err := b.Load(ctx, own.URL+"/", false)
	if err != nil {
		t.Fatal(err)
	}
	if p.Title != "open open" {
		t.Errorf("WebSockets: %q", p.Title)
	}
	mu.Lock()
	served := len(own.got()) + secure
	mu.Unlock()
	if n := fetch.Sent(); n != int64(served) {
		t.Errorf("counted %d requests, the servers got %d", n, served)
	}

	// The budget spent: the page alone.
	fetch.Reset()
	fetch.Allow = func(h string) bool { return h == "127.0.0.1" }
	fetch.MaxRequests = 1
	before := len(own.got())
	_ = fetch.Spend(ctx)
	p, _ = b.Load(ctx, own.URL+"/", false)
	if got := own.got()[before:]; len(got) != 1 {
		t.Errorf("sent %q under a budget of 1", got)
	}
	if !p.Capped || strings.Contains(p.Title, "open") {
		t.Errorf("capped %v, WebSockets %q", p.Capped, p.Title)
	}
}

// The guard connects to names as the run's HTTP client does: through the
// run's resolver.
func TestGuardResolver(t *testing.T) {
	b := startChrome(t)
	own := newRecorder(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><head><title>found</title></head></html>`)
	})
	defer own.Close()
	u, _ := url.Parse(own.URL)
	fetch.Reset()
	fetch.Allow = func(h string) bool { return h == "app.azhaq.test" }
	fetch.Resolver = func(_ context.Context, host string) []string {
		if host == "app.azhaq.test" {
			return []string{"127.0.0.1"}
		}
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	_ = fetch.Spend(ctx)
	p, err := b.Load(ctx, "http://app.azhaq.test:"+u.Port()+"/", false)
	if err != nil || p.Title != "found" {
		t.Errorf("title %q, %v", p.Title, err)
	}
}

// The first bytes of a connection tell TLS from plain HTTP, and a
// WebSocket from the rest.
func TestSniff(t *testing.T) {
	hello := func(protos ...string) []byte {
		client, server := net.Pipe()
		defer client.Close()
		go func() {
			_ = tls.Client(client, &tls.Config{ServerName: "x.test", NextProtos: protos, InsecureSkipVerify: true}).Handshake()
		}()
		buf := make([]byte, 1<<15)
		_ = server.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, _ := io.ReadAtLeast(server, buf, 5)
		for n < 5+(int(buf[3])<<8|int(buf[4])) {
			m, err := server.Read(buf[n:])
			if err != nil {
				break
			}
			n += m
		}
		server.Close()
		return buf[:n]
	}
	for _, c := range []struct {
		name    string
		in      []byte
		tls, ws bool
	}{
		{"get", []byte("GET / HTTP/1.1\r\nHost: a\r\nConnection: keep-alive\r\n\r\n"), false, false},
		{"websocket", []byte("GET /ws HTTP/1.1\r\nHost: a\r\nConnection: Upgrade\r\nUpgrade: WebSocket\r\nSec-WebSocket-Version: 13\r\n\r\n"), false, true},
		{"tls h2", hello("h2", "http/1.1"), true, false},
		{"tls websocket", hello("http/1.1"), true, true},
		{"tls no alpn", hello(), true, false},
	} {
		r := bufio.NewReaderSize(bytes.NewReader(c.in), 5+1<<14)
		tls, ws, err := sniff(r)
		if err != nil || tls != c.tls || ws != c.ws {
			t.Errorf("%s: tls %v ws %v, %v", c.name, tls, ws, err)
		}
		if rest, _ := io.ReadAll(r); !bytes.Equal(rest, c.in) {
			t.Errorf("%s: sniffing consumed the bytes", c.name)
		}
	}
}
