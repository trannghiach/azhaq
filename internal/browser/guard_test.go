package browser

import (
	"context"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"io"
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

	"github.com/trannghiach/azhaq/internal/egress"
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
	egress.SetScope(func(h string) bool { return h == "127.0.0.1" })
	d, err := proxy.SOCKS5("tcp", b.guard.Addr(), nil, proxy.Direct)
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
	_ = egress.Spend(context.Background())
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
	egress.SetScope(func(h string) bool { return h == "127.0.0.1" })
	_ = egress.Spend(ctx)
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
	if n := egress.Sent(); n != int64(served) {
		t.Errorf("counted %d requests, the servers got %d", n, served)
	}

	// The budget spent: the page alone.
	fetch.Reset()
	egress.SetScope(func(h string) bool { return h == "127.0.0.1" })
	egress.SetMaxRequests(1)
	before := len(own.got())
	_ = egress.Spend(ctx)
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
	egress.SetScope(func(h string) bool { return h == "app.azhaq.test" })
	egress.SetResolver(func(_ context.Context, host string) []string {
		if host == "app.azhaq.test" {
			return []string{"127.0.0.1"}
		}
		return nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	_ = egress.Spend(ctx)
	p, err := b.Load(ctx, "http://app.azhaq.test:"+u.Port()+"/", false)
	if err != nil || p.Title != "found" {
		t.Errorf("title %q, %v", p.Title, err)
	}
}
