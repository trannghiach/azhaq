package browser

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/trannghiach/azhaq/internal/fetch"
	"github.com/trannghiach/azhaq/internal/ledger"
)

// proxyLog is a forward proxy that writes down what it is asked: a plain
// request by its method and URL, a tunnel by its CONNECT line.
type proxyLog struct {
	*httptest.Server
	mu       sync.Mutex
	requests []string
	connects []string
}

func newProxyLog() *proxyLog {
	p := &proxyLog{}
	tr := &http.Transport{Proxy: nil}
	p.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			p.mu.Lock()
			p.connects = append(p.connects, r.Host)
			p.mu.Unlock()
			up, err := net.Dial("tcp", r.Host)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadGateway)
				return
			}
			c, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				up.Close()
				return
			}
			_, _ = c.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
			go func() { _, _ = io.Copy(up, c); up.Close() }()
			_, _ = io.Copy(c, up)
			c.Close()
			return
		}
		if r.URL.Host == "" {
			http.Error(w, "not a proxy request", http.StatusBadRequest)
			return
		}
		p.mu.Lock()
		p.requests = append(p.requests, r.Method+" "+r.URL.String())
		p.mu.Unlock()
		out, _ := http.NewRequestWithContext(r.Context(), r.Method, r.URL.String(), r.Body)
		out.Header = r.Header.Clone()
		resp, err := tr.RoundTrip(out)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		for k, vs := range resp.Header {
			w.Header()[k] = vs
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	}))
	return p
}

func (p *proxyLog) seen() (requests, connects []string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.requests...), append([]string(nil), p.connects...)
}

// Every request Chrome sends to a target goes through the run's -proxy,
// loopback targets too, as a request the proxy can read: the proxy holds
// as many as the ledger lists as Chrome's, and the server got no other.
func TestChromeRequestsPassThroughTheRunsProxy(t *testing.T) {
	b := startChrome(t)
	target := newRecorder(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><body><img src="/a.png"><img src="/b.png?x=1"><script src="/app.js"></script>
<script>fetch('/api/data?id=7')</script></body></html>`)
		case "/app.js":
			w.Header().Set("Content-Type", "text/javascript")
			fmt.Fprint(w, "var x = 1;")
		default:
			fmt.Fprint(w, "x")
		}
	})
	defer target.Close()
	prox := newProxyLog()
	defer prox.Close()
	pu, _ := url.Parse(prox.URL)

	path := filepath.Join(t.TempDir(), "l.jsonl")
	l, err := ledger.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	ledger.Use(l)
	defer ledger.Use(nil)
	fetch.Reset()
	fetch.Allow = func(h string) bool { return h == "127.0.0.1" }
	fetch.ProxyURL = pu
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	_ = fetch.Spend(ctx) // the page, which Load's caller counts
	if _, err := b.Load(ctx, target.URL+"/", false); err != nil {
		t.Fatal(err)
	}
	time.Sleep(500 * time.Millisecond)
	b.Close()
	l.Close()

	var chrome []string
	_ = ledger.Read(path, func(e ledger.Entry) error {
		if e.Kind == "chrome" {
			chrome = append(chrome, e.Method+" "+e.Target)
		}
		return nil
	})
	requests, _ := prox.seen()
	got := target.got()
	slices.Sort(chrome)
	slices.Sort(requests)
	if len(chrome) < 3 {
		t.Fatalf("the ledger lists %d requests of Chrome's, want the page and its resources: %v", len(chrome), chrome)
	}
	if !slices.Equal(chrome, requests) {
		t.Errorf("the ledger lists what Chrome sent, the proxy was asked for something else\nledger %v\nproxy  %v", chrome, requests)
	}
	if len(got) != len(requests) {
		t.Errorf("the server got %d requests, %d came through the proxy: %v", len(got), len(requests), got)
	}
	for _, r := range requests {
		if !strings.Contains(r, target.URL) {
			t.Errorf("the proxy was asked for %q", r)
		}
	}
}

// A page over TLS cannot be read by a proxy: the tunnel it is asked for is
// the same the run's own client opens.
func TestChromeTLSGoesThroughTheRunsProxyAsATunnel(t *testing.T) {
	b := startChrome(t)
	var mu sync.Mutex
	var paths []string
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<html><body>secure</body></html>")
	}))
	defer target.Close()
	prox := newProxyLog()
	defer prox.Close()
	pu, _ := url.Parse(prox.URL)
	fetch.Reset()
	fetch.Allow = func(h string) bool { return h == "127.0.0.1" }
	fetch.ProxyURL = pu
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	_ = fetch.Spend(ctx)
	if _, err := b.Load(ctx, target.URL+"/", false); err != nil {
		t.Fatal(err)
	}
	_, connects := prox.seen()
	u, _ := url.Parse(target.URL)
	if !slices.Contains(connects, u.Host) {
		t.Errorf("the proxy was asked for tunnels to %v, not to %s", connects, u.Host)
	}
	mu.Lock()
	defer mu.Unlock()
	if !slices.Contains(paths, "/") {
		t.Errorf("the server got %v", paths)
	}
}

// -chrome-proxy is held to the same: Chrome's plain requests reach that
// proxy as requests it can read.
func TestChromeProxyOptionGetsPlainRequests(t *testing.T) {
	if _, err := Find(); err != nil {
		t.Skip(err)
	}
	target := newRecorder(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body><script src="/app.js"></script></body></html>`)
	})
	defer target.Close()
	prox := newProxyLog()
	defer prox.Close()
	b := &Browser{Proxy: prox.URL}
	t.Cleanup(fetch.Reset)
	if err := b.Start(); errors.Is(err, ErrNoSandbox) {
		t.Skip(err)
	} else if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	fetch.Reset()
	fetch.Allow = func(h string) bool { return h == "127.0.0.1" }
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	_ = fetch.Spend(ctx)
	if _, err := b.Load(ctx, target.URL+"/", false); err != nil {
		t.Fatal(err)
	}
	requests, _ := prox.seen()
	want := []string{"GET " + target.URL + "/", "GET " + target.URL + "/app.js"}
	slices.Sort(requests)
	slices.Sort(want)
	if !slices.Equal(requests, want) {
		t.Errorf("the proxy was asked for %q, want %q", requests, want)
	}
}

// A sign-in in Chrome goes through the run's proxy too: its POST, body and
// all, is a request the proxy reads, and the answer, cookie included, comes
// back whole.
func TestChromeSignInPassesThroughTheRunsProxy(t *testing.T) {
	const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJtZW1iZXIifQ.c2lnbmVk"
	srv := newRecorder(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/login" {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, loginPage)
			return
		}
		var body struct{ Email, Password string }
		if err := decodeJSON(r, &body); err != nil || body.Email != "member@x.test" || body.Password != "s3cret" {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: "abc123", Path: "/", HttpOnly: true})
		fmt.Fprintf(w, `{"token":%q,"bid":7}`, jwt)
	})
	defer srv.Close()
	prox := newProxyLog()
	defer prox.Close()
	pu, _ := url.Parse(prox.URL)
	b := startChrome(t)
	fetch.Reset()
	fetch.Allow = func(h string) bool { return h == "127.0.0.1" }
	fetch.ProxyURL = pu
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	s, err := b.Login(ctx, srv.URL+"/login", "member@x.test", "s3cret")
	if err != nil {
		t.Fatal(err)
	}
	if s.Bearer != jwt || len(s.Cookies) != 1 || s.Cookies[0] != "sid=abc123" {
		t.Errorf("signed in as %q with cookies %v", s.Bearer, s.Cookies)
	}
	requests, connects := prox.seen()
	if !slices.Contains(requests, "POST "+srv.URL+"/api/login") || !slices.Contains(requests, "GET "+srv.URL+"/login") {
		t.Errorf("the proxy was asked for %q (tunnels %q)", requests, connects)
	}
	if len(srv.got()) != len(requests) {
		t.Errorf("the server got %v, %d came through the proxy", srv.got(), len(requests))
	}
}

// Chrome's own services (updates, time, sign-in) reach for Google while a
// page loads and the browser idles, whatever flags turn off: the guard
// refuses each connection and counts it, and the proxy is asked for the
// target and nothing else.
func TestChromeBackgroundConnectionsAreRefusedAndCounted(t *testing.T) {
	b := startChrome(t)
	target := newRecorder(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<html><body>quiet</body></html>")
	})
	defer target.Close()
	prox := newProxyLog()
	defer prox.Close()
	pu, _ := url.Parse(prox.URL)
	fetch.Reset()
	fetch.Allow = func(h string) bool { return h == "127.0.0.1" }
	fetch.ProxyURL = pu
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	_ = fetch.Spend(ctx)
	if _, err := b.Load(ctx, target.URL+"/", false); err != nil {
		t.Fatal(err)
	}
	time.Sleep(6 * time.Second) // the updater and the time service start within seconds
	n, hosts := b.GuardDenied()
	b.Close()
	t.Logf("Chrome opened %d connections of its own, all refused: %v", n, hosts)
	for _, h := range hosts {
		if h == "127.0.0.1" {
			t.Errorf("the target's own address was counted as outside the scope")
		}
	}
	requests, connects := prox.seen()
	for _, r := range append(requests, connects...) {
		if !strings.Contains(r, "127.0.0.1") {
			t.Errorf("the proxy was asked for %q: a connection outside the scope got through", r)
		}
	}
}
