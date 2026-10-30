package fetch

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/trannghiach/azhaq/internal/neterr"
)

func TestDoSingleflight(t *testing.T) {
	Reset()

	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n.Add(1)
		time.Sleep(50 * time.Millisecond)
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(srv.Close)

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, _, err := Do(context.Background(), srv.Client(), srv.URL+"/"); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if n.Load() != 1 {
		t.Fatalf("server hits %d, want 1", n.Load())
	}
}

func TestRedirectHops(t *testing.T) {
	Reset()
	mux := http.NewServeMux()
	mux.HandleFunc("/admin", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", "/login")
		w.WriteHeader(http.StatusSeeOther)
	})
	mux.HandleFunc("/login", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("login"))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	res, _, err := Do(context.Background(), srv.Client(), srv.URL+"/admin")
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != http.StatusSeeOther {
		t.Fatalf("status %d hops %+v", res.Status, res.Hops)
	}
	if len(res.Hops) < 2 || res.Hops[0].Status != 303 || res.Hops[1].Status != 200 {
		t.Fatalf("hops %+v", res.Hops)
	}
}

// -no-follow: the URL asked is the only request, its redirect recorded.
func TestNoFollowAsksOnce(t *testing.T) {
	Reset()
	defer Reset()
	NoFollow = true
	asked := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked++
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/home", http.StatusFound)
		}
	}))
	t.Cleanup(srv.Close)
	res, _, err := Do(context.Background(), srv.Client(), srv.URL+"/")
	if err != nil {
		t.Fatal(err)
	}
	if asked != 1 || len(res.Hops) != 1 || res.Hops[0].Location != "/home" {
		t.Fatalf("asked %d, hops %+v", asked, res.Hops)
	}
}

func TestExtraHeadersAndUA(t *testing.T) {
	Reset()
	h := make(http.Header)
	h.Set("Cookie", "c1=v1; c2=v2")
	h.Set("User-Agent", "allowlist/1")
	Extra = h

	var gotUA, gotCookie string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
		gotCookie = r.Header.Get("Cookie")
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(srv.Close)

	if _, _, err := Do(context.Background(), srv.Client(), srv.URL+"/"); err != nil {
		t.Fatal(err)
	}
	if gotUA != "allowlist/1" {
		t.Fatalf("ua %q", gotUA)
	}
	if gotCookie != "c1=v1; c2=v2" {
		t.Fatalf("cookie %q", gotCookie)
	}
}

func TestDefaultUA(t *testing.T) {
	Reset()
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("User-Agent")
	}))
	t.Cleanup(srv.Close)
	if _, _, err := Do(context.Background(), srv.Client(), srv.URL+"/"); err != nil {
		t.Fatal(err)
	}
	if got != UserAgent {
		t.Fatalf("ua %q want %s", got, UserAgent)
	}
}

func TestDefaultAccept(t *testing.T) {
	Reset()
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Accept")
	}))
	t.Cleanup(srv.Close)
	if _, _, err := Do(context.Background(), srv.Client(), srv.URL+"/"); err != nil {
		t.Fatal(err)
	}
	if got == "" {
		t.Fatal("missing Accept")
	}
}

func TestBodyTruncated(t *testing.T) {
	Reset()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(bytes.Repeat([]byte("x"), MaxBody+64))
	}))
	t.Cleanup(srv.Close)
	res, _, err := Do(context.Background(), srv.Client(), srv.URL+"/")
	if err != nil {
		t.Fatal(err)
	}
	if !res.Truncated || len(res.Body) != MaxBody {
		t.Fatalf("truncated=%v len=%d", res.Truncated, len(res.Body))
	}
}

func TestRedirectLoopCachedOnce(t *testing.T) {
	Reset()
	var n atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/a", func(w http.ResponseWriter, _ *http.Request) {
		n.Add(1)
		w.Header().Set("Location", "/b")
		w.WriteHeader(http.StatusFound)
	})
	mux.HandleFunc("/b", func(w http.ResponseWriter, _ *http.Request) {
		n.Add(1)
		w.Header().Set("Location", "/a")
		w.WriteHeader(http.StatusFound)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	if _, _, err := Do(context.Background(), srv.Client(), srv.URL+"/a"); err != nil {
		t.Fatal(err)
	}
	first := n.Load()
	if _, _, err := Do(context.Background(), srv.Client(), srv.URL+"/b"); err != nil {
		t.Fatal(err)
	}
	if n.Load() != first {
		t.Fatalf("second walk hit server: %d after %d", n.Load(), first)
	}
}

func TestHostParallel(t *testing.T) {
	Reset()
	HostParallel = 1
	t.Cleanup(func() { HostParallel = 2 })

	var cur, max atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := cur.Add(1)
		if n > max.Load() {
			max.Store(n)
		}
		time.Sleep(40 * time.Millisecond)
		cur.Add(-1)
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(srv.Close)

	var wg sync.WaitGroup
	for _, path := range []string{"/a", "/b", "/c"} {
		wg.Add(1)
		go func(path string) {
			defer wg.Done()
			if _, _, err := Do(context.Background(), srv.Client(), srv.URL+path); err != nil {
				t.Error(err)
			}
		}(path)
	}
	wg.Wait()
	if max.Load() > 1 {
		t.Fatalf("max concurrent %d, want 1", max.Load())
	}
}

func TestNoLogoutWithSession(t *testing.T) {
	Reset()
	defer Reset()
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++ }))
	defer srv.Close()
	if _, _, err := Do(context.Background(), srv.Client(), srv.URL+"/rest/user/logout"); err != nil {
		t.Fatalf("anonymous run may visit logout: %v", err)
	}
	Extra = http.Header{"Authorization": {"Bearer x"}}
	if _, _, err := Do(context.Background(), srv.Client(), srv.URL+"/account/Sign-Out?next=/"); !errors.Is(err, neterr.ErrEndsSession) {
		t.Fatalf("logout with a session: %v", err)
	}
	if hits != 1 {
		t.Errorf("requests %d, want 1", hits)
	}
}

func TestScopeStopsRequestsAndRedirects(t *testing.T) {
	Reset()
	defer Reset()
	outside := 0
	out := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { outside++ }))
	defer out.Close()
	in := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, strings.Replace(out.URL, "127.0.0.1", "localhost", 1)+"/sso", http.StatusFound)
	}))
	defer in.Close()
	Allow = func(host string) bool { return host == "127.0.0.1" }
	res, _, err := Do(context.Background(), in.Client(), in.URL+"/login")
	if err != nil || len(res.Hops) != 1 || res.Hops[0].Status != http.StatusFound {
		t.Fatalf("hops %+v err %v", res.Hops, err)
	}
	if _, _, err := Do(context.Background(), in.Client(), strings.Replace(out.URL, "127.0.0.1", "localhost", 1)+"/x"); !errors.Is(err, neterr.ErrOutOfScope) {
		t.Fatalf("out of scope: %v", err)
	}
	if outside != 0 {
		t.Errorf("%d requests left the scope", outside)
	}
}

// Without a scope, a redirect stays in the site: the registrable domain,
// or the very address or name when there is none.
func TestFollowableSite(t *testing.T) {
	for _, c := range []struct {
		from, to string
		want     bool
	}{
		{"https://app.example.com/", "https://www.example.com/x", true},
		{"https://example.com/", "https://EXAMPLE.com./x", true},
		{"https://app.example.com/", "https://sso.example.net/", false},
		{"http://127.0.0.1:8898/", "http://127.0.0.1:8897/", true},
		{"http://127.0.0.1:8898/", "http://localhost:8897/", false},
		{"http://127.0.0.1/", "http://127.0.0.2/", false},
		{"http://intranet/", "http://wiki/", false},
		{"https://a.github.io/", "https://b.github.io/", false},
	} {
		if got := followable(c.from, c.to); got != c.want {
			t.Errorf("%s → %s: %v", c.from, c.to, got)
		}
	}
}

// SameSite is what a page may load from other hosts: the scope's hosts
// with one, the page's site without.
func TestSameSiteScope(t *testing.T) {
	Reset()
	t.Cleanup(Reset)
	const www, api, cdn = "https://www.example.com/", "https://api.example.com/v1/users", "https://cdn.example.net/app.js"
	if !SameSite(www, api) || SameSite(www, cdn) {
		t.Error("without a scope: the registrable domain")
	}
	Allow = func(h string) bool { return h == "www.example.com" || h == "cdn.example.net" }
	if SameSite(www, api) || !SameSite(www, cdn) {
		t.Error("with a scope: its hosts")
	}
}

// -H 'Host: x' is the Host the request goes with (virtual hosts).
func TestHostHeaderIsTheRequestHost(t *testing.T) {
	Reset()
	defer Reset()
	Extra = http.Header{"Host": {"vhost.lab.test"}}
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got = r.Host }))
	t.Cleanup(srv.Close)
	if _, _, err := Do(context.Background(), srv.Client(), srv.URL+"/"); err != nil {
		t.Fatal(err)
	}
	if got != "vhost.lab.test" {
		t.Errorf("Host %q", got)
	}
}

// A pace that cannot be kept before the deadline waits for it: the work
// is cut short, not failed.
func TestPacePastTheDeadlineIsTheDeadline(t *testing.T) {
	Reset()
	defer Reset()
	SetRate(1)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	_ = Pace(ctx)
	err := Pace(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err %v, want the deadline", err)
	}
}

// A request waiting for the pace when the kill file appears is not sent:
// the wait ends at once with the kill.
func TestKillEndsTheWaitForThePace(t *testing.T) {
	Reset()
	defer Reset()
	path := filepath.Join(t.TempDir(), "stop")
	defer SetKill(path)()
	SetRate(0.5) // one request every 2 s
	ctx := context.Background()
	if err := Spend(ctx); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- Spend(ctx) }() // waits about 2 s for its turn
	time.Sleep(100 * time.Millisecond)
	os.WriteFile(path, nil, 0o644)
	start := time.Now()
	select {
	case err := <-done:
		var k *neterr.Killed
		if !errors.As(err, &k) {
			t.Errorf("err %v, want the kill", err)
		}
		if waited := time.Since(start); waited > 400*time.Millisecond {
			t.Errorf("the wait ended %v after the file", waited)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the waiting request went on after the kill file")
	}
	if Sent() != 1 {
		t.Errorf("counted %d, want 1 (the one that waited was not sent)", Sent())
	}
}
