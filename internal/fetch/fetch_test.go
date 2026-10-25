package fetch

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
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
