package browser

import (
	"context"
	"encoding/base64"
	"fmt"
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

// The ledger and the count hold what reached the server, no more: a page
// still asking when it is closed, paced, has requests waiting that are
// never sent, and a WebSocket's line has its path.
func TestLedgerHoldsWhatTheServerGot(t *testing.T) {
	b := startChrome(t)
	page := `<html><body><script>
new WebSocket('ws://' + location.host + '/sock?sid=7');
let i = 0; setInterval(() => fetch('/tick' + (i++)), 20);
</script>`
	for n := 0; n < 12; n++ {
		page += fmt.Sprintf(`<img src="/img%d.png">`, n)
	}
	page += `</body></html>`
	own := newRecorder(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, page)
			return
		}
		wsHandler(w, r)
	})
	defer own.Close()
	path := filepath.Join(t.TempDir(), "l.jsonl")
	l, err := ledger.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	ledger.Use(l)
	defer ledger.Use(nil)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	fetch.Reset()
	fetch.Allow = func(h string) bool { return h == "127.0.0.1" }
	fetch.SetRate(8)     // slower than the page asks: some wait when it closes
	_ = fetch.Spend(ctx) // the page, which Load's caller counts
	if _, err := b.Load(ctx, own.URL+"/", false); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Second)
	b.Close()
	l.Close()
	var listed []string
	_ = ledger.Read(path, func(e ledger.Entry) error {
		u, _ := url.Parse(e.Target)
		listed = append(listed, u.Path)
		if u.Scheme == "ws" && u.RawQuery != "sid=7" {
			t.Errorf("WebSocket line %s: no path and query", e.Target)
		}
		return nil
	})
	got := own.got()
	slices.Sort(listed)
	slices.Sort(got)
	if !slices.Equal(listed, got) {
		t.Errorf("ledger %d lines, server got %d\nledger %v\nserver %v", len(listed), len(got), listed, got)
	}
	if n := fetch.Sent(); n != int64(len(got)) {
		t.Errorf("counted %d requests, the server got %d", n, len(got))
	}
}

// A script several pages share is answered from Chrome's cache after the
// first: the ledger and the count hold the one that reached the server.
func TestCacheHitsAreNotListed(t *testing.T) {
	b := startChrome(t)
	own := newRecorder(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/shared.js", "/shared.css":
			w.Header().Set("Cache-Control", "max-age=3600")
			if r.URL.Path == "/shared.js" {
				w.Header().Set("Content-Type", "text/javascript")
				fmt.Fprint(w, "document.title = 'ok';")
				return
			}
			w.Header().Set("Content-Type", "text/css")
			fmt.Fprint(w, "body{}")
		default:
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><head><link rel=stylesheet href="/shared.css"><script src="/shared.js"></script></head><body>page</body></html>`)
		}
	})
	defer own.Close()
	path := filepath.Join(t.TempDir(), "l.jsonl")
	l, err := ledger.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	ledger.Use(l)
	defer ledger.Use(nil)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	fetch.Reset()
	fetch.Allow = func(h string) bool { return h == "127.0.0.1" }
	for _, p := range []string{"/a", "/b", "/c"} {
		_ = fetch.Spend(ctx) // each page, which Load's caller counts
		if _, err := b.Load(ctx, own.URL+p, false); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(500 * time.Millisecond)
	b.Close()
	l.Close()
	var listed []string
	_ = ledger.Read(path, func(e ledger.Entry) error {
		u, _ := url.Parse(e.Target)
		listed = append(listed, u.Path)
		return nil
	})
	got := own.got()
	slices.Sort(listed)
	slices.Sort(got)
	if !slices.Equal(listed, got) {
		t.Errorf("ledger %v\nserver %v", listed, got)
	}
	if n := fetch.Sent(); n != int64(len(got)) {
		t.Errorf("counted %d requests, the server got %d: %v", n, len(got), got)
	}
}

// A page of 22 requests at 4 a second takes longer than its tab's
// wall-clock time would give, and is still taken whole: the pace is a
// cap per second at the server, and the ledger, the count and the server
// agree on what was sent.
func TestPoliteShotIsWhole(t *testing.T) {
	b := startChrome(t)
	b.Timeout = 4 * time.Second // the page needs about 6 s at this pace
	var mu sync.Mutex
	var stamps []time.Time
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		stamps = append(stamps, time.Now())
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		switch {
		case r.URL.Path == "/":
			w.Header().Set("Content-Type", "text/html")
			html := "<html><head><title>polite</title><link rel=stylesheet href=/a.css><script src=/a.js></script></head><body>"
			for n := 0; n < 20; n++ {
				html += fmt.Sprintf(`<img src="/i%d.png" width=10 height=10>`, n)
			}
			fmt.Fprint(w, html+"</body></html>")
		case strings.HasSuffix(r.URL.Path, ".css"):
			w.Header().Set("Content-Type", "text/css")
		case strings.HasSuffix(r.URL.Path, ".js"):
			w.Header().Set("Content-Type", "text/javascript")
		default:
			w.Header().Set("Content-Type", "image/png")
			_, _ = w.Write(tinyPNG)
		}
	}))
	defer srv.Close()
	path := filepath.Join(t.TempDir(), "l.jsonl")
	l, err := ledger.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	ledger.Use(l)
	defer ledger.Use(nil)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	fetch.Reset()
	fetch.Allow = func(h string) bool { return h == "127.0.0.1" }
	fetch.SetRate(4)
	_ = fetch.Spend(ctx) // the page, which Load's caller counts
	p, err := b.Load(ctx, srv.URL+"/", true)
	if err != nil {
		t.Fatal(err)
	}
	if p.Partial || p.Unloaded != 0 || p.Resources != 22 || len(p.Image) == 0 {
		t.Errorf("page not whole: partial %v, %d of %d unloaded, %d bytes", p.Partial, p.Unloaded, p.Resources, len(p.Image))
	}
	time.Sleep(500 * time.Millisecond)
	b.Close()
	l.Close()
	mu.Lock()
	defer mu.Unlock()
	best := 0
	for i := range stamps {
		n := 0
		for _, s := range stamps {
			if d := s.Sub(stamps[i]); d >= 0 && d < time.Second {
				n++
			}
		}
		best = max(best, n)
	}
	if best > 4+2 {
		t.Errorf("%d requests within a second at -rate 4", best)
	}
	var listed []string
	_ = ledger.Read(path, func(e ledger.Entry) error {
		u, _ := url.Parse(e.Target)
		listed = append(listed, u.Path)
		return nil
	})
	slices.Sort(listed)
	got := slices.Clone(paths)
	slices.Sort(got)
	if !slices.Equal(listed, got) {
		t.Errorf("ledger %d lines, server got %d", len(listed), len(got))
	}
	if n := fetch.Sent(); n != int64(len(got)) {
		t.Errorf("counted %d requests, the server got %d", n, len(got))
	}
}

// A picture taken while the page still waits for its images says so.
func TestShotOfAStalledPageIsPartial(t *testing.T) {
	b := startChrome(t)
	b.Timeout = 4 * time.Second
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow.png" {
			select {
			case <-r.Context().Done():
			case <-time.After(20 * time.Second):
			}
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body><img src="/slow.png"></body></html>`)
	}))
	defer srv.Close()
	fetch.Reset()
	fetch.Allow = func(h string) bool { return h == "127.0.0.1" }
	p, err := b.Load(context.Background(), srv.URL+"/", true)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Partial || p.Unloaded != 1 || len(p.Image) == 0 {
		t.Errorf("want a partial picture, got partial %v, %d unloaded, %d bytes", p.Partial, p.Unloaded, len(p.Image))
	}
}

var tinyPNG, _ = base64.StdEncoding.DecodeString("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==")
