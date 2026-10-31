package browser

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/trannghiach/azhaq/internal/egress"
	"github.com/trannghiach/azhaq/internal/fetch"
)

// A page that calls alert() on load is shot in moments, not when its
// time is up; what Chrome saw of it (headers, console, requests) is
// kept, and the options shape the picture.
func TestDialogRecordAndOptions(t *testing.T) {
	b := startChrome(t)
	b.Width, b.Height = 700, 500
	b.Format, b.Quality = "jpeg", 40
	b.Wait = -1
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			w.Header().Set("X-Probe", "yes")
			fmt.Fprint(w, `<html><head><title>dlg</title></head><body><script>console.log('hello'); alert('x'); document.write('<img src="/a.png">')</script></body></html>`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	fetch.Reset()
	egress.SetScope(func(h string) bool { return h == "127.0.0.1" })
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	start := time.Now()
	p, err := b.Load(ctx, srv.URL+"/", true)
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Errorf("a page with a dialog took %v", d)
	}
	if p.Format != "jpeg" || len(p.Image) < 3 || p.Image[0] != 0xff || p.Image[1] != 0xd8 {
		t.Errorf("not a jpeg: format %q, %d bytes", p.Format, len(p.Image))
	}
	r := p.Record
	if r.Status != 200 || r.Protocol == "" {
		t.Errorf("answer: %d %q", r.Status, r.Protocol)
	}
	if !slices.ContainsFunc(r.Headers, func(h Header) bool { return h.Key == "X-Probe" && h.Value == "yes" }) {
		t.Errorf("headers %v", r.Headers)
	}
	if !slices.ContainsFunc(r.Console, func(c ConsoleLn) bool { return c.Type == "log" && c.Value == "hello" }) {
		t.Errorf("console %v", r.Console)
	}
	if !slices.ContainsFunc(r.Network, func(n NetEntry) bool { return n.URL == srv.URL+"/a.png" && n.Status == 404 }) {
		t.Errorf("network %v", r.Network)
	}
}

// A page taller than the screen is as tall as it is with FullPage.
func TestFullPage(t *testing.T) {
	b := startChrome(t)
	b.Width, b.Height = 600, 400
	b.FullPage = true
	b.Wait = -1
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body style="margin:0"><div style="height:2000px;background:#a33"></div></body></html>`)
	}))
	defer srv.Close()
	fetch.Reset()
	egress.SetScope(func(h string) bool { return h == "127.0.0.1" })
	p, err := b.Load(context.Background(), srv.URL+"/", true)
	if err != nil {
		t.Fatal(err)
	}
	h := int(p.Image[22])<<24 | int(p.Image[23])<<16 | int(p.Image[24])<<8 | int(p.Image[25]) // PNG IHDR height
	if h < 2000 {
		t.Errorf("full page is %d pixels tall, want 2000", h)
	}
}
