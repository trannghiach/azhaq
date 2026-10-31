package browser

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/trannghiach/azhaq/internal/egress"
)

// A page that saves a file as it loads (<a download>), and a URL that is
// a file (Content-Disposition: attachment): Chrome saves neither, nothing
// lands in the user's Downloads folder, and both are listed as refused
// with the name Chrome would have given them.
func TestDownloadsDenied(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_DOWNLOAD_DIR", filepath.Join(home, "Downloads"))
	b := startChrome(t)
	srv := newRecorder(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			fmt.Fprint(w, `<html><body><a id=d href="/report.csv?day=1" download>get</a><a href="/ftp/file.bin">file</a><script>document.getElementById('d').click()</script></body></html>`)
		case "/report.csv":
			w.Header().Set("Content-Type", "text/csv")
			fmt.Fprint(w, "a,b\n1,2\n")
		case "/ftp/file.bin":
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Content-Disposition", `attachment; filename="incident-support.kdbx"`)
			fmt.Fprint(w, strings.Repeat("x", 1024))
		default:
			http.NotFound(w, r)
		}
	})
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	p, err := b.Load(ctx, srv.URL+"/", false)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{srv.URL + "/report.csv (report.csv)"}; !slices.Equal(p.Downloads, want) {
		t.Errorf("the page's downloads: %q, want %q", p.Downloads, want)
	}
	if len(p.Blocked) != 0 {
		t.Errorf("a download is not a request outside the scope: %q", p.Blocked)
	}

	// The URL is the file: the navigation is the download.
	p, _ = b.Load(ctx, srv.URL+"/ftp/file.bin", false)
	if want := []string{srv.URL + "/ftp/file.bin (incident-support.kdbx)"}; !slices.Equal(p.Downloads, want) {
		t.Errorf("the file's download: %q, want %q", p.Downloads, want)
	}
	if n, _, _ := b.Refused(); n != 0 {
		t.Errorf("downloads are not counted as refused for where they went: %d", n)
	}
	b.Close()
	if got := b.LeftoverDownloads(); len(got) != 0 {
		t.Errorf("listed by their pages, not again as leftovers: %q", got)
	}
	// The requests were sent (the file is the target's answer to map), and
	// nothing was saved.
	if got := srv.got(); !slices.Contains(got, "/report.csv") || !slices.Contains(got, "/ftp/file.bin") {
		t.Errorf("the downloads' requests were not sent: %q", got)
	}
	entries, _ := os.ReadDir(filepath.Join(home, "Downloads"))
	for _, e := range entries {
		t.Errorf("saved to Downloads: %s", e.Name())
	}
}

// A page read for its requests and its document is loaded without its
// images, fonts and media (not sent, not counted, not among its
// Requests); its scripts and their calls still are. A screenshot has
// them all.
func TestLeanPage(t *testing.T) {
	b := startChrome(t)
	srv := newRecorder(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><head><style>@font-face{font-family:f;src:url(/f.woff2)}body{font-family:f}</style></head><body>x<img src="/logo"><audio src="/s.mp3"></audio><script src="/app.js"></script></body></html>`)
		case "/app.js":
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprint(w, `fetch("/api/me")`)
		default:
			fmt.Fprint(w, "x")
		}
	})
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	egress.SetScope(func(h string) bool { return h == "127.0.0.1" })
	p, err := b.Load(ctx, srv.URL+"/", false)
	if err != nil {
		t.Fatal(err)
	}
	got := srv.got()
	for _, path := range []string{"/logo", "/s.mp3", "/f.woff2"} {
		if slices.Contains(got, path) {
			t.Errorf("%s fetched for a page that is read, not shot", path)
		}
	}
	for _, path := range []string{"/app.js", "/api/me"} {
		if !slices.Contains(got, path) {
			t.Errorf("%s not fetched: %q", path, got)
		}
	}
	if slices.Contains(p.Requests, srv.URL+"/logo") || !slices.Contains(p.Requests, srv.URL+"/api/me") {
		t.Errorf("requests %q", p.Requests)
	}
	sent := egress.Sent()
	if _, err := b.Load(ctx, srv.URL+"/", true); err != nil {
		t.Fatal(err)
	}
	if got := srv.got(); !slices.Contains(got, "/logo") {
		t.Errorf("a screenshot without the page's images: %q", got)
	}
	if egress.Sent() <= sent {
		t.Errorf("the screenshot's requests are not counted")
	}
}
