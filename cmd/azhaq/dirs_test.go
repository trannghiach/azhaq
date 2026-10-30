package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/trannghiach/azhaq/internal/collectors/dirscol"
)

func dirsServer(t *testing.T, status map[string]int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if code, ok := status[r.URL.Path]; ok {
			w.WriteHeader(code)
			fmt.Fprintf(w, "answer for %s", r.URL.Path)
			return
		}
		if r.URL.Path == "/" {
			fmt.Fprint(w, "front page")
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// With no -w, the sweep uses the built-in list; a URL with a path is
// swept from it.
func TestDirsBuiltInListAndPathBase(t *testing.T) {
	srv := dirsServer(t, map[string]int{"/admin": 403, "/sub/": 200, "/sub/admin": 200})
	out, errOut, err := captureBoth(t, func() error { return cmdDirs([]string{"-u", srv.URL + "/", "-silent"}) })
	if err != nil {
		t.Fatalf("%v\n%s", err, errOut)
	}
	if strings.TrimSpace(out) != srv.URL+"/admin" {
		t.Errorf("built-in list at the root: %q", out)
	}
	out, errOut, err = captureBoth(t, func() error { return cmdDirs([]string{"-u", srv.URL + "/sub/?q=1", "-silent"}) })
	if err != nil {
		t.Fatalf("%v\n%s", err, errOut)
	}
	if strings.TrimSpace(out) != srv.URL+"/sub/admin" {
		t.Errorf("under /sub/: %q", out)
	}
	if n := len(dirscol.DefaultWords()); n < 4700 || n > 4800 {
		t.Errorf("built-in list has %d words", n)
	}
}

// ffuf's filters and the 200-299 range work; a bad value is a usage
// error; a sweep answered 429 says so and exits 3.
func TestDirsFiltersAndRateLimit(t *testing.T) {
	srv := dirsServer(t, map[string]int{"/admin": 250, "/backup": 200, "/settings": 200})
	words := wlist(t, "admin", "backup", "settings", "nothing")
	out, _, err := captureBoth(t, func() error { return cmdDirs([]string{"-u", srv.URL + "/", "-w", words, "-silent"}) })
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "/admin") || !strings.Contains(out, "/backup") {
		t.Errorf("a 250 is in the default range: %q", out)
	}
	size := fmt.Sprint(len("answer for /backup"))
	out, _, err = captureBoth(t, func() error {
		return cmdDirs([]string{"-u", srv.URL + "/", "-w", words, "-fs", size, "-fc", "250", "-silent"})
	})
	if err != nil || strings.TrimSpace(out) != srv.URL+"/settings" || strings.Contains(out, "/backup") || strings.Contains(out, "/admin") {
		t.Errorf("-fs and -fc: %q, %v", out, err)
	}
	if _, _, err = captureBoth(t, func() error { return cmdDirs([]string{"-u", srv.URL + "/", "-w", words, "-ms", "x"}) }); err == nil || !strings.Contains(err.Error(), "-ms") {
		t.Errorf("a bad -ms: %v", err)
	}
	limited := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			w.WriteHeader(http.StatusTooManyRequests)
		}
	}))
	t.Cleanup(limited.Close)
	_, errOut, err := captureBoth(t, func() error { return cmdDirs([]string{"-u", limited.URL + "/", "-w", words, "-silent"}) })
	if exitCode(err) != 3 || !strings.Contains(errOut, "answered 429") {
		t.Errorf("a 429 sweep: exit %d, %q", exitCode(err), errOut)
	}
}
