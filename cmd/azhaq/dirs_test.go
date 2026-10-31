package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
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

// An empty line of the wordlist is a word: it asks for the base URL itself,
// as in ffuf, and counts like any other.
func TestDirsBlankWordAsksTheBase(t *testing.T) {
	srv := dirsServer(t, map[string]int{"/admin": 403})
	words := wlist(t, "", "admin", "nothing")
	out, errOut, err := captureBoth(t, func() error { return cmdDirs([]string{"-u", srv.URL + "/", "-w", words, "-json"}) })
	if err != nil {
		t.Fatalf("%v\n%s", err, errOut)
	}
	if !strings.Contains(out, `"url":"`+srv.URL+`/"`) || !strings.Contains(out, srv.URL+"/admin") {
		t.Errorf("the blank word's answer is missing: %q", out)
	}
	rep := lastReport(t, errOut)
	if rep.Requests < 3 || rep.Results != 2 {
		t.Errorf("summary %+v, want the blank word counted", rep)
	}
}

// A filter given by hand turns calibration off, as in ffuf: no guesses are
// sent, and every word the filter does not remove is listed.
func TestDirsFilterTurnsCalibrationOff(t *testing.T) {
	var mu sync.Mutex
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		if r.URL.Path == "/admin" {
			fmt.Fprint(w, strings.Repeat("a", 99))
			return
		}
		fmt.Fprint(w, strings.Repeat("c", 50)) // every unknown path: one size
	}))
	defer srv.Close()
	words := wlist(t, "admin", "foo", "bar")
	out, errOut, err := captureBoth(t, func() error {
		return cmdDirs([]string{"-u", srv.URL + "/", "-w", words, "-fs", "7", "-mc", "all", "-silent", "-json"})
	})
	if err != nil {
		t.Fatalf("%v\n%s", err, errOut)
	}
	var asked []string // the service's own front page is probed first, not swept
	for _, p := range paths {
		if p != "/" {
			asked = append(asked, p)
		}
	}
	sort.Strings(asked)
	if fmt.Sprint(asked) != "[/admin /bar /foo]" {
		t.Errorf("requests %v: calibration guesses were sent", paths)
	}
	var got []string
	for _, l := range lines(out) {
		var m map[string]any
		if json.Unmarshal([]byte(l), &m) == nil {
			got = append(got, strings.TrimPrefix(m["url"].(string), srv.URL))
		}
	}
	sort.Strings(got)
	if fmt.Sprint(got) != "[/admin /bar /foo]" {
		t.Errorf("listed %v", got)
	}
	if !strings.Contains(errOut, "no calibration") {
		t.Errorf("the summary does not say so:\n%s", errOut)
	}
	// Without a filter the catch-all size is calibrated away.
	paths = nil
	out, _, err = captureBoth(t, func() error {
		return cmdDirs([]string{"-u", srv.URL + "/", "-w", words, "-silent"})
	})
	if err != nil || strings.TrimSpace(out) != srv.URL+"/admin" || len(paths) <= 4 {
		t.Errorf("default: %q %v, %d requests", out, err, len(paths))
	}
}
