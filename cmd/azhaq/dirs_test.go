package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/trannghiach/azhaq/internal/collectors/dirscol"
	"github.com/trannghiach/azhaq/store"
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
	asked := append([]string(nil), paths...)
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

// A -timeout that ends a sweep is a stop, not a finish: exit 4, the words
// not asked are left, and resume asks exactly those.
func TestDirsTimeoutStopsAndResumeFinishes(t *testing.T) {
	var mu sync.Mutex
	seen := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen[r.URL.Path]++
		mu.Unlock()
		if strings.HasPrefix(r.URL.Path, "/w") && strings.HasSuffix(r.URL.Path, "0") {
			fmt.Fprint(w, "found "+r.URL.Path)
			return
		}
		if r.URL.Path == "/" {
			fmt.Fprint(w, "front page")
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	var words []string
	for i := range 50 {
		words = append(words, fmt.Sprintf("w%d", i))
	}
	wl := wlist(t, words...)
	hitsOf := func(out string) []string {
		var got []string
		for _, l := range lines(out) {
			var m map[string]any
			if json.Unmarshal([]byte(l), &m) == nil {
				got = append(got, m["url"].(string))
			}
		}
		sort.Strings(got)
		return got
	}
	// What one uninterrupted run finds.
	want, _, err := captureBoth(t, func() error {
		return cmdDirs([]string{"-u", srv.URL + "/", "-w", wl, "-json", "-ledger", "off"})
	})
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	seen = map[string]int{}
	mu.Unlock()

	db := filepath.Join(t.TempDir(), "d.db")
	_, errOut, err := captureBoth(t, func() error {
		return cmdDirs([]string{"-u", srv.URL + "/", "-w", wl, "-json", "-ledger", "off", "-db", db, "-rate", "5", "-timeout", "1s"})
	})
	if exitCode(err) != exitLimit {
		t.Fatalf("exit %d, want %d: %v\n%s", exitCode(err), exitLimit, err, errOut)
	}
	rep := lastReport(t, errOut)
	if rep.Complete || rep.Stopped == "" || !strings.Contains(rep.Resume, "azhaq resume -db") {
		t.Fatalf("a stopped run says %+v", rep)
	}
	mu.Lock()
	first := 0
	for p := range seen {
		if strings.HasPrefix(p, "/w") {
			first++
		}
	}
	mu.Unlock()
	if first == 0 || first >= 50 {
		t.Fatalf("%d of 50 words asked before the stop", first)
	}
	_, errOut, err = captureBoth(t, func() error { return cmdResume([]string{"-db", db, "-json", "-timeout", "0", "-dirs-rate", "1000"}) })
	if err != nil {
		t.Fatalf("resume: %v\n%s", err, errOut)
	}
	mu.Lock()
	for _, w := range words {
		if seen["/"+w] != 1 {
			t.Errorf("/%s asked %d times", w, seen["/"+w])
		}
	}
	mu.Unlock()
	// The stopped run's hits and the resume's together are one run's.
	st, err := store.OpenExisting(db)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ents, _ := st.Entities()
	var found []string
	for _, e := range ents {
		if strings.Contains(e.Key, "/w") {
			found = append(found, e.Key)
		}
	}
	sort.Strings(found)
	if fmt.Sprint(found) != fmt.Sprint(hitsOf(want)) {
		t.Errorf("after the resume %v, one run %v", found, hitsOf(want))
	}
}

// A sweep sends one request for each word and nothing else: no page is
// asked first (a redirecting front page would add its target), so -fs and
// -max-requests with the words' count are enough, as with ffuf.
func TestDirsSendsOneRequestPerWord(t *testing.T) {
	var mu sync.Mutex
	seen := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen[r.URL.Path]++
		mu.Unlock()
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		fmt.Fprint(w, "sign in")
	}))
	defer srv.Close()
	words := []string{"", "login"}
	for i := range 18 {
		words = append(words, fmt.Sprintf("w%d", i))
	}
	wl := wlist(t, words...)
	_, errOut, err := captureBoth(t, func() error {
		return cmdDirs([]string{"-u", srv.URL + "/", "-w", wl, "-mc", "all", "-fs", "28", "-max-requests", "20", "-json", "-ledger", "off"})
	})
	if err != nil {
		t.Fatalf("a budget of the 20 words stopped the sweep: %v\n%s", err, errOut)
	}
	mu.Lock()
	defer mu.Unlock()
	total := 0
	for p, n := range seen {
		total += n
		if n != 1 {
			t.Errorf("%s asked %d times", p, n)
		}
	}
	if total != 20 {
		t.Errorf("%d requests for 20 words: %v", total, seen)
	}
	if rep := lastReport(t, errOut); rep.Requests != 20 {
		t.Errorf("the summary counts %d requests", rep.Requests)
	}
}

// A service that does not answer ends the sweep after its first words, and
// is listed as unreachable, as the front page check did.
func TestDirsDeadServiceStopsAtOnce(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	words := make([]string, 50)
	for i := range words {
		words[i] = fmt.Sprintf("w%d", i)
	}
	wl := wlist(t, words...)
	for _, filter := range [][]string{{"-fs", "7"}, nil} {
		_, errOut, err := captureBoth(t, func() error {
			return cmdDirs(append([]string{"-u", "http://" + addr + "/", "-w", wl, "-json", "-ledger", "off"}, filter...))
		})
		rep := lastReport(t, errOut)
		if exitCode(err) != exitPartial || len(rep.Unreachable) != 1 || rep.Requests > 6 {
			t.Errorf("%v: exit %d, unreachable %v, %d requests\n%s", filter, exitCode(err), rep.Unreachable, rep.Requests, errOut)
		}
	}
}

// azhaq resume of a dirs run prints as dirs: its rows, with command dirs.
// The rows of the stopped run and of the resume are those of one run, none
// twice.
func TestDirsResumePrintsAsDirs(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/w") && strings.HasSuffix(r.URL.Path, "0") || strings.HasSuffix(r.URL.Path, "5") && strings.HasPrefix(r.URL.Path, "/w") {
			fmt.Fprint(w, "found "+r.URL.Path)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	var words []string
	for i := range 40 {
		words = append(words, fmt.Sprintf("w%d", i))
	}
	wl := wlist(t, words...)
	urls := func(out string) []string {
		var got []string
		for _, l := range lines(out) {
			var m map[string]any
			if json.Unmarshal([]byte(l), &m) == nil {
				got = append(got, m["url"].(string))
			}
		}
		sort.Strings(got)
		return got
	}
	// -fs: no calibration, so a budget counts words.
	base := []string{"-u", srv.URL + "/", "-w", wl, "-fs", "19", "-json", "-ledger", "off"}
	want, _, err := captureBoth(t, func() error { return cmdDirs(base) })
	if err != nil || len(urls(want)) != 8 {
		t.Fatalf("one run: %v, %q", err, want)
	}
	db := filepath.Join(t.TempDir(), "d.db")
	first, errOut, err := captureBoth(t, func() error { return cmdDirs(append(slices.Clone(base), "-db", db, "-max-requests", "25")) })
	if exitCode(err) != exitLimit {
		t.Fatalf("exit %d: %v\n%s", exitCode(err), err, errOut)
	}
	if rep := lastReport(t, errOut); rep.Command != "dirs" || rep.Results != len(urls(first)) {
		t.Fatalf("the stopped run's summary: %+v", rep)
	}
	second, errOut, err := captureBoth(t, func() error { return cmdResume([]string{"-db", db, "-max-requests", "100", "-json"}) })
	if err != nil {
		t.Fatalf("resume: %v\n%s", err, errOut)
	}
	rep := lastReport(t, errOut)
	if rep.Command != "dirs" || rep.Results != len(urls(second)) || rep.Exit != exitOK {
		t.Errorf("the resume's summary: %+v", rep)
	}
	if len(urls(first)) == 0 || len(urls(second)) == 0 {
		t.Errorf("rows: %d then %d", len(urls(first)), len(urls(second)))
	}
	got := urls(first + second)
	if fmt.Sprint(got) != fmt.Sprint(urls(want)) {
		t.Errorf("the two runs printed\n%v\none run printed\n%v", got, urls(want))
	}
}
