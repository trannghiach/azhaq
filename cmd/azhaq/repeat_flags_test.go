package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
)

// run -url given twice maps both addresses: the second is not dropped.
func TestRunKeepsEveryURLGiven(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.URL.Path)
		mu.Unlock()
		fmt.Fprint(w, `<html><title>x</title></html>`)
	}))
	defer srv.Close()
	dir := t.TempDir()
	_, errOut, code := cli(t, "run", "-url", srv.URL+"/books/alice", "-url", srv.URL+"/books/bob", "-depth", "0", "-no-paths",
		"-db", filepath.Join(dir, "r.db"), "-ledger", "off", "-json")
	if code != exitOK && code != exitPartial {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, p := range []string{"/books/alice", "/books/bob"} {
		if !slices.Contains(seen, p) {
			t.Errorf("%s was never asked for; the server saw %v", p, seen)
		}
	}
}

// roles compares the endpoints of every -url of its run options.
func TestRolesComparesEveryURLGiven(t *testing.T) {
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		user := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if user != "alice" && user != "bob" {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"sign in"}`)
			return
		}
		switch r.URL.Path {
		case "/books/v1/alice_book", "/books/v1/bob_book":
			fmt.Fprintf(w, `{"book_title":%q,"owner":%q,"secret":"s-%s"}`, r.URL.Path, strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/books/v1/"), "_book"), r.URL.Path)
		default:
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"error":"not found"}`)
		}
	}))
	defer site.Close()
	out, errOut, err := captureBoth(t, func() error {
		return cmdRoles([]string{"-json", "-all", "-dir", t.TempDir(), "-role", "anon", "-role", "alice=Authorization: Bearer alice",
			"-role", "bob=Authorization: Bearer bob", "--", "-url", site.URL + "/books/v1/alice_book", "-url", site.URL + "/books/v1/bob_book", "-depth", "0"})
	})
	if err != nil {
		t.Fatalf("%v\n%s", err, errOut)
	}
	var urls []string
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		var row roleRow
		if json.Unmarshal([]byte(l), &row) == nil {
			urls = append(urls, strings.TrimPrefix(row.URL, site.URL))
		}
	}
	for _, p := range []string{"/books/v1/alice_book", "/books/v1/bob_book"} {
		if !slices.Contains(urls, p) {
			t.Errorf("%s is not among the endpoints compared: %v", p, urls)
		}
	}
}

// A flag that takes one value, given twice with two values, is a usage error:
// the second is never dropped silently.
func TestSingleValueFlagsRefuseASecondValue(t *testing.T) {
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a.txt"), filepath.Join(dir, "b.txt")
	for _, f := range []string{a, b} {
		if err := os.WriteFile(f, []byte("example.org\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, args := range [][]string{
		{"run", "-list", a, "-list", b, "-probe"},
		{"run", "-org", "one", "-org", "two", "-probe"},
		{"subs", "-dL", a, "-dL", b},
		{"crawl", "-l", a, "-l", b},
		{"probe", "-l", a, "-l", b},
	} {
		_, errOut, code := cli(t, args...)
		if code != exitUsage || !strings.Contains(errOut, "given twice") {
			t.Errorf("%v: exit %d, %q", args, code, errOut)
		}
	}
	// The same value again is harmless, and a repeatable flag still repeats.
	fs := newFlags("x")
	list := onceString(fs, "l", "")
	if err := fs.Parse([]string{"-l", a, "-l", a}); err != nil || *list != a {
		t.Errorf("the same value twice: %v %q", err, *list)
	}
}

func TestDropFlagRemovesBothForms(t *testing.T) {
	got := dropFlag([]string{"-url", "u", "-list=/x/a.txt", "-depth", "0", "--list", "b", "-in=c"}, "list")
	want := []string{"-url", "u", "-depth", "0", "-in=c"}
	if !slices.Equal(got, want) {
		t.Errorf("%v, want %v", got, want)
	}
}
