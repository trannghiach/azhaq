package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/trannghiach/azhaq/internal/collectors/subcol"
	"github.com/trannghiach/azhaq/internal/fuzz"
)

// atTerminal makes stderr a terminal for the hints.
func atTerminal(t *testing.T) {
	t.Helper()
	old := hintTerminal
	hintTerminal = func() bool { return true }
	t.Cleanup(func() { hintTerminal = old })
}

// runText runs a command line and returns what it wrote to stdout and stderr.
func runText(t *testing.T, args ...string) (string, string) {
	t.Helper()
	out, errOut, _ := captureAll(t, func() error { return run(args) })
	return out, errOut
}

// nextLines are the "next:" lines of a summary.
func nextLines(stderr string) []string {
	var out []string
	for _, l := range strings.Split(stderr, "\n") {
		if l = strings.TrimSpace(l); strings.HasPrefix(l, "next: ") {
			out = append(out, strings.TrimPrefix(l, "next: "))
		}
	}
	return out
}

func subsSources(t *testing.T, names ...string) {
	t.Helper()
	t.Cleanup(subcol.UseTestSources(subcol.TestSource{Name: "s", Default: true, Names: names}))
}

// subs that found names suggests -permute with the names it measured, then
// run, and says nothing where a person is not reading.
func TestSubsNextPermuteThenRun(t *testing.T) {
	t.Chdir(t.TempDir())
	subsSources(t, "api.example.org", "www.example.org", "mail.example.org")
	atTerminal(t)
	_, errOut := runText(t, "subs", "-d", "example.org", "-no-history")
	next := nextLines(errOut)
	if len(next) != 2 {
		t.Fatalf("want two next lines, got %q\n%s", next, errOut)
	}
	if !strings.HasPrefix(next[0], "azhaq subs -d example.org -permute   (try variations of the 3 names found, such as api1.example.org and api-dev.example.org for api.example.org)") {
		t.Errorf("permute hint: %q", next[0])
	}
	if !strings.HasPrefix(next[1], "azhaq run -domain example.org   (one command: names, services, crawl, files and a ranked map, in one workspace)") {
		t.Errorf("run hint: %q", next[1])
	}
}

func TestSubsNextHiddenWhereNoPersonReads(t *testing.T) {
	t.Chdir(t.TempDir())
	subsSources(t, "api.example.org", "www.example.org")
	for name, tc := range map[string]struct {
		terminal bool
		args     []string
		want     bool
	}{
		"not a terminal":      {false, []string{"-no-history"}, false},
		"not a terminal, -v":  {false, []string{"-no-history", "-v"}, true},
		"terminal":            {true, []string{"-no-history"}, true},
		"-json":               {true, []string{"-no-history", "-json"}, false},
		"-silent with a fail": {true, []string{"-no-history", "-silent"}, false},
	} {
		old := hintTerminal
		hintTerminal = func() bool { return tc.terminal }
		_, errOut := runText(t, append([]string{"subs", "-d", "example.org"}, tc.args...)...)
		hintTerminal = old
		if got := len(nextLines(errOut)) > 0 || strings.Contains(errOut, `"next"`); got != tc.want {
			t.Errorf("%s: hints shown %v, want %v\n%s", name, got, tc.want, errOut)
		}
	}
	t.Setenv("AZHAQ_NO_HINTS", "1")
	atTerminal(t)
	if _, errOut := runText(t, "subs", "-d", "example.org", "-no-history"); len(nextLines(errOut)) > 0 {
		t.Errorf("AZHAQ_NO_HINTS did not hide them:\n%s", errOut)
	}
}

// The run hint is shown once for a workspace: the second command into it is quiet.
func TestRunHintOncePerWorkspace(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	subsSources(t, "api.example.org", "www.example.org")
	atTerminal(t)
	db := filepath.Join(dir, "w.db")
	_, first := runText(t, "subs", "-d", "example.org", "-no-history", "-db", db)
	_, second := runText(t, "subs", "-d", "example.org", "-no-history", "-db", db)
	runLine := func(s string) string {
		for _, n := range nextLines(s) {
			if strings.HasPrefix(n, "azhaq run ") {
				return n
			}
		}
		return ""
	}
	if got := runLine(first); !strings.HasPrefix(got, "azhaq run -domain example.org -db "+db+"   (") {
		t.Errorf("first run: %q\n%s", got, first)
	}
	if got := runLine(second); got != "" {
		t.Errorf("second run into the same workspace repeated it: %q", got)
	}
	// Not shown, not recorded: a run nobody read leaves the hint for the next.
	db2 := filepath.Join(dir, "w2.db")
	hintTerminal = func() bool { return false }
	_, quiet := runText(t, "subs", "-d", "example.org", "-no-history", "-db", db2)
	hintTerminal = func() bool { return true }
	_, after := runText(t, "subs", "-d", "example.org", "-no-history", "-db", db2)
	if runLine(quiet) != "" || runLine(after) == "" {
		t.Errorf("a hidden hint was recorded as shown:\n%s\n%s", quiet, after)
	}
}

func TestRunTargetOf(t *testing.T) {
	list := writeTemp(t, "one.txt", "https://a.example.org/\n")
	two := writeTemp(t, "two.txt", "https://a.example.org/\nhttps://b.example.org/\n")
	bare := writeTemp(t, "bare.txt", "a.example.org\n")
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"-passive", "-domain", "example.org", "-allow", "example.org"}, "-domain example.org"},
		{[]string{"-domain=example.org"}, "-domain example.org"},
		{[]string{"-domain", "a.org", "-domain", "b.org"}, ""},
		{[]string{"-url", "https://x.test/"}, "-url https://x.test/"},
		{[]string{"-list", list}, "-url https://a.example.org/"},
		{[]string{"-list", two}, ""},
		{[]string{"-list", bare}, ""},
		{[]string{"-list", list, "-domain", "example.org"}, ""},
		{nil, ""},
	} {
		if got := runTargetOf(tc.args); got != tc.want {
			t.Errorf("%q: %q, want %q", tc.args, got, tc.want)
		}
	}
}

// A single-page app: its front page is an empty shell, a script names routes,
// and every path answers with that shell.
func spaServer() *httptest.Server {
	const shell = `<!doctype html><html><head><title>app</title></head><body><div id="root"></div><script src="/main.js"></script></body></html>`
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/main.js" {
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprint(w, `var routes=["/dashboard","/settings/profile","/admin/users","/reports/monthly","/teams/list","/billing/plans","/billing/invoices","/audit/log","/exports/csv","/imports/new","/keys/api","/webhooks/all","/members/invite"];route(routes);`)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, shell)
	}))
}

func TestCrawlAndRunNextBrowserInteractOnCatchAll(t *testing.T) {
	srv := spaServer()
	defer srv.Close()
	atTerminal(t)
	_, errOut := runText(t, "crawl", "-u", srv.URL+"/", "-silent")
	if n := nextLines(errOut); len(n) != 0 {
		t.Fatalf("-silent printed hints: %q", n)
	}
	_, errOut = runText(t, "crawl", "-u", srv.URL+"/")
	want := "azhaq crawl -u " + srv.URL + "/ -browser -interact   ("
	if n := nextLines(errOut); len(n) == 0 || !strings.HasPrefix(n[0], want) || !strings.Contains(n[0], "answered with the page every unknown path gets; Chrome clicks find the routes only a click shows)") {
		t.Errorf("crawl hints %q\n%s", n, errOut)
	}
	_, errOut = runText(t, "crawl", "-u", srv.URL+"/", "-interact")
	for _, n := range nextLines(errOut) {
		if strings.Contains(n, "-browser -interact") {
			t.Errorf("-interact was given and it is suggested: %q", n)
		}
	}
	_, errOut = runText(t, "run", "-url", srv.URL+"/", "-db", filepath.Join(t.TempDir(), "spa.db"))
	want = "azhaq run -url " + srv.URL + "/ -browser -interact   ("
	if n := nextLines(errOut); !hasPrefix(n, want) {
		t.Errorf("run hints %q\n%s", n, errOut)
	}
}

func hasPrefix(lines []string, prefix string) bool {
	for _, l := range lines {
		if strings.HasPrefix(l, prefix) {
			return true
		}
	}
	return false
}

// A site that answers 404 for unknown paths measures no catch-all.
func TestCrawlNoNextOnServerBuiltSite(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><body><h1>Shop</h1><p>`+strings.Repeat("words ", 80)+`</p><a href="/a">a</a> <a href="/b">b</a></body></html>`)
		case "/a", "/b":
			fmt.Fprint(w, "<html><body>page</body></html>")
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	atTerminal(t)
	_, errOut := runText(t, "crawl", "-u", srv.URL+"/")
	for _, n := range nextLines(errOut) {
		if strings.Contains(n, "-interact") {
			t.Errorf("a server-built site got %q", n)
		}
	}
}

func TestRunAndHuntNextRolesWhenSignedIn(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html><title>x</title><body>`+strings.Repeat("words ", 80)+`<a href="/a">a</a></body></html>`)
	}))
	defer srv.Close()
	dir := t.TempDir()
	t.Chdir(dir)
	atTerminal(t)
	hasRoles := func(lines []string) bool { return hasPrefix(lines, "azhaq roles -role anon") }
	signed, plain := filepath.Join(dir, "signed.db"), filepath.Join(dir, "plain.db")
	_, errOut := runText(t, "run", "-url", srv.URL+"/", "-db", signed, "-header", "Authorization: Bearer abc", "-quiet")
	if !hasRoles(nextLines(errOut)) {
		t.Errorf("a signed-in run has no roles hint:\n%s", errOut)
	}
	_, errOut = runText(t, "run", "-url", srv.URL+"/", "-db", plain, "-quiet")
	if hasRoles(nextLines(errOut)) {
		t.Errorf("a run with no session has one:\n%s", errOut)
	}
	_, errOut = runText(t, "run", "-url", srv.URL+"/", "-db", filepath.Join(dir, "j.db"), "-header", "Authorization: Bearer abc", "-quiet", "-json")
	if strings.Contains(errOut, "azhaq roles") {
		t.Errorf("-json carries the hint:\n%s", errOut)
	}
	if _, errOut = runText(t, "hunt", "-db", signed); !hasRoles(nextLines(errOut)) {
		t.Errorf("hunt on a signed-in workspace:\n%s", errOut)
	}
	if _, errOut = runText(t, "hunt", "-db", plain); hasRoles(nextLines(errOut)) {
		t.Errorf("hunt on a workspace with no session:\n%s", errOut)
	}
}

func TestTokenHintMeasuresBeforeItSuggests(t *testing.T) {
	form := fuzz.Template{Method: "POST", URL: "http://x.test/login", Data: "csrf_token=abc&user=a&pass=FUZZ"}
	for name, tc := range map[string]struct {
		tmpl              fuzz.Template
		answered, refused int
		want              string
	}{
		"refused":              {form, 100, 98, "TOKEN:csrf_token   (the request sends csrf_token with a fixed value and 98 of 100 answers were 403 or 419;"},
		"too few answers":      {form, 9, 9, ""},
		"most answers fine":    {form, 100, 40, ""},
		"no token field":       {fuzz.Template{URL: "http://x.test/FUZZ", Data: "user=a&pass=b"}, 100, 100, ""},
		"token in the query":   {fuzz.Template{URL: "http://x.test/login?authenticity_token=zz&p=FUZZ"}, 50, 50, "TOKEN:authenticity_token"},
		"token in a JSON body": {fuzz.Template{Data: `{"_token":"zz","p":"FUZZ"}`}, 50, 50, "TOKEN:_token"},
	} {
		got := tokenHint(tc.tmpl, tc.answered, tc.refused)
		if (tc.want == "") != (got == "") || !strings.Contains(got, tc.want) {
			t.Errorf("%s: %q, want it to hold %q", name, got, tc.want)
		}
	}
}

// Hints are not in the JSON summary, whatever the terminal.
func TestHintsNeverInJSONSummary(t *testing.T) {
	r := newReport("subs")
	r.hint("azhaq subs -d example.com -permute   (x)")
	raw, _ := json.Marshal(r)
	if strings.Contains(string(raw), "permute") {
		t.Errorf("the JSON summary holds a hint: %s", raw)
	}
	r.hintsVrb = true
	var b strings.Builder
	r.print(&b)
	if !strings.Contains(b.String(), "  next: azhaq subs -d example.com -permute") {
		t.Errorf("-v did not show it:\n%s", b.String())
	}
	r = newReport("subs")
	r.hint("a")
	r.hint("b")
	r.hint("c")
	r.hintsVrb = true
	b.Reset()
	r.print(&b)
	if n := strings.Count(b.String(), "next:"); n != maxHints {
		t.Errorf("%d hint lines, want at most %d:\n%s", n, maxHints, b.String())
	}
}

// run's older -browser line already points to Chrome for a thin map: one
// suggestion, not two.
func TestRunNextBrowserNotTwice(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/main.js" {
			fmt.Fprint(w, `var r=["/dashboard","/settings/profile","/admin/users"];`)
			return
		}
		fmt.Fprint(w, `<html><body><div id="root"></div><script src="/main.js"></script></body></html>`)
	}))
	defer srv.Close()
	atTerminal(t)
	_, errOut := runText(t, "run", "-url", srv.URL+"/", "-db", filepath.Join(t.TempDir(), "x.db"), "-quiet")
	n := 0
	for _, l := range nextLines(errOut) {
		if strings.Contains(l, "-browser") {
			n++
		}
	}
	if n != 1 {
		t.Errorf("%d lines point to Chrome, want 1:\n%s", n, errOut)
	}
}
