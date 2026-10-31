package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/trannghiach/azhaq/internal/browser"
)

// The recipes below are in docs/RECIPES.md. Each test takes the command lines
// from the page, so a recipe whose flags or output change fails here.

// recipesPath is absolute: the tests change directory.
var recipesPath, _ = filepath.Abs("../../docs/RECIPES.md")

// recipeLines are the lines of the fenced blocks under a "## title" heading
// of docs/RECIPES.md, not the ones of the next heading.
func recipeLines(t *testing.T, title string) []string {
	t.Helper()
	var out []string
	in, fenced := false, false
	for _, l := range strings.Split(readDoc(t, recipesPath), "\n") {
		if strings.HasPrefix(l, "## ") {
			in = l == "## "+title
		}
		if !in {
			continue
		}
		if strings.HasPrefix(strings.TrimSpace(l), "```") {
			fenced = !fenced
			continue
		}
		if fenced && strings.TrimSpace(l) != "" {
			out = append(out, strings.TrimSpace(l))
		}
	}
	if len(out) == 0 {
		t.Fatalf("no command lines under %q in docs/RECIPES.md", title)
	}
	return out
}

// azhaqArgs are the arguments of a recipe line that starts with azhaq, up to
// its first pipe or redirect, with host standing for the page's example host.
func azhaqArgs(t *testing.T, line, host string) []string {
	t.Helper()
	line = strings.ReplaceAll(line, "https://app.example.com", host)
	var args []string
	var cur strings.Builder
	quoted, has := false, false
loop:
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case c == '\'':
			quoted, has = !quoted, true
		case quoted:
			cur.WriteByte(c)
		case c == ' ':
			if has {
				args = append(args, cur.String())
				cur.Reset()
				has = false
			}
		case c == '|' || c == '>' || c == '#':
			break loop
		default:
			cur.WriteByte(c)
			has = true
		}
	}
	if has {
		args = append(args, cur.String())
	}
	if len(args) < 2 || args[0] != "azhaq" {
		t.Fatalf("not an azhaq line: %q", line)
	}
	return args[1:]
}

// csrfApp is a login with a one-use token: the form hands out a fresh
// csrf_token, a POST with any other is refused with 403, and the password
// letmein answers 302.
func csrfApp() *httptest.Server {
	var mu sync.Mutex
	issued := map[string]bool{}
	n := 0
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Method == http.MethodGet {
			n++
			tok := fmt.Sprintf("tok%d", n)
			issued[tok] = true
			fmt.Fprintf(w, `<form method="post"><input type="hidden" name="csrf_token" value="%s"><input name="user"><input name="pass"></form>`, tok)
			return
		}
		_ = r.ParseForm()
		tok := r.PostForm.Get("csrf_token")
		if !issued[tok] {
			http.Error(w, "invalid csrf token", http.StatusForbidden)
			return
		}
		delete(issued, tok)
		if r.PostForm.Get("pass") == "letmein" {
			http.Redirect(w, r, "/home", http.StatusFound)
			return
		}
		fmt.Fprint(w, "bad credentials")
	}))
}

func TestRecipeFuzzFormWithCSRFToken(t *testing.T) {
	srv := csrfApp()
	defer srv.Close()
	t.Chdir(t.TempDir())
	atTerminal(t)
	lines := recipeLines(t, "Fuzz a form that has a CSRF token")
	var fuzzes []string
	var printfLine string
	for _, l := range lines {
		switch {
		case strings.HasPrefix(l, "azhaq fuzz "):
			fuzzes = append(fuzzes, l)
		case strings.HasPrefix(l, "printf "):
			printfLine = l
		}
	}
	if len(fuzzes) != 2 || printfLine != `printf 'GET /login HTTP/1.1\n\n' > page.req` {
		t.Fatalf("the recipe's lines changed: %q", lines)
	}
	words := []string{"admin", "root", "toor", "123456", "qwerty", "dragon", "monkey", "master", "shadow", "sunshine", "princess", "letmein", "welcome", "football"}
	must(t, os.WriteFile("pass.txt", []byte(strings.Join(words, "\n")+"\n"), 0o644))
	must(t, os.WriteFile("page.req", []byte("GET /login HTTP/1.1\n\n"), 0o644))

	// Without the preflight every guess is refused, and the summary says what to do.
	out, errOut, _ := cli(t, azhaqArgs(t, fuzzes[0], srv.URL)...)
	if got := strings.Count(out, "Status: 403"); got != len(words) {
		t.Errorf("%d of %d answers were 403:\n%s", got, len(words), out)
	}
	next := nextLines(errOut)
	want := "azhaq fuzz … -preflight PAGE.req -preflight-var-auto TOKEN:csrf_token   (the request sends csrf_token with a fixed value and 14 of 14 answers were 403 or 419;"
	if len(next) != 1 || !strings.HasPrefix(next[0], want) {
		t.Errorf("next lines %q\n%s", next, errOut)
	}

	// With it the right password is the one row.
	out, errOut, code := cli(t, azhaqArgs(t, fuzzes[1], srv.URL)...)
	if code != exitOK || !strings.Contains(out, "letmein") || !strings.Contains(out, "Status: 302") || strings.Count(out, "Status:") != 1 {
		t.Errorf("exit %d, rows:\n%s\n%s", code, out, errOut)
	}
	if !strings.Contains(errOut, fmt.Sprintf("%d preflight/postflight requests were sent", len(words))) {
		t.Errorf("the summary does not count the page requests:\n%s", errOut)
	}
	if n := nextLines(errOut); len(n) != 0 {
		t.Errorf("hints with the preflight given: %q", n)
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func TestRecipeSubdomainsByVariation(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	resolvers := serveZone(t, fakeZone{a: map[string]string{
		"www.example.com": "192.0.2.1", "api.example.com": "192.0.2.2",
		"api2.example.com": "192.0.2.3", "www-dev.example.com": "192.0.2.4",
	}})
	subsSources(t, "www.example.com", "api.example.com")
	lines := recipeLines(t, "Find subdomains by variation")
	if len(lines) != 2 {
		t.Fatalf("the recipe's lines changed: %q", lines)
	}
	args := azhaqArgs(t, lines[0], "")
	if args[0] != "subs" {
		t.Fatalf("first line: %q", lines[0])
	}
	out, errOut, code := cli(t, append(args, "-resolvers", resolvers, "-no-history")...)
	if code != exitOK {
		t.Fatalf("exit %d\n%s", code, errOut)
	}
	got := map[string]string{}
	for _, r := range jsonRows(t, out) {
		got[r["host"].(string)], _ = r["source"].(string)
	}
	for _, name := range []string{"api2.example.com", "www-dev.example.com"} {
		if got[name] != "permute" {
			t.Errorf("%s: source %q, want permute; rows %v", name, got[name], got)
		}
	}
	counts := sumMap(t, errOut)["counts"].(map[string]any)
	if counts["found by guessing"] != float64(2) || counts["asked by guessing"] == nil {
		t.Errorf("counts %v", counts)
	}

	// The same inside run: the map holds the names the variations found.
	rargs := azhaqArgs(t, lines[1], "")
	if rargs[0] != "run" {
		t.Fatalf("second line: %q", lines[1])
	}
	out, errOut, code = cli(t, append(rargs, "-resolvers", resolvers, "-no-history", "-skip", skipAllBut("azhaq-subdomains", "azhaq-dns", "azhaq-permute"))...)
	if code != exitOK || !strings.Contains(out, "api2.example.com") || !strings.Contains(out, "www-dev.example.com") {
		t.Errorf("run: exit %d\n%s\n%s", code, out, errOut)
	}
}

// spaClickServer is an app whose menu is buttons: a click changes the
// address and calls an API route nothing else names.
func spaClickServer() *httptest.Server {
	const page = `<!doctype html><html><head><title>app</title></head><body><div id="root"></div>
<script src="/main.js"></script></body></html>`
	const js = `
const root = document.getElementById('root');
root.innerHTML = '<nav><button id="b">Billing</button> <button id="r">Reports</button></nav><p>Welcome</p>';
document.getElementById('b').onclick = () => { history.pushState({}, '', '/billing'); fetch('/api/billing/plans'); };
document.getElementById('r').onclick = () => { history.pushState({}, '', '/reports'); fetch('/api/reports/monthly'); };
`
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/main.js":
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprint(w, js)
		case strings.HasPrefix(r.URL.Path, "/api/"):
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"ok":true}`)
		default:
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, page)
		}
	}))
}

func TestRecipeRoutesOnlyAClickShows(t *testing.T) {
	if _, err := browser.Find(); err != nil {
		t.Skip(err)
	}
	srv := spaClickServer()
	defer srv.Close()
	t.Chdir(t.TempDir())
	lines := recipeLines(t, "Find the routes only a click shows")
	if len(lines) != 3 {
		t.Fatalf("the recipe's lines changed: %q", lines)
	}
	for i, l := range lines {
		args := azhaqArgs(t, l, srv.URL)
		if i < 2 {
			args = append(args, "-allow", "127.0.0.1")
		}
		out, errOut, code := cli(t, args...)
		if strings.Contains(errOut, "sandbox") || strings.Contains(errOut, "Chrome") && strings.Contains(errOut, "cannot") {
			t.Skip("Chrome cannot run here")
		}
		if code != exitOK {
			t.Fatalf("%q: exit %d\n%s", l, code, errOut)
		}
		switch i {
		case 0, 1:
			if !strings.Contains(errOut, "-interact: ") || !strings.Contains(errOut, "clicks on") {
				t.Errorf("%q: no click note in the summary:\n%s", l, errOut)
			}
		case 2:
			for _, want := range []string{"/api/billing/plans", "/api/reports/monthly"} {
				if !strings.Contains(out, want) {
					t.Errorf("the query does not list %s:\n%s", want, out)
				}
			}
		}
	}
}
