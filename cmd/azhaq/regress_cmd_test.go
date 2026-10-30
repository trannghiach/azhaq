package main

import (
	"encoding/json"
	"fmt"
	"github.com/trannghiach/azhaq/internal/browser"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// SAF-09: an MCP port scan counts against the server's request budget and
// follows its -rate: with the budget spent, no scan runs.
func TestRegressSAF09MCPPortsHonourTheBudget(t *testing.T) {
	dir := t.TempDir()
	script := `#!/bin/sh
echo "$@" >> "$FAKE_DIR/args"
echo '{"type":"summary","command":"ports","exit":0,"complete":true,"results":0,"requests":7}' >&2
`
	exe := filepath.Join(dir, "azhaq")
	if err := os.WriteFile(exe, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FAKE_DIR", dir)
	s := &mcpServer{exe: exe, dir: dir, lock: []string{"-allow", "127.0.0.1"}, locked: true, budget: 10, rate: 5}
	call := func() (string, bool) {
		return callText(t, s, "azhaq_ports", map[string]any{"hosts": []any{"127.0.0.1"}, "ports": "full"})
	}
	if text, isErr := call(); isErr {
		t.Fatalf("a scan with budget left failed: %s", text)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "args"))
	for _, want := range []string{"-rate 5", "-max-requests 10", "-allow 127.0.0.1"} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("the scan ran as %q, want %q in it", strings.TrimSpace(string(raw)), want)
		}
	}
	if s.used != 7 {
		t.Errorf("the scan's connects were not counted: used %d", s.used)
	}
	s.used = s.budget
	os.Remove(filepath.Join(dir, "args"))
	text, isErr := call()
	if !isErr || !strings.Contains(text, "request budget of this server (10) is spent") {
		t.Errorf("a scan after the budget was spent: err %v, %q", isErr, text)
	}
	if _, err := os.Stat(filepath.Join(dir, "args")); err == nil {
		t.Error("azhaq ports ran with the budget spent")
	}
}

// SCP-02: -scope with targets of your own filters them; it adds none of
// the program's own.
func TestRegressSCP02ScopeFiltersTheListGiven(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	var hits [3]atomic.Int64
	serve := func(i int, host string) string {
		l, err := net.Listen("tcp", host+":0")
		if err != nil {
			t.Skip(err)
		}
		srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits[i].Add(1)
			fmt.Fprint(w, "<html><title>"+host+"</title></html>")
		})}
		go srv.Serve(l)
		t.Cleanup(func() { srv.Close() })
		return l.Addr().String()
	}
	inScope := serve(0, "127.0.0.1")
	excluded := serve(1, "127.0.0.2")
	other := serve(2, "127.0.0.3") // in the scope file, not in the list
	scopeFile := writeFile(t, dir, "scope.txt", "127.0.0.1\n"+other+"\nhttp://"+other+"/\n")
	list := writeFile(t, dir, "l.txt", inScope+"\n"+excluded+"\n")
	out, errOut, _ := cli(t, "probe", "-l", list, "-scope", scopeFile, "-json", "-no-tech", "-db", filepath.Join(dir, "p.db"))
	if !strings.Contains(out, "127.0.0.1") || strings.Contains(out, "127.0.0.2") || strings.Contains(out, "127.0.0.3") {
		t.Errorf("rows %s\n%s", out, errOut)
	}
	if hits[0].Load() == 0 || hits[1].Load() != 0 || hits[2].Load() != 0 {
		t.Errorf("requests: in scope %d (%s), excluded %d (%s), scope file's own %d (%s)", hits[0].Load(), inScope, hits[1].Load(), excluded, hits[2].Load(), other)
	}
	if !strings.Contains(errOut, "127.0.0.2") {
		t.Errorf("the excluded target is not in the summary: %s", errOut)
	}
}

// ROL-03 and ROL-10: roles with -quiet among the run's flags prints its
// matrix and summary, and under -json (with -all) stderr is JSON only.
func TestRegressROL03And10RolesOutput(t *testing.T) {
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/":
			fmt.Fprint(w, `<html><a href="/api/me">me</a> <a href="/api/open">open</a></html>`)
		case "/api/me":
			if r.Header.Get("Cookie") == "" {
				w.WriteHeader(http.StatusUnauthorized)
				fmt.Fprint(w, `{"error":"sign in"}`)
				return
			}
			fmt.Fprint(w, `{"user":"a","token":"abc"}`)
		case "/api/open":
			fmt.Fprint(w, `{"ok":true}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer site.Close()
	roles := []string{"-role", "anon", "-role", "a=Cookie: x=1"}

	out, errOut, _ := cli(t, append(append([]string{"roles", "-dir", t.TempDir()}, roles...), "--", "-url", site.URL+"/", "-quiet")...)
	if !strings.Contains(out, "roles  anon · a") || !strings.Contains(errOut, "azhaq roles:") || !strings.Contains(errOut, "endpoints listed") {
		t.Errorf("-quiet among the run's flags hid the result:\nstdout %q\nstderr %q", out, errOut)
	}

	_, errOut, _ = cli(t, append(append([]string{"roles", "-all", "-json", "-dir", t.TempDir()}, roles...), "--", "-url", site.URL+"/")...)
	summaries := 0
	for _, l := range lines(errOut) {
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Errorf("stderr under -json holds a line that is not JSON: %q", l)
			continue
		}
		if m["type"] == "summary" {
			summaries++
		}
	}
	if summaries != 1 {
		t.Errorf("%d summaries on stderr, want 1:\n%s", summaries, errOut)
	}
}

// ROL-14: a static document every visitor gets (a PDF) is not ranked as
// "the same answer for a session that did not find it".
func TestRegressROL14StaticDocumentIsNotShared(t *testing.T) {
	if !staticDoc("http://app.test/docs/DVWA_v1.3.pdf") || staticDoc("http://app.test/api/basket/1") {
		t.Fatal("staticDoc names the wrong URLs")
	}
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			if r.Header.Get("Cookie") != "" { // only the signed-in session sees the link
				fmt.Fprint(w, `<html><a href="/docs/guide.pdf">guide</a></html>`)
				return
			}
			fmt.Fprint(w, `<html>welcome</html>`)
		case "/docs/guide.pdf":
			w.Header().Set("Content-Type", "application/pdf")
			fmt.Fprint(w, "%PDF-1.4 the same file for everyone")
		default:
			http.NotFound(w, r)
		}
	}))
	defer site.Close()
	out, errOut, _ := cli(t, "roles", "-all", "-json", "-dir", t.TempDir(), "-role", "anon", "-role", "a=Cookie: x=1", "--", "-url", site.URL+"/")
	found := false
	for _, l := range lines(out) {
		var row roleRow
		if err := json.Unmarshal([]byte(l), &row); err != nil {
			t.Fatal(err)
		}
		if strings.HasSuffix(row.URL, "/docs/guide.pdf") {
			found = true
			if row.Verdict == verdictShared {
				t.Errorf("a PDF is ranked %q", row.Verdict)
			}
		}
	}
	if !found {
		t.Errorf("the PDF was not compared:\n%s\n%s", out, errOut)
	}
}

// ROL-16: a capped run behind a sign-in prints a resume line that carries
// the credential flags.
func TestRegressROL16ResumeHintCarriesTheLogin(t *testing.T) {
	got := resumeHint("a.db", false, true, "alice@x.test")
	if got != "azhaq resume -db a.db -login-user alice@x.test -login-pass PASS" {
		t.Errorf("resume hint %q", got)
	}
	if got := resumeHint("a.db", true, false, ""); got != "azhaq resume -db a.db -timeout 0" {
		t.Errorf("resume hint %q", got)
	}
}

// OUT-04: an address given as a target is a host, and an export that finds
// nothing says why on stderr.
func TestRegressOUT04ExportHostsAndEmptyReason(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<html><title>x</title></html>")
	}))
	defer site.Close()
	db := filepath.Join(dir, "e.db")
	if _, errOut, code := cli(t, "run", "-url", site.URL+"/", "-db", db, "-quiet"); code != exitOK {
		t.Fatalf("run exit %d\n%s", code, errOut)
	}
	// An address given as a target, no web service answered: still a host.
	ipdb := filepath.Join(dir, "ip.db")
	if _, errOut, code := cli(t, "run", "-list", writeFile(t, dir, "ip.txt", "127.0.0.1\n"), "-passive", "-db", ipdb, "-quiet"); code != exitOK {
		t.Fatalf("run exit %d\n%s", code, errOut)
	}
	out, _, code := cli(t, "export", "-db", ipdb, "-format", "hosts")
	if code != exitOK || !strings.Contains(out, "127.0.0.1") {
		t.Errorf("hosts of an address target: exit %d, %q", code, out)
	}
	for _, format := range []string{"names", "secrets"} {
		out, errOut, code := cli(t, "export", "-db", db, "-format", format)
		if out != "" || code != exitOK || !strings.Contains(errOut, "azhaq export:") || !strings.Contains(errOut, "no ") && !strings.Contains(errOut, "holds") {
			t.Errorf("%s: an empty export said nothing: exit %d, stdout %q, stderr %q", format, code, out, errOut)
		}
	}
}

// OUT-06: watch sees a JSON listing grow and a page's status or title
// change, and says nothing about an unchanged run.
func TestRegressOUT06WatchSeesListingsAndStatusChanges(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	var users atomic.Int64
	users.Store(2)
	var title atomic.Value
	title.Store("Account")
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			fmt.Fprint(w, `<html><title>site</title><a href="/api/users">u</a> <a href="/account">a</a></html>`)
		case "/api/users":
			w.Header().Set("Content-Type", "application/json")
			var items []string
			for i := range users.Load() {
				items = append(items, fmt.Sprintf(`{"id":%d,"name":"user%d"}`, i, i))
			}
			fmt.Fprintf(w, "[%s]", strings.Join(items, ","))
		case "/account":
			fmt.Fprint(w, "<html><title>"+title.Load().(string)+"</title></html>")
		default:
			http.NotFound(w, r)
		}
	}))
	defer site.Close()
	db := filepath.Join(dir, "w.db")
	watch := func() map[string]any {
		out, errOut, code := cli(t, "watch", "-db", db, "-json", "--", "-url", site.URL+"/", "-skip", "azhaq-paths")
		if code != exitOK {
			t.Fatalf("exit %d\n%s", code, errOut)
		}
		var ch map[string]any
		if err := json.Unmarshal([]byte(out), &ch); err != nil {
			t.Fatalf("%v: %q", err, out)
		}
		return ch
	}
	watch() // the baseline
	users.Store(3)
	title.Store("Account (now public)")
	second := watch()
	changed, _ := json.Marshal(second["changed"])
	for _, want := range []string{"/api/users: [200] 2 items", "3 items", "[200] Account → [200] Account (now public)"} {
		if !strings.Contains(string(changed), want) {
			t.Errorf("changed lacks %q: %s", want, changed)
		}
	}
	if third := watch(); third["changed"] != nil || third["urls"] != nil {
		t.Errorf("an unchanged run reported %v", third)
	}
}

// OUT-10: every command in the table is in the usage and in help -json,
// with typed flags; --version works; scope prints text; show takes -json
// after its key.
func TestRegressOUT10CLIPapercuts(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	if out, _, code := cli(t, "--version"); code != exitOK || !strings.HasPrefix(out, "azhaq ") {
		t.Errorf("--version: exit %d, %q", code, out)
	}
	var buf strings.Builder
	printOverview(&buf)
	usage := buf.String()
	raw, _ := json.Marshal(buildManifest()) // what help -json prints (too large for the capture pipe)
	var m manifestForTest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	inManifest := map[string]manifestCommand{}
	for _, c := range m.Commands {
		inManifest[c.Name] = c
	}
	for _, c := range commands {
		if !strings.Contains(usage, "  "+c.name+" ") {
			t.Errorf("the usage does not list %q", c.name)
		}
		if _, ok := inManifest[c.name]; !ok {
			t.Errorf("help -json does not list %q", c.name)
		}
	}
	for _, name := range []string{"resume", "worker"} {
		if _, ok := inManifest[name]; !ok {
			t.Errorf("%s is missing from help -json", name)
		}
	}
	types := map[string]string{}
	for _, f := range inManifest["run"].Flags {
		types[f.Name] = f.Type
	}
	for flagName, want := range map[string]string{"max-requests": "int", "rate": "float", "timeout": "duration", "depth": "int", "quiet": "bool"} {
		if types[flagName] != want {
			t.Errorf("run -%s is typed %q, want %q", flagName, types[flagName], want)
		}
	}
	scopeFile := writeFile(t, dir, "scope.txt", "127.0.0.1\n!127.0.0.2\n")
	if out, _, code := cli(t, "scope", "-scope", scopeFile); code != exitOK || strings.HasPrefix(strings.TrimSpace(out), "{") {
		t.Errorf("scope without -json printed %q (exit %d)", out, code)
	}
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<html><title>x</title></html>")
	}))
	defer site.Close()
	db := filepath.Join(dir, "d.db")
	cli(t, "run", "-url", site.URL+"/", "-db", db, "-quiet")
	out, errOut, code := cli(t, "show", "-db", db, site.URL+"/", "-json")
	if code != exitOK || !strings.HasPrefix(strings.TrimSpace(out), "{") {
		t.Errorf("show URL -json: exit %d, %q %q", code, out, errOut)
	}
	out, _, code = cli(t, "diff", "-db", db)
	if code != exitOK || strings.TrimSpace(out) == "" {
		t.Errorf("diff of a one-run workspace printed nothing (exit %d)", code)
	}
}

type manifestCommand struct {
	Name  string `json:"name"`
	Flags []struct {
		Name string `json:"name"`
		Type string `json:"type"`
	} `json:"flags"`
}

type manifestForTest struct {
	Commands []manifestCommand `json:"commands"`
}

// MAP-21: -browser says when Chrome found nothing the static pass had not.
func TestRegressMAP21BrowserNoteWhenChromeAddsNothing(t *testing.T) {
	if _, err := browser.Find(); err != nil {
		t.Skip(err)
	}
	dir := t.TempDir()
	t.Chdir(dir)
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			fmt.Fprint(w, `<html><title>x</title><a href="/about">about</a></html>`)
			return
		}
		fmt.Fprint(w, "<html><title>about</title></html>")
	}))
	defer site.Close()
	_, errOut, _ := cli(t, "run", "-url", site.URL+"/", "-browser", "-json", "-quiet", "-db", filepath.Join(dir, "b.db"))
	if strings.Contains(errOut, "no sandbox") || strings.Contains(errOut, "Chrome") && strings.Contains(errOut, "cannot") {
		t.Skip("Chrome cannot run here")
	}
	notes, _ := json.Marshal(sumMap(t, errOut)["notes"])
	if !strings.Contains(string(notes), "Chrome rendered") || !strings.Contains(string(notes), "found no URL the static pass had not") {
		t.Errorf("no note that Chrome added nothing: %s", notes)
	}
}

// MAP-29: the HTML report counts web services, not the URLs of one.
func TestRegressMAP29HTMLReportCountsServices(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html><title>`+r.URL.Path+`</title><a href="/a">a</a> <a href="/b">b</a> <a href="/c">c</a></html>`)
	}))
	defer site.Close()
	db := filepath.Join(dir, "h.db")
	if _, errOut, code := cli(t, "run", "-url", site.URL+"/", "-db", db, "-quiet"); code != exitOK {
		t.Fatalf("exit %d\n%s", code, errOut)
	}
	out, _, code := cli(t, "export", "-db", db, "-format", "html")
	if code != exitOK || !strings.Contains(out, "Web services (1)") {
		i := strings.Index(out, "Web services")
		t.Errorf("exit %d; the report says %.40q, want one web service for one origin", code, out[max(i, 0):])
	}
}

// SUB-05: a subs run that exits 0 while sources failed says so on the
// first line of its summary, not only in a field.
func TestRegressSUB05DegradedIsOnTheFirstLine(t *testing.T) {
	r := newReport("subs")
	r.what = "names"
	r.Results = 41
	r.Counts = map[string]int{"sources asked": 38, "sources answered": 31, "sources failed": 7}
	r.Degraded = true
	r.settle()
	var b strings.Builder
	r.print(&b)
	first, _, _ := strings.Cut(b.String(), "\n")
	if r.Exit != exitOK || !strings.Contains(first, "DEGRADED: 7 of 38 sources failed") {
		t.Errorf("exit %d, first line %q", r.Exit, first)
	}
	r.Degraded = false
	b.Reset()
	r.print(&b)
	if strings.Contains(b.String(), "DEGRADED") {
		t.Errorf("a run that was not degraded says so: %s", b.String())
	}
}
