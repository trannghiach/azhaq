package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The rows that took one assertion each: they run the built azhaq against
// servers of their own, on 127.0.0.1, and need no network and no docker.

var smokeBin string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "azhaq-smoke")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	smokeBin = filepath.Join(dir, "azhaq")
	if out, err := exec.Command("go", "build", "-o", smokeBin, "../cmd/azhaq").CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "go build: %v\n%s", err, out)
		os.Exit(2)
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// smoke runs azhaq in dir and returns stdout, stderr and the exit code.
func smoke(t *testing.T, dir string, args ...string) (string, string, int) {
	t.Helper()
	cmd := exec.Command(smokeBin, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "AZHAQ_DATA_DIR="+filepath.Join(os.TempDir(), "azhaq-smoke-data"))
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return out.String(), errb.String(), code
}

// site serves a front page linking n pages (through index pages of 40, as a
// crawler keeps only some links of one page), a 100 KB page and a 404 for the rest.
func site(n int) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/":
			var b strings.Builder
			b.WriteString("<html><title>fixture</title>")
			for i := 0; i*40 < n; i++ {
				fmt.Fprintf(&b, `<a href="/i%d">index %d</a>`, i, i)
			}
			fmt.Fprint(w, b.String(), "</html>")
		case numbered(r.URL.Path, "/i"):
			var i int
			fmt.Sscanf(r.URL.Path, "/i%d", &i)
			var b strings.Builder
			b.WriteString("<html><title>index</title>")
			for j := i * 40; j < min(n, (i+1)*40); j++ {
				fmt.Fprintf(&b, `<a href="/p%d">p%d</a>`, j, j)
			}
			fmt.Fprint(w, b.String(), "</html>")
		case r.URL.Path == "/big":
			fmt.Fprint(w, strings.Repeat("x", 100000))
		case numbered(r.URL.Path, "/p"):
			fmt.Fprint(w, "<html>page</html>")
		default:
			http.NotFound(w, r)
		}
	}))
}

// numbered is true for prefix followed by digits only: a calibration path
// of random letters must not look like one of the pages.
func numbered(path, prefix string) bool {
	rest, ok := strings.CutPrefix(path, prefix)
	if !ok || rest == "" {
		return false
	}
	for _, c := range rest {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func lineCount(s string) int { return len(lines([]byte(s))) }

// query without -limit lists every row, not a first page.
func TestQueryDefaultUnlimited(t *testing.T) {
	s := site(150)
	defer s.Close()
	dir := t.TempDir()
	smoke(t, dir, "run", "-url", s.URL+"/", "-db", "m.db", "-quiet")
	out, _, _ := smoke(t, dir, "query", "-db", "m.db", "-type", "URL")
	if n := lineCount(out); n < 150 {
		t.Fatalf("query -type URL listed %d rows of 150+ pages", n)
	}
	out, _, _ = smoke(t, dir, "query", "-db", "m.db", "-type", "URL", "-limit", "5")
	if n := lineCount(out); n != 5 {
		t.Fatalf("query -limit 5 listed %d rows", n)
	}
}

// export names says why it wrote nothing when a run of a URL has no host names.
func TestExportNamesEmptyReason(t *testing.T) {
	s := site(2)
	defer s.Close()
	dir := t.TempDir()
	smoke(t, dir, "run", "-url", s.URL+"/", "-db", "m.db", "-quiet")
	out, errs, _ := smoke(t, dir, "export", "-db", "m.db", "-format", "names")
	if strings.TrimSpace(out) != "" || !strings.Contains(errs, "no host names") {
		t.Fatalf("export names: stdout %q, stderr %q", out, errs)
	}
}

// show -json gives the same answer with its flags before or after the key.
func TestShowJSONFlagOrder(t *testing.T) {
	s := site(2)
	defer s.Close()
	dir := t.TempDir()
	smoke(t, dir, "run", "-url", s.URL+"/", "-db", "m.db", "-quiet")
	a, _, ca := smoke(t, dir, "show", "-db", "m.db", "-json", s.URL+"/")
	b, _, cb := smoke(t, dir, "show", s.URL+"/", "-db", "m.db", "-json")
	if ca != 0 || cb != 0 || a == "" || a != b {
		t.Fatalf("show: exits %d and %d, outputs equal %v", ca, cb, a == b)
	}
}

// plan, help and a usage error write no database.
func TestPlanAndUsageLeaveNoDB(t *testing.T) {
	s := site(2)
	defer s.Close()
	dir := t.TempDir()
	smoke(t, dir, "plan", "-url", s.URL+"/")
	smoke(t, dir, "run", "-h")
	smoke(t, dir, "run")
	smoke(t, dir, "dirs")
	ents, _ := os.ReadDir(dir)
	if len(ents) != 0 {
		var names []string
		for _, e := range ents {
			names = append(names, e.Name())
		}
		t.Fatalf("files left behind: %v", names)
	}
}

// roles -json prints JSON on stderr: every line of it parses.
func TestRolesJSONStderrIsJSON(t *testing.T) {
	s := site(3)
	defer s.Close()
	dir := t.TempDir()
	_, errs, _ := smoke(t, dir, "roles", "-json", "-role", "anon", "-role", "u=X-Role: u", "-dir", dir, "--", "-url", s.URL+"/", "-max-requests", "60")
	n := 0
	for _, l := range lines([]byte(errs)) {
		var v any
		if json.Unmarshal([]byte(l), &v) != nil {
			t.Fatalf("stderr line is not JSON: %q", l)
		}
		n++
	}
	if n == 0 {
		t.Fatal("no summary on stderr")
	}
}

// dirs reports the whole length of a page, not a cut-off one.
func TestDirsReportsFullLength(t *testing.T) {
	s := site(1)
	defer s.Close()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "w.txt"), []byte("big\nnope\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, _, _ := smoke(t, dir, "dirs", "-u", s.URL+"/", "-w", "w.txt", "-json")
	var r struct {
		URL    string `json:"url"`
		Length int    `json:"length"`
	}
	for _, l := range lines([]byte(out)) {
		_ = json.Unmarshal([]byte(l), &r)
	}
	if !strings.HasSuffix(r.URL, "/big") || r.Length != 100000 {
		t.Fatalf("dirs: %q length %d, want /big at 100000 in %q", r.URL, r.Length, out)
	}
}

// probe keeps a failed target, and query -failed lists it for a retry.
func TestProbeFailedList(t *testing.T) {
	s := site(1)
	defer s.Close()
	dir := t.TempDir()
	list := filepath.Join(dir, "l.txt")
	closed := freePorts(1)[0]
	if err := os.WriteFile(list, []byte(strings.TrimPrefix(s.URL, "http://")+"\n"+fmt.Sprintf("127.0.0.1:%d\n", closed)), 0o644); err != nil {
		t.Fatal(err)
	}
	_, _, code := smoke(t, dir, "probe", "-l", list, "-db", "p.db", "-json", "-silent")
	out, _, _ := smoke(t, dir, "query", "-db", "p.db", "-failed")
	if code != 3 || !strings.Contains(out, fmt.Sprintf("127.0.0.1:%d", closed)) {
		t.Fatalf("probe exit %d; query -failed: %q", code, out)
	}
}

// watch exits 0 when the run is complete and 3 when its target fails.
func TestWatchExitCode(t *testing.T) {
	s := site(2)
	defer s.Close()
	dir := t.TempDir()
	if _, _, code := smoke(t, dir, "watch", "-db", "w.db", "-json", "--", "-url", s.URL+"/"); code != 0 {
		t.Fatalf("watch of a live site exits %d", code)
	}
	closed := freePorts(1)[0]
	if _, _, code := smoke(t, dir, "watch", "-db", "w2.db", "-json", "--", "-url", fmt.Sprintf("http://127.0.0.1:%d/", closed)); code != 3 {
		t.Fatalf("watch of a dead target exits %d, want 3", code)
	}
}
