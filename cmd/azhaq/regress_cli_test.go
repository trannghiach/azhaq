package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/trannghiach/azhaq/store"
	"github.com/trannghiach/azhaq/types"
)

// These tests pin findings that reviewers raised and that were fixed
// without a test (REGRESSIONS.md). Each one names its row.

// cli runs one command line as main does and returns what it printed and
// its exit code. Unlike runContract it sets no flag of its own.
func cli(t *testing.T, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	out, errOut, err := captureBoth(t, func() error {
		err := run(args)
		reportError(args, err)
		return err
	})
	return out, errOut, exitCode(err)
}

// summaryOf is the last JSON summary of a command's stderr, as a map.
func sumMap(t *testing.T, stderr string) map[string]any {
	t.Helper()
	var last map[string]any
	for _, l := range strings.Split(stderr, "\n") {
		if l = strings.TrimSpace(l); strings.HasPrefix(l, "{") && strings.Contains(l, `"type":"summary"`) {
			last = map[string]any{}
			if err := json.Unmarshal([]byte(l), &last); err != nil {
				t.Fatalf("%v: %s", err, l)
			}
		}
	}
	if last == nil {
		t.Fatalf("no summary in %q", stderr)
	}
	return last
}

// deadPort is a port on 127.0.0.1 nothing listens on.
func deadPort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	addr := l.Addr().String()
	l.Close()
	return addr
}

func writeFile(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// SUB-16: dns -d DOMAIN -w FILE guesses WORD.DOMAIN as dnsx -d -w does.
func TestRegressSUB16DNSBruteFlag(t *testing.T) {
	t.Chdir(t.TempDir())
	resolvers := serveZone(t, fakeZone{a: map[string]string{"www.example.org": "192.0.2.1", "api.example.org": "192.0.2.2"}})
	words := writeFile(t, t.TempDir(), "words.txt", "www\napi\nftp\nmail\n")
	out, errOut, code := cli(t, "dns", "-d", "example.org", "-w", words, "-resolvers", resolvers, "-json")
	if code != exitOK {
		t.Fatalf("exit %d\n%s", code, errOut)
	}
	var got []string
	for _, l := range lines(out) {
		var row struct{ Host string }
		if err := json.Unmarshal([]byte(l), &row); err != nil {
			t.Fatal(err)
		}
		got = append(got, row.Host)
	}
	if strings.Join(sortedCopy(got), " ") != "api.example.org www.example.org" {
		t.Errorf("names %v, want the two that resolve and none of the others", got)
	}
}

func sortedCopy(in []string) []string {
	out := append([]string(nil), in...)
	for i := range out {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

// SUB-18: query lists every ingested name as a row of its own, not one
// folded row ("1819 names from sources, not resolved").
func TestRegressSUB18QueryListsEveryIngestedName(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	var feed strings.Builder
	const n = 25
	for i := range n {
		fmt.Fprintf(&feed, `{"host":"h%d.example.org","input":"example.org","source":["crtsh"]}`+"\n", i)
	}
	src := writeFile(t, dir, "sf.jsonl", feed.String())
	db := filepath.Join(dir, "i.db")
	if _, errOut, code := cli(t, "ingest", "-in", src, "-db", db); code != exitOK {
		t.Fatalf("ingest exit %d\n%s", code, errOut)
	}
	out, errOut, code := cli(t, "query", "-db", db, "-type", "Hostname", "-json")
	if code != exitOK {
		t.Fatalf("query exit %d\n%s", code, errOut)
	}
	keys := map[string]bool{}
	for _, l := range lines(out) {
		var row struct{ Key string }
		if err := json.Unmarshal([]byte(l), &row); err != nil {
			t.Fatal(err)
		}
		keys[row.Key] = true
	}
	if len(keys) != n || !keys["h7.example.org"] {
		t.Errorf("%d rows for %d ingested names: %v", len(keys), n, out)
	}
}

// PRB-01: every probe target ends as a row, a failure or a skip. A name
// another name redirects to is not swallowed by the redirect.
func TestRegressPRB01ProbeAccountsForEveryInput(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	var port string
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.Host, "a.") {
			http.Redirect(w, r, "http://b.example.org:"+port+"/", http.StatusFound)
			return
		}
		fmt.Fprint(w, "<html><title>"+r.Host+"</title></html>")
	}))
	defer site.Close()
	port = portOf(site.URL)
	resolvers := serveZone(t, fakeZone{a: map[string]string{
		"a.example.org": "127.0.0.1", "b.example.org": "127.0.0.1", "dead.example.org": "127.0.0.1",
	}})
	inputs := []string{"a.example.org", "b.example.org", "dead.example.org:" + portOf("http://"+deadPort(t))}
	list := writeFile(t, dir, "l.txt", strings.Join(inputs, "\n")+"\n")
	out, errOut, _ := cli(t, "probe", "-l", list, "-json", "-allow", "example.org", "-resolvers", resolvers, "-web-ports", port, "-parallel", "1", "-host-parallel", "1", "-no-tech", "-db", filepath.Join(dir, "p.db"))
	sum := sumMap(t, errOut)
	answered := map[string]bool{}
	for _, l := range lines(out) {
		var row struct{ Host string }
		if err := json.Unmarshal([]byte(l), &row); err != nil {
			t.Fatal(err)
		}
		answered[row.Host] = true
	}
	said, _ := json.Marshal([]any{sum["failed"], sum["skipped"], sum["unreachable"]})
	for _, in := range inputs {
		host, _, _ := strings.Cut(in, ":")
		if !answered[host] && !strings.Contains(string(said), host) {
			t.Errorf("%s is neither a row, a failure nor a skip:\n%s\n%s", host, out, said)
		}
	}
	if !answered["b.example.org"] {
		t.Errorf("b.example.org, which a.example.org redirects to, has no row of its own:\n%s", out)
	}
}

func portOf(u string) string { return u[strings.LastIndex(u, ":")+1:] }

// PRB-03: the failures of a probe are all listed by query -failed, not 5
// per kind.
func TestRegressPRB03QueryFailedListsEveryTarget(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	var targets []string
	var ls []net.Listener
	for range 12 {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Skip(err)
		}
		targets = append(targets, l.Addr().String())
		ls = append(ls, l)
	}
	for _, l := range ls {
		l.Close() // the ports now refuse
	}
	list := writeFile(t, dir, "dead.txt", strings.Join(targets, "\n")+"\n")
	db := filepath.Join(dir, "p.db")
	cli(t, "probe", "-l", list, "-json", "-db", db)
	out, errOut, code := cli(t, "query", "-db", db, "-failed")
	if code != exitOK {
		t.Fatalf("exit %d\n%s", code, errOut)
	}
	for _, tg := range targets {
		if !strings.Contains(out, tg) {
			t.Errorf("%s is not in the failed list:\n%s", tg, out)
		}
	}
}

// PRB-10: a plain ports run is not "capped".
func TestRegressPRB10PortsSummaryIsNotCapped(t *testing.T) {
	t.Chdir(t.TempDir())
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	port := fmt.Sprint(l.Addr().(*net.TCPAddr).Port)
	_, errOut, code := cli(t, "ports", "-host", "127.0.0.1", "-p", port, "-json")
	sum := sumMap(t, errOut)
	if _, has := sum["capped"]; has || code != exitOK || sum["complete"] != true {
		t.Errorf("exit %d, summary %v", code, sum)
	}
}

// PRB-19: a file where a directory is expected is a usage error that names
// the path and the flag to change.
func TestRegressPRB19DirectoryErrorsNameThePath(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	file := writeFile(t, dir, "some-file", "x")
	for _, c := range []struct {
		args []string
		want []string
	}{
		{[]string{"shots", "-u", "http://127.0.0.1:1/", "-dir", file}, []string{file, "-dir"}},
		{[]string{"shots", "-u", "http://127.0.0.1:1/", "-o", dir}, []string{dir, "-dir"}},
	} {
		_, errOut, code := cli(t, c.args...)
		if code != exitUsage {
			t.Errorf("%v: exit %d, want 2\n%s", c.args, code, errOut)
		}
		for _, w := range c.want {
			if !strings.Contains(errOut, w) {
				t.Errorf("%v: the message leaves out %q: %s", c.args, w, errOut)
			}
		}
	}
}

// MAP-07: a fetch that failed is an error row, not a visited one.
func TestRegressMAP07ErroredFetchIsNotVisited(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	addr := deadPort(t)
	db := filepath.Join(dir, "m.db")
	_, errOut, code := cli(t, "run", "-url", "http://"+addr+"/", "-db", db, "-json", "-quiet")
	if code != exitPartial {
		t.Errorf("exit %d, want 3\n%s", code, errOut)
	}
	out, _, _ := cli(t, "query", "-db", db, "-type", "URL", "-json")
	for _, l := range lines(out) {
		var row struct{ Coverage string }
		_ = json.Unmarshal([]byte(l), &row)
		if row.Coverage == "visited" {
			t.Errorf("a URL that did not answer is visited: %s", l)
		}
	}
	if !strings.Contains(out, `"coverage":"error"`) {
		t.Errorf("no row has coverage error:\n%s", out)
	}
}

// OUT-03: query prints every row that matches unless -limit is given.
func TestRegressOUT03QueryPrintsEveryRow(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	db := filepath.Join(dir, "q.db")
	st, err := store.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.BeginRun("r1", 1, 0); err != nil {
		t.Fatal(err)
	}
	var keys []string
	for i := range 230 {
		keys = append(keys, fmt.Sprintf("https://app.example.org/page/%c%c", 'a'+i/26, 'a'+i%26))
	}
	if err := st.UpsertMany(types.TypeURL, keys, time.Now(), "", ""); err != nil {
		t.Fatal(err)
	}
	st.Close()
	out, errOut, code := cli(t, "query", "-db", db, "-type", "URL", "-json", "-fields", "key", "-match", "/page/")
	if code != exitOK {
		t.Fatalf("exit %d\n%s", code, errOut)
	}
	// Templates fold the rows of one family: ask for them as they are stored.
	got := len(lines(out))
	sum := sumMap(t, errOut)
	if int(sum["results"].(float64)) != got || got != len(keys) {
		t.Errorf("%d rows printed, results %v: query stops at 200 rows", got, sum["results"])
	}
}

// OUT-07: watch exits with the code of its run.
func TestRegressOUT07WatchExitCode(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	addr := deadPort(t)
	_, _, code := cli(t, "watch", "-db", filepath.Join(dir, "w.db"), "--", "-url", "http://"+addr+"/")
	if code != exitPartial {
		t.Errorf("watch of an unreachable target exits %d, want 3", code)
	}
}

// OUT-09: plan and a usage error leave no azhaq-*.db behind.
func TestRegressOUT09NoStrayDatabases(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	cli(t, "plan", "-url", "http://127.0.0.1:1/")
	_, _, code := cli(t, "run", "-url", "http://127.0.0.1:1/", "-dirs", filepath.Join(dir, "none.txt"), "-depth", "0", "-no-such-flag")
	if code != exitUsage {
		t.Errorf("a bad flag exits %d, want 2", code)
	}
	cli(t, "run", "-dns-brute", "x") // active options without a target
	files, _ := filepath.Glob(filepath.Join(dir, "azhaq-*"))
	if len(files) > 0 {
		t.Errorf("left in the working directory: %v", files)
	}
}

// OUT-17: a usage error under -quiet still says what is wrong.
func TestRegressOUT17QuietUsageErrorPrints(t *testing.T) {
	t.Chdir(t.TempDir())
	_, errOut, code := cli(t, "run", "-quiet", "-no-such-flag")
	if code != exitUsage || !strings.Contains(errOut, "no-such-flag") {
		t.Errorf("exit %d, stderr %q", code, errOut)
	}
}

// OUT-20: the standard library's "Unsolicited response received on idle
// HTTP channel" never reaches stderr, so probe -silent leaves it empty.
func TestRegressOUT20NoStdlibLogOnStderr(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				buf := make([]byte, 4096)
				if _, err := c.Read(buf); err != nil {
					return
				}
				body := "<html><title>x</title></html>"
				fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
				time.Sleep(50 * time.Millisecond)
				fmt.Fprint(c, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n") // stray bytes on the idle connection
				time.Sleep(time.Second)
			}()
		}
	}()
	cmd := exec.Command(os.Args[0], "probe", "-u", "http://"+l.Addr().String()+"/", "-silent", "-no-tech")
	cmd.Env = append(os.Environ(), "AZHAQ_TEST_AS_MAIN=1")
	var stderr strings.Builder
	cmd.Stderr = &stderr
	_ = cmd.Run()
	if stderr.Len() != 0 {
		t.Errorf("stderr under -silent: %q", stderr.String())
	}
}
