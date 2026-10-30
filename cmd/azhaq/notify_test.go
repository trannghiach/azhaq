package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// captureAll runs f with standard output and error going to pipes.
func captureAll(t *testing.T, f func() error) (stdout, stderr string, err error) {
	t.Helper()
	outR, outW, _ := os.Pipe()
	errR, errW, _ := os.Pipe()
	so, se := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = outW, errW
	done := make(chan [2]string)
	go func() {
		a, _ := io.ReadAll(outR)
		b, _ := io.ReadAll(errR)
		done <- [2]string{string(a), string(b)}
	}()
	err = f()
	os.Stdout, os.Stderr = so, se
	outW.Close()
	errW.Close()
	r := <-done
	return r[0], r[1], err
}

func writeTemp(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// recorder answers every request with status and keeps the bodies.
type recorder struct {
	mu     sync.Mutex
	bodies []string
	paths  []string
}

func (r *recorder) server(status int) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		b, _ := io.ReadAll(req.Body)
		r.mu.Lock()
		r.bodies = append(r.bodies, string(b))
		r.paths = append(r.paths, req.URL.Path)
		r.mu.Unlock()
		w.WriteHeader(status)
		io.WriteString(w, "refused "+req.URL.String())
	}))
}

func TestNotifyCommandSendsLikeNotify(t *testing.T) {
	rec := &recorder{}
	srv := rec.server(200)
	defer srv.Close()
	cfg := writeTemp(t, "pc.yaml", "custom:\n  - id: c\n    custom_webhook_url: "+srv.URL+"/in\n    custom_method: POST\n    custom_format: \"[{{count}}] {{data}}\"\n")
	in := writeTemp(t, "in.txt", "aaa\nbbb\nccc\nddd\n")
	out, errOut, err := captureAll(t, func() error {
		return cmdNotify([]string{"-pc", cfg, "-i", in, "-bulk", "-cl", "9", "-rl", "0", "-json"})
	})
	if err != nil {
		t.Fatalf("%v\n%s", err, errOut)
	}
	want := []string{"[1] aaa\nbbb", "[2] ccc\nddd"}
	if strings.Join(rec.bodies, "|") != strings.Join(want, "|") {
		t.Errorf("posted %q, want %q", rec.bodies, want)
	}
	if lines := strings.Split(strings.TrimSpace(out), "\n"); len(lines) != 2 || !strings.Contains(lines[0], `"message":"aaa\nbbb"`) {
		t.Errorf("stdout %q", out)
	}
	var sum map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(errOut)), &sum); err != nil || sum["results"] != float64(2) || sum["exit"] != float64(0) {
		t.Errorf("summary %q", errOut)
	}
}

// A message a provider refused is a failure in the summary and exit 3, and
// the summary does not hold the URL the server echoed.
func TestNotifyCommandNamesWhatWasNotDelivered(t *testing.T) {
	rec := &recorder{}
	srv := rec.server(400)
	defer srv.Close()
	cfg := writeTemp(t, "pc.yaml", "custom:\n  - id: broken\n    custom_webhook_url: "+srv.URL+"/hook/TOKEN-abcdef123\n    custom_method: POST\n")
	in := writeTemp(t, "in.txt", "one\ntwo\n")
	_, errOut, err := captureAll(t, func() error {
		return cmdNotify([]string{"-pc", cfg, "-i", in, "-rl", "0"})
	})
	if exitCode(err) != exitPartial {
		t.Fatalf("exit %d, want 3: %v", exitCode(err), err)
	}
	if !strings.Contains(errOut, "custom failed") || !strings.Contains(errOut, "broken") || !strings.Contains(errOut, "400") || strings.Contains(errOut, "abcdef123") {
		t.Errorf("summary %q", errOut)
	}
	if len(rec.bodies) != 2 {
		t.Errorf("%d posts: a 400 is not tried again", len(rec.bodies))
	}
}

func TestNotifyCommandUsageErrors(t *testing.T) {
	cfg := writeTemp(t, "pc.yaml", "custom:\n  - id: a\n    custom_webhook_url: http://127.0.0.1:1/\n    custom_method: POST\n")
	in := writeTemp(t, "in.txt", "x\n")
	for name, args := range map[string][]string{
		"no entry matches": {"-pc", cfg, "-i", in, "-id", "zzz"},
		"unknown provider": {"-pc", cfg, "-i", in, "-p", "sms"},
		"no config":        {"-pc", filepath.Join(t.TempDir(), "none.yaml"), "-i", in},
		"tiny limit":       {"-pc", cfg, "-i", in, "-cl", "3"},
		"mistyped key":     {"-pc", writeTemp(t, "bad.yaml", "custom:\n  - custom_url: x\n"), "-i", in},
		"v and silent":     {"-pc", cfg, "-i", in, "-v", "-silent"},
	} {
		if _, _, err := captureAll(t, func() error { return cmdNotify(args) }); exitCode(err) != exitUsage {
			t.Errorf("%s: exit %d (%v), want 2", name, exitCode(err), err)
		}
	}
}

func TestNotifyConfigFlagsAndPrecedence(t *testing.T) {
	rec := &recorder{}
	srv := rec.server(200)
	defer srv.Close()
	pc := writeTemp(t, "pc.yaml", "custom:\n  - id: c\n    custom_webhook_url: "+srv.URL+"/in\n    custom_method: POST\n")
	in := writeTemp(t, "in.txt", "a\nb\nc\n")
	conf := writeTemp(t, "config.yaml", "bulk: true\nrate-limit: 0\nprovider-config: "+pc+"\nchar-limit: 2\n")
	// char-limit: 2 in the file is overridden by -cl on the command line.
	if _, errOut, err := captureAll(t, func() error { return cmdNotify([]string{"-config", conf, "-i", in, "-cl", "4000", "-silent"}) }); err != nil {
		t.Fatalf("%v %s", err, errOut)
	}
	if len(rec.bodies) != 1 || rec.bodies[0] != "a\nb\nc" {
		t.Errorf("bulk from the file: %q", rec.bodies)
	}
}

// notify writes every flag with its default into config.yaml; -v names only
// the keys that change something.
func TestNotifyConfigDefaultsAreQuiet(t *testing.T) {
	rec := &recorder{}
	srv := rec.server(200)
	defer srv.Close()
	pc := writeTemp(t, "pc.yaml", "custom:\n  - id: c\n    custom_webhook_url: "+srv.URL+"/in\n    custom_method: POST\n")
	in := writeTemp(t, "in.txt", "a\n")
	conf := writeTemp(t, "config.yaml", "silent: \"false\"\nnc: \"false\"\nid: []\nbulk: \"true\"\n")
	_, errOut, err := captureAll(t, func() error { return cmdNotify([]string{"-config", conf, "-pc", pc, "-i", in, "-v"}) })
	if err != nil {
		t.Fatalf("%v %s", err, errOut)
	}
	if !strings.Contains(errOut, conf+" sets bulk\n") || strings.Contains(errOut, "silent") || strings.Contains(errOut, ": nc") {
		t.Errorf("stderr: %s", errOut)
	}
}

// The webhook's token is on no path out of watch: not the command line, not
// stdout, stderr or the workspace. A hook that cannot be reached, answers
// 500 and echoes the URL, or rate-limits all stay quiet about it, and the
// run still says that nothing arrived (exit 3).
func TestWatchKeepsTheTokenOut(t *testing.T) {
	const tok = "TOKEN-zq81x7mpl"
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html><title>site</title></html>"))
	}))
	defer site.Close()
	rec := &recorder{}
	echo := rec.server(500)
	defer echo.Close()
	dead := httptest.NewServer(nil)
	deadURL := dead.URL
	dead.Close()
	hooks := writeTemp(t, "hooks.txt", "# the team channel\n"+deadURL+"/services/"+tok+"\n"+echo.URL+"/echo/"+tok+"?key="+tok+"\n")
	db := filepath.Join(t.TempDir(), "w.db")
	t.Setenv("AZHAQ_NOTIFY", "http://127.0.0.1:1/env/"+tok)
	out, errOut, err := captureAll(t, func() error {
		return cmdWatch([]string{"-db", db, "-always", "-notify", "@" + hooks, "-notify-rate", "0", "--", "-url", site.URL + "/", "-skip", "azhaq-paths"})
	})
	if exitCode(err) != exitPartial {
		t.Errorf("exit %d (%v): a notification that did not arrive is exit 3", exitCode(err), err)
	}
	raw, _ := os.ReadFile(db)
	for name, s := range map[string]string{"stdout": out, "stderr": errOut, "workspace": string(raw)} {
		if strings.Contains(s, tok) || strings.Contains(s, "zq81x7mpl") {
			t.Errorf("the token is in the %s", name)
		}
	}
	if got := strings.Count(errOut, "azhaq watch: "); got < 3 {
		t.Errorf("%d failure lines for three hooks:\n%s", got, errOut)
	}
}

func TestWatchSendsToProviderConfig(t *testing.T) {
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html><title>site</title></html>"))
	}))
	defer site.Close()
	rec := &recorder{}
	srv := rec.server(200)
	defer srv.Close()
	pc := writeTemp(t, "pc.yaml", "custom:\n  - id: ops\n    custom_webhook_url: "+srv.URL+"/ops\n    custom_method: POST\n    custom_format: \"watch says: {{data}}\"\n  - id: other\n    custom_webhook_url: "+srv.URL+"/other\n    custom_method: POST\n")
	db := filepath.Join(t.TempDir(), "w.db")
	_, errOut, err := captureAll(t, func() error {
		return cmdWatch([]string{"-db", db, "-always", "-notify-config", pc, "-notify-id", "ops", "-notify-rate", "0", "--", "-url", site.URL + "/", "-skip", "azhaq-paths"})
	})
	if err != nil {
		t.Fatalf("%v %s", err, errOut)
	}
	if len(rec.bodies) != 1 || rec.paths[0] != "/ops" || !strings.HasPrefix(rec.bodies[0], "watch says: azhaq watch ") {
		t.Errorf("%q %q", rec.paths, rec.bodies)
	}
}

func TestHooksFromFileAndEnvironment(t *testing.T) {
	f := writeTemp(t, "h.txt", "# c\n\nhttps://a.test/x\n  https://b.test/y  \n")
	got, err := hooksFrom([]string{"https://c.test/z", "@" + f}, "https://d.test/1, https://e.test/2\nhttps://f.test/3")
	want := "https://c.test/z https://a.test/x https://b.test/y https://d.test/1 https://e.test/2 https://f.test/3"
	if err != nil || strings.Join(got, " ") != want {
		t.Errorf("%v %v", got, err)
	}
	if _, err := hooksFrom([]string{"@/nonexistent/hooks"}, ""); exitCode(err) != exitUsage || strings.Contains(err.Error(), "https") {
		t.Errorf("%v", err)
	}
}
