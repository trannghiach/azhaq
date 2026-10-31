package main

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// serveWithWorker runs `azhaq run -serve` and one `azhaq worker`, each as its
// own process (the test binary again), and gives their stderr and the run's
// exit code. A worker is a process of its own with its own settings, so a
// rule or a session the run does not send it is not there.
func serveWithWorker(t *testing.T, runArgs ...string) (runErr, workerErr string, code int) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	dir := t.TempDir()
	env := append(os.Environ(), "AZHAQ_TEST_AS_MAIN=1", "AZHAQ_DATA_DIR="+dir)
	args := append([]string{"run", "-serve", addr, "-worker-token", "tok", "-parallel", "1", "-quiet", "-json", "-ledger", "off", "-db", filepath.Join(dir, "r.db")}, runArgs...)
	srv := exec.Command(os.Args[0], args...)
	srv.Env = env
	var srvErr, wrkErr safeBuf
	srv.Stderr = &srvErr
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	for i := 0; ; i++ {
		if c, err := net.Dial("tcp", addr); err == nil {
			c.Close()
			break
		}
		if i > 200 {
			_ = srv.Process.Kill()
			t.Fatalf("the run did not listen:\n%s", srvErr.String())
		}
		time.Sleep(25 * time.Millisecond)
	}
	wrk := exec.Command(os.Args[0], "worker", "-server", addr, "-token", "tok", "-slots", "4")
	wrk.Env = env
	wrk.Stderr = &wrkErr
	if err := wrk.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- srv.Wait() }()
	select {
	case <-done:
	case <-time.After(60 * time.Second):
		_ = srv.Process.Kill()
		_ = wrk.Process.Kill()
		t.Fatalf("the run did not end:\n%s", srvErr.String())
	}
	wd := make(chan error, 1)
	go func() { wd <- wrk.Wait() }()
	select {
	case <-wd:
	case <-time.After(30 * time.Second):
		_ = wrk.Process.Kill()
		t.Errorf("the worker did not stop when the run ended:\n%s", wrkErr.String())
	}
	return srvErr.String(), wrkErr.String(), srv.ProcessState.ExitCode()
}

type safeBuf struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *safeBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *safeBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func tasksDoneHere(workerErr string) int {
	var n int
	if i := strings.Index(workerErr, "the run is over; "); i >= 0 {
		fmt.Sscanf(workerErr[i:], "the run is over; %d tasks done here", &n)
	}
	return n
}

// A worker holds the run's -deny-path rules: a path check it would send into
// a denied path is not sent, and the run lists the URL as not requested, with
// the rule, as if it had kept it out itself. Six sites give the run several
// sweeps at once, so that the worker takes some.
func TestWorkerHoldsDenyPathAndReportsIt(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	var sites []*httptest.Server
	for i := 0; i < 6; i++ {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			seen = append(seen, r.Host+r.URL.Path)
			mu.Unlock()
			if r.URL.Path == "/" {
				time.Sleep(400 * time.Millisecond) // the run's own slot is busy; the worker takes the others
				w.Header().Set("Content-Type", "text/html")
				fmt.Fprint(w, `<title>home</title>`)
				return
			}
			http.NotFound(w, r)
		}))
		t.Cleanup(srv.Close)
		sites = append(sites, srv)
	}
	const rule = `^/(admin|\.git)`
	var list []string
	for _, s := range sites {
		list = append(list, s.URL+"/")
	}
	file := filepath.Join(t.TempDir(), "urls.txt")
	if err := os.WriteFile(file, []byte(strings.Join(list, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runErr, workerErr, code := serveWithWorker(t, "-list", file, "-allow", "127.0.0.1", "-deny-path", rule)
	if code != exitOK && code != exitPartial {
		t.Fatalf("exit %d\n%s", code, runErr)
	}
	if n := tasksDoneHere(workerErr); n < 2 {
		t.Fatalf("the worker ran %d tasks: the test shows nothing\n%s\n%s", n, workerErr, runErr)
	}
	mu.Lock()
	for _, p := range seen {
		if strings.Contains(p, "/admin") || strings.Contains(p, "/.git") {
			t.Errorf("%s was requested, by a process the rule did not reach", p)
		}
	}
	mu.Unlock()
	listed := skippedFor(lastReport(t, runErr), "-deny-path "+rule)
	for _, s := range sites {
		for _, u := range []string{"/admin", "/.git/HEAD"} {
			if !slices.Contains(listed, s.URL+u) {
				t.Errorf("%s is not listed as not requested, by the rule: %v", s.URL+u, listed)
			}
		}
	}
}

// A signed-in run with workers does not go on as an anonymous visitor
// either: a session given by cookie cannot be renewed, so when a link ends
// it the run ends its signed-in work with a failure (exit 3).
func TestWorkersSessionGivenByCookieEndsTheRun(t *testing.T) {
	var mu sync.Mutex
	live := map[string]bool{"s1": true}
	var anon []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, _ := r.Cookie("sid")
		mu.Lock()
		ok := c != nil && live[c.Value]
		if !ok && strings.HasPrefix(r.URL.Path, "/p") {
			anon = append(anon, r.URL.Path)
		}
		if r.URL.Path == "/logout" && ok {
			delete(live, c.Value)
		}
		mu.Unlock()
		switch {
		case r.URL.Path == "/login":
			fmt.Fprint(w, "<title>sign in</title>")
		case r.URL.Path == "/logout":
			http.SetCookie(w, &http.Cookie{Name: "sid", Value: "", MaxAge: -1, Path: "/"})
			http.Redirect(w, r, "/login", http.StatusFound)
		case !ok:
			http.Redirect(w, r, "/login", http.StatusFound)
		case r.URL.Path == "/":
			w.Header().Set("Content-Type", "text/html")
			var a []string
			for i := 1; i <= 30; i++ {
				a = append(a, fmt.Sprintf(`<a href="/p%d">%d</a>`, i, i))
				if i == 3 {
					a = append(a, `<a href="/logout">out</a>`)
				}
			}
			fmt.Fprint(w, "<title>home</title>"+strings.Join(a, " "))
		default:
			time.Sleep(100 * time.Millisecond)
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, "<title>%s</title>page %s", r.URL.Path, r.URL.Path)
		}
	}))
	t.Cleanup(srv.Close)
	runErr, workerErr, code := serveWithWorker(t, "-url", srv.URL+"/", "-allow", "127.0.0.1", "-cookie", "sid=s1", "-depth", "3")
	if code != exitPartial {
		t.Fatalf("exit %d, want %d\n%s", code, exitPartial, runErr)
	}
	if n := tasksDoneHere(workerErr); n < 3 {
		t.Fatalf("the worker ran %d tasks: the test shows nothing\n%s", n, workerErr)
	}
	rep := lastReport(t, runErr)
	found := false
	for _, f := range rep.Failed {
		found = found || strings.Contains(f.Error, "the session ended")
	}
	if !found {
		t.Errorf("no failure says the session ended: %+v", rep.Failed)
	}
	// Only the tasks in flight when the run learned of it (4 slots, one of the
	// run's own) were answered without the session; the run did not go on to
	// ask the other 20 pages.
	mu.Lock()
	n := len(anon)
	mu.Unlock()
	if n > 6 {
		t.Errorf("%d pages were asked without the session after it ended: %v", n, anon)
	}
}
