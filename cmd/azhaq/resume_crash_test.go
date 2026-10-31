package main

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/trannghiach/azhaq/internal/ledger"
	"github.com/trannghiach/azhaq/store"
)

// A run killed (SIGKILL) while a POST and a GET were on their way has them
// in its ledger and no answer for either. The resume asks the GET again
// and never sends the POST a second time, and says both.
func TestResumeAfterSIGKILLNeverSendsAWriteTwice(t *testing.T) {
	var posts, slows atomic.Int32
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			if posts.Add(1) == 1 {
				<-release
			}
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body><form action="/feedback" method="post"><input name="q"></form></body></html>`)
	}))
	defer srv.Close()
	// A second host: one request at a time goes to a host, so the GET that
	// is lost waits on its own.
	l2, err := net.Listen("tcp", "127.0.0.2:0")
	if err != nil {
		t.Skipf("no 127.0.0.2: %v", err)
	}
	srv2 := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow" && slows.Add(1) == 1 {
			<-release
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<html><body>slow</body></html>")
	}))
	srv2.Listener = l2
	srv2.Start()
	defer srv2.Close()
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	dir := t.TempDir()
	db := filepath.Join(dir, "k.db")
	cmd := exec.Command(os.Args[0], "crawl", "-u", srv.URL+"/", "-u", srv2.URL+"/slow", "-allow", "127.0.0.1", "-allow", "127.0.0.2", "-submit-forms", "-db", db, "-json")
	cmd.Env = append(os.Environ(), "AZHAQ_TEST_AS_MAIN=1", "AZHAQ_DATA_DIR="+dir)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 400 && (posts.Load() == 0 || slows.Load() == 0); i++ {
		time.Sleep(25 * time.Millisecond)
	}
	if posts.Load() != 1 || slows.Load() != 1 {
		_ = cmd.Process.Kill()
		t.Fatalf("before the kill the server saw %d POSTs and %d GETs of /slow, want 1 and 1:\n%s", posts.Load(), slows.Load(), stderr.String())
	}
	_ = cmd.Process.Signal(syscall.SIGKILL)
	_ = cmd.Wait()
	close(release)
	if raw, _ := os.ReadFile(db + ".ledger.jsonl"); strings.Contains(string(raw), `"kind":"seal"`) || !strings.Contains(string(raw), `"method":"POST"`) {
		t.Fatalf("the killed run's ledger is sealed or has no POST:\n%s", raw)
	}

	dataDirs.Store(t.Name(), dir) // the resume reads what the killed run kept there
	_, rep, code := runContract(t, "resume", "-db", db)
	if code != exitOK {
		t.Fatalf("resume: exit %d\n%+v", code, rep)
	}
	if posts.Load() != 1 {
		t.Errorf("the POST reached the server %d times", posts.Load())
	}
	if slows.Load() != 2 {
		t.Errorf("GET /slow, whose answer was lost, reached the server %d times, want 2", slows.Load())
	}
	notes := strings.Join(rep.Notes, "\n")
	if !strings.Contains(notes, "1 write was sent before the run was killed") || !regexp.MustCompile(`\d+ requests sent before the run was killed had no stored answer and were asked again`).MatchString(notes) {
		after, _ := os.ReadFile(db + ".ledger.jsonl")
		t.Errorf("the notes do not say what the resume did:\n%s\nsummary: %+v\nledger after the resume:\n%s", notes, rep, after)
	}
	if strings.Contains(notes, "POST forms were submitted") {
		t.Errorf("a POST that was held back is counted as submitted:\n%s", notes)
	}
	if len(rep.Skipped) != 1 || !strings.Contains(rep.Skipped[0].Reason, "not sent again (POST "+srv.URL+"/feedback)") {
		t.Errorf("skipped %+v", rep.Skipped)
	}
	if len(rep.Failed) != 0 {
		t.Errorf("a write held back is no failure: %+v", rep.Failed)
	}
}

// A second resume, after the first was stopped by a limit and sealed the
// ledger, still holds the writes of the killed run.
func TestResumeKeepsHoldingTheKilledRunsWrites(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "w.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.BeginRun("r1", 1, 10); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "w.ledger.jsonl")
	l, _ := ledger.Open(path)
	l.Record(ledger.Entry{Kind: "http", Method: "DELETE", Target: "http://a.test/x/1"})
	l.Record(ledger.Entry{Kind: "seal"}) // as if the run's end were cut off below
	_ = l.Close()
	raw, _ := os.ReadFile(path)
	cut := raw[:strings.LastIndex(strings.TrimSuffix(string(raw), "\n"), "\n")+1]
	if err := os.WriteFile(path, cut, 0o644); err != nil {
		t.Fatal(err)
	}
	for i := range 2 { // the first resume sees the unsealed file; the second a sealed one
		l, err := ledger.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		r := &runLedger{l: l, owned: true}
		r.holdWrites(st, "r1")
		ledger.Use(l)
		if !ledger.Held("DELETE", "http://a.test/x/1") {
			t.Errorf("resume %d does not hold the DELETE", i+1)
		}
		ledger.Use(nil)
		if len(r.writes) != 1 {
			t.Errorf("resume %d lists %d held writes", i+1, len(r.writes))
		}
		_ = l.Close()
	}
}
