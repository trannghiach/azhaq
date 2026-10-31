package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// The signals a supervisor or a closed terminal sends end a command as
// Ctrl-C does.
func TestStopContextEndsOnEachStopSignal(t *testing.T) {
	for _, sig := range []syscall.Signal{syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP} {
		ctx, stop := stopContext()
		if err := syscall.Kill(os.Getpid(), sig); err != nil {
			t.Fatal(err)
		}
		select {
		case <-ctx.Done():
		case <-time.After(3 * time.Second):
			t.Errorf("%v did not end the context", sig)
		}
		stop()
	}
}

// pagedSite answers every GET with a page of links, so a paced run always
// has work left; hits counts the requests.
func pagedSite(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := hits.Add(1)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "<html><title>p</title>")
		for i := 0; i < 5; i++ {
			fmt.Fprintf(w, `<a href="/p%d-%d">x</a>`, n, i)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

func waitHits(t *testing.T, hits *atomic.Int32, n int32) {
	t.Helper()
	for i := 0; i < 400 && hits.Load() < n; i++ {
		time.Sleep(25 * time.Millisecond)
	}
	if hits.Load() < n {
		t.Fatalf("the run sent %d requests in 10 s, want %d", hits.Load(), n)
	}
}

// kill, timeout and systemd send SIGTERM, a closed terminal SIGHUP: a paced
// run is stopped like Ctrl-C stops it (exit 4, the summary, the ledger
// sealed), not killed.
func TestRunStopsOnTermAndHupLikeCtrlC(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX signals")
	}
	for _, sig := range []syscall.Signal{syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP} {
		t.Run(sig.String(), func(t *testing.T) {
			srv, hits := pagedSite(t)
			dir := t.TempDir()
			db := filepath.Join(dir, "r.db")
			cmd := exec.Command(os.Args[0], "run", "-url", srv.URL+"/", "-rate", "5", "-depth", "3", "-db", db, "-json")
			cmd.Env = append(os.Environ(), "AZHAQ_TEST_AS_MAIN=1", "AZHAQ_DATA_DIR="+dir)
			var stderr strings.Builder
			cmd.Stderr = &stderr
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			waitHits(t, hits, 3)
			time.Sleep(200 * time.Millisecond)
			if err := cmd.Process.Signal(sig); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()
			var err error
			select {
			case err = <-done:
			case <-time.After(20 * time.Second):
				_ = cmd.Process.Kill()
				t.Fatalf("the run did not stop on %v:\n%s", sig, stderr.String())
			}
			if code := cmd.ProcessState.ExitCode(); code != exitLimit {
				t.Fatalf("%v: exit %d (%v), want %d\n%s", sig, code, err, exitLimit, stderr.String())
			}
			sum := sumMap(t, stderr.String())
			if sum["exit"] != float64(exitLimit) || !strings.Contains(fmt.Sprint(sum["stopped"]), "interrupted") {
				t.Errorf("summary %v", sum)
			}
			out, errOut, code := cli(t, "ledger", "-verify", db+".ledger.jsonl")
			if code != exitOK || strings.Contains(out+errOut, "NOT SEALED") || !strings.Contains(out, "sealed") {
				t.Errorf("ledger after %v: exit %d\n%s%s", sig, code, out, errOut)
			}
		})
	}
}

// A tool call in flight when the server is told to stop is interrupted,
// as the client's cancellation interrupts it, and no other call starts.
func TestMCPStopInterruptsCallsInFlight(t *testing.T) {
	dir := t.TempDir()
	s := &mcpServer{exe: fakeAzhaq(t, dir), dir: dir, lock: []string{"-allow", "127.0.0.1"}, locked: true, budget: 100}
	t.Setenv("FAKE_SLOW", "1")
	defer func(first time.Duration) { progressFirst = first }(progressFirst)
	progressFirst = 20 * time.Millisecond
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	go func() {
		_ = s.serve(inR, outW)
		outW.Close()
	}()
	msgs := make(chan map[string]any, 16)
	go func() {
		sc := bufio.NewScanner(outR)
		for sc.Scan() {
			var m map[string]any
			_ = json.Unmarshal(sc.Bytes(), &m)
			msgs <- m
		}
		close(msgs)
	}()
	_, _ = io.WriteString(inW, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"azhaq_map","arguments":{"url":"http://127.0.0.1/","workspace":"c"},"_meta":{"progressToken":"t"}}}`+"\n")
	select {
	case <-msgs: // progress: the command is running
	case <-time.After(5 * time.Second):
		t.Fatal("the call did not start")
	}
	s.cancelAll()
	_, _ = io.WriteString(inW, `{"jsonrpc":"2.0","id":2,"method":"ping"}`+"\n")
	s.calls.Wait()
	inW.Close()
	if _, err := os.Stat(filepath.Join(dir, "stopped")); err != nil {
		t.Error("the command in flight was not interrupted")
	}
	gotFirst := false
	for m := range msgs {
		switch m["id"] {
		case float64(1):
			gotFirst = true
		case float64(2):
			t.Errorf("a request after the stop was served: %v", m)
		}
	}
	if !gotFirst {
		t.Error("the call in flight got no answer with its summary")
	}
}

// The server itself ends on SIGTERM, as on Ctrl-C, instead of being killed.
func TestMCPServerStopsOnSIGTERM(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX signals")
	}
	dir := t.TempDir()
	cmd := exec.Command(os.Args[0], "mcp", "-allow", "127.0.0.1", "-dir", filepath.Join(dir, "ws"))
	cmd.Env = append(os.Environ(), "AZHAQ_TEST_AS_MAIN=1", "AZHAQ_DATA_DIR="+dir)
	in, _ := cmd.StdinPipe()
	out, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	// An answer to the handshake says the server is up, with its handler.
	_, _ = io.WriteString(in, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}`+"\n")
	if _, err := bufio.NewReader(out).ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("the server was killed by SIGTERM instead of stopping: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the server did not stop")
	}
}
