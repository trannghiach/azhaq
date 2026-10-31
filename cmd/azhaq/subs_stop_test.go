package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/trannghiach/azhaq/internal/collectors/subcol"
)

// silentResolver is a UDP resolver that reads every query and never answers;
// asked counts them.
func silentResolver(t *testing.T) (addr string, asked *atomic.Int32) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no UDP: %v", err)
	}
	asked = new(atomic.Int32)
	go func() {
		buf := make([]byte, 1500)
		for {
			if _, _, err := pc.ReadFrom(buf); err != nil {
				return
			}
			asked.Add(1)
		}
	}()
	t.Cleanup(func() { pc.Close() })
	return pc.LocalAddr().String(), asked
}

// SIGTERM while the names wait for DNS: the run says it was stopped (exit 4,
// complete false), and the names whose answer had not come are counted as
// not asked, never as "did not resolve".
func TestSubsStoppedBySignalDuringDNSIsAStop(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX signals")
	}
	resolver, asked := silentResolver(t)
	dir := t.TempDir()
	cmd := exec.Command(os.Args[0], "subs", "-d", "example.org", "-live", "-resolvers", resolver, "-no-history", "-json")
	cmd.Env = append(os.Environ(), "AZHAQ_TEST_AS_MAIN=1", "AZHAQ_DATA_DIR="+dir, "AZHAQ_TEST_SUBS_NAMES=a.example.org,b.example.org,c.example.org,d.example.org")
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 400 && asked.Load() == 0; i++ {
		time.Sleep(25 * time.Millisecond)
	}
	if asked.Load() == 0 {
		_ = cmd.Process.Kill()
		t.Fatalf("no name reached the resolver:\n%s", stderr.String())
	}
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatalf("the run did not stop on SIGTERM:\n%s", stderr.String())
	}
	if code := cmd.ProcessState.ExitCode(); code != exitLimit {
		t.Fatalf("exit %d, want %d\n%s", code, exitLimit, stderr.String())
	}
	sum := sumMap(t, stderr.String())
	if sum["complete"] != false || !strings.Contains(fmt.Sprint(sum["stopped"]), "interrupted") {
		t.Errorf("summary %v", sum)
	}
	counts, _ := sum["counts"].(map[string]any)
	if counts["did not resolve"] != nil || counts["not asked"] != float64(4) {
		t.Errorf("counts %v: four names were not asked, none was found dead", counts)
	}
	if counts["from sources"] != float64(4) {
		t.Errorf("counts %v", counts)
	}
}

// The same holds for -timeout: a run cut in its DNS phase is a stop.
func TestSubsTimeoutDuringDNSIsAStop(t *testing.T) {
	resolver, _ := silentResolver(t)
	defer subcol.UseTestSources(subcol.TestSource{Name: "s", Default: true, Names: []string{"a.example.org", "b.example.org"}})()
	t.Chdir(t.TempDir())
	_, rep, code := runContract(t, "subs", "-d", "example.org", "-live", "-resolvers", resolver, "-no-history", "-timeout", "1s")
	if code != exitLimit || rep.Complete || rep.Stopped == "" {
		t.Fatalf("exit %d, summary %+v", code, rep)
	}
	if rep.Counts["did not resolve"] != 0 || rep.Counts["not asked"] != 2 {
		t.Errorf("counts %v", rep.Counts)
	}
}
