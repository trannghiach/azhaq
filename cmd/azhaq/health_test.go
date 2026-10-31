package main

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/trannghiach/azhaq/internal/collectors/subcol"
)

// The -json summary of subs says how many sources answered, which failed
// and why, and what each gave, so exit 0 is not read as "all of them did".
func TestSubsSummaryHasSourceHealth(t *testing.T) {
	t.Chdir(t.TempDir())
	defer subcol.UseTestSources(
		subcol.TestSource{Name: "good", Default: true, Names: []string{"a.example.org", "b.example.org"}},
		subcol.TestSource{Name: "wayback", Default: true, Err: errors.New("429 Too Many Requests")},
		subcol.TestSource{Name: "flaky", Default: false, Err: errors.New("connection refused")},
	)()
	_, rep, code := runContract(t, "subs", "-d", "example.org", "-all-sources", "-no-history")
	if code != exitOK {
		t.Fatalf("exit %d %+v", code, rep)
	}
	h := rep.Sources
	if h == nil || h.Asked != 3 || h.Answered != 1 || h.Failed != 1 || h.OffByDefaultFailed != 1 {
		t.Fatalf("health %+v", h)
	}
	if h.Names["good"] != 2 || h.Names["wayback"] != 0 {
		t.Errorf("names %v", h.Names)
	}
	if h.FailedSources["wayback"] != "429 Too Many Requests" || h.FailedSources["flaky"] != "connection refused" || len(h.FailedSources) != 2 {
		t.Errorf("failed sources %v", h.FailedSources)
	}
	// It agrees with the counts the summary already had.
	if rep.Counts["sources asked"] != h.Asked || rep.Counts["sources failed"] != h.Failed {
		t.Errorf("counts %v", rep.Counts)
	}
}

// With several domains each reason names its domain.
func TestSubsHealthNamesTheDomainsOfAFailure(t *testing.T) {
	t.Chdir(t.TempDir())
	defer subcol.UseTestSources(
		subcol.TestSource{Name: "good", Default: true, Names: []string{"a.example.org", "a.example.net"}},
		subcol.TestSource{Name: "bad", Default: true, Err: errors.New("boom")},
	)()
	_, rep, _ := runContract(t, "subs", "-d", "example.org,example.net", "-no-history")
	h := rep.Sources
	if h == nil || h.Asked != 4 || h.Failed != 2 || h.FailedSources["bad"] != "example.net: boom; example.org: boom" {
		t.Errorf("health %+v", h)
	}
}

// The text summary says it plainly, and why the exit code is 0 (or 3).
func TestSubsSummaryLineSaysWhatTheExitCodeMeans(t *testing.T) {
	t.Chdir(t.TempDir())
	defer subcol.UseTestSources(
		subcol.TestSource{Name: "good", Default: true, Names: []string{"a.example.org"}},
		subcol.TestSource{Name: "bad", Default: true, Err: errors.New("boom")},
	)()
	t.Setenv("AZHAQ_DATA_DIR", t.TempDir())
	_, errOut, err := captureBoth(t, func() error { return run([]string{"subs", "-d", "example.org", "-no-history"}) })
	if err != nil {
		t.Fatal(err)
	}
	want := "1 of 2 sources answered, 1 failed (listed above); exit 0 because other sources answered for the same domain (-fail-on-errors makes it 3)"
	if !strings.Contains(errOut, want) {
		t.Errorf("no %q in\n%s", want, errOut)
	}
	// -silent still says a source failed: something failed.
	_, errOut, err = captureBoth(t, func() error { return run([]string{"subs", "-d", "example.org", "-no-history", "-silent"}) })
	if err != nil || !strings.Contains(errOut, want) {
		t.Errorf("-silent hid it (%v):\n%s", err, errOut)
	}
	_, errOut, err = captureBoth(t, func() error {
		return run([]string{"subs", "-d", "example.org", "-no-history", "-silent", "-fail-on-errors"})
	})
	if exitCode(err) != exitPartial || !strings.Contains(errOut, "exit 3 because -fail-on-errors counts every failed source") {
		t.Errorf("-fail-on-errors (%v):\n%s", err, errOut)
	}
	// A clean run stays quiet under -silent.
	defer subcol.UseTestSources(subcol.TestSource{Name: "good", Default: true, Names: []string{"a.example.org"}})()
	_, errOut, err = captureBoth(t, func() error { return run([]string{"subs", "-d", "example.org", "-no-history", "-silent"}) })
	if err != nil || strings.TrimSpace(errOut) != "" {
		t.Errorf("a clean -silent run printed %q (%v)", errOut, err)
	}
}

// urls says the same of its archives: one answered, one failed and why,
// and the exit code is explained.
func TestURLsSummaryHasArchiveHealth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/wayback") {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		fmt.Fprint(w, `{"has_next":false,"url_list":[{"url":"http://example.org/otx"},{"url":"http://example.org/otx2"}]}`)
	}))
	defer srv.Close()
	args := []string{"-d", "example.org", "-providers", "wayback,otx", "-retries", "0", "-urls-pause", "0",
		"-archive", "wayback=" + srv.URL + "/wayback", "-archive", "otx=" + srv.URL + "/otx"}
	_, errOut, err := urlsRun(t, append(args, "-json")...)
	if exitCode(err) != exitPartial {
		t.Fatalf("exit %d", exitCode(err))
	}
	h := lastReport(t, errOut).Sources
	if h == nil || h.Asked != 2 || h.Answered != 1 || h.Failed != 1 || h.URLs["otx"] != 2 || !strings.Contains(h.FailedSources["wayback"], "429") {
		t.Fatalf("health %+v", h)
	}
	_, errOut, _ = urlsRun(t, args...)
	if !strings.Contains(errOut, "1 of 2 archives answered, 1 failed (listed above); exit 3 because an archive that failed is not made up for by the others") {
		t.Errorf("summary:\n%s", errOut)
	}
	// B3: the counts per archive and the failure with its tries.
	if !strings.Contains(errOut, "URLs by archive: otx 2, wayback 0 (failed after 1 try, 429 Too Many Requests)") {
		t.Errorf("no per-archive counts:\n%s", errOut)
	}
}

// crt.sh is a source like the others: its failure, with other sources
// answering, is partial and leaves the exit code at 0 (-fail-on-errors: 3).
func TestCrtshFailureDoesNotMakeExit3(t *testing.T) {
	t.Chdir(t.TempDir())
	defer subcol.UseTestSources(
		subcol.TestSource{Name: "certspotter", Default: true, Names: []string{"a.example.org"}},
		subcol.TestSource{Name: "crtsh", Default: true, Err: errors.New("crt.sh 502")},
	)()
	_, rep, code := runContract(t, "subs", "-d", "example.org", "-no-history")
	if failed, partial := failedSource(rep, "crtsh"); code != exitOK || !failed || !partial {
		t.Errorf("exit %d, failed %+v", code, rep.Failed)
	}
	if rep.Sources == nil || rep.Sources.FailedSources["crtsh"] != "crt.sh 502" {
		t.Errorf("health %+v", rep.Sources)
	}
	if _, _, code = runContract(t, "subs", "-d", "example.org", "-no-history", "-fail-on-errors"); code != exitPartial {
		t.Errorf("-fail-on-errors: exit %d", code)
	}
}

// A Wayback 429 with a Retry-After is waited out, and its URLs are in the
// result with the others': the run does not collapse to one archive.
func TestURLsWaitsOutAWaybackRateLimit(t *testing.T) {
	var asked atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/wayback") && asked.Add(1) == 1:
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
		case r.URL.Path == "/wayback" && r.URL.Query().Get("page") == "0":
			fmt.Fprint(w, `[["original"],["http://example.org/from-wayback?id=1"]]`)
		case strings.HasPrefix(r.URL.Path, "/wayback"):
			w.WriteHeader(http.StatusBadRequest)
		default:
			fmt.Fprint(w, `{"has_next":false,"url_list":[{"url":"http://example.org/from-otx"}]}`)
		}
	}))
	defer srv.Close()
	t0 := time.Now()
	lines, errOut, err := urlsRun(t, "-d", "example.org", "-providers", "wayback,otx", "-urls-pause", "0", "-json",
		"-archive", "wayback="+srv.URL+"/wayback", "-archive", "otx="+srv.URL+"/otx")
	if err != nil || len(lines) != 2 {
		t.Fatalf("%v %v", lines, err)
	}
	if took := time.Since(t0); took < 900*time.Millisecond {
		t.Errorf("the Retry-After was not waited for: %s", took)
	}
	rep := lastReport(t, errOut)
	if h := rep.Sources; h == nil || h.Answered != 2 || h.URLs["wayback"] != 1 {
		t.Errorf("health %+v", h)
	}
}

// The summary's sources block has each source's seconds, so what set the
// run's time is in -json too.
func TestSubsHealthHasSecondsPerSource(t *testing.T) {
	t.Chdir(t.TempDir())
	defer subcol.UseTestSources(
		subcol.TestSource{Name: "fast", Default: true, Names: []string{"a.example.org"}},
		subcol.TestSource{Name: "slow", Default: true, Delay: 1200 * time.Millisecond, Names: []string{"b.example.org"}},
	)()
	_, rep, _ := runContract(t, "subs", "-d", "example.org", "-no-history")
	h := rep.Sources
	if h == nil || h.Seconds["slow"] < 1.1 || h.Seconds["fast"] > 0.5 {
		t.Errorf("seconds %+v", h)
	}
}
