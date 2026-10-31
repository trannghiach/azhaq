package main

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// A paced run says where it stands: requests, the pace of the last
// interval, the tasks known and not done, and what ends it and when.
func TestProgressLine(t *testing.T) {
	cfg := progressCfg{Cap: 80, CapBy: "-max-requests"}
	prev := progressSnap{At: 80 * time.Second, Sent: 52, Left: 40}
	cur := progressSnap{At: 90 * time.Second, Sent: 62, Done: 70, Left: 38}
	if got, want := cfg.line(prev, cur), "azhaq: 1m30s, 62 requests sent (1/s), 38 tasks left; -max-requests 80 ends it in about 18 s"; got != want {
		t.Errorf("line\n%s\nwant\n%s", got, want)
	}
	// The cap spent: nothing is said to end it. No cap: nothing either.
	if got := cfg.line(prev, progressSnap{At: 90 * time.Second, Sent: 80, Left: 1}); strings.Contains(got, "ends it") || !strings.Contains(got, "1 task left") {
		t.Errorf("a spent cap: %s", got)
	}
	if got := (progressCfg{}).line(prev, cur); strings.Contains(got, "ends it") {
		t.Errorf("no cap: %s", got)
	}
	// The sooner of the cap and the timeout; an idle interval says 0/s and cannot tell the cap's time.
	soon := progressCfg{Cap: 1000, CapBy: "-max-requests", Timeout: 100 * time.Second}
	if got := soon.line(prev, cur); !strings.Contains(got, "-timeout 1m40s ends it in about 10 s") {
		t.Errorf("timeout first: %s", got)
	}
	if got := cfg.line(cur, progressSnap{At: 100 * time.Second, Sent: 62, Left: -1}); !strings.Contains(got, "(0/s)") || strings.Contains(got, "ends it") || strings.Contains(got, "left") {
		t.Errorf("idle: %s", got)
	}
	for r, want := range map[float64]string{0.5: "0.5/s", 0.333: "0.33/s", 1: "1/s", 1.5: "1.5/s", 12.4: "12/s", 250: "250/s"} {
		if got := rateText(r); got != want {
			t.Errorf("rateText(%v) = %s, want %s", r, got, want)
		}
	}
	for d, want := range map[time.Duration]string{18 * time.Second: "18 s", 90 * time.Second: "90 s", 5 * time.Minute: "5 min", 3 * time.Hour: "3.0 h"} {
		if got := aboutDuration(d); got != want {
			t.Errorf("aboutDuration(%v) = %s, want %s", d, got, want)
		}
	}

	// -json: the same, as one object.
	raw, _ := json.Marshal(cfg.object(prev, cur))
	want := `{"type":"progress","seconds":90,"requests":62,"requests_per_second":1,"tasks_done":70,"tasks_left":38,"ends_by":"-max-requests 80","ends_in_seconds":18}`
	if string(raw) != want {
		t.Errorf("object\n%s\nwant\n%s", raw, want)
	}
}

func TestPaceLine(t *testing.T) {
	cfg := progressCfg{Cap: 80, CapBy: "-max-requests"}
	if got := cfg.paceLine(1); !strings.Contains(got, "-rate 1 paces requests to 1/s") || !strings.Contains(got, "80 requests (-max-requests) takes at least 80 s") {
		t.Errorf("paced with a cap: %q", got)
	}
	if got := cfg.paceLine(100); got != "" {
		t.Errorf("a fast pace says nothing: %q", got)
	}
	if got := cfg.paceLine(0); got != "" {
		t.Errorf("no pace says nothing: %q", got)
	}
	if got := (progressCfg{}).paceLine(2); !strings.Contains(got, "-rate 2 paces requests to 2/s") {
		t.Errorf("paced without a cap: %q", got)
	}
}

type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuf) lines() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return lines(l.b.String())
}

// One line a interval while it works, none when it is done sooner, and
// none after it stops.
func TestProgressTicker(t *testing.T) {
	defer func(d time.Duration) { stderrProgressEvery = d }(stderrProgressEvery)
	stderrProgressEvery = 30 * time.Millisecond
	var count atomic.Int64
	snap := func() progressSnap {
		n := count.Add(5)
		return progressSnap{At: time.Duration(n) * time.Second, Sent: n, Left: 3}
	}

	var quick lockedBuf
	stop := startProgress(context.Background(), progressCfg{}, &quick, snap)
	time.Sleep(5 * time.Millisecond)
	stop()
	time.Sleep(80 * time.Millisecond)
	if got := quick.lines(); len(got) != 0 {
		t.Errorf("a run done within the interval printed %q", got)
	}

	var slow lockedBuf
	stop = startProgress(context.Background(), progressCfg{JSON: true}, &slow, snap)
	time.Sleep(140 * time.Millisecond)
	stop()
	got := slow.lines()
	if len(got) < 2 || len(got) > 5 {
		t.Fatalf("%d lines in 140 ms at 30 ms: %q", len(got), got)
	}
	for _, l := range got {
		var o map[string]any
		if json.Unmarshal([]byte(l), &o) != nil || o["type"] != "progress" {
			t.Errorf("not a progress object: %s", l)
		}
	}
	time.Sleep(80 * time.Millisecond)
	if after := slow.lines(); len(after) != len(got) {
		t.Errorf("lines after stop: %d, then %d", len(got), len(after))
	}

	var cut lockedBuf
	ctx, cancel := context.WithCancel(context.Background())
	stop = startProgress(ctx, progressCfg{}, &cut, snap)
	cancel()
	time.Sleep(80 * time.Millisecond)
	stop()
	if got := cut.lines(); len(got) != 0 {
		t.Errorf("a cancelled run printed %q", got)
	}
}

func TestProgressMode(t *testing.T) {
	for _, c := range []struct {
		quiet, verbose, json bool
		forced, want         string
	}{
		{false, false, false, "", "text"},
		{false, false, true, "", "json"},
		{true, false, false, "", ""},
		{true, false, true, "", ""},
		{true, true, false, "", "text"},
		{true, false, false, "json", "json"}, // a drop-in's -json, which hushes the run itself
	} {
		if got := progressMode(c.quiet, c.verbose, c.json, c.forced); got != c.want {
			t.Errorf("%+v: %q", c, got)
		}
	}
}

// A run that works longer than the interval writes progress lines to
// stderr only: with -json as JSON objects beside the summary, stdout holds
// the map and nothing else, and -quiet gives none.
func TestRunProgressOnStderrOnly(t *testing.T) {
	defer func(d time.Duration) { stderrProgressEvery = d }(stderrProgressEvery)
	stderrProgressEvery = 250 * time.Millisecond
	srv, _ := pagedSite(t)
	dir := t.TempDir()
	t.Chdir(dir)
	args := []string{"run", "-url", srv.URL + "/", "-rate", "10", "-max-requests", "20", "-depth", "3"}

	out, errOut, code := cli(t, append(args, "-json", "-db", "j.db")...)
	if code != exitLimit {
		t.Fatalf("exit %d\n%s", code, errOut)
	}
	var progress int
	for _, l := range lines(errOut) {
		var o map[string]any
		if err := json.Unmarshal([]byte(l), &o); err != nil {
			t.Fatalf("a stderr line under -json is not JSON: %s", l)
		}
		if o["type"] == "progress" {
			progress++
			if o["requests"] == nil || o["seconds"] == nil {
				t.Errorf("progress object %s", l)
			}
		}
	}
	if progress == 0 {
		t.Errorf("no progress object in\n%s", errOut)
	}
	for _, l := range lines(out) {
		if strings.Contains(l, `"type":"progress"`) || strings.Contains(l, `"type":"summary"`) {
			t.Errorf("stdout holds %s", l)
		}
	}

	_, errOut, _ = cli(t, append(args, "-quiet", "-json", "-db", "q.db")...)
	if strings.Contains(errOut, `"type":"progress"`) {
		t.Errorf("-quiet printed progress:\n%s", errOut)
	}
	_, errOut, _ = cli(t, append(args, "-db", "t.db")...)
	if !strings.Contains(errOut, "requests sent (") || !strings.Contains(errOut, "-max-requests 20 ends it in about") {
		t.Errorf("text progress missing:\n%s", errOut)
	}
}
