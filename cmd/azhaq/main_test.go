package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/trannghiach/azhaq/internal/fetch"
	"github.com/trannghiach/azhaq/store"
	"github.com/trannghiach/azhaq/types"
)

func captureStdout(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	fnErr := fn()
	_ = w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatal(err)
	}
	_ = r.Close()
	return buf.String(), fnErr
}

// captureBoth runs fn with stdout and stderr captured.
func captureBoth(t *testing.T, fn func() error) (string, string, error) {
	t.Helper()
	var errOut string
	out, err := captureStdout(t, func() error {
		r, w, perr := os.Pipe()
		if perr != nil {
			t.Fatal(perr)
		}
		old := os.Stderr
		os.Stderr = w
		done := make(chan string)
		go func() {
			var buf bytes.Buffer
			_, _ = io.Copy(&buf, r)
			done <- buf.String()
		}()
		ferr := fn()
		_ = w.Close()
		os.Stderr = old
		errOut = <-done
		return ferr
	})
	return out, errOut, err
}

// lastReport is the last JSON summary in a command's stderr.
func lastReport(t *testing.T, errOut string) report {
	t.Helper()
	var last report
	found := false
	for _, line := range strings.Split(errOut, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "{") || !strings.Contains(line, `"type":"summary"`) {
			continue
		}
		if err := json.Unmarshal([]byte(line), &last); err != nil {
			t.Fatalf("summary %q: %v", line, err)
		}
		found = true
	}
	if !found {
		t.Fatalf("no summary JSON in %q", errOut)
	}
	return last
}

func TestUniqueDBNoCollision(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	a := uniqueDB()
	b := uniqueDB()
	if a == b {
		t.Fatalf("same path %s", a)
	}
	if !strings.Contains(a, ".db") || !strings.Contains(b, ".db") {
		t.Fatalf("%s %s", a, b)
	}
}

func TestApplyExtraJoinsCookiesAndHonorsUA(t *testing.T) {
	fetch.Reset()
	if err := applyExtra(
		[]string{"c1=v1", "c2=v2"},
		[]string{"User-Agent: allowlist/1", "X-A: 1", "X-B: 2"},
	); err != nil {
		t.Fatal(err)
	}
	if got := fetch.Extra.Get("Cookie"); got != "c1=v1; c2=v2" {
		t.Fatalf("cookie %q", got)
	}
	if n := len(fetch.Extra.Values("Cookie")); n != 1 {
		t.Fatalf("cookie headers %d", n)
	}
	if fetch.Extra.Get("User-Agent") != "allowlist/1" {
		t.Fatalf("ua %q", fetch.Extra.Get("User-Agent"))
	}
	if fetch.Extra.Get("X-A") == "" || fetch.Extra.Get("X-B") == "" {
		t.Fatal("headers")
	}
}

func TestParseCLIURL(t *testing.T) {
	if _, err := parseCLIURL("not a url"); err == nil {
		t.Fatal("want reject")
	}
	if _, err := parseCLIURL("javascript:alert(1)"); err == nil {
		t.Fatal("want reject js")
	}
	if _, err := parseCLIURL("https://example.com/a"); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"http://127.0.0.1:3001/ ginandjuice.shop", "https://a.test/\tb", "https://a.test/\x7f"} {
		if _, err := parseCLIURL(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	if _, err := parseSeedLine([]byte(`{"type":"URL","keys":{"url":"https://a.test/x y"}}`)); err == nil {
		t.Error("seed file URL with a space accepted")
	}
}

func TestParseSeedLineUnknownType(t *testing.T) {
	if _, err := parseSeedLine([]byte(`{"type":"Nope","keys":{"id":"x"}}`)); err == nil {
		t.Fatal("want unknown type")
	}
	s, err := parseSeedLine([]byte(`{"type":"Domain","keys":{"domain":"a.test"}}`))
	if err != nil || s.Type != types.TypeDomain {
		t.Fatalf("%+v %v", s, err)
	}
}

func TestResolveDBFlagAndEnv(t *testing.T) {
	t.Setenv("AZHAQ_DB", "")
	p, remember := resolveDB("named.db")
	if p != "named.db" || remember {
		t.Fatalf("%s %v", p, remember)
	}
	t.Setenv("AZHAQ_DB", "from-env.db")
	p, remember = resolveDB("")
	if p != "from-env.db" || remember {
		t.Fatalf("env %s %v", p, remember)
	}
}

func TestLoadSeedsCloudMissing(t *testing.T) {
	if _, err := loadSeeds("", "", filepath.Join(t.TempDir(), "nope.json"), ""); err == nil {
		t.Fatal("want missing cloud file")
	}
}

func TestApplyExtraNeedsCookiePair(t *testing.T) {
	if err := applyExtra([]string{"nosesame"}, nil); err == nil {
		t.Fatal("want cookie error")
	}
}

func TestNewRunID(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		id := newRunID()
		if id == "" || !strings.Contains(id, "-") {
			t.Fatalf("run_id %q", id)
		}
		if seen[id] {
			t.Fatalf("collision %q", id)
		}
		seen[id] = true
	}
}

func TestRunDemoSummaryJSON(t *testing.T) {
	t.Chdir(t.TempDir())
	out, errOut, err := captureBoth(t, func() error {
		return run([]string{"run", "-demo", "-quiet", "-json", "-db", "demo.db"})
	})
	if err != nil {
		t.Fatal(err)
	}
	if out != "" {
		t.Fatalf("-quiet printed a map: %q", out)
	}
	sum := lastReport(t, errOut)
	if sum.RunID == "" || sum.Results == 0 || sum.DB != "demo.db" || !sum.Complete || sum.Exit != 0 {
		t.Fatalf("%+v", sum)
	}
}

func TestRunConnectorFailureCounted(t *testing.T) {
	t.Chdir(t.TempDir())
	_, errOut, err := captureBoth(t, func() error {
		return run([]string{"run", "-demo", "-quiet", "-json", "-db", "conn.db", "-exec", "/bin/false"})
	})
	if exitCode(err) != exitPartial {
		t.Fatalf("a failed connector leaves the run incomplete: exit %d (%v)\n%s", exitCode(err), err, errOut)
	}
	sum := lastReport(t, errOut)
	if len(sum.Failed) == 0 || sum.Failed[0].Collector != "connector" || sum.Complete {
		t.Fatalf("want the connector failure listed: %+v", sum)
	}
	st, err := store.OpenExisting("conn.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if ents, _ := st.Entities(); len(ents) == 0 {
		t.Fatal("native collectors should still write the db")
	}
}

func TestRunMaxItemsStops(t *testing.T) {
	t.Chdir(t.TempDir())
	_, errOut, err := captureBoth(t, func() error {
		return run([]string{"run", "-demo", "-quiet", "-json", "-db", "cap.db", "-max-items", "1"})
	})
	if exitCode(err) != exitLimit {
		t.Fatalf("exit %d, want %d: %s", exitCode(err), exitLimit, errOut)
	}
	sum := lastReport(t, errOut)
	if sum.Stopped == "" || !strings.Contains(sum.Resume, "azhaq resume -db cap.db") {
		t.Fatalf("%+v", sum)
	}
}

func TestRunJSONOnly(t *testing.T) {
	t.Chdir(t.TempDir())
	out, errOut, err := captureBoth(t, func() error {
		return run([]string{"run", "-demo", "-json", "-db", "json.db"})
	})
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) < 3 {
		t.Fatalf("want map rows: %q", out)
	}
	for _, line := range lines {
		var row map[string]any
		if err := json.Unmarshal([]byte(line), &row); err != nil || row["type"] == nil || row["key"] == nil {
			t.Fatalf("not a map row: %q", line)
		}
	}
	if n := strings.Count(errOut, `"type":"summary"`); n != 1 {
		t.Fatalf("want one summary on stderr, got %d in %q", n, errOut)
	}
}

func TestRunDepthZeroJSON(t *testing.T) {
	t.Chdir(t.TempDir())
	out, errOut, err := captureBoth(t, func() error {
		return run([]string{"run", "-demo", "-json", "-depth", "0", "-db", "d0.db"})
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `/app.js"`) {
		t.Fatalf("the script found at depth 0 is listed: %q", out)
	}
	if sum := lastReport(t, errOut); sum.Exit != 0 {
		t.Fatalf("%+v", sum)
	}
}

func TestRunDemoPassive(t *testing.T) {
	t.Chdir(t.TempDir())
	_, errOut, err := captureBoth(t, func() error {
		return run([]string{"run", "-demo", "-passive", "-json", "-db", "pass.db"})
	})
	if err != nil {
		t.Fatal(err)
	}
	sum := lastReport(t, errOut)
	if sum.Results == 0 || sum.Stopped != "" || sum.Requests != 0 {
		t.Fatalf("passive: seed entities, nothing sent, nothing left: %+v", sum)
	}
	exp, err := captureStdout(t, func() error {
		return run([]string{"export", "-db", "pass.db"})
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(exp, `"coverage":"capped"`) {
		t.Fatalf("passive leftover is a hint: %s", exp)
	}
}

func TestCompactIncludesParams(t *testing.T) {
	got := compact(json.RawMessage(`{"params":["q","next"],"url":"https://app.test/"}`))
	if !strings.Contains(got, "params=") || !strings.Contains(got, "q") {
		t.Fatalf("%q", got)
	}
}

func TestPrintDiffJSONLAndCounts(t *testing.T) {
	dir := t.TempDir()
	oldPath := filepath.Join(dir, "old.db")
	newPath := filepath.Join(dir, "new.db")
	old, err := store.Open(oldPath)
	if err != nil {
		t.Fatal(err)
	}
	neu, err := store.Open(newPath)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	gone, err := old.UpsertEntity(types.TypeHostname, "gone.test", now)
	if err != nil {
		t.Fatal(err)
	}
	// It resolved in the old run: its absence now is a removal.
	if _, err := old.AddObservation(gone.ID, types.Observation{Collector: "azhaq-dns", Kind: "dns", Payload: json.RawMessage(`{"fqdn":"gone.test","ips":["192.0.2.1"]}`), ObservedAt: now}); err != nil {
		t.Fatal(err)
	}
	// Heard of from a source, never resolved: not heard of again is not a removal.
	if _, err := old.UpsertEntity(types.TypeHostname, "rumour.test", now); err != nil {
		t.Fatal(err)
	}
	if _, err := neu.UpsertEntity(types.TypeHostname, "new.test", now); err != nil {
		t.Fatal(err)
	}
	_ = old.Close()
	_ = neu.Close()

	out, err := captureStdout(t, func() error {
		return printDiff(oldPath, newPath, diffOpts{JSONL: true})
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `"kind":"added"`) || !strings.Contains(out, `"kind":"removed"`) || !strings.Contains(out, `"key":"rumour.test","kind":"not_seen_again"`) {
		t.Fatalf("jsonl %q", out)
	}
	text, err := captureStdout(t, func() error {
		return printDiff(oldPath, newPath, diffOpts{Quiet: true})
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, "added=1 removed=1 not_seen_again=1 observations=0") {
		t.Fatalf("counts %q", text)
	}
}

func TestPrintDiffLabelsOtherSeeds(t *testing.T) {
	dir := t.TempDir()
	paths := []string{filepath.Join(dir, "juice.db"), filepath.Join(dir, "vampi.db")}
	for i, in := range []string{"URL http://127.0.0.1:3001/", "URL http://127.0.0.1:5002/"} {
		st, err := store.Open(paths[i])
		if err != nil {
			t.Fatal(err)
		}
		if err := st.SaveInput(in); err != nil {
			t.Fatal(err)
		}
		_ = st.Close()
	}
	out, err := captureStdout(t, func() error { return printDiff(paths[0], paths[1], diffOpts{}) })
	if err != nil || !strings.Contains(out, "different seeds") {
		t.Fatalf("not labelled: %q %v", out, err)
	}
	out, err = captureStdout(t, func() error { return printDiff(paths[0], paths[1], diffOpts{JSONL: true}) })
	if err != nil || !strings.Contains(out, `"seeds_differ":true`) {
		t.Fatalf("jsonl not labelled: %q %v", out, err)
	}
}

func TestPreviousRunSameSeedsOnly(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	juice, vampi := "URL http://127.0.0.1:3001/", "URL http://127.0.0.1:5002/"
	for _, f := range []string{"a.db", "b.db"} {
		if err := os.WriteFile(f, nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := recordRun(juice, "a.db"); err != nil {
		t.Fatal(err)
	}
	if err := recordRun(vampi, "b.db"); err != nil {
		t.Fatal(err)
	}
	if got := previousRun(juice); got != "a.db" {
		t.Fatalf("juice previous %q", got)
	}
	if got := previousRun("URL https://other.test/"); got != "" {
		t.Fatalf("unrelated seeds diffed against %q", got)
	}
}
