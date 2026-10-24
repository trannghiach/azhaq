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

	"azhaq/internal/fetch"
	"azhaq/internal/store"
	"azhaq/internal/types"
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

func lastSummary(t *testing.T, out string) store.Stats {
	t.Helper()
	var last store.Stats
	found := false
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "{") || !strings.Contains(line, `"kind":"summary"`) {
			continue
		}
		if err := json.Unmarshal([]byte(line), &last); err != nil {
			t.Fatalf("summary %q: %v", line, err)
		}
		found = true
	}
	if !found {
		t.Fatalf("no summary JSON in %q", out)
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
	out, err := captureStdout(t, func() error {
		return run([]string{"run", "-demo", "-quiet", "-db", "demo.db"})
	})
	if err != nil {
		t.Fatal(err)
	}
	sum := lastSummary(t, out)
	if sum.RunID == "" || sum.Entities == 0 {
		t.Fatalf("%+v out=%q", sum, out)
	}
	if !strings.Contains(out, "run_id="+sum.RunID) {
		t.Fatalf("human line missing run_id in %q", out)
	}
}

func TestRunConnectorFailureCounted(t *testing.T) {
	t.Chdir(t.TempDir())
	out, err := captureStdout(t, func() error {
		return run([]string{"run", "-demo", "-quiet", "-db", "conn.db", "-exec", "/bin/false"})
	})
	if err != nil {
		t.Fatalf("connector failure should not abort: %v\n%s", err, out)
	}
	sum := lastSummary(t, out)
	if sum.Errors == 0 {
		t.Fatalf("want errors>=1, got %+v", sum)
	}
	if sum.Entities == 0 {
		t.Fatal("native collectors should still write the db")
	}
	_, failErr := captureStdout(t, func() error {
		return run([]string{"run", "-demo", "-quiet", "-db", "conn-fail.db", "-exec", "/bin/false", "-fail-on-errors"})
	})
	if failErr == nil {
		t.Fatal("want fail-on-errors")
	}
	st, err := store.OpenExisting("conn-fail.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ents, _ := st.Entities()
	if len(ents) == 0 {
		t.Fatal("fail-on-errors must not leave an empty db")
	}
}

func TestRunFailOnCapped(t *testing.T) {
	t.Chdir(t.TempDir())
	out, err := captureStdout(t, func() error {
		return run([]string{"run", "-demo", "-quiet", "-db", "cap.db", "-max-items", "1"})
	})
	if err != nil {
		t.Fatal(err)
	}
	if !lastSummary(t, out).Capped {
		t.Fatalf("want capped: %q", out)
	}
	out, err = captureStdout(t, func() error {
		return run([]string{"run", "-demo", "-quiet", "-db", "cap-fail.db", "-max-items", "1", "-fail-on-capped"})
	})
	if err == nil {
		t.Fatal("want fail-on-capped")
	}
	if !lastSummary(t, out).Capped {
		t.Fatalf("summary should still print: %q", out)
	}
}

func TestRunJSONOnly(t *testing.T) {
	t.Chdir(t.TempDir())
	out, err := captureStdout(t, func() error {
		return run([]string{"run", "-demo", "-json", "-db", "json.db"})
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "db ") || strings.Contains(out, "entities=") {
		t.Fatalf("json mode leaked human lines: %q", out)
	}
	sum := lastSummary(t, out)
	if sum.RunID == "" || sum.DB == "" || sum.Entities == 0 {
		t.Fatalf("%+v", sum)
	}
	if n := strings.Count(out, `"kind":"summary"`); n != 1 {
		t.Fatalf("want one summary, got %d in %q", n, out)
	}
}

func TestRunDepthZeroJSON(t *testing.T) {
	t.Chdir(t.TempDir())
	out, err := captureStdout(t, func() error {
		return run([]string{"run", "-demo", "-json", "-depth", "0", "-db", "d0.db"})
	})
	if err != nil {
		t.Fatal(err)
	}
	sum := lastSummary(t, out)
	if sum.Depth != 0 {
		t.Fatalf("depth %+v", sum)
	}
	if !strings.Contains(out, `"depth":0`) {
		t.Fatalf("depth omitted: %q", out)
	}
}

func TestRunDemoPassive(t *testing.T) {
	t.Chdir(t.TempDir())
	out, err := captureStdout(t, func() error {
		return run([]string{"run", "-demo", "-passive", "-json", "-db", "pass.db"})
	})
	if err != nil {
		t.Fatal(err)
	}
	sum := lastSummary(t, out)
	if sum.Entities == 0 {
		t.Fatalf("want seed entities: %+v", sum)
	}
	if sum.Capped {
		t.Fatalf("passive demo must not be capped: %+v", sum)
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
	if _, err := old.UpsertEntity(types.TypeHostname, "gone.test", now); err != nil {
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
	if !strings.Contains(out, `"kind":"added"`) || !strings.Contains(out, `"kind":"removed"`) {
		t.Fatalf("jsonl %q", out)
	}
	text, err := captureStdout(t, func() error {
		return printDiff(oldPath, newPath, diffOpts{Quiet: true})
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, "added=1 removed=1 observations=0") {
		t.Fatalf("counts %q", text)
	}
}
