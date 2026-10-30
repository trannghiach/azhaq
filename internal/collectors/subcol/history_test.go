package subcol

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/trannghiach/azhaq/types"
)

// No test writes into the real data directory.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "azhaq-subcol-test")
	if err != nil {
		panic(err)
	}
	os.Setenv("AZHAQ_DATA_DIR", dir)
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

func resolving(live ...string) func(context.Context, string, []string) ([]string, []string) {
	set := map[string]bool{}
	for _, n := range live {
		set[n] = true
	}
	return func(_ context.Context, _ string, names []string) ([]string, []string) {
		var out []string
		for _, n := range names {
			if set[n] {
				out = append(out, n)
			}
		}
		return out, nil
	}
}

func TestHistoryDir(t *testing.T) {
	t.Setenv("AZHAQ_DATA_DIR", "/data/a")
	t.Setenv("XDG_DATA_HOME", "/xdg")
	if got := DataDir(); got != "/data/a" {
		t.Errorf("AZHAQ_DATA_DIR: %q", got)
	}
	t.Setenv("AZHAQ_DATA_DIR", "")
	if got := DataDir(); got != "/xdg/azhaq" {
		t.Errorf("XDG_DATA_HOME: %q", got)
	}
	t.Setenv("XDG_DATA_HOME", "")
	t.Setenv("HOME", "/home/u")
	if got := DataDir(); got != "/home/u/.local/share/azhaq" {
		t.Errorf("home: %q", got)
	}
	if historyPath("../x") != "" || historyPath("a/b") != "" {
		t.Error("a domain that is not a name got a path")
	}
}

// A name a source gave once is back in the next run through history, when
// DNS says it resolves, and only then.
func TestHistoryBringsBackNamesThatResolve(t *testing.T) {
	t.Setenv("AZHAQ_DATA_DIR", t.TempDir())
	t1 := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	now = func() time.Time { return t1 }
	defer func() { now = time.Now }()

	first := collector(Options{Verify: resolving()},
		fake("a", noKey, true, []string{"www.example.org", "old.example.org", "gone.example.org"}, nil),
		historySource(),
	)
	payload, _ := run(t, first, context.Background())
	if payload["count"] != float64(3) {
		t.Fatalf("first run: %v", payload["names"])
	}
	raw, err := os.ReadFile(filepath.Join(os.Getenv("AZHAQ_DATA_DIR"), "names", "example.org.json"))
	if err != nil {
		t.Fatal(err)
	}
	var stored map[string]seenName
	if err := json.Unmarshal(raw, &stored); err != nil {
		t.Fatal(err)
	}
	if e := stored["old.example.org"]; len(stored) != 3 || e.First != "2026-10-01T00:00:00Z" || e.Last != e.First || strings.Join(e.Sources, ",") != "a" {
		t.Errorf("stored %v", stored)
	}

	t2 := t1.Add(48 * time.Hour)
	now = func() time.Time { return t2 }
	second := func(live ...string) map[string]any {
		c := collector(Options{Verify: resolving(live...)},
			fake("a", noKey, true, []string{"www.example.org", "new.example.org"}, nil),
			historySource(),
		)
		p, _ := run(t, c, context.Background())
		return p
	}

	// old resolves, gone does not.
	p := second("old.example.org")
	if got := strings.Join(strs(p["names"]), ","); got != "new.example.org,old.example.org,www.example.org" {
		t.Errorf("names with history: %s", got)
	}
	fb := p["found_by"].(map[string]any)
	if got := fmt.Sprint(fb["old.example.org"]); got != "[history]" {
		t.Errorf("old found by %v", got)
	}
	if _, credited := fb["gone.example.org"]; credited {
		t.Errorf("a name that did not resolve got credit: %v", fb["gone.example.org"])
	}
	row := p["sources"].(map[string]any)["history"].(map[string]any)
	if row["count"] != float64(3) || row["kept"] != float64(1) || row["dropped_unresolved"] != float64(1) {
		t.Errorf("history row %v", row)
	}

	// Nothing resolves: history adds nothing.
	p = second()
	if got := strings.Join(strs(p["names"]), ","); got != "new.example.org,www.example.org" {
		t.Errorf("names when stored names do not resolve: %s", got)
	}
	if fb := p["found_by"].(map[string]any); fb["old.example.org"] != nil {
		t.Errorf("old credited: %v", fb["old.example.org"])
	}

	// The stored file keeps first_seen and moves last_seen of what the run kept.
	raw, _ = os.ReadFile(filepath.Join(os.Getenv("AZHAQ_DATA_DIR"), "names", "example.org.json"))
	stored = nil
	json.Unmarshal(raw, &stored)
	if e := stored["www.example.org"]; e.First != t1.Format(time.RFC3339) || e.Last != t2.Format(time.RFC3339) {
		t.Errorf("www: %+v", e)
	}
	if e := stored["gone.example.org"]; e.Last != t1.Format(time.RFC3339) {
		t.Errorf("a name the run did not keep changed: %+v", e)
	}
	if e := stored["old.example.org"]; strings.Join(e.Sources, ",") != "a" || e.Last != t2.Format(time.RFC3339) {
		t.Errorf("old, kept through history, loses its sources or is not marked seen: %+v", e)
	}
	left, _ := filepath.Glob(filepath.Join(os.Getenv("AZHAQ_DATA_DIR"), "names", "*.tmp*"))
	if len(left) != 0 {
		t.Errorf("temp files left: %v", left)
	}
}

func runOn(t *testing.T, c *Collector) (map[string]any, types.RunMeta) {
	t.Helper()
	return run(t, c, context.Background())
}

func seedOf(domain string) types.Seed {
	return types.Seed{Type: types.TypeDomain, Keys: map[string]string{"domain": domain}}
}

func TestHistoryOnlyHoldsVerifiedNames(t *testing.T) {
	t.Setenv("AZHAQ_DATA_DIR", t.TempDir())
	pad := fake("pad", noKey, true, []string{"junk.example.org", "real.example.org"}, nil)
	pad.verify = true
	// A padding name that did not resolve is dropped, so it is not stored.
	c := collector(Options{Verify: resolving("real.example.org")}, pad, fake("a", noKey, true, []string{"www.example.org"}, nil))
	run(t, c, context.Background())
	m, err := loadHistory(historyPath("example.org"))
	if err != nil || len(m) != 2 || m["junk.example.org"].Last != "" {
		t.Errorf("stored %v (%v)", m, err)
	}
	// With no way to check them, the padding source's names are not stored.
	t.Setenv("AZHAQ_DATA_DIR", t.TempDir())
	c = collector(Options{}, pad, fake("a", noKey, true, []string{"www.example.org"}, nil))
	run(t, c, context.Background())
	m, _ = loadHistory(historyPath("example.org"))
	if len(m) != 1 || m["www.example.org"].Last == "" {
		t.Errorf("unchecked padding names stored: %v", m)
	}
}

func TestNoHistoryNeitherReadsNorWrites(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AZHAQ_DATA_DIR", dir)
	c := collector(Options{NoHistory: true}, fake("a", noKey, true, []string{"www.example.org"}, nil), historySource())
	planned, _ := c.plan()
	for _, s := range planned {
		if s.name == historyName {
			t.Error("history is in the plan with -no-history")
		}
	}
	if got := New(Options{}).Asks(seedOf("example.org")); has(got, historyName) {
		t.Errorf("history is a local file, not a query: %v", got)
	}
	def, _ := New(Options{}).plan()
	found := false
	for _, s := range def {
		found = found || s.name == historyName
	}
	if !found {
		t.Error("history is not a default source")
	}
	payload, _ := runOn(t, c)
	if _, ok := payload["sources"].(map[string]any)[historyName]; ok {
		t.Error("history row with -no-history")
	}
	if _, err := os.Stat(filepath.Join(dir, "names")); err == nil {
		t.Error("-no-history wrote the history")
	}
}

func TestHistoryCapDropsOldest(t *testing.T) {
	t.Setenv("AZHAQ_DATA_DIR", t.TempDir())
	maxHistory = 3
	defer func() { maxHistory = 200000 }()
	defer func() { now = time.Now }()
	for i, n := range []string{"a", "b", "c", "d"} {
		at := time.Date(2026, 10, 1+i, 0, 0, 0, 0, time.UTC)
		now = func() time.Time { return at }
		name := n + ".example.org"
		if err := remember("example.org", []string{name}, map[string][]string{name: {"x"}}, nil); err != nil {
			t.Fatal(err)
		}
	}
	m, err := loadHistory(historyPath("example.org"))
	if err != nil || len(m) != 3 {
		t.Fatalf("%v %v", m, err)
	}
	if _, ok := m["a.example.org"]; ok {
		t.Errorf("the oldest stayed: %v", m)
	}
}

func TestCorruptHistoryIsSetAside(t *testing.T) {
	t.Setenv("AZHAQ_DATA_DIR", t.TempDir())
	path := historyPath("example.org")
	os.MkdirAll(filepath.Dir(path), 0o755)
	os.WriteFile(path, []byte("{not json"), 0o644)
	c := collector(Options{}, fake("a", noKey, true, []string{"www.example.org"}, nil), historySource())
	payload, _ := runOn(t, c)
	if row := payload["sources"].(map[string]any)[historyName].(map[string]any); row["error"] == nil {
		t.Errorf("a file that does not parse is said: %v", row)
	}
	if _, err := os.Stat(path + ".bad"); err != nil {
		t.Errorf("not set aside: %v", err)
	}
	if m, err := loadHistory(path); err != nil || len(m) != 1 {
		t.Errorf("new history %v %v", m, err)
	}
}
