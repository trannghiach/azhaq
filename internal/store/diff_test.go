package store

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/trannghiach/azhaq/internal/types"
)

func TestOpenExistingMissing(t *testing.T) {
	if _, err := OpenExisting(filepath.Join(t.TempDir(), "nope.db")); err == nil {
		t.Fatal("want error for missing db")
	}
}

func TestCompare(t *testing.T) {
	dir := t.TempDir()
	a, err := Open(filepath.Join(dir, "a.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	b, err := Open(filepath.Join(dir, "b.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })

	now := time.Now().UTC()
	if _, err := a.UpsertEntity(types.TypeHostname, "old.example.test", now); err != nil {
		t.Fatal(err)
	}
	if _, err := b.UpsertEntity(types.TypeHostname, "old.example.test", now); err != nil {
		t.Fatal(err)
	}
	if _, err := b.UpsertEntity(types.TypeURL, "https://new.example.test/", now); err != nil {
		t.Fatal(err)
	}
	d, err := Compare(a, b)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Added) != 1 || d.Added[0].Key != "https://new.example.test/" {
		t.Fatalf("added %+v", d.Added)
	}
	if len(d.Removed) != 0 {
		t.Fatalf("removed %+v", d.Removed)
	}
}

func TestCountIssues(t *testing.T) {
	obs := []types.StoredObservation{
		{Observation: types.Observation{Kind: "error", Payload: json.RawMessage(`{"error":"boom"}`)}},
		{Observation: types.Observation{Kind: "dns", Payload: json.RawMessage(`{"error":"nxdomain"}`)}},
		{Observation: types.Observation{Collector: "azhaq-cdx", Kind: "cdx", Payload: json.RawMessage(`{"status":429}`)}},
		{Observation: types.Observation{Collector: "azhaq-ct", Kind: "ct", Payload: json.RawMessage(`{"skipped":"reserved"}`)}},
	}
	errors, degraded := CountIssues(obs)
	if errors != 1 || degraded != 1 {
		t.Fatalf("errors=%d degraded=%d", errors, degraded)
	}
}

func TestSummaryIncludesIssues(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	sum, err := st.Summary()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(sum, "errors=0") || !strings.Contains(sum, "degraded=0") {
		t.Fatalf("summary %q", sum)
	}
}

func TestStatsIncludesRunID(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.SetMeta("run_id", "20260101T000000-1"); err != nil {
		t.Fatal(err)
	}
	if err := st.SetMeta("capped", "1"); err != nil {
		t.Fatal(err)
	}
	stats, err := st.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if stats.Kind != "summary" || stats.RunID != "20260101T000000-1" || !stats.Capped {
		t.Fatalf("%+v", stats)
	}
	if !strings.Contains(stats.Line(), "run_id=20260101T000000-1") {
		t.Fatalf("line %q", stats.Line())
	}
}

func TestConcurrentRunsIsolated(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shared.db")
	a, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	b, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })
	if err := a.BeginRun("run-a", 3, 256); err != nil {
		t.Fatal(err)
	}
	if err := b.BeginRun("run-b", 3, 256); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	ea, err := a.UpsertEntity(types.TypeHostname, "a.example.test", now)
	if err != nil {
		t.Fatal(err)
	}
	eb, err := b.UpsertEntity(types.TypeHostname, "b.example.test", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.AddObservation(ea.ID, types.Observation{
		Collector: "test", Kind: "dns", Payload: json.RawMessage(`{"fqdn":"a.example.test"}`), ObservedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	sa, err := a.Stats()
	if err != nil {
		t.Fatal(err)
	}
	sb, err := b.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if sa.RunID != "run-a" || sb.RunID != "run-b" {
		t.Fatalf("ids %q %q", sa.RunID, sb.RunID)
	}
	if sa.Entities != 1 || sa.Observations != 1 {
		t.Fatalf("run-a %+v", sa)
	}
	if sb.Entities != 1 || sb.Observations != 0 {
		t.Fatalf("run-b %+v", sb)
	}
	_ = eb
}

func TestStatsDepthZeroJSON(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.BeginRun("run-zero", 0, 512); err != nil {
		t.Fatal(err)
	}
	stats, err := st.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if stats.Depth != 0 {
		t.Fatalf("%+v", stats)
	}
	b, err := json.Marshal(stats)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"depth":0`) {
		t.Fatalf("depth omitted: %s", b)
	}
}

func TestSummaryCapped(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.SetMeta("capped", "1"); err != nil {
		t.Fatal(err)
	}
	sum, err := st.Summary()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(sum, "capped=1") {
		t.Fatalf("summary %q", sum)
	}
}
