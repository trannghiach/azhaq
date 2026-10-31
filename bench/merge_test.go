package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestMergeJoinsSectionRecords(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	a := write("a.json", `{"date":"2026-10-31T12:00:00Z","commit":"abc","go":"go1","tools":[{"name":"httpx"}],
		"probe":{},"apps":[{}],"polite":{"probe":{}},
		"checks":[{"name":"probe ok","pass":true,"detail":""}],"runs":[{"tool":"httpx"}]}`)
	b := write("b.json", `{"date":"2026-10-31T11:00:00Z","commit":"abc","go":"go1","tools":[{"name":"httpx"},{"name":"ffuf"}],
		"scope":{"trap_requests":1},"polite":{"dirs":{}},
		"checks":[{"name":"scope ok","pass":false,"detail":"no"}],"runs":[{"tool":"ffuf"}]}`)
	out := filepath.Join(dir, "out")
	if err := mergeRecords([]string{a, b}, out); err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob(filepath.Join(out, "*.json"))
	if len(files) != 1 || filepath.Base(files[0]) != "2026-10-31T110000-abc.json" {
		t.Fatalf("record files %v", files)
	}
	raw, _ := os.ReadFile(files[0])
	var got map[string]any
	_ = json.Unmarshal(raw, &got)
	if n := len(got["checks"].([]any)); n != 2 {
		t.Errorf("checks %d, want 2", n)
	}
	if n := len(got["tools"].([]any)); n != 2 {
		t.Errorf("tools %d, want 2 (listed once)", n)
	}
	if got["scope"] == nil || got["probe"] == nil || got["apps"] == nil {
		t.Errorf("a section row was lost: %v", got)
	}
	p := got["polite"].(map[string]any)
	if p["probe"] == nil || p["dirs"] == nil {
		t.Errorf("polite rows not joined: %v", p)
	}
}

func TestMergeRefusesTwoCommits(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.json")
	b := filepath.Join(dir, "b.json")
	_ = os.WriteFile(a, []byte(`{"commit":"abc","checks":[]}`), 0o644)
	_ = os.WriteFile(b, []byte(`{"commit":"def","checks":[]}`), 0o644)
	if err := mergeRecords([]string{a, b}, dir); err == nil {
		t.Fatal("records of two commits were joined")
	}
}
