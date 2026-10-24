package cloudcol

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"azhaq/internal/types"
)

func TestInventoryHints(t *testing.T) {
	path := filepath.Join(t.TempDir(), "inv.json")
	if err := os.WriteFile(path, []byte(`{
		"domains":["example.test"],
		"hosts":["www.example.test"],
		"urls":["https://www.example.test/"]
	}`), 0o644); err != nil {
		t.Fatal(err)
	}
	col := New()
	meta, err := col.Run(context.Background(), types.Seed{
		Type: types.TypeCloudAccount,
		Keys: map[string]string{"id": "lab", "path": path},
	}, func(types.Observation) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if len(meta.NextHints) != 3 {
		t.Fatalf("hints %+v", meta.NextHints)
	}
}

func TestUnknownSchemaWarns(t *testing.T) {
	path := filepath.Join(t.TempDir(), "inv.json")
	if err := os.WriteFile(path, []byte(`{"Resources":[{"id":"i-1"}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	col := New()
	var warning string
	var extracted float64
	meta, err := col.Run(context.Background(), types.Seed{
		Type: types.TypeCloudAccount,
		Keys: map[string]string{"id": "lab", "path": path},
	}, func(o types.Observation) error {
		if o.Kind != "cloud" {
			return nil
		}
		var p map[string]any
		_ = json.Unmarshal(o.Payload, &p)
		warning, _ = p["warning"].(string)
		extracted, _ = p["extracted"].(float64)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if warning == "" || extracted != 0 {
		t.Fatalf("want empty-extract warning, got %q extracted=%v", warning, extracted)
	}
	if len(meta.NextHints) != 0 {
		t.Fatalf("hints %+v", meta.NextHints)
	}
}

func TestRejectRemotePath(t *testing.T) {
	col := New()
	_, err := col.Run(context.Background(), types.Seed{
		Type: types.TypeCloudAccount,
		Keys: map[string]string{"path": "https://evil.test/inv.json"},
	}, func(types.Observation) error { return nil })
	if err == nil {
		t.Fatal("expected error")
	}
}
