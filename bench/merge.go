package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// mergeRecords joins the records of section jobs run apart (CI runs each
// group of sections on its own runner) into one record, as one run writes.
func mergeRecords(paths []string, out string) error {
	if len(paths) == 0 {
		return fmt.Errorf("-merge: name the records to join")
	}
	all := map[string]any{}
	for _, p := range paths {
		raw, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		var r map[string]any
		if err := json.Unmarshal(raw, &r); err != nil {
			return fmt.Errorf("%s: %v", p, err)
		}
		if a, b := all["commit"], r["commit"]; a != nil && b != nil && a != b {
			return fmt.Errorf("%s measures commit %v, the others %v", p, b, a)
		}
		mergeInto(all, r)
	}
	raw, _ := json.Marshal(all)
	rec = record{}
	if err := json.Unmarshal(raw, &rec); err != nil {
		return err
	}
	printReport()
	if err := os.MkdirAll(out, 0o755); err != nil {
		return err
	}
	name := filepath.Join(out, recordName(rec.Date, rec.Commit))
	b, _ := json.MarshalIndent(rec, "", "  ")
	if err := os.WriteFile(name, append(b, '\n'), 0o644); err != nil {
		return err
	}
	fmt.Printf("\nrecord %s (joined from %d)\n", name, len(paths))
	return nil
}

// mergeInto adds src to dst: lists of checks and runs are joined, tools
// are listed once, the earliest date stays, and each section's row comes
// from the record that measured it.
func mergeInto(dst, src map[string]any) {
	for k, v := range src {
		if v == nil {
			continue
		}
		switch k {
		case "checks", "runs":
			a, _ := dst[k].([]any)
			b, _ := v.([]any)
			dst[k] = append(a, b...)
			continue
		case "tools":
			a, _ := dst[k].([]any)
			seen := map[string]bool{}
			for _, t := range a {
				seen[fmt.Sprint(t.(map[string]any)["name"])] = true
			}
			for _, t := range v.([]any) {
				if n := fmt.Sprint(t.(map[string]any)["name"]); !seen[n] {
					seen[n] = true
					a = append(a, t)
				}
			}
			dst[k] = a
			continue
		case "date":
			if d, ok := dst[k].(string); ok && d <= v.(string) {
				continue
			}
		}
		if m, ok := v.(map[string]any); ok {
			if d, ok := dst[k].(map[string]any); ok {
				mergeInto(d, m)
				continue
			}
		}
		if dst[k] == nil || k == "date" {
			dst[k] = v
		}
	}
}

// recordName is the file name of a record taken at date (RFC 3339).
func recordName(date, commit string) string {
	t, err := time.Parse(time.RFC3339, date)
	if err != nil {
		t = time.Now()
	}
	return t.UTC().Format("2006-01-02T150405") + "-" + commit + ".json"
}
