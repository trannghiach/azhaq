package dnscol

import (
	"encoding/json"
	"testing"
)

func TestRecordHostsDropsEmpty(t *testing.T) {
	got := recordHosts([]string{".", "", "mail.example.test.", " "})
	if len(got) != 1 || got[0] != "mail.example.test" {
		t.Fatalf("%v", got)
	}
	raw, err := json.Marshal(recordHosts([]string{".", ""}))
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "[]" {
		t.Fatalf("json %s", raw)
	}
}
