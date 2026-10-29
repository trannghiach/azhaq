package main

import (
	"strings"
	"testing"

	"github.com/trannghiach/azhaq/internal/hunt"
)

// hunt weighs the roles verdicts by their text; the text lives here.
func TestHuntKnowsTheRolesVerdicts(t *testing.T) {
	for _, v := range []string{verdictCross, verdictAnyoneSecrets, verdictWriteCross, verdictWriteAnyone, verdictWriteUnread} {
		rows, err := hunt.ReadRoles(strings.NewReader(`{"url":"http://t/x","verdict":"` + v + `"}`))
		if err != nil || len(rows) != 1 {
			t.Fatal(err)
		}
		if got := hunt.Build(hunt.Input{Roles: rows}); len(got) != 1 || got[0].Score < 90 {
			t.Errorf("verdict %q does not rank: %+v", v, got)
		}
	}
}

func TestHuntFlags(t *testing.T) {
	if err := cmdHunt([]string{"-db", t.TempDir() + "/none.db", "-limit", "0"}); err == nil {
		t.Error("-limit 0 is a usage error")
	}
	if err := cmdHunt([]string{"-db", t.TempDir() + "/none.db", "-roles", "/nonexistent/roles.jsonl"}); err == nil {
		t.Error("a missing -roles file is an error")
	}
}
