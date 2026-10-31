package main

import (
	"os"
	"strings"
	"testing"
)

// The ledger holds what azhaq sends: where -role-cmd and the ledger are
// documented, the docs say a helper's own requests are not in it.
func TestDocsSayRoleCmdRequestsAreNotInTheLedger(t *testing.T) {
	want := "own requests are not azhaq's and are not in the ledger or held to the scope; give tokens directly or use `-role-login` to keep every request in the ledger"
	for _, f := range []string{"../../docs/commands/roles.md", "../../docs/CONCEPTS.md"} {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(raw), want) {
			t.Errorf("%s does not say: %s", f, want)
		}
	}
	raw, err := os.ReadFile("../../docs/OUTPUT.md")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "requests of a helper outside azhaq") {
		t.Error("docs/OUTPUT.md does not say a helper's requests are not in the ledger")
	}
}
