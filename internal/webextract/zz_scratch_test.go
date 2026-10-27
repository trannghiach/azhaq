package webextract

import (
	"os"
	"testing"
)

func TestScratchJuice(t *testing.T) {
	b, err := os.ReadFile("/tmp/claude-1001/-foqs/417774b6-785a-4dd6-bf55-c5a4f7854324/scratchpad/jsmap/juice/main.js")
	if err != nil {
		t.Skip()
	}
	rs := ClientRoutes(string(b))
	for _, r := range rs {
		t.Logf("%s  %q", r.Path, r.Guard)
	}
	t.Logf("%d routes, hash %v", len(rs), HashRouting(string(b)))
}
