package urlcol

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/trannghiach/azhaq/types"
)

// PRB-21 (open, owner A1: urls): the summary of a run says, per source,
// how many URLs it gave, its error, and how fresh its newest URL is, so an
// empty result is told from a source that answered nothing.
func TestRegressPRB21PerSourceCountsAndFreshness(t *testing.T) {
	t.Skip("open: PRB-21 (owner A1: urls)")
	srv := archives(t)
	c := New(Options{Client: srv.Client(), Out: filepath.Join(t.TempDir(), "urls.txt")})
	c.pauses = nil
	var summary map[string]any
	_, err := c.Run(context.Background(), types.Seed{Type: types.TypeDomain, Keys: map[string]string{"domain": "example.org"}}, func(o types.Observation) error {
		if o.Kind == "urls" {
			_ = json.Unmarshal(o.Payload, &summary)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for name, v := range summary["sources"].(map[string]any) {
		src := v.(map[string]any)
		if _, ok := src["count"]; !ok {
			t.Errorf("%s: no count", name)
		}
		if _, ok := src["newest"]; !ok {
			t.Errorf("%s: no freshness (newest)", name)
		}
	}
}
