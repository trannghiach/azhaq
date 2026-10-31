package jscol

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/trannghiach/azhaq/catalog"
	"github.com/trannghiach/azhaq/types"
)

// What the scripts name goes to the scheduler before the secrets are
// gathered, so a run's pace is not left without a request to send while a
// large bundle is read to the end.
func TestHintsGoBeforeTheSecretsAreGathered(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/main.js", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		fmt.Fprint(w, `var t="ghp_abcdefghijklmnopqrstuvwxyz0123456789"; fetch("/api/Users");`)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><script src="/main.js"></script></html>`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	hinted := make(chan struct{})
	var hints []string
	ctx := catalog.WithHints(context.Background(), func(seeds []types.Seed) {
		for _, s := range seeds {
			hints = append(hints, strings.TrimPrefix(s.Key(), srv.URL))
		}
		select {
		case <-hinted:
		default:
			close(hinted)
		}
	})
	var early bool
	meta, err := New(srv.Client()).Run(ctx, types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": srv.URL + "/"}},
		func(o types.Observation) error {
			if o.Kind == "secrets" {
				select {
				case <-hinted:
					early = true
				case <-time.After(2 * time.Second):
				}
			}
			return nil
		})
	if err != nil {
		t.Fatal(err)
	}
	if !early {
		t.Error("the secrets were emitted before the hints went to the scheduler")
	}
	if len(meta.NextHints) != 0 || len(hints) == 0 {
		t.Errorf("hints handed over %v, left in NextHints %d", hints, len(meta.NextHints))
	}
}
