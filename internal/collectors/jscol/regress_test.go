package jscol

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/trannghiach/azhaq/internal/fetch"
	"github.com/trannghiach/azhaq/types"
)

// MAP-05: a page whose scripts exceed what one page's pass reads says so,
// and a page within the caps says nothing.
func TestRegressMAP05CapNoteIsSaid(t *testing.T) {
	notes := func(scripts int) []string {
		fetch.Reset()
		defer fetch.Reset()
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/" {
				var b strings.Builder
				b.WriteString("<!doctype html><title>x</title>")
				for i := range scripts {
					fmt.Fprintf(&b, `<script src="/s%d.js"></script>`, i)
				}
				w.Header().Set("Content-Type", "text/html")
				fmt.Fprint(w, b.String())
				return
			}
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprint(w, `fetch("/api/one")`)
		}))
		defer srv.Close()
		var got []string
		_, err := New(srv.Client()).Run(context.Background(), types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": srv.URL + "/"}}, func(o types.Observation) error {
			if o.Kind == "note" {
				var p map[string]any
				_ = json.Unmarshal(o.Payload, &p)
				got = append(got, fmt.Sprint(p["warning"]))
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	if got := notes(maxScripts + 44); len(got) != 1 || !strings.Contains(got[0], "hold more than Azhaq reads from one page") {
		t.Errorf("a page with %d scripts: notes %v", maxScripts+44, got)
	}
	if got := notes(3); len(got) != 0 {
		t.Errorf("a page within the caps said %v", got)
	}
}
