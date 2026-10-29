package browser

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/trannghiach/azhaq/internal/fetch"
	"github.com/trannghiach/azhaq/internal/ledger"
)

// The ledger and the count hold what reached the server, no more: a page
// still asking when it is closed, paced, has requests waiting that are
// never sent, and a WebSocket's line has its path.
func TestLedgerHoldsWhatTheServerGot(t *testing.T) {
	b := startChrome(t)
	page := `<html><body><script>
new WebSocket('ws://' + location.host + '/sock?sid=7');
let i = 0; setInterval(() => fetch('/tick' + (i++)), 20);
</script>`
	for n := 0; n < 12; n++ {
		page += fmt.Sprintf(`<img src="/img%d.png">`, n)
	}
	page += `</body></html>`
	own := newRecorder(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, page)
			return
		}
		wsHandler(w, r)
	})
	defer own.Close()
	path := filepath.Join(t.TempDir(), "l.jsonl")
	l, err := ledger.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	ledger.Use(l)
	defer ledger.Use(nil)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	fetch.Reset()
	fetch.Allow = func(h string) bool { return h == "127.0.0.1" }
	fetch.SetRate(8)     // slower than the page asks: some wait when it closes
	_ = fetch.Spend(ctx) // the page, which Load's caller counts
	if _, err := b.Load(ctx, own.URL+"/", false); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Second)
	b.Close()
	l.Close()
	var listed []string
	_ = ledger.Read(path, func(e ledger.Entry) error {
		u, _ := url.Parse(e.Target)
		listed = append(listed, u.Path)
		if u.Scheme == "ws" && u.RawQuery != "sid=7" {
			t.Errorf("WebSocket line %s: no path and query", e.Target)
		}
		return nil
	})
	got := own.got()
	slices.Sort(listed)
	slices.Sort(got)
	if !slices.Equal(listed, got) {
		t.Errorf("ledger %d lines, server got %d\nledger %v\nserver %v", len(listed), len(got), listed, got)
	}
	if n := fetch.Sent(); n != int64(len(got)) {
		t.Errorf("counted %d requests, the server got %d", n, len(got))
	}
}
