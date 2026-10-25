package crawlcol

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/trannghiach/azhaq/internal/fetch"
	"github.com/trannghiach/azhaq/internal/types"
)

// Juice Shop's /api/Challenges is JSON whose strings hold HTML. Read as
// HTML it produced /api/%5C%22/ftp/legal.md%5C%22.
func TestJSONIsNotHTML(t *testing.T) {
	fetch.Reset()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_, _ = w.Write([]byte(`{"data":[{"description":"Read <a href=\"/ftp/legal.md\">our legal</a>."}]}`))
	}))
	t.Cleanup(srv.Close)
	var urls []string
	_, err := New(srv.Client()).Run(context.Background(), types.Seed{
		Type: types.TypeURL, Keys: map[string]string{"url": srv.URL + "/api/Challenges"},
	}, func(o types.Observation) error {
		var p struct {
			URL string `json:"url"`
		}
		_ = json.Unmarshal(o.Payload, &p)
		urls = append(urls, p.URL)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(urls, " ")
	if got != srv.URL+"/ftp/legal.md" {
		t.Fatalf("urls %q", got)
	}
}

func TestCatchAllPageNotCrawled(t *testing.T) {
	fetch.Reset()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<title>Shop</title><a href="/about">about</a>`))
	}))
	t.Cleanup(srv.Close)
	n := 0
	_, err := New(srv.Client()).Run(context.Background(), types.Seed{
		Type: types.TypeURL, Keys: map[string]string{"url": srv.URL + "/.git/HEAD"},
	}, func(types.Observation) error { n++; return nil })
	if err != nil || n != 0 {
		t.Fatalf("catch-all page crawled: %d facts, err %v", n, err)
	}
}
