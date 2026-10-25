package urlcol

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/trannghiach/azhaq/types"
)

// archives serves every source: Wayback in two pages, OTX in two pages,
// urlscan in one, Common Crawl refusing with 503 and arquivo empty.
func archives(t *testing.T) *httptest.Server {
	var limited atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		switch r.URL.Path {
		case "/wayback":
			if q.Get("showNumPages") == "true" {
				fmt.Fprint(w, "2")
				return
			}
			if q.Get("page") == "1" && limited.Add(1) == 1 {
				w.WriteHeader(http.StatusTooManyRequests) // once: the retry gets it
				return
			}
			rows := map[string]string{
				"0": `[["original"],["https://example.org/product?id=1"],["https://example.org/product?id=2"],["https://www.example.org/logo.png"]]`,
				"1": `[["original"],["https://api.example.org/v1/users/42"],["https://evil.test/x"]]`,
			}
			fmt.Fprint(w, rows[q.Get("page")])
		case "/otx/domain/example.org/url_list":
			if q.Get("page") == "1" {
				fmt.Fprint(w, `{"has_next":true,"url_list":[{"url":"http://example.org/login.php?next=/"}]}`)
			} else {
				fmt.Fprint(w, `{"has_next":false,"url_list":[{"url":"https://api.example.org/v1/users/43"}]}`)
			}
		case "/urlscan":
			fmt.Fprint(w, `{"has_more":false,"results":[{"page":{"url":"https://example.org/"},"task":{"url":"https://example.org"},"sort":[1700000000000,"abc"]}]}`)
		case "/cc":
			w.WriteHeader(http.StatusServiceUnavailable)
		case "/arquivo":
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	waybackBase, otxBase, urlscanBase = srv.URL+"/wayback", srv.URL+"/otx", srv.URL+"/urlscan"
	commonCrawlInfo, arquivoBase = srv.URL+"/cc", srv.URL+"/arquivo"
	backoff = []time.Duration{time.Millisecond, time.Millisecond, time.Millisecond}
	return srv
}

func TestSourcesMergeAndReport(t *testing.T) {
	srv := archives(t)
	out := filepath.Join(t.TempDir(), "urls.txt")
	c := New(Options{Client: srv.Client(), Out: out})
	c.pauses = nil
	var summary map[string]any
	var rows []map[string]any
	meta, err := c.Run(context.Background(), types.Seed{Type: types.TypeDomain, Keys: map[string]string{"domain": "example.org"}}, func(o types.Observation) error {
		var m map[string]any
		_ = json.Unmarshal(o.Payload, &m)
		if o.Kind == "urls" {
			summary = m
		} else {
			rows = append(rows, m)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	file, _ := os.ReadFile(out)
	got := strings.Fields(string(file))
	if len(got) != 7 || strings.Contains(string(file), "evil.test") {
		t.Fatalf("file %q", got)
	}
	srcs := summary["sources"].(map[string]any)
	if w := srcs["wayback"].(map[string]any); w["count"].(float64) != 4 || w["error"] != nil {
		t.Errorf("wayback after one 429: %v", w)
	}
	if cc := srcs["commoncrawl"].(map[string]any); !strings.Contains(fmt.Sprint(cc["error"]), "rate limited (503)") {
		t.Errorf("commoncrawl %v", cc)
	}
	if summary["degraded"] != true || meta.Status != types.StatusDegraded {
		t.Errorf("a refusing source must mark the result degraded: %v", summary)
	}
	if summary["assets"].(float64) != 1 || summary["templates"].(float64) != 4 {
		t.Errorf("templates %v assets %v", summary["templates"], summary["assets"])
	}
	// Parameters and APIs first; the product pages are one template.
	if len(rows) != 4 || !strings.Contains(rows[0]["url"].(string), "?") {
		t.Fatalf("rows %v", rows)
	}
	for _, r := range rows {
		if strings.Contains(r["url"].(string), "product") && r["count"].(float64) != 2 {
			t.Errorf("product template %v", r)
		}
	}
}

func TestReservedDomain(t *testing.T) {
	c := New(Options{})
	var p map[string]any
	_, err := c.Run(context.Background(), types.Seed{Type: types.TypeDomain, Keys: map[string]string{"domain": "app.test"}}, func(o types.Observation) error {
		return json.Unmarshal(o.Payload, &p)
	})
	if err != nil || p["skipped"] != "reserved" {
		t.Fatalf("%v %v", p, err)
	}
}
