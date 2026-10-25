package cdxcol

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/trannghiach/azhaq/internal/types"
)

func TestMain(m *testing.M) {
	retryWait = 5 * time.Millisecond
	os.Exit(m.Run())
}

func TestBackoffThenSuccess(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if n.Add(1) == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_, _ = w.Write([]byte(`[["https://app.example.test/a","200","text/html","2020"]]`))
	}))
	t.Cleanup(srv.Close)
	col := &Collector{Client: srv.Client(), BaseURL: srv.URL}
	var p map[string]any
	meta, err := col.Run(context.Background(), types.Seed{
		Type: types.TypeDomain, Keys: map[string]string{"domain": "example.test"},
	}, func(o types.Observation) error {
		if o.Kind == "cdx" {
			_ = json.Unmarshal(o.Payload, &p)
		}
		return nil
	})
	if err != nil || meta.Status != types.StatusOK || p["count"] != 1.0 || p["degraded"] != nil {
		t.Fatalf("meta %+v payload %v err %v tries %d", meta, p, err, n.Load())
	}
}

func TestParseAndFilter(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/cdx/search/cdx" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`[
			["original","statuscode","mimetype","timestamp"],
			["https://app.example.test/login","200","text/html","20200101120000"],
			["https://evil.test/out","200","text/html","20200101120000"],
			["https://app.example.test/style.css","200","text/css","20200101120000"]
		]`))
	}))
	t.Cleanup(srv.Close)

	col := &Collector{Client: srv.Client(), BaseURL: srv.URL}
	var urls []string
	meta, err := col.Run(context.Background(), types.Seed{
		Type: types.TypeDomain,
		Keys: map[string]string{"domain": "example.test"},
	}, func(o types.Observation) error {
		if o.Kind == "url" {
			var p struct {
				URL string `json:"url"`
			}
			_ = json.Unmarshal(o.Payload, &p)
			urls = append(urls, p.URL)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if meta.EmitCount < 2 {
		t.Fatalf("emit %d urls=%v", meta.EmitCount, urls)
	}
	for _, u := range urls {
		if u == "https://evil.test/out" {
			t.Fatal("out of site")
		}
	}
	hinted := false
	for _, h := range meta.NextHints {
		if h.Key() == "https://app.example.test/login" {
			hinted = true
		}
		if h.Key() == "https://app.example.test/style.css" {
			t.Fatal("static hinted")
		}
	}
	if !hinted {
		t.Fatalf("login not hinted: %+v", meta.NextHints)
	}
}

func TestBusyIsNotError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	t.Cleanup(srv.Close)

	col := &Collector{Client: srv.Client(), BaseURL: srv.URL}
	var status any
	meta, err := col.Run(context.Background(), types.Seed{
		Type: types.TypeDomain,
		Keys: map[string]string{"domain": "example.test"},
	}, func(o types.Observation) error {
		if o.Kind == "cdx" {
			var p map[string]any
			_ = json.Unmarshal(o.Payload, &p)
			status = p["status"]
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if meta.Status != types.StatusDegraded {
		t.Fatalf("status %s", meta.Status)
	}
	if fmt.Sprint(status) != "429" {
		t.Fatalf("payload status %v", status)
	}
}

func TestFallbackOnBusy(t *testing.T) {
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	t.Cleanup(primary.Close)
	fb := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/cdx/search/cdx" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`[["https://app.example.test/old","200","text/html","20200101"]]`))
	}))
	t.Cleanup(fb.Close)

	col := &Collector{Client: primary.Client(), BaseURL: primary.URL, Fallback: fb.URL}
	var count float64
	var src string
	_, err := col.Run(context.Background(), types.Seed{
		Type: types.TypeDomain, Keys: map[string]string{"domain": "example.test"},
	}, func(o types.Observation) error {
		if o.Kind == "cdx" {
			var p map[string]any
			_ = json.Unmarshal(o.Payload, &p)
			count, _ = p["count"].(float64)
			src, _ = p["source"].(string)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if count < 1 || !strings.Contains(src, fb.URL) {
		t.Fatalf("count=%v src=%q", count, src)
	}
}

func TestSkipReservedLive(t *testing.T) {
	c := New(nil)
	var skipped string
	_, err := c.Run(context.Background(), types.Seed{
		Type: types.TypeDomain, Keys: map[string]string{"domain": "example.test"},
	}, func(o types.Observation) error {
		var p struct {
			Skipped string `json:"skipped"`
		}
		_ = json.Unmarshal(o.Payload, &p)
		skipped = p.Skipped
		return nil
	})
	if err != nil || skipped != "reserved" {
		t.Fatalf("skipped=%q err=%v", skipped, err)
	}
}

func TestParseCDXLines(t *testing.T) {
	rows, err := parseCDX([]byte(`{"urlkey": "com,vulnweb)/", "timestamp": "20190621044323", "url": "http://vulnweb.com/", "status": "200"}
{"urlkey": "com,vulnweb)/x", "timestamp": "20200107063436", "url": "http://www.vulnweb.com/x", "status": "404"}
`))
	if err != nil || len(rows) != 2 || rows[1].URL != "http://www.vulnweb.com/x" || rows[1].Status != "404" {
		t.Fatalf("rows %+v err %v", rows, err)
	}
}
