package ctcol

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/trannghiach/azhaq/internal/store"
	"github.com/trannghiach/azhaq/internal/types"
)

type ctPayload struct {
	Names    []string       `json:"names"`
	Count    int            `json:"count"`
	Degraded bool           `json:"degraded"`
	Warning  string         `json:"warning"`
	Error    string         `json:"error"`
	Sources  map[string]any `json:"sources"`
}

func runCT(t *testing.T, c *Collector, domain string) (ctPayload, types.RunMeta, types.Observation) {
	t.Helper()
	var p ctPayload
	var obs types.Observation
	meta, err := c.Run(context.Background(), types.Seed{
		Type: types.TypeDomain, Keys: map[string]string{"domain": domain},
	}, func(o types.Observation) error {
		obs = o
		return json.Unmarshal(o.Payload, &p)
	})
	if err != nil {
		t.Fatal(err)
	}
	return p, meta, obs
}

func src(name string, names []string, err error) source {
	return source{name, func(context.Context, string) ([]string, error) { return names, err }}
}

func TestUnionOfSources(t *testing.T) {
	c := &Collector{srcs: []source{
		src("a", []string{"www.example.org", "api.example.org"}, nil),
		src("b", []string{"api.example.org", "mail.example.org"}, nil),
	}}
	p, meta, _ := runCT(t, c, "example.org")
	sort.Strings(p.Names)
	if strings.Join(p.Names, ",") != "api.example.org,mail.example.org,www.example.org" {
		t.Fatalf("names %v", p.Names)
	}
	if p.Degraded || meta.Status != types.StatusOK || len(meta.NextHints) != 3 {
		t.Fatalf("degraded=%v meta=%+v", p.Degraded, meta)
	}
}

// vulnweb.com on 2026-10-25: crt.sh 502, Cert Spotter an empty list.
// That used to be stored as count=0 with no error.
func TestFailedSourceIsNotASilentZero(t *testing.T) {
	c := &Collector{srcs: []source{
		src("crt.sh", nil, errors.New("crt.sh 502")),
		src("certspotter", nil, nil),
	}}
	p, meta, obs := runCT(t, c, "vulnweb.com")
	if p.Count != 0 || !p.Degraded || !strings.Contains(p.Warning, "crt.sh 502") || meta.Status != types.StatusDegraded {
		t.Fatalf("payload %+v meta %+v", p, meta)
	}
	if p.Error != "" {
		t.Fatalf("one source answered; not an outright failure: %+v", p)
	}
	_, degraded := store.CountIssues([]types.StoredObservation{{Observation: obs}})
	if degraded != 1 {
		t.Fatalf("summary does not count it: degraded=%d", degraded)
	}
}

func TestAllSourcesFail(t *testing.T) {
	c := &Collector{srcs: []source{
		src("crt.sh", nil, errors.New("crt.sh 503")),
		src("certspotter", nil, errors.New("timeout")),
	}}
	p, meta, obs := runCT(t, c, "example.org")
	if p.Error == "" || !p.Degraded || meta.Status != types.StatusDegraded {
		t.Fatalf("payload %+v", p)
	}
	errs, degraded := store.CountIssues([]types.StoredObservation{{Observation: obs}})
	if errs+degraded != 1 {
		t.Fatalf("errors=%d degraded=%d", errs, degraded)
	}
}

func TestCrtCompatibleServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("q") != "%.example.org" {
			http.Error(w, "bad query", http.StatusBadRequest)
			return
		}
		_, _ = w.Write([]byte(`[{"name_value":"*.example.org\nwww.example.org"},{"name_value":"other.test"}]`))
	}))
	t.Cleanup(srv.Close)
	p, _, _ := runCT(t, &Collector{Client: srv.Client(), BaseURL: srv.URL}, "example.org")
	sort.Strings(p.Names)
	if strings.Join(p.Names, ",") != "example.org,www.example.org" {
		t.Fatalf("names %v", p.Names)
	}
}

func TestSkipReservedLive(t *testing.T) {
	c := New(nil)
	var n int
	var skipped string
	meta, err := c.Run(context.Background(), types.Seed{
		Type: types.TypeDomain,
		Keys: map[string]string{"domain": "example.test"},
	}, func(o types.Observation) error {
		n++
		var p struct {
			Skipped string `json:"skipped"`
		}
		_ = json.Unmarshal(o.Payload, &p)
		skipped = p.Skipped
		return nil
	})
	if err != nil || meta.EmitCount != 1 || n != 1 || skipped != "reserved" {
		t.Fatalf("meta %+v n=%d skipped=%q err=%v", meta, n, skipped, err)
	}
}

func TestCrtRetriesErrorsNotTimeouts(t *testing.T) {
	defer func(a, b time.Duration) { crtTimeout, retryWait = a, b }(crtTimeout, retryWait)
	crtTimeout, retryWait = 300*time.Millisecond, time.Millisecond

	var n atomic.Int32
	flaky := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if n.Add(1) == 1 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		_, _ = w.Write([]byte(`[{"name_value":"www.example.org"}]`))
	}))
	t.Cleanup(flaky.Close)
	p, _, _ := runCT(t, &Collector{Client: flaky.Client(), BaseURL: flaky.URL}, "example.org")
	if p.Count != 1 || n.Load() != 2 {
		t.Fatalf("502 then 200: count=%d tries=%d", p.Count, n.Load())
	}

	var m atomic.Int32
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.Add(1)
		select {
		case <-r.Context().Done():
		case <-time.After(2 * time.Second):
		}
	}))
	t.Cleanup(slow.Close)
	t0 := time.Now()
	p, _, _ = runCT(t, &Collector{Client: slow.Client(), BaseURL: slow.URL}, "example.org")
	if m.Load() != 1 || p.Error == "" || time.Since(t0) > time.Second {
		t.Fatalf("timeout retried: tries=%d err=%q took %s", m.Load(), p.Error, time.Since(t0))
	}
}
