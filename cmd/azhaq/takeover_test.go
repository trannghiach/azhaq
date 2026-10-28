package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/trannghiach/azhaq/types"
)

// A front page that is a hosting service's page for a name nobody claimed
// is a takeover candidate in the summary.
func TestTakeoverInSummary(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
		w.Write([]byte(`<html><body><p><strong>There isn't a GitHub Pages site here.</strong></p></body></html>`))
	}))
	defer srv.Close()
	_, errOut, _ := captureBoth(t, func() error {
		return cmdRun([]string{"-url", srv.URL + "/", "-db", filepath.Join(t.TempDir(), "w.db"), "-json", "-depth", "0"})
	})
	var sum struct {
		Takeover []struct{ Host, Service, Strength, Evidence string }
	}
	line := errOut[strings.LastIndex(strings.TrimSpace(errOut), "\n")+1:]
	if err := json.Unmarshal([]byte(line), &sum); err != nil || len(sum.Takeover) != 1 || sum.Takeover[0].Service != "GitHub Pages" || sum.Takeover[0].Host != "127.0.0.1" {
		t.Fatalf("summary %s (%v)", errOut, err)
	}
}

// A service's page is judged again by where DNS says the name points.
func TestTakeoverPageAndCNAME(t *testing.T) {
	page := func(host string) types.StoredObservation {
		raw, _ := json.Marshal(map[string]any{"url": "https://" + host + "/", "takeover": map[string]any{"service": "GitHub Pages", "strength": "page",
			"evidence": `GitHub Pages's page for a name nobody claimed: "There isn't a GitHub Pages site here." (no CNAME known: check where the name points)`}})
		return types.StoredObservation{Observation: types.Observation{Collector: "azhaq-http", Payload: raw}}
	}
	dns := func(host string, cnames ...string) types.StoredObservation {
		raw, _ := json.Marshal(map[string]any{"fqdn": host, "cnames": cnames})
		return types.StoredObservation{Observation: types.Observation{Collector: "azhaq-dns", Payload: raw}}
	}
	got := takeovers(nil, []types.StoredObservation{
		page("a.example.com"), dns("a.example.com", "acme.github.io"), // to the service: strong
		page("b.example.com"), dns("b.example.com", "lb.example.net"), // elsewhere: nothing
		page("c.example.com"), // no CNAME known: the page alone
	})
	if len(got) != 2 || got[0].Host != "a.example.com" || got[0].Strength != "strong" || got[0].Target != "acme.github.io" ||
		got[1].Host != "c.example.com" || got[1].Strength != "page" {
		t.Errorf("%+v", got)
	}
}
