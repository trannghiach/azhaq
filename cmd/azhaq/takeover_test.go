package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
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
