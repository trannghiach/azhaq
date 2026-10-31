package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/trannghiach/azhaq/internal/browser"
	"github.com/trannghiach/azhaq/types"
)

// shots marks a page that was drawn without the assets of a host outside
// the scope as partial, in the text line, the JSON row and the summary,
// and names the host to allow. The scope is the user's: the exit code stays 0.
func TestShotsMarksOffScopeAssetsPartial(t *testing.T) {
	if _, err := browser.Find(); err != nil {
		t.Skip(err)
	}
	cdn := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "x") }))
	defer cdn.Close()
	cu, _ := url.Parse(cdn.URL)
	o := "http://localhost:" + cu.Port()
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<html><head><title>app</title><link rel=stylesheet href="%s/bootstrap.css"></head><body><h1>hi</h1><img src="%s/logo.png"></body></html>`, o, o)
	}))
	defer site.Close()

	text, errOut, err := captureBoth(t, func() error {
		return cmdShots([]string{"-u", site.URL + "/", "-dir", filepath.Join(t.TempDir(), "s"), "-db", filepath.Join(t.TempDir(), "w.db")})
	})
	if err != nil {
		t.Fatalf("exit %d (%v), want 0: the scope is the user's, not a failure\n%s", exitCode(err), err, errOut)
	}
	if !strings.Contains(text, "  partial (2 off-scope assets blocked: localhost)") {
		t.Errorf("the text line does not say so:\n%s", text)
	}
	if !strings.Contains(errOut, "outside the scope were blocked") || !strings.Contains(errOut, "-allow localhost loads them") {
		t.Errorf("the summary lacks the note:\n%s", errOut)
	}

	js, _, err := captureBoth(t, func() error {
		return cmdShots([]string{"-u", site.URL + "/", "-dir", filepath.Join(t.TempDir(), "s"), "-db", filepath.Join(t.TempDir(), "w.db"), "-json"})
	})
	if err != nil {
		t.Fatalf("exit %d (%v), want 0", exitCode(err), err)
	}
	var row struct {
		Partial      bool
		Blocked      int
		BlockedHosts []string `json:"blocked_hosts"`
	}
	if err := json.Unmarshal([]byte(strings.SplitN(js, "\n", 2)[0]), &row); err != nil || !row.Partial || row.Blocked != 2 || len(row.BlockedHosts) != 1 || row.BlockedHosts[0] != "localhost" {
		t.Errorf("row %+v (%v): %s", row, err, js)
	}
}

// partialShots counts a picture whose own assets did not load, and not one
// that is partial only for the scope.
func TestPartialShotsExitRule(t *testing.T) {
	shot := func(payload string) []types.StoredObservation {
		return []types.StoredObservation{{Observation: types.Observation{Collector: "azhaq-shots", Kind: "screenshot", Payload: json.RawMessage(payload)}}}
	}
	for payload, want := range map[string]bool{
		`{"partial":true,"blocked":3,"blocked_hosts":["cdn.test"]}`: false, // the scope only
		`{"partial":true,"unloaded":2,"resources":9}`:               true,  // its own assets did not load
		`{"partial":true,"unloaded":2,"resources":9,"blocked":3}`:   true,  // both
		`{"partial":true}`:  true, // an older row
		`{"title":"whole"}`: false,
	} {
		if got := partialShots(shot(payload)); got != want {
			t.Errorf("%s: %v, want %v", payload, got, want)
		}
	}
}
