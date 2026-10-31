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
)

// shots marks a page that was drawn without the assets of a host outside
// the scope as partial, in the text line, the JSON row and the summary
// (exit 3), and names the host to allow.
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
	if exitCode(err) != exitPartial {
		t.Fatalf("exit %d (%v), want 3\n%s", exitCode(err), err, errOut)
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
	if exitCode(err) != exitPartial {
		t.Fatalf("exit %d (%v)", exitCode(err), err)
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
