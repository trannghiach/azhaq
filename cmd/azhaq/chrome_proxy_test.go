package main

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/trannghiach/azhaq/internal/browser"
)

// -proxy holds for Chrome too: run -browser and shots send every request to
// a loopback target through it, the proxy's list is the ledger's, and the
// server got no request that did not pass through.
func TestBrowserRequestsPassThroughProxy(t *testing.T) {
	if _, err := browser.Find(); err != nil {
		t.Skip(err)
	}
	var mu sync.Mutex
	var served []string
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		served = append(served, r.URL.RequestURI())
		mu.Unlock()
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><head><title>app</title></head><body><h1>hi</h1><script>fetch('/api/data?id=7')</script></body></html>`)
	}))
	defer site.Close()
	var pmu sync.Mutex
	var proxied []string
	tr := &http.Transport{Proxy: nil}
	prox := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Host == "" || r.Method == http.MethodConnect {
			http.Error(w, "this proxy relays plain requests", http.StatusBadRequest)
			return
		}
		pmu.Lock()
		proxied = append(proxied, r.URL.RequestURI())
		pmu.Unlock()
		out, _ := http.NewRequestWithContext(r.Context(), r.Method, r.URL.String(), r.Body)
		out.Header = r.Header.Clone()
		resp, err := tr.RoundTrip(out)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		for k, vs := range resp.Header {
			w.Header()[k] = vs
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	}))
	defer prox.Close()

	for name, args := range map[string][]string{
		"run":   {"run", "-url", site.URL + "/", "-allow", "127.0.0.1", "-browser", "-no-paths", "-no-tech", "-depth", "1", "-proxy", prox.URL, "-json", "-quiet"},
		"shots": {"shots", "-u", site.URL + "/", "-allow", "127.0.0.1", "-proxy", prox.URL, "-dir", filepath.Join(t.TempDir(), "s"), "-json"},
	} {
		mu.Lock()
		served = nil
		mu.Unlock()
		pmu.Lock()
		proxied = nil
		pmu.Unlock()
		db := filepath.Join(t.TempDir(), name+".db")
		args = append(args, "-db", db)
		_, errOut, code := cli(t, args...)
		if code != exitOK || strings.Contains(errOut, "no sandbox") {
			if strings.Contains(errOut, "sandbox") || strings.Contains(errOut, "Chrome") && strings.Contains(errOut, "cannot") {
				t.Skip("Chrome cannot run here")
			}
			t.Fatalf("%s: exit %d\n%s", name, code, errOut)
		}
		mu.Lock()
		got := slices.Clone(served)
		mu.Unlock()
		pmu.Lock()
		via := slices.Clone(proxied)
		pmu.Unlock()
		slices.Sort(got)
		slices.Sort(via)
		if !slices.Equal(got, via) {
			t.Errorf("%s: the server got %q, the proxy was asked for %q", name, got, via)
		}
		ledger, err := os.ReadFile(db + ".ledger.jsonl")
		if err != nil {
			t.Fatal(err)
		}
		if n := strings.Count(string(ledger), `"kind":"http"`) + strings.Count(string(ledger), `"kind":"chrome"`); n != len(via) {
			t.Errorf("%s: the ledger lists %d requests, the proxy was asked for %d\n%s", name, n, len(via), ledger)
		}
		if !slices.Contains(via, "/") {
			t.Errorf("%s: the page did not go through the proxy: %q", name, via)
		}
	}
}
