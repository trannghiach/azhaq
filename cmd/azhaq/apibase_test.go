package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

// An API mounted under its own base serves its description there: the
// run finds it from a route the page's script calls, and maps its paths.
func TestSpecUnderAPIBase(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<html><script>fetch("/identity/api/v2/user/dashboard")</script></html>`))
		case "/identity/api/v2/user/dashboard":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"name":"x"}`))
		case "/identity/api/v2/openapi.json":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"openapi":"3.0.0","info":{"title":"identity","version":"1"},"servers":[{"url":"/identity/api/v2"}],
				"paths":{"/user/orders/{id}":{"get":{"responses":{"200":{"description":"ok"}}}},"/admin/users":{"get":{"responses":{"200":{"description":"ok"}}}}}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	out, _, err := captureBoth(t, func() error {
		return cmdRun([]string{"-url", srv.URL + "/", "-db", filepath.Join(t.TempDir(), "w.db"), "-json"})
	})
	if err != nil && exitCode(err) != exitPartial {
		t.Fatal(err)
	}
	var keys []string
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		var row struct{ Key string }
		if json.Unmarshal([]byte(line), &row) == nil {
			keys = append(keys, strings.TrimPrefix(row.Key, srv.URL))
		}
	}
	all := strings.Join(keys, " ")
	if !strings.Contains(all, "/identity/api/v2/admin/users") || !strings.Contains(all, "/identity/api/v2/user/orders/") {
		t.Errorf("the description under /identity/api/v2/ was not read: %s", all)
	}
}
