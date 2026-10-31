package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

// A Juice Shop-like app: bases scripts join paths to, a route that fails
// without its input, a route written to. The map says how each is known
// and lists no prefix.
func TestMapRowsSayHowKnownAndListNoPrefix(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<html><title>shop</title><script src="/main.js"></script></html>`))
		case "/main.js":
			w.Header().Set("Content-Type", "application/javascript")
			w.Write([]byte("class A{hostServer=F.hostServer;host=this.hostServer+`/rest/admin`;v(){return this.http.get(this.host+`/application-version`)}}\n" +
				"class U{hostServer=F.hostServer;host=this.hostServer+`/rest/user`;q(e){return this.http.get(this.host+`/security-question`,{params:{email:e}})}}\n" +
				`function r(userId){return fetch("/api/admin/users/" + userId + "/reset", {method:"PATCH", body: JSON.stringify({level: 1})})}`))
		case "/rest/admin/application-version":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"version":"1"}`))
		case "/rest/user/security-question":
			w.WriteHeader(500)
			w.Write([]byte("<html><title>Error</title><pre>TypeError: Cannot read properties of undefined</pre></html>"))
		default:
			if strings.HasPrefix(r.URL.Path, "/rest/") || strings.HasPrefix(r.URL.Path, "/api/") {
				w.WriteHeader(500)
				w.Write([]byte("<html><title>Error</title></html>"))
				return
			}
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	db := filepath.Join(t.TempDir(), "w.db")
	out, _, err := captureBoth(t, func() error {
		return cmdRun([]string{"-url", srv.URL + "/", "-db", db, "-json"})
	})
	if err != nil && exitCode(err) != exitPartial {
		t.Fatal(err)
	}
	rows := map[string]map[string]any{}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		var row map[string]any
		if json.Unmarshal([]byte(line), &row) == nil && row["type"] == "URL" {
			rows[strings.TrimPrefix(row["key"].(string), srv.URL)] = row
		}
	}
	for _, prefix := range []string{"/rest/admin", "/rest/user", "/api/admin/users"} {
		if rows[prefix] != nil {
			t.Errorf("%s is a prefix scripts join paths to, not a route: %v", prefix, rows[prefix])
		}
	}
	sq := rows["/rest/user/security-question"]
	if sq == nil || sq["evidence"] != "answered" || sq["answer"] != "500 without input" || sq["status"] != float64(500) {
		t.Errorf("a 500 to a request without the email it takes: %v", sq)
	}
	if ok := rows["/rest/admin/application-version"]; ok == nil || ok["evidence"] != "answered" || ok["answer"] != nil {
		t.Errorf("a 200: %v", ok)
	}
	if w := rows["/api/admin/users/{userId}/reset"]; w == nil || w["evidence"] != "called" || w["coverage"] != "hint" || w["answer"] != nil {
		t.Errorf("a route only a script calls, never asked: %v", w)
	}
	// The strings are kept apart, with the reason.
	crawl, _, err := captureBoth(t, func() error {
		return cmdCrawl([]string{"-u", srv.URL + "/", "-rejected", "-json"})
	})
	if err != nil && exitCode(err) != exitPartial {
		t.Fatal(err)
	}
	if !strings.Contains(crawl, `"rejected":"/rest/admin"`) || !strings.Contains(crawl, "the start of a path a script joins more to") {
		t.Errorf("crawl -rejected lacks the prefixes:\n%s", crawl)
	}
}
