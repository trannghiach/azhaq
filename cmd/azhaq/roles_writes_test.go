package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestWriteMethods(t *testing.T) {
	m, err := writeMethods("post, PUT,patch")
	if err != nil || !m["POST"] || !m["PUT"] || !m["PATCH"] || m["DELETE"] {
		t.Fatalf("%v %v", m, err)
	}
	for _, bad := range []string{"get", "", "put,trace"} {
		if _, err := writeMethods(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// A HAR gives the owner's writes on the run's hosts, without the session
// that sent them (cookies, tokens, a CSRF token), and never a logout.
func TestHARWrites(t *testing.T) {
	h := map[string]any{"log": map[string]any{"entries": []any{
		entry("POST", "http://app.test/api/items", `{"basketId":7}`, 201, "Authorization", "Bearer secret", "X-CSRF-Token", "c", "Cookie", "s=1", "Content-Type", "application/json"),
		entry("POST", "http://app.test/api/items", `{"basketId":7}`, 201),
		entry("POST", "http://app.test/logout", "", 302),
		entry("GET", "http://app.test/api/items", "", 200),
		entry("PUT", "http://elsewhere.test/api/x", "{}", 200),
		entry("DELETE", "http://app.test/api/items/3", "", 204),
	}}}
	raw, _ := json.Marshal(h)
	path := filepath.Join(t.TempDir(), "alice.har")
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	ws, err := harWrites("alice", path, map[string]bool{"POST": true, "PUT": true}, map[string]bool{"app.test": true})
	if err != nil || len(ws) != 1 {
		t.Fatalf("%+v %v", ws, err)
	}
	w := ws[0]
	if w.owner != "alice" || w.method != "POST" || string(w.body) != `{"basketId":7}` || w.status != 201 || w.from != "alice.har" {
		t.Errorf("write %+v", w)
	}
	if w.header.Get("Authorization") != "" || w.header.Get("Cookie") != "" || w.header.Get("X-Csrf-Token") != "" || w.header.Get("Content-Type") != "application/json" {
		t.Errorf("headers %v", w.header)
	}
}

func entry(method, u, body string, status int, headers ...string) map[string]any {
	var hs []any
	for i := 0; i+1 < len(headers); i += 2 {
		hs = append(hs, map[string]any{"name": headers[i], "value": headers[i+1]})
	}
	req := map[string]any{"method": method, "url": u, "headers": hs}
	if body != "" {
		req["postData"] = map[string]any{"mimeType": "application/json", "text": body}
	}
	return map[string]any{"request": req, "response": map[string]any{"status": status}}
}

// The routes' writes on each role's own objects: PUT and PATCH with an
// empty JSON object, DELETE when asked; a form's write and a POST to an
// object are left to the HAR.
func TestMapWrites(t *testing.T) {
	made := map[string]instance{
		"http://app.test/api/items/3": {template: "http://app.test/api/items/{id}", owner: "alice", value: "3"},
		"http://app.test/api/items/9": {template: "http://app.test/api/items/{id}"}, // nobody's
		"http://app.test/forms/4":     {template: "http://app.test/forms/{id}", owner: "bob"},
	}
	writes := map[string][]writeOp{
		"http://app.test/api/items/{id}": {{method: "PUT", bodyType: "json"}, {method: "DELETE"}, {method: "POST"}},
		"http://app.test/forms/{id}":     {{method: "PUT", bodyType: "application/x-www-form-urlencoded"}},
	}
	got := mapWrites(made, writes, map[string]bool{"PUT": true, "POST": true})
	if len(got) != 1 || got[0].method != "PUT" || string(got[0].body) != "{}" || !got[0].empty || got[0].owner != "alice" || got[0].from != "PUT /api/items/{id} with an empty body" {
		t.Fatalf("%+v", got)
	}
	if got := mapWrites(made, writes, map[string]bool{"DELETE": true}); len(got) != 1 || got[0].method != "DELETE" || got[0].body != nil {
		t.Fatalf("delete %+v", got)
	}
}

// An app that lets any signed-in user write anyone's item, and the
// anonymous visitor nothing.
func TestReplayWrites(t *testing.T) {
	var mu sync.Mutex
	var log []string
	deleted := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		log = append(log, r.Method+" "+r.URL.Path+" "+r.Header.Get("A")+" "+string(body))
		mu.Unlock()
		if r.Header.Get("A") == "" {
			w.WriteHeader(401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && deleted:
			w.WriteHeader(404)
		case r.Method == http.MethodDelete:
			deleted = true
			w.WriteHeader(204)
		default:
			w.Write([]byte(`{"id":3,"owner":"alice","note":"hi","updatedAt":"2026-10-27T10:00:00Z"}`))
		}
	}))
	defer srv.Close()
	h := func(v string) http.Header { x := http.Header{}; x.Set("A", v); return x }
	roles := []role{{name: "anon"}, {name: "alice", headers: []string{"A: 1"}, session: h("1")}, {name: "bob", headers: []string{"A: 2"}, session: h("2")}}
	u := srv.URL + "/api/items/3"
	before, _ := readAnswer(200, []byte(`{"id":3,"owner":"alice","note":"hi","updatedAt":"2026-10-27T09:00:00Z"}`), "application/json")
	answers := map[string]map[string]answer{"alice": {u: before}}
	own := map[string]bool{"127.0.0.1": true}
	put := writeReq{owner: "alice", method: "PUT", url: u, header: http.Header{"Content-Type": {"application/json"}}, body: []byte("{}"), empty: true, from: "PUT /api/items/{id} with an empty body"}
	rows, n, err := replayWrites(roles, []writeReq{put}, answers, own, 0, 100)
	if err != nil || len(rows) != 1 || n != 4 {
		t.Fatalf("rows %+v sent %d err %v", rows, n, err)
	}
	if r := rows[0]; r.Verdict != verdictWriteCross || strings.Join(r.Readers, ",") != "bob" || r.Method != "PUT" || r.Status["anon"] != 401 || r.label() != "bob writes alice's object" {
		t.Errorf("put row %+v", r)
	}
	// A DELETE goes to the others alone, the anonymous role first, stops at
	// the first let, and asks the owner afterwards.
	log = nil
	del := writeReq{owner: "alice", method: "DELETE", url: u, header: http.Header{}}
	rows, _, _ = replayWrites(roles, []writeReq{del}, answers, own, 0, 100)
	if r := rows[0]; r.Verdict != verdictWriteCross || !strings.Contains(r.OwnerBy, "afterwards its owner got 404") {
		t.Errorf("delete row %+v", r)
	}
	if want := []string{"DELETE /api/items/3  ", "DELETE /api/items/3 2 ", "GET /api/items/3 1 "}; strings.Join(log, "|") != strings.Join(want, "|") {
		t.Errorf("requests %q", log)
	}
}

// An empty write that changes the owner's object stops there: nobody
// else is asked.
func TestReplayWriteChangedObject(t *testing.T) {
	var asked []string
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked = append(asked, r.Method+" "+r.Header.Get("A"))
		if r.Method != http.MethodGet {
			n++
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"id":3,"name":"` + strings.Repeat("x", n) + `"}`))
	}))
	defer srv.Close()
	h := http.Header{}
	h.Set("A", "1")
	roles := []role{{name: "alice", headers: []string{"A: 1"}, session: h}, {name: "bob", headers: []string{"A: 2"}}}
	u := srv.URL + "/api/items/3"
	before, _ := readAnswer(200, []byte(`{"id":3,"name":""}`), "application/json")
	rows, _, _ := replayWrites(roles, []writeReq{{owner: "alice", method: "PATCH", url: u, header: http.Header{}, body: []byte("{}"), empty: true}},
		map[string]map[string]answer{"alice": {u: before}}, map[string]bool{"127.0.0.1": true}, 0, 100)
	if len(rows) != 1 || rows[0].Verdict != verdictWriteVoid || len(asked) != 2 {
		t.Errorf("rows %+v asked %q", rows, asked)
	}
}

func TestReplayWritesFlags(t *testing.T) {
	for _, args := range [][]string{
		{"-replay-writes", "put", "-role", "anon", "-role", "a=A: 1", "--", "-url", "http://127.0.0.1:1/"},
		{"-har", "a=x.har", "-role", "anon", "-role", "a=A: 1", "--", "-url", "http://127.0.0.1:1/", "-allow", "127.0.0.1"},
		{"-replay-writes", "put", "-har", "anon=x.har", "-role", "anon", "-role", "a=A: 1", "--", "-url", "http://127.0.0.1:1/", "-allow", "127.0.0.1"},
		{"-replay-writes", "get", "-role", "anon", "-role", "a=A: 1", "--", "-url", "http://127.0.0.1:1/", "-allow", "127.0.0.1"},
	} {
		if err := cmdRoles(append([]string{"-dir", t.TempDir()}, args...)); exitCode(err) != exitUsage {
			t.Errorf("%q: %v", args, err)
		}
	}
}
