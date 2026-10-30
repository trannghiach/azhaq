package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
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

// An app where any signed-in user really writes anyone's object: bob's PUT
// changes alice's object, so the cross write is proved; the anonymous
// visitor is refused.
func TestReplayWritesProved(t *testing.T) {
	var mu sync.Mutex
	note := "hi"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("A") == "" {
			w.WriteHeader(401)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if r.Method != http.MethodGet {
			var m map[string]any
			body, _ := io.ReadAll(r.Body)
			if json.Unmarshal(body, &m) == nil {
				if s, ok := m["note"].(string); ok {
					note = s
				}
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"id":3,"owner":"alice","note":"` + note + `","updatedAt":"2026-10-27T10:00:00Z"}`))
	}))
	defer srv.Close()
	h := func(v string) http.Header { x := http.Header{}; x.Set("A", v); return x }
	roles := []role{{name: "anon"}, {name: "alice", headers: []string{"A: 1"}, session: h("1")}, {name: "bob", headers: []string{"A: 2"}, session: h("2")}}
	u := srv.URL + "/api/items/3"
	before, _ := readAnswer(200, []byte(`{"id":3,"owner":"alice","note":"hi","updatedAt":"2026-10-27T09:00:00Z"}`), "application/json")
	answers := map[string]map[string]answer{"alice": {u: before}}
	own := map[string]bool{"127.0.0.1": true}
	// A HAR write with a body of alice's: bob's session changes alice's note.
	put := writeReq{owner: "alice", method: "PUT", url: u, header: http.Header{"Content-Type": {"application/json"}}, body: []byte(`{"note":"pwned"}`), status: 200, from: "alice.har"}
	rows, _, err := replayWrites(roles, []writeReq{put}, answers, own, 0, 100)
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows %+v err %v", rows, err)
	}
	if r := rows[0]; r.Verdict != verdictWriteCross || strings.Join(r.Readers, ",") != "bob" || r.Status["anon"] != 401 || r.label() != "bob writes alice's object" {
		t.Errorf("put row %+v", r)
	}
	if !strings.Contains(rows[0].OwnerBy, "after bob's PUT the owner's object changed") {
		t.Errorf("owner_by %q", rows[0].OwnerBy)
	}
}

// A real cross DELETE: bob's DELETE removes alice's object, so the owner's
// read afterwards is gone and the write is proved.
func TestReplayWriteDeleteProved(t *testing.T) {
	var mu sync.Mutex
	deleted := false
	var log []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		log = append(log, r.Method+" "+r.Header.Get("A"))
		g := deleted
		if r.Method == http.MethodDelete && r.Header.Get("A") != "" {
			deleted = true
		}
		mu.Unlock()
		switch {
		case r.Header.Get("A") == "":
			w.WriteHeader(401)
		case r.Method == http.MethodGet && g:
			w.WriteHeader(404)
		case r.Method == http.MethodDelete:
			w.WriteHeader(204)
		default:
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"id":3,"owner":"alice"}`))
		}
	}))
	defer srv.Close()
	h := func(v string) http.Header { x := http.Header{}; x.Set("A", v); return x }
	roles := []role{{name: "anon"}, {name: "alice", headers: []string{"A: 1"}, session: h("1")}, {name: "bob", headers: []string{"A: 2"}, session: h("2")}}
	u := srv.URL + "/api/items/3"
	before, _ := readAnswer(200, []byte(`{"id":3,"owner":"alice"}`), "application/json")
	answers := map[string]map[string]answer{"alice": {u: before}}
	del := writeReq{owner: "alice", method: "DELETE", url: u, header: http.Header{}}
	rows, _, _ := replayWrites(roles, []writeReq{del}, answers, map[string]bool{"127.0.0.1": true}, 0, 100)
	if r := rows[0]; r.Verdict != verdictWriteCross || strings.Join(r.Readers, ",") != "bob" || !strings.Contains(r.OwnerBy, "the owner's object is gone") {
		t.Errorf("delete row %+v", r)
	}
	// anon DELETE (refused, no owner read), bob DELETE (let), owner GET (gone).
	if want := "DELETE |DELETE 2|GET 1"; strings.Join(log, "|") != want {
		t.Errorf("requests %q", log)
	}
}

// VAmPI's PUT /users/v1/{username}/email changes the caller's email,
// whatever the path says: bob's write on alice's path answers 2xx but
// leaves alice's object unchanged, so it is not a cross write.
func TestReplayWriteCallerObject(t *testing.T) {
	var mu sync.Mutex
	emails := map[string]string{"alice": "alice@x.test", "bob": "bob@x.test"}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		caller := r.Header.Get("A")
		if caller == "" {
			w.WriteHeader(401)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet:
			// /users/v1/{username}: anyone may read it.
			who := strings.TrimPrefix(r.URL.Path, "/users/v1/")
			w.Write([]byte(`{"username":"` + who + `","email":"` + emails[who] + `"}`))
		default:
			// The write changes the caller's email, not the path's.
			var m map[string]any
			body, _ := io.ReadAll(r.Body)
			if json.Unmarshal(body, &m) == nil {
				if s, ok := m["email"].(string); ok {
					emails[caller] = s
				}
			}
			w.WriteHeader(204)
		}
	}))
	defer srv.Close()
	h := func(v string) http.Header { x := http.Header{}; x.Set("A", v); return x }
	roles := []role{{name: "anon"}, {name: "alice", headers: []string{"A: alice"}, session: h("alice")}, {name: "bob", headers: []string{"A: bob"}, session: h("bob")}}
	obj := srv.URL + "/users/v1/alice"
	before, _ := readAnswer(200, []byte(`{"username":"alice","email":"alice@x.test"}`), "application/json")
	answers := map[string]map[string]answer{"alice": {obj: before}}
	put := writeReq{owner: "alice", method: "PUT", url: srv.URL + "/users/v1/alice/email",
		header: http.Header{"Content-Type": {"application/json"}}, body: []byte(`{"email":"pwned@x.test"}`), status: 204, from: "alice.har"}
	rows, _, _ := replayWrites(roles, []writeReq{put}, answers, map[string]bool{"127.0.0.1": true}, 0, 100)
	if len(rows) != 1 || rows[0].Verdict != verdictWriteNoChange {
		t.Fatalf("rows %+v", rows)
	}
	if emails["alice"] != "alice@x.test" {
		t.Errorf("alice's email changed: %q", emails["alice"])
	}
}

// A POST to a collection creates a new object; even when the other role is
// let, it is a create, never a cross write.
func TestReplayWriteCreate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("A") == "" {
			w.WriteHeader(401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(201)
		w.Write([]byte(`{"owner":"` + r.Header.Get("A") + `"}`))
	}))
	defer srv.Close()
	h := func(v string) http.Header { x := http.Header{}; x.Set("A", v); return x }
	roles := []role{{name: "anon"}, {name: "alice", headers: []string{"A: alice"}, session: h("alice")}, {name: "bob", headers: []string{"A: bob"}, session: h("bob")}}
	post := writeReq{owner: "alice", method: "POST", url: srv.URL + "/books/v1", header: http.Header{"Content-Type": {"application/json"}}, body: []byte(`{"title":"t"}`), status: 201, from: "alice.har"}
	rows, _, _ := replayWrites(roles, []writeReq{post}, nil, map[string]bool{"127.0.0.1": true}, 0, 100)
	if len(rows) != 1 || rows[0].Verdict != verdictWriteCreate || !slices.Contains(rows[0].Readers, "bob") {
		t.Fatalf("rows %+v", rows)
	}
	if listed(verdictWriteCreate) {
		t.Errorf("a create should not be listed by default")
	}
}

// A create the other roles' requests made the server fail (a unique key it
// already holds: SQLAlchemy's 500) is no refusal, and is said to be neither.
func TestReplayWriteServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("A") == "" {
			w.WriteHeader(401)
			return
		}
		w.WriteHeader(500)
		w.Write([]byte("sqlite3.IntegrityError: UNIQUE constraint failed: books.book_title"))
	}))
	defer srv.Close()
	h := func(v string) http.Header { x := http.Header{}; x.Set("A", v); return x }
	roles := []role{{name: "alice", headers: []string{"A: alice"}, session: h("alice")}, {name: "bob", headers: []string{"A: bob"}, session: h("bob")}}
	post := writeReq{owner: "alice", method: "POST", url: srv.URL + "/books/v1", header: http.Header{"Content-Type": {"application/json"}}, body: []byte(`{"title":"t"}`), status: 200, from: "alice.har"}
	rows, _, _ := replayWrites(roles, []writeReq{post}, nil, map[string]bool{"127.0.0.1": true}, 0, 100)
	if len(rows) != 1 || rows[0].Verdict != verdictWriteFailed {
		t.Fatalf("rows %+v", rows)
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

// A route that only takes a write (PUT /users/v1/{username}/email, with no
// GET) still gets an instance filled with each role's own identifier, from
// -id and from learned identity, so -replay-writes has something to send.
func TestWriteOnlyTemplateReplayed(t *testing.T) {
	const route = "http://app.test/users/v1/{username}/email"
	templates := map[string]bool{route: true}
	writes := map[string][]writeOp{route: {{method: "PUT", bodyType: "application/json"}}}

	// With -id.
	rolesID := []role{{name: "alice", headers: []string{"A: 1"}}, {name: "bob", headers: []string{"A: 2"}}}
	given, err := parseIDs([]string{"alice:username=alice"}, rolesID)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]runSeen{"alice": newRunSeen(), "bob": newRunSeen()}
	who := identities(rolesID, map[string]map[string]answer{}, seen, nil)
	made := instances(rolesID, templates, seen, map[string]map[string]answer{}, given, who)
	if in, ok := made["http://app.test/users/v1/alice/email"]; !ok || in.owner != "alice" || in.template != route {
		t.Fatalf("by -id: %+v", made)
	}
	if reqs := mapWrites(made, writes, map[string]bool{"PUT": true}); len(reqs) != 1 || reqs[0].owner != "alice" || string(reqs[0].body) != "{}" {
		t.Fatalf("by -id map writes: %+v", reqs)
	}

	// With learned identity: a /me answer names alice's username.
	me := "http://app.test/me"
	s := newRunSeen()
	s.add(me, map[string][]string{"username": {"alice"}})
	seen2 := map[string]runSeen{"alice": s, "bob": newRunSeen()}
	meAns, _ := readAnswer(200, []byte(`{"username":"alice"}`), "application/json")
	answers := map[string]map[string]answer{"alice": {me: meAns}}
	who2 := identities(rolesID, answers, seen2, nil)
	made2 := instances(rolesID, templates, seen2, answers, nil, who2)
	if in, ok := made2["http://app.test/users/v1/alice/email"]; !ok || in.owner != "alice" {
		t.Fatalf("by identity: %+v", made2)
	}
	if reqs := mapWrites(made2, writes, map[string]bool{"PUT": true}); len(reqs) != 1 || reqs[0].owner != "alice" {
		t.Fatalf("by identity map writes: %+v", reqs)
	}
}

func TestReplayWritesFlags(t *testing.T) {
	for _, args := range [][]string{
		{"-replay-writes", "put", "-role", "anon", "-role", "a=A: 1", "--", "-domain", "example.test"},
		{"-har", "a=x.har", "-role", "anon", "-role", "a=A: 1", "--", "-url", "http://127.0.0.1:1/", "-allow", "127.0.0.1"},
		{"-replay-writes", "put", "-har", "anon=x.har", "-role", "anon", "-role", "a=A: 1", "--", "-url", "http://127.0.0.1:1/", "-allow", "127.0.0.1"},
		{"-replay-writes", "get", "-role", "anon", "-role", "a=A: 1", "--", "-url", "http://127.0.0.1:1/", "-allow", "127.0.0.1"},
	} {
		if err := cmdRoles(append([]string{"-dir", t.TempDir()}, args...)); exitCode(err) != exitUsage {
			t.Errorf("%q: %v", args, err)
		}
	}
}

func TestURLHostsAreTheWriteScope(t *testing.T) {
	got := urlHosts([]string{"-url", "http://127.0.0.1:5002/", "-depth", "2", "--url=https://App.example.org/x"})
	if strings.Join(got, ",") != "127.0.0.1,app.example.org" {
		t.Fatalf("%v", got)
	}
}

// A map DELETE no other role is let to send is a protected object, not
// an owner refused: its owner was never asked.
func TestReplayWriteDeleteRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
	}))
	defer srv.Close()
	h := http.Header{}
	h.Set("A", "1")
	roles := []role{{name: "anon"}, {name: "alice", headers: []string{"A: 1"}, session: h}, {name: "bob", headers: []string{"A: 2"}, session: h}}
	rows, _, _ := replayWrites(roles, []writeReq{{owner: "alice", method: "DELETE", url: srv.URL + "/api/items/3", header: http.Header{}}},
		nil, map[string]bool{"127.0.0.1": true}, 0, 100)
	if len(rows) != 1 || rows[0].Verdict != verdictWriteRefused {
		t.Errorf("%+v", rows)
	}
}
