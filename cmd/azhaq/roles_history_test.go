package main

import (
	"encoding/base64"
	"encoding/json"
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
	"time"
)

// harEntry is a HAR entry sent at a time, with headers as name, value pairs.
func harEntry(at, method, u, body string, status int, headers ...string) map[string]any {
	e := entry(method, u, body, status, headers...)
	e["startedDateTime"] = at
	return e
}

func writeHAR(t *testing.T, name string, entries ...map[string]any) string {
	t.Helper()
	list := make([]any, len(entries))
	for i, e := range entries {
		list[i] = e
	}
	raw, _ := json.Marshal(map[string]any{"log": map[string]any{"version": "1.2", "entries": list}})
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// A HAR's requests: method, URL, headers (HTTP/2 pseudo-headers left out,
// cookies from the cookie list when no header says them), the body (text,
// or a form's params) and what the server answered.
func TestReadHAR(t *testing.T) {
	h := map[string]any{"log": map[string]any{"entries": []any{
		map[string]any{"startedDateTime": "2026-10-29T10:00:00.000Z", "request": map[string]any{
			"method": "post", "url": "http://app.test/api/items",
			"headers":  []any{map[string]any{"name": ":authority", "value": "app.test"}, map[string]any{"name": "authorization", "value": "Bearer a"}},
			"cookies":  []any{map[string]any{"name": "sid", "value": "1"}, map[string]any{"name": "lang", "value": "en"}},
			"postData": map[string]any{"mimeType": "application/json", "text": `{"n":1}`},
		}, "response": map[string]any{"status": 201}},
		map[string]any{"request": map[string]any{
			"method": "POST", "url": "http://app.test/form",
			"postData": map[string]any{"mimeType": "application/x-www-form-urlencoded", "params": []any{map[string]any{"name": "a", "value": "1 2"}, map[string]any{"name": "b", "value": "x"}}},
		}, "response": map[string]any{"status": 302}},
		map[string]any{"request": map[string]any{"method": "GET"}, "response": map[string]any{"status": 200}}, // no URL: skipped
	}}}
	raw, _ := json.Marshal(h)
	path := filepath.Join(t.TempDir(), "a.har")
	os.WriteFile(path, raw, 0o644)
	es, err := readHAR(path)
	if err != nil || len(es) != 2 {
		t.Fatalf("%+v %v", es, err)
	}
	e := es[0]
	if e.method != "POST" || e.url != "http://app.test/api/items" || e.status != 201 || string(e.body) != `{"n":1}` || e.mime != "application/json" ||
		e.header.Get("Authorization") != "Bearer a" || e.header.Get(":authority") != "" || e.header.Get("Cookie") != "sid=1; lang=en" ||
		!e.at.Equal(time.Date(2026, 10, 29, 10, 0, 0, 0, time.UTC)) {
		t.Errorf("entry %+v", e)
	}
	if string(es[1].body) != "a=1+2&b=x" || es[1].status != 302 {
		t.Errorf("form entry %+v", es[1])
	}
	bad := filepath.Join(t.TempDir(), "x.har")
	os.WriteFile(bad, []byte("<items/>"), 0o644)
	if _, err := readHAR(bad); err == nil || !strings.Contains(err.Error(), "not a HAR") {
		t.Errorf("a Burp file read as HAR: %v", err)
	}
}

// A Burp "Save items" file: the raw request, base64 or plain, with its
// URL, method, status and time.
func TestReadBurp(t *testing.T) {
	post := "POST /api/items HTTP/1.1\r\nHost: app.test\r\nAuthorization: Bearer b\r\nContent-Type: application/json\r\nCookie: sid=2\r\n\r\n{\"n\":2}"
	get := "GET /api/items/7?x=1 HTTP/1.1\r\nHost: app.test\r\nAccept: */*\r\n\r\n"
	xml := `<?xml version="1.0"?>
<items burpVersion="2025.5">
  <item>
    <time>Thu Oct 29 10:00:05 UTC 2026</time>
    <url><![CDATA[http://app.test/api/items]]></url>
    <method><![CDATA[POST]]></method>
    <request base64="true"><![CDATA[` + base64.StdEncoding.EncodeToString([]byte(post)) + `]]></request>
    <status>201</status>
    <response base64="true"><![CDATA[SFRUUC8xLjEgMjAxDQoNCg==]]></response>
  </item>
  <item>
    <time>Thu Oct 29 10:00:09 UTC 2026</time>
    <url><![CDATA[http://app.test/api/items/7?x=1]]></url>
    <method><![CDATA[GET]]></method>
    <request base64="false"><![CDATA[` + get + `]]></request>
    <status>200</status>
  </item>
  <item><url>http://app.test/none</url><request base64="true"></request></item>
</items>`
	path := filepath.Join(t.TempDir(), "a.xml")
	os.WriteFile(path, []byte(xml), 0o644)
	es, err := readBurp(path)
	if err != nil || len(es) != 2 {
		t.Fatalf("%+v %v", es, err)
	}
	p := es[0]
	if p.method != "POST" || p.url != "http://app.test/api/items" || p.status != 201 || string(p.body) != `{"n":2}` || p.mime != "application/json" ||
		p.header.Get("Authorization") != "Bearer b" || p.header.Get("Cookie") != "sid=2" || p.at.IsZero() {
		t.Errorf("base64 item %+v", p)
	}
	g := es[1]
	if g.method != "GET" || g.url != "http://app.test/api/items/7?x=1" || g.status != 200 || len(g.body) != 0 || g.header.Get("Accept") != "*/*" || !g.at.After(p.at) {
		t.Errorf("plain item %+v", g)
	}
	notBurp := filepath.Join(t.TempDir(), "b.xml")
	os.WriteFile(notBurp, []byte("{}"), 0o644)
	if _, err := readBurp(notBurp); err == nil {
		t.Error("JSON read as Burp XML")
	}
}

func historyOf(name string, es ...histEntry) *history {
	for i := range es {
		es[i].seq = i
		if es[i].header == nil {
			es[i].header = http.Header{}
		}
	}
	return &history{name: name, entries: es}
}

func hreq(method, u string, kv ...string) histEntry {
	h := http.Header{}
	for i := 0; i+1 < len(kv); i += 2 {
		h.Set(kv[i], kv[i+1])
	}
	return histEntry{method: method, url: u, header: h, status: 200}
}

// Only the origins most of a role's requests go to are the target: the
// analytics and CDN calls of its pages are not, and nothing is read from
// them, not even a session; -allow keeps another origin.
func TestHistoryIgnoresThirdParties(t *testing.T) {
	var es []histEntry
	for i := 0; i < 8; i++ {
		es = append(es, hreq("GET", fmt.Sprintf("https://app.test/api/items/%d", i), "Authorization", "Bearer mine"))
	}
	for i := 0; i < 3; i++ {
		es = append(es, hreq("GET", "https://api.app.test/v2/x", "Authorization", "Bearer api")) // 3 of 13: under a quarter
	}
	es = append(es, hreq("GET", "https://www.google-analytics.com/collect", "Authorization", "Bearer analytics", "Cookie", "_ga=1"))
	es = append(es, hreq("GET", "https://cdn.test/lib.js"))
	h := historyOf("alice", es...)
	sc := historyScope([]*history{h}, nil)
	if !sc.has("https://app.test/anything") || sc.has("https://api.app.test/v2/x") || sc.has("https://www.google-analytics.com/collect") || sc.has("https://cdn.test/lib.js") {
		t.Fatalf("scope %v", sc.origins)
	}
	if got := strings.Join(sc.hostnames(), ","); got != "app.test" {
		t.Errorf("hosts %s", got)
	}
	if n := sc.note(); !strings.Contains(n, "www.google-analytics.com (1)") || !strings.Contains(n, "cdn.test (1)") || !strings.Contains(n, "api.app.test (3)") {
		t.Errorf("note %q", n)
	}
	if lines := h.session(sc); len(lines) != 1 || lines[0] != "Authorization: Bearer mine" {
		t.Errorf("session %v", lines)
	}
	// An origin with a quarter of the requests, and one named with -allow, count.
	sc = historyScope([]*history{h}, []string{"www.google-analytics.com"})
	if !sc.has("https://www.google-analytics.com/collect") {
		t.Error("-allow host left out")
	}
	var half []histEntry
	for i := 0; i < 6; i++ {
		half = append(half, hreq("GET", fmt.Sprintf("https://app.test/p/%d", i)), hreq("GET", fmt.Sprintf("https://api.app.test/q/%d", i)))
	}
	if sc := historyScope([]*history{historyOf("b", half...)}, nil); !sc.has("https://api.app.test/q/1") {
		t.Error("an origin with half the requests is the target too")
	}
}

// A role's session is the Authorization and the Cookie header of its most
// recent request to the target: by time when the file has one, a header
// each, and a token the page had not got yet is none.
func TestHistorySession(t *testing.T) {
	at := func(m int) time.Time { return time.Date(2026, 10, 29, 10, m, 0, 0, time.UTC) }
	old := hreq("GET", "https://app.test/a", "Authorization", "Bearer old", "Cookie", "sid=old")
	old.at = at(1)
	newest := hreq("GET", "https://app.test/b", "Authorization", "Bearer new")
	newest.at = at(9)
	cookie := hreq("GET", "https://app.test/c", "Cookie", "sid=new; theme=dark")
	cookie.at = at(5)
	// Later in the file, earlier in time: the time wins.
	stale := hreq("GET", "https://app.test/d", "Authorization", "Bearer stale")
	stale.at = at(2)
	third := hreq("GET", "https://tracker.test/t", "Authorization", "Bearer tracker", "Cookie", "t=1")
	third.at = at(10)
	nulled := hreq("GET", "https://app.test/e", "Authorization", "Bearer null")
	nulled.at = at(11)
	var many []histEntry
	for i := 0; i < 20; i++ {
		many = append(many, hreq("GET", fmt.Sprintf("https://app.test/x/%d", i)))
	}
	h := historyOf("alice", append(many, old, newest, cookie, stale, third, nulled)...)
	sc := historyScope([]*history{h}, nil)
	got := h.session(sc)
	want := []string{"Authorization: Bearer new", "Cookie: sid=new; theme=dark"}
	if !slices.Equal(got, want) {
		t.Errorf("session %v, want %v", got, want)
	}
	// No credential anywhere: the role is anonymous.
	if lines := historyOf("anon", hreq("GET", "https://app.test/")).session(historyScope([]*history{historyOf("anon", hreq("GET", "https://app.test/"))}, nil)); len(lines) != 0 {
		t.Errorf("anonymous history has a session %v", lines)
	}
}

// -har and -burp name roles: a -role of that name without headers takes
// its session from the history, and an anonymous role is added unless
// -no-anon says not.
func TestAddHistories(t *testing.T) {
	h1 := historyOf("alice", hreq("GET", "https://app.test/a", "Authorization", "Bearer a"))
	h2 := historyOf("bob", hreq("GET", "https://app.test/a", "Authorization", "Bearer b"))
	sc := historyScope([]*history{h1, h2}, nil)
	roles := addHistories([]role{{name: "bob"}}, []*history{h1, h2}, sc, false)
	names := []string{}
	for _, r := range roles {
		names = append(names, r.name)
	}
	if strings.Join(names, ",") != "bob,alice,anon" || roles[0].headers[0] != "Authorization: Bearer b" || roles[1].headers[0] != "Authorization: Bearer a" || !roles[2].anonymous() {
		t.Errorf("%+v", roles)
	}
	// Headers given with -role win over the history's.
	roles = addHistories([]role{{name: "alice", headers: []string{"Authorization: Bearer given"}}}, []*history{h1}, sc, true)
	if len(roles) != 1 || roles[0].headers[0] != "Authorization: Bearer given" {
		t.Errorf("%+v", roles)
	}
	// An anonymous role is there already: none is added.
	roles = addHistories([]role{{name: "visitor"}}, []*history{h1}, sc, false)
	if len(roles) != 2 {
		t.Errorf("%+v", roles)
	}
}

// The URLs of the histories are instances of routes: numbers always, words
// when they differ in one place and an answer held one as an identifier.
func TestHistoryTemplates(t *testing.T) {
	seen := map[string]runSeen{"alice": newRunSeen(), "bob": newRunSeen()}
	seen["alice"].add("http://app.test/books/v1/ab", map[string][]string{"book_title": {"ab"}, "owner": {"alice"}})
	seen["bob"].add("http://app.test/books/v1/bb", map[string][]string{"book_title": {"bb"}, "owner": {"bob"}})
	urls := []string{
		"http://app.test/books/v1/ab", "http://app.test/books/v1/bb", "http://app.test/books/v1",
		"http://app.test/rest/basket/6", "http://app.test/rest/basket/7", "http://app.test/rest/user/whoami", "http://app.test/rest/user/details",
		"http://app.test/api/Users/3/orders/9",
	}
	got := historyTemplates(urls, seen)
	want := []string{"http://app.test/api/Users/{id}/orders/{id2}", "http://app.test/books/v1/{book_title}", "http://app.test/rest/basket/{id}"}
	if !slices.Equal(got, want) {
		t.Errorf("templates %v, want %v", got, want)
	}
}

// Writes on a user's object that the owner's answer does not show: bob's
// PUT of alice's password is accepted, and nothing can say whether it
// took. Listed with that verdict, not as proved and never as "changed
// nothing"; the same write on a field the object shows is judged by it.
func TestWriteCannotBeReadBack(t *testing.T) {
	var mu sync.Mutex
	email := "alice@x.test"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == "GET" && r.URL.Path == "/users/alice":
			fmt.Fprintf(w, `{"username":"alice","email":%q}`, email)
		case r.Method == "PUT" && r.URL.Path == "/users/alice/password":
			w.WriteHeader(204)
		case r.Method == "PUT" && r.URL.Path == "/users/alice/email":
			// writes the caller's own object, whatever the path says
			if r.Header.Get("Authorization") == "Bearer alice" {
				b, _ := io.ReadAll(r.Body)
				var m map[string]string
				json.Unmarshal(b, &m)
				email = m["email"]
			}
			w.WriteHeader(204)
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	h := func(v string) http.Header { x := http.Header{}; x.Set("Authorization", v); return x }
	roles := []role{{name: "anon"}, {name: "alice", headers: []string{"Authorization: Bearer alice"}, session: h("Bearer alice")}, {name: "bob", headers: []string{"Authorization: Bearer bob"}, session: h("Bearer bob")}}
	jh := http.Header{"Content-Type": {"application/json"}}
	reqs := []writeReq{
		{owner: "alice", method: "PUT", url: srv.URL + "/users/alice/password", header: jh, body: []byte(`{"password":"n3w"}`), status: 204},
		{owner: "alice", method: "PUT", url: srv.URL + "/users/alice/email", header: jh, body: []byte(`{"email":"new@x.test"}`), status: 204},
	}
	// The history never read /users/alice: its own answers hold nothing to check by.
	rows, _, err := replayWrites(roles, reqs, map[string]map[string]answer{}, map[string]bool{"127.0.0.1": true}, 0, 100, false)
	if err != nil || len(rows) != 2 {
		t.Fatalf("%+v %v", rows, err)
	}
	pw := rows[0]
	if pw.Verdict != verdictWriteUnread || strings.Join(pw.Readers, ",") != "bob" || !listed(pw.Verdict) ||
		pw.label() != "bob writes alice's object: accepted (204); the change cannot be read back to confirm" ||
		!strings.Contains(pw.Evidence, "/users/alice shows no password") || pw.Status["anon"] != 401 {
		t.Errorf("password row %+v\nlabel %q", pw, pw.label())
	}
	if strings.Contains(pw.label(), "changed nothing") || pw.Verdict == verdictWriteNoChange {
		t.Errorf("an unchecked write is not 'changed nothing': %q", pw.label())
	}
	// The email is in the object, which did not change: the write was not taken.
	if em := rows[1]; em.Verdict != verdictWriteNoChange || listed(em.Verdict) {
		t.Errorf("email row %+v", em)
	}
	// Nothing at all of the owner's object can be read: the same verdict.
	rows, _, _ = replayWrites(roles, reqs[:1], map[string]map[string]answer{}, map[string]bool{"127.0.0.1": true}, 0, 100, false)
	if len(rows) != 1 || rows[0].Verdict != verdictWriteUnread {
		t.Errorf("%+v", rows)
	}
	srv404 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			w.WriteHeader(404)
			return
		}
		if r.Header.Get("Authorization") != "" {
			w.WriteHeader(204)
		} else {
			w.WriteHeader(401)
		}
	}))
	defer srv404.Close()
	rows, _, _ = replayWrites(roles, []writeReq{{owner: "alice", method: "PUT", url: srv404.URL + "/x/alice/pw", header: jh, body: []byte(`{"password":"n"}`), status: 204}},
		map[string]map[string]answer{}, map[string]bool{"127.0.0.1": true}, 0, 100, false)
	if len(rows) != 1 || rows[0].Verdict != verdictWriteUnread || !strings.Contains(rows[0].Evidence, "no GET of the owner's object") {
		t.Errorf("unreadable object: %+v", rows)
	}
}

// A refused write is not a cross write and not listed: a 401 or 403, a
// "Only Admins may delete users!" said with 2xx, an error shaped as data.
func TestRefusedWritesAreNotListed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == "GET":
			fmt.Fprint(w, `{"username":"alice","email":"alice@x.test"}`)
		case r.URL.Path == "/users/alice" && r.Method == "DELETE":
			w.WriteHeader(401)
			fmt.Fprint(w, `{"status":"fail","message":"Only Admins may delete users!"}`)
		case r.URL.Path == "/soft/alice" && r.Method == "DELETE":
			fmt.Fprint(w, `Only admins may delete users`) // 200, said in text
		case r.URL.Path == "/json/alice" && r.Method == "DELETE":
			fmt.Fprint(w, `{"status":"fail","message":"nope"}`)
		case r.URL.Path == "/forbidden/alice" && r.Method == "PUT":
			w.WriteHeader(403)
		default:
			w.WriteHeader(204)
		}
	}))
	defer srv.Close()
	h := http.Header{}
	h.Set("A", "1")
	roles := []role{{name: "anon"}, {name: "alice", headers: []string{"A: 1"}, session: h}, {name: "bob", headers: []string{"A: 2"}, session: h}}
	reqs := []writeReq{
		{owner: "alice", method: "DELETE", url: srv.URL + "/users/alice", header: http.Header{}, status: 401},
		{owner: "alice", method: "DELETE", url: srv.URL + "/soft/alice", header: http.Header{}, status: 200},
		{owner: "alice", method: "DELETE", url: srv.URL + "/json/alice", header: http.Header{}, status: 200},
		{owner: "alice", method: "PUT", url: srv.URL + "/forbidden/alice", header: http.Header{"Content-Type": {"application/json"}}, body: []byte(`{"email":"x@y.test"}`), status: 200},
	}
	rows, _, err := replayWrites(roles, reqs, map[string]map[string]answer{"alice": {}}, map[string]bool{"127.0.0.1": true}, 0, 200, false)
	if err != nil || len(rows) != len(reqs) {
		t.Fatalf("%+v %v", rows, err)
	}
	for _, r := range rows {
		if listed(r.Verdict) || r.Verdict == verdictWriteCross || r.Verdict == verdictWriteAnyone || r.Verdict == verdictWriteUnread {
			t.Errorf("a refused write is %q: %s %s", r.Verdict, r.Method, r.URL)
		}
	}
	if a := rows[1].Answers["bob"]; !a.Refusal || reads(a) {
		t.Errorf("a 200 'Only admins' is a refusal: %+v", a)
	}
}

// roles from nothing but two accounts' histories: no -role, no run
// options, no crawl. The sessions come from the files (the third-party
// calls in them are neither sent nor read from), the pages each account
// reached are asked of the others, and writes go only to the history's
// origin.
func TestRolesFromHistory(t *testing.T) {
	notes := map[string]string{"n-alice": "alice", "n-bob": "bob"}
	passwords := map[string]string{"alice": "pw-alice", "bob": "pw-bob"}
	var mu sync.Mutex
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got = append(got, r.Method+" "+r.URL.Path+" "+r.Header.Get("Authorization"))
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		user := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer tok-")
		signedIn := user == "alice" || user == "bob"
		p := r.URL.Path
		switch {
		case p == "/api/debug":
			mu.Lock()
			fmt.Fprintf(w, `{"users":[{"name":"alice","password":%q},{"name":"bob","password":%q}]}`, passwords["alice"], passwords["bob"])
			mu.Unlock()
		case !signedIn:
			w.WriteHeader(401)
			fmt.Fprint(w, `{"error":"sign in"}`)
		case p == "/api/me":
			fmt.Fprintf(w, `{"data":{"username":%q}}`, user)
		case strings.HasPrefix(p, "/api/notes/") && r.Method == "GET" && notes[strings.TrimPrefix(p, "/api/notes/")] != "":
			id := strings.TrimPrefix(p, "/api/notes/")
			fmt.Fprintf(w, `{"note_id":%q,"owner":%q,"secret":"what %s wrote"}`, id, notes[id], notes[id])
		case r.Method == "PUT" && strings.HasPrefix(p, "/api/users/") && strings.HasSuffix(p, "/password"):
			// Vulnerable like VAmPI: the path's user is changed, not the
			// caller's, whoever the session belongs to.
			target := strings.TrimSuffix(strings.TrimPrefix(p, "/api/users/"), "/password")
			var body struct {
				Password string `json:"password"`
			}
			b, _ := io.ReadAll(r.Body)
			json.Unmarshal(b, &body)
			mu.Lock()
			passwords[target] = body.Password
			mu.Unlock()
			w.WriteHeader(204)
		case r.Method == "DELETE" && strings.HasPrefix(p, "/api/users/"):
			w.WriteHeader(401)
			fmt.Fprint(w, `{"status":"fail","message":"Only Admins may delete users!"}`)
		case r.Method == "GET" && strings.HasPrefix(p, "/api/users/"):
			n := strings.TrimPrefix(p, "/api/users/")
			fmt.Fprintf(w, `{"username":%q,"email":"%s@x.test"}`, n, n)
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	const third = "http://analytics.third-party.invalid/collect"
	browse := func(file, user, note string) string {
		tok := "Bearer tok-" + user
		at := func(m int) string { return fmt.Sprintf("2026-10-29T10:%02d:00.000Z", m) }
		return writeHAR(t, file,
			harEntry(at(0), "GET", srv.URL+"/api/me", "", 200, "Authorization", tok),
			harEntry(at(1), "GET", srv.URL+"/api/notes/"+note, "", 200, "Authorization", tok),
			harEntry(at(2), "GET", srv.URL+"/api/users/"+user, "", 200, "Authorization", tok),
			harEntry(at(3), "GET", srv.URL+"/api/debug", "", 200, "Authorization", tok),
			harEntry(at(4), "GET", third, "", 200, "Authorization", "Bearer tracker", "Cookie", "_t=1"),
			harEntry(at(5), "PUT", srv.URL+"/api/users/"+user+"/password", `{"password":"n3w"}`, 204, "Authorization", tok, "Content-Type", "application/json"),
			harEntry(at(6), "DELETE", srv.URL+"/api/users/"+user, "", 401, "Authorization", tok),
			harEntry(at(7), "POST", srv.URL+"/logout", "", 200, "Authorization", tok),
			harEntry(at(8), "GET", srv.URL+"/api/me", "", 200, "Authorization", tok),
		)
	}
	alice, bob := browse("alice.har", "alice", "n-alice"), browse("bob.har", "bob", "n-bob")
	run := func(extra ...string) (map[string]roleRow, string) {
		args := append([]string{"-json", "-dir", t.TempDir(), "-har", "alice=" + alice, "-har", "bob=" + bob}, extra...)
		out, errOut, err := captureBoth(t, func() error { return cmdRoles(args) })
		if err != nil {
			t.Fatalf("%v\n%s", err, errOut)
		}
		rows := map[string]roleRow{}
		for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
			if l == "" {
				continue
			}
			var row roleRow
			if err := json.Unmarshal([]byte(l), &row); err != nil {
				t.Fatalf("%v: %s", err, l)
			}
			rows[row.Method+" "+strings.TrimPrefix(row.URL, srv.URL)] = row
		}
		return rows, errOut
	}
	rows, errOut := run()
	cross := rows[" /api/notes/n-alice"]
	if cross.Verdict != verdictCross || strings.Join(cross.Readers, ",") != "bob" || cross.Owner != "alice" || cross.Confidence == "" {
		t.Errorf("alice's note: %+v", cross)
	}
	if r := rows[" /api/notes/n-bob"]; r.Verdict != verdictCross || strings.Join(r.Readers, ",") != "alice" {
		t.Errorf("bob's note: %+v", r)
	}
	if r := rows[" /api/debug"]; r.Verdict != verdictAnyoneSecrets || !slices.Contains(r.Sensitive, "password") || r.Status["anon"] != 200 {
		t.Errorf("debug: %+v", r)
	}
	if !strings.Contains(errOut, "left out") || !strings.Contains(errOut, "analytics.third-party.invalid (2)") {
		t.Errorf("summary does not name the third party left out:\n%s", errOut)
	}
	for _, l := range got {
		if strings.Contains(l, "tracker") || strings.Contains(l, "/logout") {
			t.Errorf("sent %q", l)
		}
		if strings.HasPrefix(l, "PUT") || strings.HasPrefix(l, "DELETE") || strings.HasPrefix(l, "POST") {
			t.Errorf("a write without -replay-writes: %q", l)
		}
	}
	if !slices.Contains(got, "GET /api/notes/n-alice Bearer tok-bob") {
		t.Errorf("bob was not asked for alice's note with his session: %v", got)
	}

	// -no-anon: no anonymous role, no row says anyone.
	rows, _ = run("-no-anon")
	if r := rows[" /api/debug"]; r.Verdict == verdictAnyoneSecrets {
		t.Errorf("anonymous role added under -no-anon: %+v", r)
	}

	// With writes: alice's own GET never shows a password, but /api/debug
	// does, and the map already knows it (it was flagged verdictAnyoneSecrets
	// above): bob's replay of alice's password PUT is read back there and
	// proved. The refused DELETE is not a cross write.
	rows, _ = run("-replay-writes", "put,delete", "-all")
	pw := rows["PUT /api/users/alice/password"]
	if pw.Verdict != verdictWriteCross || strings.Join(pw.Readers, ",") != "bob" || !strings.Contains(pw.OwnerBy, "debug") {
		t.Errorf("password write: %+v", pw)
	}
	for k, r := range rows {
		if strings.HasPrefix(k, "DELETE") && (listed(r.Verdict) || strings.Contains(r.Verdict, "writes another role's object")) {
			t.Errorf("refused delete listed: %s %+v", k, r)
		}
	}
	for _, l := range got {
		if strings.HasPrefix(l, "DELETE") && strings.Contains(l, "tracker") {
			t.Errorf("sent to the third party: %q", l)
		}
	}

	// -proxy carries every request: the history reads and the replay too.
	var viaProxy int
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		viaProxy++
		mu.Unlock()
		out := r.Clone(r.Context())
		out.RequestURI = ""
		resp, err := http.DefaultTransport.RoundTrip(out)
		if err != nil {
			w.WriteHeader(502)
			return
		}
		defer resp.Body.Close()
		for k, vs := range resp.Header {
			w.Header()[k] = vs
		}
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
	}))
	defer proxy.Close()
	mu.Lock()
	got = nil
	mu.Unlock()
	run("-proxy", proxy.URL, "-replay-writes", "put")
	mu.Lock()
	defer mu.Unlock()
	if len(got) == 0 || viaProxy != len(got) {
		t.Errorf("the server got %d requests, the proxy carried %d", len(got), viaProxy)
	}
}

// A write is proved in the field it sets: quantity 2 is not seen in an
// object that held a ProductId of 2 already. Two writes the owner sent, one
// after the other, are each judged against the object as the last one left
// it; one that sets what the object holds says so.
func TestWriteProvedInItsField(t *testing.T) {
	var mu sync.Mutex
	qty := 3
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(401)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if r.Method == "PUT" {
			var m map[string]int
			b, _ := io.ReadAll(r.Body)
			json.Unmarshal(b, &m)
			qty = m["quantity"]
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"data":{"id":10,"ProductId":2,"BasketId":6,"quantity":%d}}`, qty)
	}))
	defer srv.Close()
	h := func(v string) http.Header { x := http.Header{}; x.Set("Authorization", v); return x }
	roles := []role{{name: "anon"}, {name: "alice", headers: []string{"Authorization: Bearer alice"}, session: h("Bearer alice")}, {name: "bob", headers: []string{"Authorization: Bearer bob"}, session: h("Bearer bob")}}
	u := srv.URL + "/api/BasketItems/10"
	jh := http.Header{"Content-Type": {"application/json"}}
	read := func() answer {
		a, _ := readAnswer(200, []byte(`{"data":{"id":10,"ProductId":2,"BasketId":6,"quantity":3}}`), "application/json")
		return a
	}
	reqs := []writeReq{
		{owner: "alice", method: "PUT", url: u, header: jh, body: []byte(`{"quantity":2}`), status: 200},
		{owner: "alice", method: "PUT", url: u, header: jh, body: []byte(`{"quantity":3}`), status: 200},
		{owner: "alice", method: "PUT", url: u, header: jh, body: []byte(`{"quantity":3}`), status: 200},
	}
	rows, _, err := replayWrites(roles, reqs, map[string]map[string]answer{"alice": {u: read()}}, map[string]bool{"127.0.0.1": true}, 0, 100, false)
	if err != nil || len(rows) != 3 {
		t.Fatalf("%+v %v", rows, err)
	}
	for _, r := range rows[:2] {
		if r.Verdict != verdictWriteCross || strings.Join(r.Readers, ",") != "bob" {
			t.Errorf("%s: %q", r.reqBody, r.Verdict)
		}
	}
	if r := rows[2]; r.Verdict != verdictWriteNoChange || !strings.Contains(r.OwnerBy, "already held what the write sets") {
		t.Errorf("a write of what the object holds: %q %q", r.Verdict, r.OwnerBy)
	}
}
