package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// TestRolesOnAnApp runs roles -json on a small API with three users: the
// rows it lists and a stderr that holds the summary and nothing else.
func TestRolesOnAnApp(t *testing.T) {
	notes := map[string]string{"n-alice": "alice", "n-bob": "bob"}
	addresses := map[string]string{"11": "alice", "12": "bob", "13": "admin"}
	spec := `{"openapi":"3.0.0","info":{"title":"notes","version":"1"},"paths":{
		"/api/debug":{"get":{}},"/api/notes":{"get":{}},"/api/addresses":{"get":{}},"/api/me":{"get":{}},"/api/profile":{"get":{}},
		"/api/notes/{note_id}":{"get":{"parameters":[{"name":"note_id","in":"path","required":true}]}},
		"/api/addresses/{id}":{"get":{"parameters":[{"name":"id","in":"path","required":true}]}}}}`
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		user := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		signedIn := user == "alice" || user == "bob" || user == "admin"
		p := r.URL.Path
		if strings.HasPrefix(p, "/api/") && p != "/api/debug" && p != "/api/notes" && p != "/api/profile" && !signedIn {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"sign in"}`)
			return
		}
		switch {
		case p == "/":
			fmt.Fprint(w, `{"name":"notes"}`)
		case p == "/openapi.json":
			fmt.Fprint(w, spec)
		case p == "/api/debug":
			fmt.Fprint(w, `{"users":[{"name":"alice","password":"pw-alice"},{"name":"bob","password":"pw-bob"}]}`)
		case p == "/api/notes":
			fmt.Fprint(w, `{"notes":[{"note_id":"n-alice","user":"alice"},{"note_id":"n-bob","user":"bob"}]}`)
		case strings.HasPrefix(p, "/api/notes/") && notes[strings.TrimPrefix(p, "/api/notes/")] != "":
			id := strings.TrimPrefix(p, "/api/notes/")
			fmt.Fprintf(w, `{"note_id":%q,"owner":%q,"secret":"what %s wrote"}`, id, notes[id], notes[id])
		case p == "/api/addresses":
			var ids []string
			for id, owner := range addresses {
				if owner == user {
					ids = append(ids, `{"id":`+id+`}`)
				}
			}
			fmt.Fprintf(w, `{"status":"success","data":[%s]}`, strings.Join(ids, ","))
		case strings.HasPrefix(p, "/api/addresses/") && addresses[strings.TrimPrefix(p, "/api/addresses/")] != "":
			id := strings.TrimPrefix(p, "/api/addresses/")
			switch owner := addresses[id]; {
			case owner == user || owner == "bob": // bob's address is everyone's to read
				fmt.Fprintf(w, `{"status":"success","data":{"id":%s,"street":"%s street"}}`, id, owner)
			case owner == "admin":
				fmt.Fprint(w, `{"status":"error","data":"Malicious activity detected."}`)
			default:
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprint(w, `{"status":"error","data":"Malicious activity detected."}`)
			}
		case p == "/api/me":
			fmt.Fprintf(w, `{"user":{"name":%q,"auth_token":"token-of-%s"}}`, user, user)
		case p == "/api/profile":
			role := ""
			if user == "admin" {
				role = `,"role":"admin"`
			}
			fmt.Fprintf(w, `{"data":{"user":{"email":"%s@x.test"%s}}}`, user, role)
		default:
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"error":"not found"}`)
		}
	}))
	defer site.Close()

	out, errOut, err := captureBoth(t, func() error {
		return cmdRoles([]string{"-json", "-dir", t.TempDir(), "-role", "anon", "-role", "alice=Authorization: Bearer alice",
			"-role", "bob=Authorization: Bearer bob", "-role", "admin=Authorization: Bearer admin", "-id", "alice:note_id=n-alice",
			"--", "-url", site.URL + "/"})
	})
	if err != nil {
		t.Fatalf("%v\n%s", err, errOut)
	}
	lines := strings.Split(strings.TrimSpace(errOut), "\n")
	var sum map[string]any
	if len(lines) != 1 || json.Unmarshal([]byte(lines[0]), &sum) != nil || sum["type"] != "summary" {
		t.Fatalf("stderr under -json is one JSON summary, got %q", errOut)
	}
	got := map[string]string{}
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		var row roleRow
		if err := json.Unmarshal([]byte(l), &row); err != nil {
			t.Fatalf("%v: %s", err, l)
		}
		v := row.Verdict
		if len(row.Readers) > 0 {
			v += " " + strings.Join(row.Readers, ",")
		}
		if row.Owner != "" {
			v += " of " + row.Owner
		}
		if len(row.Sensitive) > 0 {
			v += ": " + strings.Join(row.Sensitive, ",")
		}
		got[strings.TrimPrefix(row.URL, site.URL)] = v
	}
	want := map[string]string{
		"/api/debug":         verdictAnyoneSecrets + ": password",
		"/api/notes/n-alice": verdictCross + " bob,admin of alice: secret",
		"/api/notes/n-bob":   verdictObject + ": secret",
		"/api/addresses/12":  verdictCross + " alice,admin of bob",
		"/api/addresses/11":  verdictOnly + " alice of alice",
		"/api/addresses/13":  verdictOnly + " admin of admin",
		"/api/addresses":     verdictSignedIn,
		"/api/me":            verdictSignedIn,
		"/api/profile":       verdictFields,
	}
	if !reflect.DeepEqual(got, want) {
		var keys []string
		for k := range got {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			t.Logf("%s  %s", k, got[k])
		}
		t.Errorf("rows %v\nwant %v", got, want)
	}
}

func TestRoleSpecs(t *testing.T) {
	roles, err := parseRoles([]string{"anon", "admin=Cookie: sid=1", "admin=X-Tenant: 2"})
	if err != nil {
		t.Fatal(err)
	}
	roles, err = addLogins(roles, []string{"member=m@x.test:pa:ss"})
	if err != nil {
		t.Fatal(err)
	}
	want := []role{{name: "anon"}, {name: "admin", headers: []string{"Cookie: sid=1", "X-Tenant: 2"}}, {name: "member", user: "m@x.test", pass: "pa:ss"}}
	if !reflect.DeepEqual(roles, want) {
		t.Errorf("roles %+v", roles)
	}
	for _, bad := range []string{"member", "member=nopass", "a b=u:p"} {
		if _, err := addLogins(nil, []string{bad}); err == nil {
			t.Errorf("-role-login %q accepted", bad)
		}
	}
	if _, err := addLogins(want, []string{"anon=u:p"}); err == nil {
		t.Error("a login role named like another role accepted")
	}
}

func TestRoleVerdicts(t *testing.T) {
	roles := []role{{name: "anon"}, {name: "alice", user: "a", pass: "p"}, {name: "bob", user: "b", pass: "p"}}
	ok := func(hash string, keys ...string) answer {
		return answer{Status: 200, Length: 10, Hash: hash, Keys: keys}
	}
	no := func(s int) answer { return answer{Status: s} }
	answers := map[string]map[string]answer{
		"anon": {"/": ok("h"), "/api/me": no(401), "/api/settings": no(401), "/api/users": no(401), "/rest/basket/6": no(401), "/api/products": ok("p")},
		"alice": {"/": ok("h"), "/api/me": ok("a", "email"), "/api/settings": ok("s"), "/api/users": ok("u", "email", "id"),
			"/rest/basket/6": ok("b6", "items"), "/api/products": ok("p")},
		"bob": {"/": ok("h"), "/api/me": ok("b", "email"), "/api/settings": no(403), "/api/users": ok("u2", "id"),
			"/rest/basket/6": ok("b6", "items"), "/api/products": ok("p")},
	}
	found := map[string][]string{
		"/": {"anon", "alice", "bob"}, "/api/me": {"anon", "alice", "bob"}, "/api/settings": {"anon", "alice", "bob"},
		"/api/users": {"anon", "alice", "bob"}, "/rest/basket/6": {"alice"}, "/api/products": {"anon", "alice", "bob"},
	}
	got := map[string]string{}
	for _, r := range roleRows(roles, answers, found, nil) {
		got[r.URL] = r.Verdict
	}
	want := map[string]string{
		"/":              verdictSame,
		"/api/products":  verdictSame,
		"/api/me":        verdictSignedIn,
		"/api/settings":  verdictOnly, // bob's 403 and the visitor's 401 are both refusals
		"/api/users":     verdictSignedIn,
		"/rest/basket/6": verdictStatus,
	}
	// bob gets alice's basket, which his own run never reached; the
	// anonymous visitor does not.
	want["/rest/basket/6"] = verdictShared
	if !reflect.DeepEqual(got, want) {
		t.Errorf("verdicts %v\nwant %v", got, want)
	}
	answers["anon"]["/api/x/1"], answers["alice"]["/api/x/1"], answers["bob"]["/api/x/1"] = no(401), no(400), no(400)
	found["/api/x/1"] = []string{"alice"}
	for _, r := range roleRows(roles, answers, found, nil) {
		if r.URL == "/api/x/1" && r.Verdict != verdictNone {
			t.Errorf("an object no role reads: %s", r.Verdict)
		}
	}
}

func TestKeptArgsDropSessions(t *testing.T) {
	got := keptArgs([]string{"-url", "https://app/", "-cookie", "sid=1", "-db", "x.db", "-header", "Authorization: Bearer t",
		"-header=X-Bug-Bounty: me", "-login", "https://app/login", "-login-user", "u", "-login-pass", "p", "-passive", "-max-requests=50", "-worker-token", "secret"})
	want := []string{"-url", "https://app/", "-header=X-Bug-Bounty: me", "-login", "https://app/login", "-login-user", "u", "-passive", "-max-requests=50"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("kept %q", got)
	}
}

func TestRoleRefusals(t *testing.T) {
	roles := []role{{name: "anon"}, {name: "alice", user: "a", pass: "p"}, {name: "bob", user: "b", pass: "p"}, {name: "admin", headers: []string{"X: 1"}}}
	ok := func(hash string) answer { return answer{Status: 200, Length: 10, Hash: hash} }
	no := func(s int) answer { return answer{Status: s} }
	soft := answerOf(200, []byte(`{"status":"error","data":"Malicious activity detected."}`), "application/json")
	rows := map[string][]answer{
		// Juice Shop's /api/Addresss/3: only its owner reads it; a 400 is
		// a refusal like a 401 or a 403.
		"/api/Addresss/3": {no(401), no(400), no(400), ok("a3")},
		"/api/Cards/4":    {no(401), soft, soft, ok("c4")},
		"/api/x":          {no(401), ok("x"), soft, ok("x")},
		"/api/y":          {no(401), no(422), no(404), no(405)},
		"/api/z":          {no(401), ok("z1"), ok("z2"), ok("z3")},
		"/api/w":          {ok("w"), no(400), no(400), no(400)},
	}
	answers := map[string]map[string]answer{}
	found := map[string][]string{}
	for u, as := range rows {
		for i, r := range roles {
			if answers[r.name] == nil {
				answers[r.name] = map[string]answer{}
			}
			answers[r.name][u] = as[i]
		}
		found[u] = []string{"anon", "alice", "bob", "admin"}
	}
	got := map[string]string{}
	for _, r := range roleRows(roles, answers, found, nil) {
		got[r.URL] = r.label()
	}
	want := map[string]string{
		"/api/Addresss/3": "only admin reads it",
		"/api/Cards/4":    "only admin reads it",
		"/api/x":          verdictRoleGated,
		"/api/y":          verdictNone,
		"/api/z":          verdictSignedIn,
		"/api/w":          "only anon reads it",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("verdicts %v\nwant %v", got, want)
	}
}

func TestRoleErrorShapes(t *testing.T) {
	for body, want := range map[string]bool{
		`{"status":"error","data":"Malicious activity detected."}`:                                    true,
		`{ "status": "fail", "message": "Book not found!"}`:                                           true,
		`{"success":false,"message":"no"}`:                                                            true,
		`{"error":"denied"}`:                                                                          true,
		`{"detail":"No authorization token provided","status":401,"title":"Unauthorized","type":"x"}`: true,
		`{"id":5,"status":"failed","total":3}`:                                                        false,
		`{"data":{"x":1},"errors":[{"message":"partial"}]}`:                                           false,
		`{"status":"success","data":[]}`:                                                              false,
		`[{"error":"x"}]`:                                                                             false,
	} {
		if got := answerOf(200, []byte(body), "application/json").Error; got != want {
			t.Errorf("%s: error %v, want %v", body, got, want)
		}
	}
	if !storedAnswer(200, 20, "h", []string{"error", "message"}, "").Error || storedAnswer(200, 20, "h", []string{"error", "id"}, "").Error {
		t.Error("error shape from the stored fields")
	}
}

func TestRoleSensitiveFields(t *testing.T) {
	for k, want := range map[string]string{
		"password": "secret", "hashedPassword": "secret", "password_hash": "secret", "totpSecret": "secret", "client_secret": "secret",
		"api_key": "secret", "apiKey": "secret", "private_key": "secret", "ssn": "secret", "card_number": "secret", "cvv": "secret",
		"securityAnswer": "secret", "deluxeToken": "token", "access_token": "token", "jwt": "token",
		"LABEL_PASSWORD": "", "passwordLength": "", "forgotPassword": "", "hasPassword": "", "nextPageToken": "", "csrfToken": "",
		"username": "", "email": "", "tokenType": "",
	} {
		if got := sensitiveField(k); got != want {
			t.Errorf("%s: %q, want %q", k, got, want)
		}
	}
	a := answerOf(200, []byte(`{"users":[{"username":"a","password":"pass1"},{"username":"b","password":"********"}],
		"schema":{"password":{"type":"string"}},"LABEL_PASSWORD":"Password"}`), "application/json")
	if !reflect.DeepEqual(a.Sensitive, []string{"password"}) || len(a.secrets) != 1 {
		t.Errorf("sensitive %v, %d values: a masked value, a schema and a label are not secrets", a.Sensitive, len(a.secrets))
	}

	roles := []role{{name: "anon"}, {name: "alice", headers: []string{"A: 1"}}, {name: "bob", headers: []string{"B: 1"}}}
	js := func(body string) answer { return answerOf(200, []byte(body), "application/json") }
	debug := js(`{"users":[{"username":"name1","password":"pass1"}]}`)
	users := js(`{"status":"success","data":[{"id":1,"deluxeToken":"d715c2"},{"id":2,"deluxeToken":""}]}`)
	answers := map[string]map[string]answer{
		"anon": {"/users/v1/_debug": debug, "/me": {Status: 401}, "/session": js(`{"token":"t-anon"}`), "/api/Users": {Status: 401}},
		"alice": {"/users/v1/_debug": debug, "/me": js(`{"user":{"name":"alice","auth_token":"ta"}}`), "/session": js(`{"token":"ta"}`),
			"/api/Users": users},
		"bob": {"/users/v1/_debug": debug, "/me": js(`{"user":{"name":"bob","auth_token":"tb"}}`), "/session": js(`{"token":"tb"}`),
			"/api/Users": users},
	}
	found := map[string][]string{}
	for u := range answers["anon"] {
		found[u] = []string{"anon", "alice", "bob"}
	}
	got := map[string]string{}
	for _, r := range roleRows(roles, answers, found, nil) {
		got[r.URL] = r.label()
	}
	want := map[string]string{
		// Every user's password, to a visitor who never signed in, though
		// everyone gets the same answer.
		"/users/v1/_debug": "anyone reads sensitive fields: password",
		// Each session's own token is not a finding.
		"/me":      verdictSignedIn,
		"/session": verdictData,
		// The same tokens for two sessions are no session's own.
		"/api/Users": "alice, bob read the same sensitive fields: deluxeToken",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("verdicts %v\nwant %v", got, want)
	}
}

func TestRoleNestedFields(t *testing.T) {
	js := func(body string) answer { return answerOf(200, []byte(body), "application/json") }
	user, admin := js(`{"data":{"user":{"email":"a@x.test"}}}`), js(`{"data":{"user":{"email":"b@x.test","role":"admin"}}}`)
	if !reflect.DeepEqual(user.Keys, []string{"data", "data.user", "data.user.email"}) {
		t.Errorf("paths %v", user.Keys)
	}
	if !fieldsDiffer(user, admin) {
		t.Error("data.user.role is a field one role gets")
	}
	if fieldsDiffer(js(`{"data":[]}`), js(`{"data":[{"id":1,"street":"x"}]}`)) {
		t.Error("an empty list is data, not different fields")
	}
	if fieldsDiffer(js(`{"1":{"a":1}}`), js(`{"2":{"a":1}}`)) {
		t.Error("fields named by ids are one field")
	}
	roles := []role{{name: "anon"}, {name: "user", headers: []string{"A: 1"}}, {name: "admin", headers: []string{"B: 1"}}}
	answers := map[string]map[string]answer{"anon": {"/p": js(`{"data":{"user":{"email":""}}}`)}, "user": {"/p": user}, "admin": {"/p": admin}}
	rows := roleRows(roles, answers, map[string][]string{"/p": {"anon", "user", "admin"}}, nil)
	if rows[0].Verdict != verdictFields {
		t.Errorf("%s, want %s", rows[0].Verdict, verdictFields)
	}
}

func TestRoleIDs(t *testing.T) {
	roles := []role{{name: "anon"}, {name: "alice", headers: []string{"A: 1"}}, {name: "bob", headers: []string{"B: 1"}}}
	ids, err := parseIDs([]string{"alice:book_title=My book", "basket_id=6", "bob:/rest/basket/{id}=15", "http://h/rest/basket/{id}=7"}, roles)
	if err != nil {
		t.Fatal(err)
	}
	want := []givenID{{role: "alice", name: "book_title", value: "My book"}, {name: "basket_id", value: "6"},
		{role: "bob", name: "/rest/basket/{id}", value: "15"}, {name: "http://h/rest/basket/{id}", value: "7"}}
	if !reflect.DeepEqual(ids, want) {
		t.Errorf("ids %+v", ids)
	}
	for _, bad := range []string{"alcie:book_title=x", "book_title", "alice:=x", "alice:x="} {
		if _, err := parseIDs([]string{bad}, roles); err == nil {
			t.Errorf("-id %q accepted", bad)
		}
	}
	rt, _ := newRoute("http://h/rest/basket/{id}")
	for name, want := range map[string]bool{"basket_id": true, "BasketId": true, "id": true, "{id}": true, "/rest/basket/{id}": true,
		"rest/basket/{id}": true, "http://h/rest/basket/{id}": true, "book_title": false, "/basket/{id}/items": false} {
		if rt.wants(name) != want {
			t.Errorf("/rest/basket/{id} wants %s: %v", name, !want)
		}
	}
}

func TestRoleOwnObjects(t *testing.T) {
	roles := []role{{name: "anon"}, {name: "alice", headers: []string{"A: 1"}}, {name: "bob", headers: []string{"B: 1"}}, {name: "admin", headers: []string{"C: 1"}}}
	seen := map[string]runSeen{}
	answers := map[string]map[string]answer{}
	list := answer{Status: 200, Keys: []string{"data", "status"}}
	for _, r := range roles {
		s := newRunSeen()
		answers[r.name] = map[string]answer{}
		// A public list everyone reads: whose objects they are is unknown.
		s.add("http://h/api/Products", map[string][]string{"id": {"3", "1", "2", "4"}})
		s.add("http://h/books/v1", map[string][]string{"book_title": {"b2", "b1"}, "user": {"name1", "alice"}})
		if !r.anonymous() {
			answers[r.name]["http://h/api/Addresss"] = list
		}
		seen[r.name] = s
	}
	// Each user's own addresses; alice has none. Only admin lists users.
	seen["admin"].add("http://h/api/Addresss", map[string][]string{"id": {"9", "7"}, "UserId": {"1"}})
	seen["bob"].add("http://h/api/Addresss", map[string][]string{"id": {"12"}})
	seen["admin"].add("http://h/admin/users", map[string][]string{"id": {"50"}})
	answers["admin"]["http://h/admin/users"] = list
	// A book title that alice's answers alone hold.
	seen["alice"].add("http://h/me", map[string][]string{"book_title": {"aliceOnly"}})
	templates := map[string]bool{"http://h/api/Addresss/{id}": true, "http://h/books/v1/{book_title}": true,
		"http://h/rest/basket/{id}": true, "http://h/admin/users/{id}": true}
	given := []givenID{{role: "bob", name: "/rest/basket/{id}", value: "15"}, {role: "alice", name: "basket_id", value: "14"}, {name: "nothing", value: "1"}}
	got := instances(roles, templates, seen, answers, given, nil)
	owners := map[string]string{}
	for u, in := range got {
		owners[u] = in.owner
	}
	// Up to 6 values no role owns per route, numbers by value.
	want := map[string]string{
		"http://h/api/Addresss/7": "admin", "http://h/api/Addresss/9": "admin", "http://h/api/Addresss/12": "bob",
		"http://h/api/Addresss/1": "", "http://h/api/Addresss/2": "", "http://h/api/Addresss/3": "", "http://h/api/Addresss/4": "",
		"http://h/api/Addresss/50":    "",
		"http://h/books/v1/aliceOnly": "alice", "http://h/books/v1/b1": "", "http://h/books/v1/b2": "",
		"http://h/rest/basket/14": "alice", "http://h/rest/basket/15": "bob",
		"http://h/rest/basket/1": "", "http://h/rest/basket/2": "", "http://h/rest/basket/3": "", "http://h/rest/basket/4": "",
		"http://h/rest/basket/7": "", "http://h/rest/basket/9": "",
		"http://h/admin/users/1": "", "http://h/admin/users/2": "", "http://h/admin/users/3": "", "http://h/admin/users/4": "",
		"http://h/admin/users/7": "", "http://h/admin/users/9": "",
	}
	if !reflect.DeepEqual(owners, want) {
		t.Errorf("objects %v\nwant %v", owners, want)
	}
	if !got["http://h/rest/basket/14"].given || got["http://h/api/Addresss/7"].rank != 1 || given[2].used || !given[0].used {
		t.Error("given identifiers are marked and ranked first")
	}
	if again := instances(roles, templates, seen, answers, given, nil); !reflect.DeepEqual(again, got) {
		t.Error("the same answers make other URLs")
	}
}

func TestRoleCrossTenant(t *testing.T) {
	roles := []role{{name: "anon"}, {name: "alice", headers: []string{"A: 1"}}, {name: "bob", headers: []string{"B: 1"}}}
	js := func(body string) answer { return answerOf(200, []byte(body), "application/json") }
	book := js(`{"book_title":"aliceBook","owner":"alice","secret":"s3cret"}`)
	answers := map[string]map[string]answer{
		"anon":  {"/books/v1/aliceBook": {Status: 401}, "/books/v1/bobBook": {Status: 401}, "/p/7": js(`{"id":7}`), "/a/1": js(`{"id":1,"at":"1"}`)},
		"alice": {"/books/v1/aliceBook": book, "/books/v1/bobBook": {Status: 404}, "/p/7": js(`{"id":7}`), "/a/1": js(`{"id":1,"at":"2"}`)},
		"bob": {"/books/v1/aliceBook": book, "/books/v1/bobBook": js(`{"book_title":"bobBook","owner":"bob","secret":"x"}`),
			"/p/7": js(`{"id":7}`), "/a/1": js(`{"id":1,"at":"3"}`)},
	}
	found := map[string][]string{"/books/v1/aliceBook": {"alice"}, "/books/v1/bobBook": {"bob"}, "/p/7": {"alice"}, "/a/1": {"alice"}}
	made := map[string]instance{
		"/books/v1/aliceBook": {template: "/books/v1/{book_title}", value: "aliceBook", owner: "alice", given: true},
		"/books/v1/bobBook":   {template: "/books/v1/{book_title}", value: "bobBook", owner: "bob", given: true},
		// Inferred from the answers, but the visitor reads it too: public.
		"/p/7": {template: "/p/{id}", value: "7", owner: "alice"},
		// The same object with a field that changes on every request.
		"/a/1": {template: "/a/{id}", value: "1", owner: "alice", given: true},
	}
	got := map[string]string{}
	for _, r := range roleRows(roles, answers, found, made) {
		got[r.URL] = r.label()
		if r.URL == "/books/v1/aliceBook" && (!reflect.DeepEqual(r.Readers, []string{"bob"}) || r.Owner != "alice") {
			t.Errorf("readers %v of %s's object", r.Readers, r.Owner)
		}
	}
	want := map[string]string{
		"/books/v1/aliceBook": "bob reads alice's object",
		"/books/v1/bobBook":   "only bob reads it",
		"/p/7":                verdictPublicObj,
		"/a/1":                "anon, bob read alice's object",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("verdicts %v\nwant %v", got, want)
	}
}

func TestRoleNotDeadWhenNothingIsGated(t *testing.T) {
	roles := []role{{name: "anon"}, {name: "user", headers: []string{"Authorization: Bearer x"}}}
	same := answer{Status: 200, Length: 10, Hash: "aa"}
	missing := answer{Status: 404, Length: 9, Hash: "bb"}
	rows := []roleRow{
		{URL: "http://a.test/", Answers: map[string]answer{"anon": same, "user": same}},
		{URL: "http://a.test/about", Answers: map[string]answer{"anon": same, "user": same}},
		{URL: "http://a.test/robots.txt", Answers: map[string]answer{"anon": missing, "user": missing}},
	}
	if dead := deadRoles(roles, rows); len(dead) != 0 {
		t.Fatalf("a valid role on a site where nothing is gated was called dead: %v", dead)
	}
}
