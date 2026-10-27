package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/trannghiach/azhaq/internal/browser"
	"github.com/trannghiach/azhaq/internal/fetch"
	"github.com/trannghiach/azhaq/internal/normalize"
)

func TestRoleRedirects(t *testing.T) {
	for _, c := range []struct {
		from, to, login string
		toLogin, toRoot bool
	}{
		{"http://h/app/x", "/login", "", true, false},
		{"http://h/app/x", "/users/sign_in?next=/app/x", "", true, false},
		{"http://h/app/x", "/wp-login.php", "", true, false},
		{"http://h/app/x", "https://login.microsoftonline.com/common/oauth2/authorize?x=1", "", true, false},
		{"http://h/app/x", "/portal/start", "http://h/portal/start", true, false}, // the -login page
		{"http://h/app/x", "/", "http://h/#/login", false, true},                  // a -login page on the front page is not a sign-in path
		{"http://h/app/x", "http://h/", "", false, true},
		{"http://h/", "/home", "", false, false},
		{"http://h/authors", "/authors/1", "", false, false},
		{"http://h/app/x", "/dashboard", "", false, false},
	} {
		l, r := redirectKind(c.from, c.to, c.login)
		if l != c.toLogin || r != c.toRoot {
			t.Errorf("%s → %s: to a sign-in page %v, to the front page %v", c.from, c.to, l, r)
		}
	}
	// A cookie-session app: the visitor is sent to the sign-in page.
	roles := []role{{name: "anon"}, {name: "alice", headers: []string{"Cookie: sid=a"}}, {name: "bob", headers: []string{"Cookie: sid=b"}}}
	ok := func(hash string) answer { return answer{Status: 200, Length: 10, Hash: hash} }
	to := func(loc string) answer { return answer{Status: 302, Length: 10, Hash: "login", Location: loc} }
	answers := map[string]map[string]answer{
		"anon":  {"http://h/learn": to("/login"), "http://h/app/a": to("/"), "http://h/login": ok("form"), "http://h/x": to("/next")},
		"alice": {"http://h/learn": ok("l1"), "http://h/app/a": ok("a"), "http://h/login": to("/learn"), "http://h/x": to("/next")},
		"bob":   {"http://h/learn": ok("l2"), "http://h/app/a": ok("a"), "http://h/login": to("/learn"), "http://h/x": to("/next")},
	}
	found := map[string][]string{}
	for u := range answers["anon"] {
		found[u] = []string{"anon", "alice", "bob"}
	}
	markRedirects(answers, "http://h/login")
	got := map[string]string{}
	for _, r := range roleRows(roles, answers, found, nil) {
		got[r.URL] = r.label()
	}
	want := map[string]string{
		"http://h/learn": verdictSignedIn,
		"http://h/app/a": verdictSignedIn, // back to the front page while the others read it
		"http://h/login": verdictStatus,   // signed-in roles are sent on: not a refusal
		"http://h/x":     verdictNone,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("verdicts %v\nwant %v", got, want)
	}
}

func TestRoleDeadSessions(t *testing.T) {
	ok := func(hash string) answer { return answer{Status: 200, Length: 10, Hash: hash} }
	no := func(s int) answer { return answer{Status: s} }
	me := func(hash string) answer { return answer{Status: 200, Length: 10, Hash: hash, Keys: []string{"user"}} }
	login := answer{Status: 302, Location: "/login", toLogin: true}
	type rows map[string][]answer // path → an answer per role, in order
	for _, c := range []struct {
		name  string
		roles []role
		rows  rows
		want  []string
	}{
		{"a garbage token beside a good one", []role{{name: "anon"}, {name: "u1", headers: []string{"A: 1"}}, {name: "x", headers: []string{"A: 2"}}},
			rows{"/me": {no(401), ok("me1"), no(401)}, "/books/b1": {no(401), ok("b1"), no(401)}, "/": {ok("h"), ok("h"), ok("h")}}, []string{"x"}},
		{"a garbage token alone", []role{{name: "anon"}, {name: "x", headers: []string{"A: 2"}}},
			rows{"/me": {no(401), no(401)}, "/": {ok("h"), ok("h")}}, []string{"x"}},
		{"two good sessions", []role{{name: "anon"}, {name: "u1", headers: []string{"A: 1"}}, {name: "u2", headers: []string{"A: 2"}}},
			rows{"/me": {no(401), ok("me1"), ok("me2")}, "/books/b1": {no(401), ok("b1"), no(403)}, "/": {ok("h"), ok("h"), ok("h")}}, nil},
		{"a token every endpoint refuses, no anonymous role", []role{{name: "a", headers: []string{"A: 1"}}, {name: "x", headers: []string{"A: 2"}}},
			rows{"/": {ok("h"), no(401)}, "/api": {ok("api"), no(401)}}, []string{"x"}},
		{"a cookie the app sends to its sign-in page", []role{{name: "anon"}, {name: "d1", headers: []string{"Cookie: s=1"}}, {name: "x", headers: []string{"Cookie: s=2"}}},
			rows{"/learn": {login, ok("l"), login}, "/app": {login, ok("a"), login}, "/login": {ok("f"), no(302), ok("f")}}, []string{"x"}},
		// A user refused where only the admin reads, who reads /me as itself.
		{"a user beside an admin", []role{{name: "anon"}, {name: "admin", headers: []string{"A: 1"}}, {name: "user", headers: []string{"A: 2"}}},
			rows{"/admin": {no(401), ok("adm"), no(403)}, "/api/me": {me("nobody"), me("me-a"), me("me-u")}}, nil},
		// A page that differs on every request says nothing of the session.
		{"a garbage token and an account page", []role{{name: "anon"}, {name: "u1", headers: []string{"A: 1"}}, {name: "x", headers: []string{"A: 2"}}},
			rows{"/books/b1": {no(401), ok("b1"), no(401)}, "/account": {ok("csrf1"), ok("csrf2"), ok("csrf3")}}, []string{"x"}},
	} {
		var rs []roleRow
		for u, as := range c.rows {
			row := roleRow{URL: "http://h" + u, Answers: map[string]answer{}}
			for i, r := range c.roles {
				row.Answers[r.name] = as[i]
			}
			rs = append(rs, row)
		}
		if got := deadRoles(c.roles, rs); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}

// jwt is an unsigned JSON Web Token with these claims.
func jwt(claims string) string {
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"none","typ":"JWT"}`)) + "." + enc([]byte(claims)) + ".c2ln"
}

func sortIdentity(id identity) {
	for _, vs := range id.own {
		sort.Strings(vs)
	}
}

func TestRoleIdentity(t *testing.T) {
	id := newIdentity()
	h := http.Header{}
	h.Set("Authorization", "Bearer "+jwt(`{"data":{"id":37,"email":"a@x.test","username":"","password":"5f4d","role":"customer","lastLoginIp":"0.0.0.0"},"bid":18,"iat":1}`))
	h.Set("Cookie", "lang=en; token="+jwt(`{"sub":"alice","exp":2}`))
	id.learnHeaders(h)
	want := identity{who: map[string]bool{"37": true, "a@x.test": true, "alice": true},
		own: map[string][]string{"userid": {"37", "alice"}, "email": {"a@x.test"}, "bid": {"18"}}}
	sortIdentity(id)
	sortIdentity(want)
	if !reflect.DeepEqual(id, want) {
		t.Errorf("from the tokens %+v\nwant %+v", id, want)
	}

	// What a Chrome login left: its answer and the browser's storage.
	id = newIdentity()
	id.learnSession(browser.Session{
		Answers: [][]byte{[]byte(`{"authentication":{"token":"opaque","bid":19,"umail":"b@x.test"}}`)},
		Storage: []string{"sessionStorage.bid", "19", "localStorage.user", `{"id":5,"username":"bob"}`, "localStorage.cart", `{"id":3}`,
			"localStorage.language", "en", "localStorage.requestId", "r1"},
	})
	want = identity{who: map[string]bool{"5": true, "bob": true, "b@x.test": true},
		own: map[string][]string{"bid": {"19"}, "userid": {"5"}, "username": {"bob"}, "cartid": {"3"}, "email": {"b@x.test"}}}
	sortIdentity(id)
	sortIdentity(want)
	if !reflect.DeepEqual(id, want) {
		t.Errorf("from the login %+v\nwant %+v", id, want)
	}

	// A "/me" answer the anonymous role does not get; a list of users is
	// not who the role is.
	roles := []role{{name: "anon"}, {name: "u", headers: []string{"X: 1"}, session: http.Header{"X": {"1"}}}}
	seen := map[string]runSeen{"anon": newRunSeen(), "u": newRunSeen()}
	seen["u"].add("http://h/rest/user/whoami", map[string][]string{"id": {"9"}, "email": {"u@x.test"}})
	seen["u"].add("http://h/api/me/friends", map[string][]string{"id": {"1", "2"}, "email": {"a@x.test", "b@x.test"}})
	answers := map[string]map[string]answer{
		"anon": {"http://h/rest/user/whoami": {Status: 200, Hash: "nobody"}},
		"u":    {"http://h/rest/user/whoami": {Status: 200, Hash: "u"}, "http://h/api/me/friends": {Status: 200, Hash: "all"}},
	}
	who := identities(roles, answers, seen, nil)
	if _, ok := who["anon"]; ok || !who["u"].who["9"] || !who["u"].who["u@x.test"] || who["u"].who["a@x.test"] {
		t.Errorf("identities %+v", who)
	}
}

func TestRoleOwnersFromLists(t *testing.T) {
	roles := []role{{name: "anon"}, {name: "alice", headers: []string{"A: 1"}}, {name: "bob", headers: []string{"B: 1"}}}
	seen := map[string]runSeen{}
	answers := map[string]map[string]answer{}
	// Every role reads the same list of books; alice's and bob's sort last.
	books := []byte(`{"Books":[{"book_title":"a1","user":"n1"},{"book_title":"a2","user":"n2"},{"book_title":"a3","user":"n3"},
		{"book_title":"a4","user":"n4"},{"book_title":"a5","user":"n5"},{"book_title":"a6","user":"n6"},{"book_title":"a7","user":"n7"},
		{"book_title":"z-alice","user":"alice"},{"book_title":"z-bob","user":"bob"}]}`)
	for _, r := range roles {
		a, f := readAnswer(200, books, "application/json")
		answers[r.name] = map[string]answer{"http://h/books/v1": a}
		s := newRunSeen()
		s.add("http://h/books/v1", f.ids)
		s.objects["http://h/books/v1"] = f.objects
		seen[r.name] = s
	}
	who := map[string]identity{"alice": newIdentity(), "bob": newIdentity()}
	who["alice"].who["alice"] = true
	who["bob"].who["bob"] = true
	who["bob"].keep("bid", "19") // a basket id bob's session holds
	templates := map[string]bool{"http://h/books/v1/{book_title}": true, "http://h/rest/basket/{id}": true}
	got := instances(roles, templates, seen, answers, nil, who)
	for u, owner := range map[string]string{"http://h/books/v1/z-alice": "alice", "http://h/books/v1/z-bob": "bob", "http://h/rest/basket/19": "bob"} {
		if in, ok := got[u]; !ok || in.owner != owner || in.rank != 1 {
			t.Errorf("%s: %+v, want %s's own", u, in, owner)
		}
	}
	if without := instances(roles, templates, seen, answers, nil, nil); without["http://h/books/v1/z-alice"].template != "" {
		t.Error("without identities, a value every role saw sorts after the ones tried")
	}
}

func TestRoleListFlags(t *testing.T) {
	js := func(body string) answer { return answerOf(200, []byte(body), "application/json") }
	// Juice Shop's reviews: the visitor's items say liked:true.
	anon := js(`{"status":"success","data":[{"message":"good","author":"a@x.test","_id":"r1","liked":true}]}`)
	user := js(`{"status":"success","data":[{"message":"good","author":"a@x.test","_id":"r1"}]}`)
	if fieldsDiffer(anon, user) {
		t.Error("a flag only one role's list items carry is not a field difference")
	}
	if !fieldsDiffer(js(`{"data":[{"name":"a","password":"x"}]}`), js(`{"data":[{"name":"a"}]}`)) {
		t.Error("a password one role's list items carry is")
	}
	if !fieldsDiffer(js(`{"user":{"isAdmin":true}}`), js(`{"user":{"name":"a"}}`)) {
		t.Error("a flag outside a list is a field")
	}
}

// TestReadBodiesWithoutBody: an answer the run kept without its body (a
// path the paths collector found) is asked again, and compared by its body.
func TestReadBodiesWithoutBody(t *testing.T) {
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"success":true,"users":[{"login":"a","password":"$2a$10$abcdefgh"},{"login":"b","password":"$2a$10$ijklmnop"}]}`)
	}))
	defer site.Close()
	fetch.Reset()
	defer fetch.Reset()
	u := site.URL + "/app/admin/usersapi"
	got := map[string]answer{u: storedAnswer(200, 0, "", nil, "")}
	s := newRunSeen()
	readBodies(got, map[string]string{u: u}, s, hostSet([]string{normalize.HostFromURL(u)}))
	if a := got[u]; a.Hash == "" || a.Length == 0 || !reflect.DeepEqual(a.Sensitive, []string{"password"}) || len(s.objects[u]) != 2 {
		t.Errorf("answer %+v, %d owned items", a, len(s.objects[u]))
	}
}

// rolesJSON runs roles -json and returns its rows by path, as verdict
// labels, and its summary.
func rolesJSON(t *testing.T, site string, args ...string) (map[string]string, map[string]roleRow, map[string]any, error) {
	t.Helper()
	out, errOut, err := captureBoth(t, func() error {
		return cmdRoles(append([]string{"-json", "-dir", t.TempDir()}, args...))
	})
	var sum map[string]any
	if lines := strings.Split(strings.TrimSpace(errOut), "\n"); len(lines) != 1 || json.Unmarshal([]byte(lines[0]), &sum) != nil {
		t.Fatalf("stderr under -json is one JSON summary, got %q", errOut)
	}
	labels, rows := map[string]string{}, map[string]roleRow{}
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		if l == "" {
			continue
		}
		var row roleRow
		if err := json.Unmarshal([]byte(l), &row); err != nil {
			t.Fatalf("%v: %s", err, l)
		}
		p := strings.TrimPrefix(row.URL, site)
		labels[p] = row.Verdict
		if row.Owner != "" || len(row.Readers) > 0 {
			labels[p] = fmt.Sprintf("%s %v of %s", row.Verdict, row.Readers, row.Owner)
		}
		rows[p] = row
	}
	return labels, rows, sum, err
}

// TestRolesOwnObjectsWithoutIDs: without -id, each user's own book is
// known from who the user is (a token's claims, a /me answer) and the
// owner field of the list of books, though it sorts after every other
// book; and a token the API refuses is reported.
func TestRolesOwnObjectsWithoutIDs(t *testing.T) {
	alice, bob := jwt(`{"sub":"alice"}`), "opaque-bob" // bob is known from /api/me alone
	users := map[string]string{alice: "alice", bob: "bob"}
	spec := `{"openapi":"3.0.0","info":{"title":"books","version":"1"},"paths":{"/api/me":{"get":{}},"/api/books":{"get":{}},
		"/api/books/{book_title}":{"get":{"parameters":[{"name":"book_title","in":"path","required":true}]}}}}`
	var list []string
	for i := 1; i <= 8; i++ {
		list = append(list, fmt.Sprintf(`{"book_title":"a%d","user":"u%d"}`, i, i))
	}
	list = append(list, `{"book_title":"z-alice","user":"alice"}`, `{"book_title":"z-bob","user":"bob"}`)
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		user := users[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]
		p := r.URL.Path
		switch {
		case p == "/":
			fmt.Fprint(w, `{"name":"books"}`)
		case p == "/openapi.json":
			fmt.Fprint(w, spec)
		case p == "/api/books":
			fmt.Fprintf(w, `{"Books":[%s]}`, strings.Join(list, ","))
		case user == "" && strings.HasPrefix(p, "/api/"):
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"status":"fail","message":"Invalid token."}`)
		case p == "/api/me":
			fmt.Fprintf(w, `{"data":{"username":%q,"email":"%s@x.test"},"status":"success"}`, user, user)
		case strings.HasPrefix(p, "/api/books/"):
			title := strings.TrimPrefix(p, "/api/books/")
			owner := strings.TrimPrefix(title, "z-") // any signed-in user reads any book
			fmt.Fprintf(w, `{"book_title":%q,"owner":%q,"secret":"secret of %s"}`, title, owner, owner)
		default:
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"error":"not found"}`)
		}
	}))
	defer site.Close()

	got, _, _, err := rolesJSON(t, site.URL, "-role", "anon", "-role", "alice=Authorization: Bearer "+alice, "-role", "bob=Authorization: Bearer "+bob,
		"--", "-url", site.URL+"/")
	if err != nil {
		t.Fatal(err)
	}
	for p, want := range map[string]string{
		"/api/books/z-alice": verdictCross + " [bob] of alice",
		"/api/books/z-bob":   verdictCross + " [alice] of bob",
		"/api/me":            verdictSignedIn,
	} {
		if got[p] != want {
			t.Errorf("%s: %q, want %q", p, got[p], want)
		}
	}

	// A token the API refuses everywhere a session matters.
	_, _, sum, err := rolesJSON(t, site.URL, "-role", "anon", "-role", "alice=Authorization: Bearer "+alice, "-role", "x=Authorization: Bearer garbage",
		"--", "-url", site.URL+"/")
	var exit exitErr
	note := `role x was refused wherever a session matters (the site said "Invalid token."): its session looks expired or wrong; its rows show what a visitor gets`
	if !errors.As(err, &exit) || exit.code != exitPartial || sum["exit"] != float64(exitPartial) || !slices.Contains(toStrings(sum["notes"]), note) {
		t.Errorf("a dead session: %v, summary %v", err, sum)
	}
	if slices.ContainsFunc(toStrings(sum["notes"]), func(n string) bool { return strings.Contains(n, "role alice") }) {
		t.Error("alice's session works")
	}
}

func toStrings(x any) []string {
	var out []string
	if xs, ok := x.([]any); ok {
		for _, v := range xs {
			if s, ok := v.(string); ok {
				out = append(out, s)
			}
		}
	}
	return out
}

// TestRolesOnACookieApp: a cookie-session app sends the visitor to its
// sign-in page, and an API only a -paths file names answers with every
// user's password hash: compared by its body, not its status alone.
func TestRolesOnACookieApp(t *testing.T) {
	sessions := map[string]string{"s-alice": "alice", "s-bob": "bob"}
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := ""
		if c, err := r.Cookie("sid"); err == nil {
			user = sessions[c.Value]
		}
		p := r.URL.Path
		switch {
		case p == "/":
			fmt.Fprint(w, `<html><title>shop</title><a href="/login">Sign in</a> <a href="/app/home">Home</a></html>`)
		case p == "/login" && user != "":
			http.Redirect(w, r, "/app/home", http.StatusFound)
		case p == "/login":
			fmt.Fprint(w, `<html><title>Sign in</title><form method=post><input name=username><input type=password name=password></form></html>`)
		case strings.HasPrefix(p, "/app/") && user == "":
			http.Redirect(w, r, "/login", http.StatusFound)
		case p == "/app/home":
			fmt.Fprintf(w, `<html><title>Home</title>Hello %s</html>`, user)
		case p == "/app/admin/usersapi":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"success":true,"users":[{"id":1,"login":"alice","password":"$2a$10$KoSIrDKQ8t3bLIt8DiEJ7O"},{"id":2,"login":"bob","password":"$2a$10$abcdefghijklmnopqrstuv"}]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer site.Close()
	paths := filepath.Join(t.TempDir(), "paths.txt")
	if err := os.WriteFile(paths, []byte("app/admin/usersapi\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, rows, _, err := rolesJSON(t, site.URL, "-role", "anon", "-role", "alice=Cookie: sid=s-alice", "-role", "bob=Cookie: sid=s-bob",
		"--", "-url", site.URL+"/", "-paths", paths)
	if err != nil {
		t.Fatal(err)
	}
	for p, want := range map[string]string{
		"/app/home":           verdictSignedIn,
		"/app/admin/usersapi": verdictSecrets + " [alice bob] of ",
	} {
		if got[p] != want {
			t.Errorf("%s: %q, want %q (%v)", p, got[p], want, got)
		}
	}
	if a := rows["/app/admin/usersapi"].Answers["alice"]; a.Length == 0 || a.Hash == "" || rows["/app/home"].Answers["anon"].Location != "/login" {
		t.Errorf("answers %+v", rows["/app/admin/usersapi"].Answers)
	}
}
