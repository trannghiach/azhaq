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
	if !reflect.DeepEqual(id.who, want.who) || !reflect.DeepEqual(id.own, want.own) {
		t.Errorf("from the tokens %+v\nwant %+v", id, want)
	}
	if s := id.source("alice", "bid", "18"); s != "bid claim of alice's token" {
		t.Errorf("source %q", s)
	}
	if s := id.source("alice", "userid", "37"); s != "data.id claim of alice's token" {
		t.Errorf("source %q", s)
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
	if !reflect.DeepEqual(id.who, want.who) || !reflect.DeepEqual(id.own, want.own) {
		t.Errorf("from the login %+v\nwant %+v", id, want)
	}
	if s := id.source("bob", "bid", "19"); s != "authentication.bid in bob's login answer" {
		t.Errorf("source %q", s)
	}
	if s := id.source("bob", "cartid", "3"); s != "cart.id in bob's localStorage" {
		t.Errorf("source %q", s)
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
	books := map[string]string{"z-alice": "alice", "z-bob": "bob"}
	for i := 1; i <= 8; i++ {
		books[fmt.Sprintf("a%d", i)] = fmt.Sprintf("u%d", i)
	}
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
		case strings.HasPrefix(p, "/api/books/") && books[strings.TrimPrefix(p, "/api/books/")] != "":
			// Any signed-in user reads any book there is.
			title := strings.TrimPrefix(p, "/api/books/")
			owner := books[title]
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

// TestRoleRouteKinds: a field names identifiers of a route's objects by
// the route's noun, singular or plural, in any case: bid is a basket's,
// not a BasketItem's.
func TestRoleRouteKinds(t *testing.T) {
	kinds := map[string]map[string]bool{
		"http://h/rest/basket/{id}":       {"bid": true, "basketid": true, "basketitemid": false, "userid": false},
		"http://h/api/BasketItems/{id}":   {"bid": false, "basketid": false, "basketitemid": true, "basketitemsid": true, "biid": true},
		"http://h/api/Users/{id}":         {"userid": true, "uid": true, "usersid": true, "bid": false},
		"http://h/api/Addresss/{id}":      {"addressid": true, "aid": true},
		"http://h/api/addresses/{id}":     {"addressid": true},
		"http://h/api/categories/{id}":    {"categoryid": true},
		"http://h/books/v1/{book_title}":  {"booktitle": true, "bid": false},
		"http://h/api/basketitems/{id}":   {"basketitemid": true, "bid": false}, // apart from /rest/basket/{id}
		"http://h/api/orders/{order_id}":  {"orderid": true, "oid": false},
		"http://h/api/users/{id}/profile": {"userid": true},
	}
	shorts := shortNouns(mapKeys(kinds), nil)
	for tmpl, want := range kinds {
		rt, ok := newRoute(tmpl)
		if !ok {
			t.Fatalf("%s: no route", tmpl)
		}
		rt.apart(shorts)
		for f, w := range want {
			if rt.takes(f) != w {
				t.Errorf("%s takes %s: %v", tmpl, f, !w)
			}
		}
	}
}

// juiceSeen is what each role of a Juice Shop like app saw: everyone
// reads every basket item; alice's session holds basket 8, bob's 9, under
// bid, which stands for the basket of /rest/basket/{id}.
func juiceSeen(roles []role) (map[string]runSeen, map[string]map[string]answer, map[string]identity) {
	items := []byte(`{"status":"success","data":[{"id":5,"BasketId":3,"ProductId":1},{"id":8,"BasketId":5,"ProductId":4},
		{"id":9,"BasketId":9,"ProductId":2},{"id":10,"BasketId":8,"ProductId":6}]}`)
	seen := map[string]runSeen{}
	answers := map[string]map[string]answer{}
	for _, r := range roles {
		a, f := readAnswer(200, items, "application/json")
		answers[r.name] = map[string]answer{"http://h/api/BasketItems": a}
		s := newRunSeen()
		s.add("http://h/api/BasketItems", f.ids)
		s.objects["http://h/api/BasketItems"] = f.objects
		seen[r.name] = s
	}
	who := map[string]identity{}
	shorts := shortNouns(map[string]bool{"http://h/rest/basket/{id}": true, "http://h/api/BasketItems/{id}": true}, seen)
	for name, claims := range map[string]string{"alice": `{"data":{"id":27,"email":"alice@x.test"},"bid":8}`,
		"bob": `{"data":{"id":28,"email":"bob@x.test"},"bid":9}`} {
		id := newIdentity()
		id.kinds = shorts
		id.learnHeaders(http.Header{"Authorization": {"Bearer " + jwt(claims)}})
		who[name] = id
	}
	return seen, answers, who
}

// TestRoleOwnersByKind: an identifier is a role's own only for objects of
// its kind: alice's basket 8 is /rest/basket/8, not /api/BasketItems/8,
// which is basket 5's; a basket item of her basket is hers, its product
// is not.
func TestRoleOwnersByKind(t *testing.T) {
	roles := []role{{name: "anon"}, {name: "alice", headers: []string{"A: 1"}}, {name: "bob", headers: []string{"B: 1"}}}
	seen, answers, who := juiceSeen(roles)
	templates := map[string]bool{"http://h/rest/basket/{id}": true, "http://h/api/BasketItems/{id}": true,
		"http://h/api/Products/{id}": true, "http://h/api/Users/{id}": true}
	got := instances(roles, templates, seen, answers, nil, who)
	for u, want := range map[string]string{
		"http://h/rest/basket/8":      "alice: bid claim of alice's token → /rest/basket/{id}",
		"http://h/rest/basket/9":      "bob: bid claim of bob's token → /rest/basket/{id}",
		"http://h/api/BasketItems/10": "alice: item of /api/BasketItems: BasketId 8 is alice's basket (bid claim of alice's token)",
		"http://h/api/BasketItems/9":  "bob: item of /api/BasketItems: BasketId 9 is bob's basket (bid claim of bob's token)",
		"http://h/api/BasketItems/8":  ": ",
		"http://h/api/BasketItems/5":  ": ",
		"http://h/api/Products/4":     ": ",
		"http://h/api/Products/6":     ": ",
		"http://h/api/Users/27":       "alice: data.id claim of alice's token → /api/Users/{id}",
		"http://h/api/Users/28":       "bob: data.id claim of bob's token → /api/Users/{id}",
		"http://h/rest/basket/3":      ": ",
		"http://h/rest/basket/5":      ": ",
	} {
		in, ok := got[u]
		if !ok {
			t.Errorf("%s not tried", u)
			continue
		}
		if s := in.owner + ": " + in.by; s != want {
			t.Errorf("%s: %q, want %q", u, s, want)
		}
	}
}

// TestRoleSettleOwners: what an object's answer says of whose it is
// overrules the identifier that filled its route.
func TestRoleSettleOwners(t *testing.T) {
	roles := []role{{name: "anon"}, {name: "alice", headers: []string{"A: 1"}}, {name: "bob", headers: []string{"B: 1"}}}
	_, _, who := juiceSeen(roles)
	js := func(body string) answer { return answerOf(200, []byte(body), "application/json") }
	item := func(id, basket int) answer {
		return js(fmt.Sprintf(`{"status":"success","data":{"id":%d,"BasketId":%d,"ProductId":4,"quantity":2}}`, id, basket))
	}
	answers := map[string]map[string]answer{"anon": {}, "alice": {}, "bob": {}}
	set := func(u string, a answer) {
		answers["anon"][u] = answer{Status: 401}
		answers["alice"][u], answers["bob"][u] = a, a
	}
	set("http://h/api/BasketItems/8", item(8, 5))   // basket 5: no role's
	set("http://h/api/BasketItems/11", item(11, 9)) // bob's basket
	set("http://h/api/BasketItems/12", item(12, 8)) // alice's basket, tried as no one's
	set("http://h/rest/basket/8", js(`{"status":"success","data":{"id":8,"UserId":27,"Products":[]}}`))
	set("http://h/api/Users/28", js(`{"status":"success","data":{"id":28,"email":"bob@x.test","role":"customer"}}`))
	set("http://h/api/Users/1", js(`{"status":"success","data":{"id":1,"email":"admin@x.test"}}`))
	set("http://h/x/7", js(`{"id":7,"owner":"carol"}`)) // a name: it cannot tell carol is not alice
	made := map[string]instance{
		"http://h/api/BasketItems/8":  {owner: "alice", by: "bid claim of alice's token → /api/BasketItems/{id}"},
		"http://h/api/BasketItems/11": {owner: "alice", by: "bid claim of alice's token → /api/BasketItems/{id}"},
		"http://h/api/BasketItems/12": {},
		"http://h/rest/basket/8":      {owner: "alice", by: "bid claim of alice's token → /rest/basket/{id}"},
		"http://h/api/Users/28":       {owner: "bob", by: "data.id claim of bob's token → /api/Users/{id}"},
		"http://h/api/Users/1":        {owner: "alice", given: true, by: "given with -id alice:id=1"},
		"http://h/x/7":                {owner: "alice", by: "in alice's answers alone"},
	}
	settleOwners(roles, made, answers, who)
	for u, want := range map[string]string{
		"http://h/api/BasketItems/8":  ": ",
		"http://h/api/BasketItems/11": "bob: the answer's BasketId 9 is bob's basket (bid claim of bob's token)",
		"http://h/api/BasketItems/12": "alice: the answer's BasketId 8 is alice's basket (bid claim of alice's token)",
		"http://h/rest/basket/8":      "alice: bid claim of alice's token → /rest/basket/{id}; the answer's UserId 27 names alice (data.id claim of alice's token)",
		"http://h/api/Users/28":       "bob: data.id claim of bob's token → /api/Users/{id}; the answer's email bob@x.test names bob (data.email claim of bob's token)",
		"http://h/api/Users/1":        "alice: given with -id alice:id=1",
		"http://h/x/7":                "alice: in alice's answers alone",
	} {
		if s := made[u].owner + ": " + made[u].by; s != want {
			t.Errorf("%s: %q, want %q", u, s, want)
		}
	}
	if s := shortBy(made["http://h/rest/basket/8"].by); s != "bid claim of alice's token; the answer's UserId 27 names alice" {
		t.Errorf("as the text table says it: %q", s)
	}
}

// TestRolesBasketKinds runs roles on a Juice Shop like app: the bid claim
// of a session names its basket (/rest/basket/8), not the basket item
// numbered 8, which belongs to basket 5; a basket item is its basket's
// owner's.
func TestRolesBasketKinds(t *testing.T) {
	alice := jwt(`{"status":"success","data":{"id":27,"email":"alice@x.test"},"bid":8}`)
	bob := jwt(`{"status":"success","data":{"id":28,"email":"bob@x.test"},"bid":9}`)
	users := map[string]bool{alice: true, bob: true}
	baskets := map[string]int{"3": 1, "5": 2, "8": 27, "9": 28} // basket → UserId
	items := map[string]string{"5": `{"id":5,"BasketId":3,"ProductId":1}`, "8": `{"id":8,"BasketId":5,"ProductId":4}`,
		"9": `{"id":9,"BasketId":9,"ProductId":2}`, "10": `{"id":10,"BasketId":8,"ProductId":6}`}
	spec := `{"openapi":"3.0.0","info":{"title":"shop","version":"1"},"paths":{"/api/BasketItems":{"get":{}},
		"/api/BasketItems/{id}":{"get":{"parameters":[{"name":"id","in":"path","required":true}]}},
		"/rest/basket/{id}":{"get":{"parameters":[{"name":"id","in":"path","required":true}]}}}}`
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		p := r.URL.Path
		switch {
		case p == "/":
			fmt.Fprint(w, `{"name":"shop"}`)
		case p == "/openapi.json":
			fmt.Fprint(w, spec)
		case !users[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]:
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"No Authorization header was found"}`)
		case p == "/api/BasketItems":
			var all []string
			for _, k := range []string{"5", "8", "9", "10"} {
				all = append(all, items[k])
			}
			fmt.Fprintf(w, `{"status":"success","data":[%s]}`, strings.Join(all, ","))
		case strings.HasPrefix(p, "/api/BasketItems/") && items[strings.TrimPrefix(p, "/api/BasketItems/")] != "":
			fmt.Fprintf(w, `{"status":"success","data":%s}`, items[strings.TrimPrefix(p, "/api/BasketItems/")])
		case strings.HasPrefix(p, "/rest/basket/") && baskets[strings.TrimPrefix(p, "/rest/basket/")] != 0:
			id := strings.TrimPrefix(p, "/rest/basket/")
			fmt.Fprintf(w, `{"status":"success","data":{"id":%s,"UserId":%d,"Products":[]}}`, id, baskets[id])
		default:
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"error":"not found"}`)
		}
	}))
	defer site.Close()
	got, rows, _, err := rolesJSON(t, site.URL, "-role", "anon", "-role", "alice=Authorization: Bearer "+alice, "-role", "bob=Authorization: Bearer "+bob,
		"--", "-url", site.URL+"/")
	if err != nil {
		t.Fatal(err)
	}
	for p, want := range map[string]string{
		"/rest/basket/8":      verdictCross + " [bob] of alice",
		"/rest/basket/9":      verdictCross + " [alice] of bob",
		"/api/BasketItems/10": verdictCross + " [bob] of alice",
		"/api/BasketItems/9":  verdictCross + " [alice] of bob",
		"/api/BasketItems/8":  verdictObject,
	} {
		if got[p] != want {
			t.Errorf("%s: %q, want %q", p, got[p], want)
		}
	}
	for p, want := range map[string]string{
		"/rest/basket/8":      "bid claim of alice's token → /rest/basket/{id}; the answer's UserId 27 names alice (data.id claim of alice's token)",
		"/api/BasketItems/10": "item of /api/BasketItems: BasketId 8 is alice's basket (bid claim of alice's token); the answer's BasketId 8 is alice's basket (bid claim of alice's token)",
	} {
		if rows[p].OwnerBy != want {
			t.Errorf("%s: owner_by %q, want %q", p, rows[p].OwnerBy, want)
		}
	}
}

// TestRoleShortNouns: a short name stands for a route's noun only when no
// other noun of the routes or of the answers' reference fields has its
// initials; a compound read as one word is no rival.
func TestRoleShortNouns(t *testing.T) {
	routes := func(ps ...string) map[string]bool {
		out := map[string]bool{}
		for _, p := range ps {
			out["http://h"+p+"/{id}"] = true
		}
		return out
	}
	brand := map[string]runSeen{"alice": newRunSeen()}
	brand["alice"].add("http://h/api/products", map[string][]string{"BrandId": {"8"}, "bid": {"8"}, "uid": {"1"}})
	for _, c := range []struct {
		name   string
		routes map[string]bool
		seen   map[string]runSeen
		want   map[string]string
	}{
		{"a basket", routes("/rest/basket", "/api/BasketItems"), nil, map[string]string{"bid": "basket", "biid": "basketitem"}},
		{"books beside a basket", routes("/rest/basket", "/api/books"), nil, map[string]string{"bid": ""}},
		{"books alone", routes("/api/books"), nil, map[string]string{"bid": "book"}},
		{"basketitems read as one word", routes("/rest/basket", "/api/basketitems"), nil, map[string]string{"bid": "basket"}},
		{"a BrandId beside a basket", routes("/rest/basket"), brand, map[string]string{"bid": ""}},
		{"a BrandId and no route", nil, brand, map[string]string{}},
	} {
		if got := shortNouns(c.routes, c.seen); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}

// bidShop is an app whose sessions hold a bid claim (alice 8, bob 9) and
// whose spec names paths: books every signed-in user reads alike, and
// baskets, each its owner's alone, or, when open, anyone's to read with
// the UserId they belong to.
func bidShop(paths []string, open bool) (*httptest.Server, string, string) {
	alice := jwt(`{"status":"success","data":{"id":27,"email":"alice@x.test"},"bid":8}`)
	bob := jwt(`{"status":"success","data":{"id":28,"email":"bob@x.test"},"bid":9}`)
	users := map[string]string{alice: "alice", bob: "bob"}
	var ps []string
	for _, p := range paths {
		ps = append(ps, fmt.Sprintf(`%q:{"get":{"parameters":[{"name":"id","in":"path","required":true}]}}`, p))
	}
	spec := `{"openapi":"3.0.0","info":{"title":"shop","version":"1"},"paths":{` + strings.Join(ps, ",") + `}}`
	baskets := map[string]string{"/rest/basket/8": "alice", "/rest/basket/9": "bob"}
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		p := r.URL.Path
		user := users[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]
		switch {
		case p == "/":
			fmt.Fprint(w, `{"name":"shop"}`)
		case p == "/openapi.json":
			fmt.Fprint(w, spec)
		case user == "":
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"unauthorized"}`)
		case strings.HasPrefix(p, "/api/books/"):
			id := strings.TrimPrefix(p, "/api/books/")
			fmt.Fprintf(w, `{"id":%s,"title":"Book %s","price":5}`, id, id)
		case baskets[p] != "" && open:
			fmt.Fprintf(w, `{"status":"success","data":{"id":%s,"UserId":%d,"Products":[]}}`, strings.TrimPrefix(p, "/rest/basket/"),
				map[string]int{"alice": 27, "bob": 28}[baskets[p]])
		case baskets[p] == user:
			fmt.Fprintf(w, `{"status":"success","data":{"id":%s,"Products":[]}}`, strings.TrimPrefix(p, "/rest/basket/"))
		case baskets[p] != "":
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, `{"error":"forbidden"}`)
		default:
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"error":"not found"}`)
		}
	}))
	return site, alice, bob
}

// TestRolesShortNameRivals: a session's bid is not every b-noun's: beside
// a basket route, books every signed-in user reads alike are no one's;
// with no basket, a book bid fills is the session's only when its answer
// says so; and a basket bid no longer claims is still tried, and its
// answer names its owner.
func TestRolesShortNameRivals(t *testing.T) {
	for _, c := range []struct {
		name  string
		paths []string
		open  bool
		want  map[string]string
		by    map[string]string
	}{
		{"books beside a basket", []string{"/rest/basket/{id}", "/api/books/{id}"}, false,
			map[string]string{"/api/books/8": verdictObject, "/api/books/9": verdictObject,
				"/rest/basket/8": verdictOnly + " [alice] of ", "/rest/basket/9": verdictOnly + " [bob] of "}, nil},
		{"books alone", []string{"/api/books/{id}"}, false,
			map[string]string{"/api/books/8": verdictObject, "/api/books/9": verdictObject}, nil},
		{"books beside an open basket", []string{"/rest/basket/{id}", "/api/books/{id}"}, true,
			map[string]string{"/api/books/8": verdictObject, "/rest/basket/8": verdictCross + " [bob] of alice", "/rest/basket/9": verdictCross + " [alice] of bob"},
			map[string]string{"/rest/basket/8": "the answer's UserId 27 names alice (data.id claim of alice's token)"}},
	} {
		site, alice, bob := bidShop(c.paths, c.open)
		got, rows, _, err := rolesJSON(t, site.URL, "-role", "anon", "-role", "alice=Authorization: Bearer "+alice, "-role", "bob=Authorization: Bearer "+bob,
			"--", "-url", site.URL+"/")
		site.Close()
		if err != nil {
			t.Fatal(err)
		}
		for p, want := range c.want {
			if got[p] != want {
				t.Errorf("%s: %s: %q (owner_by %q), want %q", c.name, p, got[p], rows[p].OwnerBy, want)
			}
		}
		for p, want := range c.by {
			if rows[p].OwnerBy != want {
				t.Errorf("%s: %s: owner_by %q, want %q", c.name, p, rows[p].OwnerBy, want)
			}
		}
	}
}

// whoFrom is each role's identity from the claims of its token, with what
// the routes say its short names stand for.
func whoFrom(shorts map[string]string, claims map[string]string) map[string]identity {
	who := map[string]identity{}
	for name, c := range claims {
		id := newIdentity()
		id.kinds = shorts
		id.learnHeaders(http.Header{"Authorization": {"Bearer " + jwt(c)}})
		who[name] = id
	}
	return who
}

// TestRoleRefFieldsNameTheirKind: a reference field names its kind in
// full: BookId, BrandId and BranchId are not the basket the session's bid
// is, nor a book it is not; BasketId is, when bid stands for the basket.
func TestRoleRefFieldsNameTheirKind(t *testing.T) {
	roles := []role{{name: "anon"}, {name: "alice", headers: []string{"A: 1"}}, {name: "bob", headers: []string{"B: 1"}}}
	claims := map[string]string{"alice": `{"data":{"id":27},"bid":8}`, "bob": `{"data":{"id":28},"bid":9}`}
	basket := whoFrom(map[string]string{"bid": "basket"}, claims)
	for _, c := range []struct {
		body  string
		who   map[string]identity
		owner string
		known bool
		by    string
	}{
		{`{"id":3,"BookId":8,"rating":5}`, basket, "", false, ""},
		{`{"id":4,"BrandId":8,"name":"x"}`, basket, "", false, ""},
		{`{"id":5,"BranchId":2,"amount":1}`, basket, "", false, ""},
		{`{"id":3,"BookId":8,"rating":5}`, whoFrom(nil, claims), "", false, ""},
		{`{"id":6,"BasketId":8}`, basket, "alice", true, "BasketId 8 is alice's basket (bid claim of alice's token)"},
		{`{"id":6,"BasketId":8}`, whoFrom(map[string]string{"bid": ""}, claims), "", false, ""},
		{`{"id":7,"BasketId":5}`, basket, "", true, "BasketId 5 is not alice's basket (8)"},
	} {
		a := answerOf(200, []byte(c.body), "application/json")
		if owner, by, known, _ := whose(a.self, roles, c.who, "alice", ""); owner != c.owner || known != c.known || by != c.by {
			t.Errorf("%s: %q %v %q, want %q %v %q", c.body, owner, known, by, c.owner, c.known, c.by)
		}
	}
}

// TestRoleSettleKeepsProvedOwners: an object's answer confirms or names
// an owner, but undoes one the session or the role's own list proved
// only by naming another role with an identifier of the same name: not by
// an account number, another organisation of the same user, or a number
// that equals another user's id.
func TestRoleSettleKeepsProvedOwners(t *testing.T) {
	roles := []role{{name: "anon"}, {name: "alice", headers: []string{"A: 1"}}, {name: "bob", headers: []string{"B: 1"}}}

	// Each user's list holds only their own transaction; anyone signed in
	// reads either.
	who := whoFrom(nil, map[string]string{"alice": `{"sub":"27"}`, "bob": `{"sub":"28"}`})
	lists := map[string]string{"alice": `{"data":[{"id":55,"accountId":1003,"amount":5}]}`, "bob": `{"data":[{"id":56,"accountId":1004,"amount":7}]}`}
	seen, answers := map[string]runSeen{}, map[string]map[string]answer{}
	for _, r := range roles {
		s := newRunSeen()
		answers[r.name] = map[string]answer{}
		if l, ok := lists[r.name]; ok {
			a, f := readAnswer(200, []byte(l), "application/json")
			answers[r.name]["http://h/api/transactions"] = a
			s.add("http://h/api/transactions", f.ids)
			s.objects["http://h/api/transactions"] = f.objects
		}
		seen[r.name] = s
	}
	made := instances(roles, map[string]bool{"http://h/api/transactions/{id}": true}, seen, answers, nil, who)
	for _, r := range roles[1:] {
		answers[r.name]["http://h/api/transactions/55"] = answerOf(200, []byte(`{"id":55,"accountId":1003,"amount":5}`), "application/json")
		answers[r.name]["http://h/api/transactions/56"] = answerOf(200, []byte(`{"id":56,"accountId":1004,"amount":7}`), "application/json")
	}
	settleOwners(roles, made, answers, who)
	for u, want := range map[string]string{
		"http://h/api/transactions/55": "alice: in alice's /api/transactions and not the other roles'",
		"http://h/api/transactions/56": "bob: in bob's /api/transactions and not the other roles'",
	} {
		if s := made[u].owner + ": " + made[u].by; s != want {
			t.Errorf("%s: %q, want %q", u, s, want)
		}
	}

	// One answer each, read alike by alice and bob, over what filled the
	// route.
	who = whoFrom(map[string]string{"bid": "basket"}, map[string]string{"alice": `{"sub":"3","org_id":7,"customer_id":1003}`,
		"bob": `{"sub":"4","username":"bob","email":"bob@x.test","org_id":11,"bid":9}`})
	answers = map[string]map[string]answer{"anon": {}, "alice": {}, "bob": {}}
	list := "in alice's /api/x and not the other roles'"
	cases := map[string]struct {
		in   instance
		body string
		want string
	}{
		"/api/projects/15":     {instance{owner: "alice", by: list, sure: proved}, `{"id":15,"orgId":9,"name":"side project"}`, "alice: " + list},
		"/api/transactions/55": {instance{owner: "alice", by: list}, `{"id":55,"accountId":4,"amount":5}`, "alice: " + list},
		"/api/transactions/57": {instance{owner: "alice", by: list}, `{"id":57,"customerId":1003}`,
			"alice: " + list + "; the answer's customerId 1003 is alice's customer (customer_id claim of alice's token)"},
		"/api/transactions/58": {instance{owner: "alice", by: list}, `{"id":58,"customerId":1004}`, ": "},
		"/api/notes/1":         {instance{owner: "alice", by: list, sure: proved}, `{"id":1,"owner":"bob"}`, "alice: " + list},
		"/api/notes/2":         {instance{owner: "alice", by: list, sure: proved}, `{"id":2,"createdBy":4}`, "alice: " + list},
		"/api/notes/3": {instance{owner: "alice", by: list, sure: proved}, `{"id":3,"email":"bob@x.test"}`,
			"bob: the answer's email bob@x.test names bob (email claim of bob's token)"},
		"/api/notes/4":   {instance{owner: "alice", by: list, sure: proved}, `{"id":4,"UserId":4}`, "bob: the answer's UserId 4 names bob (sub claim of bob's token)"},
		"/api/notes/5":   {instance{owner: "alice", by: list}, `{"id":5,"owner":"bob"}`, "bob: the answer's owner bob names bob (username claim of bob's token)"},
		"/rest/basket/8": {instance{owner: "alice", by: "bid claim of alice's token → /rest/basket/{id}", sure: shortName}, `{"id":8,"Products":[]}`, ": "},
		"/rest/basket/9": {instance{owner: "bob", by: "bid claim of bob's token → /rest/basket/{id}", sure: shortName}, `{"id":9,"UserId":4}`,
			"bob: bid claim of bob's token → /rest/basket/{id}; the answer's UserId 4 names bob (sub claim of bob's token)"},
		"/rest/basket/10": {instance{owner: "alice", by: "bid claim of alice's token → /rest/basket/{id}", sure: shortName}, `{"id":10,"UserId":4}`,
			"bob: the answer's UserId 4 names bob (sub claim of bob's token)"},
		"/api/BasketItems/12": {instance{owner: "alice", by: list, sure: proved}, `{"id":12,"BasketId":9}`, "alice: " + list},
	}
	made = map[string]instance{}
	for u, c := range cases {
		made[u] = c.in
		for _, r := range []string{"alice", "bob"} {
			answers[r][u] = answerOf(200, []byte(c.body), "application/json")
		}
	}
	settleOwners(roles, made, answers, who)
	for u, c := range cases {
		if s := made[u].owner + ": " + made[u].by; s != c.want {
			t.Errorf("%s: %q, want %q", u, s, c.want)
		}
	}
}

// TestRolesListOwnerOverAccountId runs roles on an app whose list of
// transactions holds each user's own alone, while anyone signed in reads
// any: the accountId of a transaction is not a user id, and bob reading
// alice's is reported.
func TestRolesListOwnerOverAccountId(t *testing.T) {
	alice, bob := jwt(`{"sub":"27","email":"alice@x.test"}`), jwt(`{"sub":"28","email":"bob@x.test"}`)
	users := map[string]string{alice: "alice", bob: "bob"}
	tx := map[string]string{"55": `{"id":55,"accountId":1003,"amount":5}`, "56": `{"id":56,"accountId":1004,"amount":7}`}
	mine := map[string]string{"alice": "55", "bob": "56"}
	spec := `{"openapi":"3.0.0","info":{"title":"bank","version":"1"},"paths":{"/api/transactions":{"get":{}},
		"/api/transactions/{id}":{"get":{"parameters":[{"name":"id","in":"path","required":true}]}}}}`
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		p := r.URL.Path
		user := users[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]
		switch {
		case p == "/":
			fmt.Fprint(w, `{"name":"bank"}`)
		case p == "/openapi.json":
			fmt.Fprint(w, spec)
		case user == "":
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"unauthorized"}`)
		case p == "/api/transactions":
			fmt.Fprintf(w, `{"data":[%s]}`, tx[mine[user]])
		case strings.HasPrefix(p, "/api/transactions/") && tx[strings.TrimPrefix(p, "/api/transactions/")] != "":
			fmt.Fprint(w, tx[strings.TrimPrefix(p, "/api/transactions/")])
		default:
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"error":"not found"}`)
		}
	}))
	defer site.Close()
	got, rows, _, err := rolesJSON(t, site.URL, "-role", "anon", "-role", "alice=Authorization: Bearer "+alice, "-role", "bob=Authorization: Bearer "+bob,
		"--", "-url", site.URL+"/")
	if err != nil {
		t.Fatal(err)
	}
	for p, want := range map[string]string{"/api/transactions/55": verdictCross + " [bob] of alice", "/api/transactions/56": verdictCross + " [alice] of bob"} {
		if got[p] != want {
			t.Errorf("%s: %q, want %q", p, got[p], want)
		}
	}
	if by := rows["/api/transactions/55"].OwnerBy; by != "in alice's /api/transactions and not the other roles'" {
		t.Errorf("owner_by %q", by)
	}
}

// TestRoleOddFields: field names and routes of any spelling are read
// without a panic, and a name that only folds to a reference field names
// no kind.
func TestRoleOddFields(t *testing.T) {
	roles := []role{{name: "anon"}, {name: "alice", headers: []string{"A: 1"}}}
	who := whoFrom(map[string]string{"bid": "basket"}, map[string]string{"alice": `{"data":{"id":27},"bid":8,"x":{"İD":3},"__":{"id":1},"Ünïd":4}`})
	for body, want := range map[string]string{`null`: "", `[]`: "", `1`: "", `"x"`: "", `{}`: "", `{"data":null}`: "", `{"data":[1,2]}`: "",
		`{"status":"ok","data":{"İD":1,"BasketİD":8,"_id":"x","Id":"","id":null}}`:                                      "",
		`{"a":{"b":{"c":{"d":{"e":{"f":{"g":{"h":{"i":{"j":{"k":{"l":{"m":{"n":{"o":{"p":{"q":{"r":1}}}}}}}}}}}}}}}}}}`: "",
		`{"ÄId":5,"__id":6,"-id":7,"id":8,"basket-id":8,"Basket.Id":8}`:                                                 "alice",
	} {
		a, _ := readAnswer(200, []byte(body), "application/json")
		if owner, _, _, _ := whose(a.self, roles, who, "alice", ""); owner != want {
			t.Errorf("%s: owner %q, want %q", body, owner, want)
		}
	}
	for _, tmpl := range []string{"http://h/{id}", "http://h/api/{id}", "http://h/x/İ/{id}", "http://h/-/{id}", "http://h/_/{id}", "http://h/123/{id}", "http://h/a%2Fb/{id}"} {
		if rt, ok := newRoute(tmpl); ok {
			rt.apart(shortNouns(map[string]bool{tmpl: true}, nil))
		}
	}
}

func TestNoteCapMarksReplayMaxStopped(t *testing.T) {
	rep := newReport("roles")
	// A plain error is a note, not a stop.
	noteCap(rep, "controls", errors.New("a transient failure"))
	if rep.Stopped != "" {
		t.Fatalf("a plain error set Stopped: %q", rep.Stopped)
	}
	// A -replay-max cap stops the run (exit 4).
	capped := fmt.Errorf("%w: 12 URLs were not asked of every role", errReplayMax)
	noteCap(rep, "replay", capped)
	if rep.Stopped == "" {
		t.Fatal("a -replay-max cap did not mark the run stopped")
	}
	rep.settle()
	if rep.Exit != exitLimit || rep.Complete {
		t.Fatalf("exit=%d complete=%v, want exit 4 and not complete", rep.Exit, rep.Complete)
	}
}
