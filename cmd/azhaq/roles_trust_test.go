package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/trannghiach/azhaq/store"
)

// objectApp is a small API whose users each own a cart and a note:
// /api/carts/{id} answers any number with a cart (the made-up ones are a
// guest's), /api/notes/{id} answers the notes there are, to any user.
func objectApp(t *testing.T, users map[string]string) *httptest.Server {
	t.Helper()
	carts := map[string]string{"11": "alice", "12": "bob"}
	notes := map[string]string{"21": "alice", "22": "bob"}
	spec := `{"openapi":"3.0.0","info":{"title":"shop","version":"1"},"paths":{"/api/me":{"get":{}},"/api/carts":{"get":{}},"/api/notes":{"get":{}},
		"/api/carts/{id}":{"get":{"parameters":[{"name":"id","in":"path","required":true}]}},
		"/api/notes/{id}":{"get":{"parameters":[{"name":"id","in":"path","required":true}]}}}}`
	own := func(m map[string]string, user string) string {
		var items []string
		for id, o := range m {
			if o == user {
				items = append(items, `{"id":`+id+`}`)
			}
		}
		return `{"data":[` + strings.Join(items, ",") + `]}`
	}
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		user := users[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]
		p := r.URL.Path
		switch {
		case p == "/":
			fmt.Fprint(w, `{"name":"shop"}`)
		case p == "/openapi.json":
			fmt.Fprint(w, spec)
		case user == "" && strings.HasPrefix(p, "/api/"):
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"sign in"}`)
		case p == "/api/me":
			fmt.Fprintf(w, `{"user":{"name":%q}}`, user)
		case p == "/api/carts":
			fmt.Fprint(w, own(carts, user))
		case p == "/api/notes":
			fmt.Fprint(w, own(notes, user))
		case strings.HasPrefix(p, "/api/carts/"):
			id := strings.TrimPrefix(p, "/api/carts/")
			if _, err := strconv.Atoi(id); err != nil {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			owner := carts[id]
			if owner == "" {
				owner = "guest"
			}
			fmt.Fprintf(w, `{"id":%s,"owner":%q,"items":["socks"]}`, id, owner)
		case strings.HasPrefix(p, "/api/notes/") && notes[strings.TrimPrefix(p, "/api/notes/")] != "":
			id := strings.TrimPrefix(p, "/api/notes/")
			fmt.Fprintf(w, `{"id":%s,"owner":%q,"secret":"s3cr3t-of-%s"}`, id, notes[id], notes[id])
		default:
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"error":"not found"}`)
		}
	}))
	t.Cleanup(site.Close)
	return site
}

// TestRolesNegativeControls: a route that answers a made-up identifier
// like a real object answers any identifier, and is not listed as one
// role reading another's; a route that refuses it keeps its cross reads,
// with the control beside them, and says when they go both ways.
func TestRolesNegativeControls(t *testing.T) {
	alice, bob := jwt(`{"sub":"alice"}`), jwt(`{"sub":"bob"}`)
	site := objectApp(t, map[string]string{alice: "alice", bob: "bob"})
	labels, rows, sum, err := rolesJSON(t, site.URL, "-role", "anon", "-role", "alice=Authorization: Bearer "+alice, "-role", "bob=Authorization: Bearer "+bob,
		"--", "-url", site.URL+"/")
	if err != nil {
		t.Fatal(err)
	}
	for p, want := range map[string]string{
		"/api/carts/11": verdictAnyID + " [bob] of alice",
		"/api/carts/12": verdictAnyID + " [alice] of bob",
		"/api/notes/21": verdictCross + " [bob] of alice",
		"/api/notes/22": verdictCross + " [alice] of bob",
	} {
		if labels[p] != want {
			t.Errorf("%s: %q, want %q", p, labels[p], want)
		}
	}
	cart := rows["/api/carts/11"]
	if c := cart.Control; c == nil || c.Value != "1000014" || !slices.Equal(c.Alike, []string{"bob"}) || c.Answers["bob"].Status != 200 ||
		c.URL != site.URL+"/api/carts/1000014" || cart.Confidence != confGuess {
		t.Errorf("cart control %+v, confidence %q", cart.Control, cart.Confidence)
	}
	if l := cart.label(); l != "answers any identifier: bob read alice's object and a made-up 1000014 alike" {
		t.Errorf("label %q", l)
	}
	note := rows["/api/notes/21"]
	if c := note.Control; c == nil || c.Value != "1000024" || len(c.Alike) != 0 || c.Answers["bob"].Status != 404 {
		t.Errorf("note control %+v", note.Control)
	}
	if !note.BothWays || note.Confidence != confProved ||
		!strings.Contains(note.Evidence, "bob got alice's answer (the same body,") ||
		!strings.Contains(note.Evidence, "a made-up 1000024 got bob 404") || !strings.Contains(note.Evidence, "both ways: alice reads bob's too") {
		t.Errorf("note row: both ways %v, confidence %q, evidence %q", note.BothWays, note.Confidence, note.Evidence)
	}
	if !slices.Contains(toStrings(sum["notes"]), "alice and bob read each other's objects on /api/notes/{id}") {
		t.Errorf("notes %q", toStrings(sum["notes"]))
	}
}

// A reader the route answers alike beside one it refuses is not a reader;
// the controls count against the budget they are given.
func TestAskControls(t *testing.T) {
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("Authorization") == "admin" {
			fmt.Fprint(w, `{"id":1,"name":"socks"}`) // anything, to an admin
			return
		}
		w.WriteHeader(404)
		fmt.Fprint(w, `{"error":"not found"}`)
	}))
	defer site.Close()
	h := func(v string) http.Header { return http.Header{"Authorization": {v}} }
	roles := []role{{name: "alice", session: h("alice")}, {name: "bob", session: h("bob")}, {name: "admin", session: h("admin")}}
	real, _ := readAnswer(200, []byte(`{"id":7,"name":"shoes"}`), "application/json")
	row := func() []roleRow {
		return []roleRow{{URL: site.URL + "/api/items/7", From: site.URL + "/api/items/{id}", value: "7", Owner: "alice", Verdict: verdictCross,
			Readers: []string{"bob", "admin"}, Answers: map[string]answer{"alice": real, "bob": real, "admin": real}}}
	}
	own := map[string]bool{"127.0.0.1": true}
	rows := row()
	n, err := askControls(roles, rows, own, nil, nil, 10)
	if err != nil || n != 2 || rows[0].Verdict != verdictCross || !slices.Equal(rows[0].Readers, []string{"bob"}) || !slices.Equal(rows[0].Control.Alike, []string{"admin"}) {
		t.Errorf("sent %d err %v row %+v control %+v", n, err, rows[0], rows[0].Control)
	}
	rows = row()
	if n, err := askControls(roles, rows, own, nil, nil, 1); err == nil || n != 1 {
		t.Errorf("a budget of 1: sent %d, err %v", n, err)
	}
	// A refusal page answered 200 is no object.
	rows = row()
	_, _ = askControls(roles, rows, own, nil, regexp.MustCompile(`socks`), 10)
	if c := rows[0].Control; len(c.Alike) != 0 || !c.Answers["admin"].Refusal {
		t.Errorf("-refusal: %+v", c)
	}
}

func TestMadeUp(t *testing.T) {
	for v, want := range map[string]string{"11": "1000014", "007": "1000010", "99999999999": "100001000002"} {
		if got := madeUp(v); got != want {
			t.Errorf("madeUp(%q) = %q, want %q", v, got, want)
		}
	}
	for _, v := range []string{"z-alice", "6f1c2a9e-3b4d-4c5e-8f60-123456789abc", "ABC-123", "x@y.test"} {
		got := madeUp(v)
		shape := func(s string) string {
			return regexp.MustCompile(`[a-z]`).ReplaceAllString(regexp.MustCompile(`[A-Z]`).ReplaceAllString(regexp.MustCompile(`[0-9]`).ReplaceAllString(s, "9"), "A"), "a")
		}
		if got == v || len(got) != len(v) || !uuidShape.MatchString(v) && shape(got) != shape(v) || uuidShape.MatchString(v) != uuidShape.MatchString(got) {
			t.Errorf("madeUp(%q) = %q", v, got)
		}
	}
	if got := madeUp("--"); got != "" {
		t.Errorf("nothing to change: %q", got)
	}
	if u, ok := swapValue("http://h/api/books/my%20book/pages", "http://h/api/books/{title}/pages", "my book", "xq zbok"); !ok || u != "http://h/api/books/xq%20zbok/pages" {
		t.Errorf("swapValue: %q %v", u, ok)
	}
}

// refusalApp answers what a visitor may not see with a 200 page that says
// so (or, with nope, one that says only "Nope."), and an order to anyone
// but its owner with the same page.
func refusalApp(t *testing.T, nope bool) *httptest.Server {
	t.Helper()
	page := `<html><head><title>Access denied</title></head><body><h1>Access denied</h1><p>Please sign in.</p></body></html>`
	if nope {
		page = `<html><body><p>Nope.</p></body></html>`
	}
	orders := map[string]string{"31": "alice", "32": "bob"}
	spec := `{"openapi":"3.0.0","info":{"title":"shop","version":"1"},"paths":{"/api/orders":{"get":{}},"/account":{"get":{}},"/settings":{"get":{}},
		"/api/orders/{id}":{"get":{"parameters":[{"name":"id","in":"path","required":true}]}}}}`
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if user != "alice" && user != "bob" {
			user = ""
		}
		p := r.URL.Path
		deny := func() {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, page)
		}
		switch {
		case p == "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><head><title>Shop</title></head><body><a href="/account">account</a> <a href="/settings">settings</a></body></html>`)
		case p == "/openapi.json":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, spec)
		case user == "":
			deny()
		case p == "/account" || p == "/settings":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, `<html><head><title>%s of %s</title></head><body><h1>%s</h1></body></html>`, p[1:], user, user)
		case p == "/api/orders":
			w.Header().Set("Content-Type", "application/json")
			for id, o := range orders {
				if o == user {
					fmt.Fprintf(w, `{"orders":[{"id":%s}]}`, id)
				}
			}
		case strings.HasPrefix(p, "/api/orders/") && orders[strings.TrimPrefix(p, "/api/orders/")] == user:
			id := strings.TrimPrefix(p, "/api/orders/")
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"id":%s,"owner":%q,"total":12}`, id, user)
		default:
			deny()
		}
	}))
	t.Cleanup(site.Close)
	return site
}

// TestRolesRefusalPage: a 200 page that says "Access denied" is a
// refusal, learned from what the anonymous role got where a signed-in
// role reads something else; -refusal says what one looks like when the
// page does not say so in words.
func TestRolesRefusalPage(t *testing.T) {
	site := refusalApp(t, false)
	labels, rows, sum, err := rolesJSON(t, site.URL, "-role", "anon", "-role", "alice=Authorization: Bearer alice", "-role", "bob=Authorization: Bearer bob",
		"--", "-url", site.URL+"/")
	if err != nil {
		t.Fatal(err)
	}
	for p, want := range map[string]string{
		"/account":       verdictSignedIn,
		"/settings":      verdictSignedIn,
		"/api/orders":    verdictSignedIn,
		"/api/orders/31": verdictOnly + " [alice] of alice",
		"/api/orders/32": verdictOnly + " [bob] of bob",
	} {
		if labels[p] != want {
			t.Errorf("%s: %q, want %q", p, labels[p], want)
		}
	}
	if a := rows["/api/orders/31"].Answers["bob"]; a.Status != 200 || !a.Refusal || answerCell(a) != "200:refused" {
		t.Errorf("bob's answer %+v", a)
	}
	note := fmt.Sprintf(`http://%s refuses with a 200 page saying "Access denied"`, strings.TrimPrefix(site.URL, "http://"))
	if !slices.ContainsFunc(toStrings(sum["notes"]), func(n string) bool { return strings.HasPrefix(n, note) }) {
		t.Errorf("notes %q", toStrings(sum["notes"]))
	}

	// Without words to learn it by, -refusal tells it.
	site = refusalApp(t, true)
	labels, _, _, err = rolesJSON(t, site.URL, "-role", "anon", "-role", "alice=Authorization: Bearer alice", "-role", "bob=Authorization: Bearer bob",
		"--", "-url", site.URL+"/")
	if err != nil {
		t.Fatal(err)
	}
	if labels["/api/orders/31"] == verdictOnly+" [alice] of alice" || labels["/account"] == verdictSignedIn {
		t.Errorf("a page that does not say it refuses: %q", labels)
	}
	labels, _, sum, err = rolesJSON(t, site.URL, "-refusal", `<p>Nope\.</p>`, "-role", "anon", "-role", "alice=Authorization: Bearer alice", "-role", "bob=Authorization: Bearer bob",
		"--", "-url", site.URL+"/")
	if err != nil {
		t.Fatal(err)
	}
	if labels["/api/orders/31"] != verdictOnly+" [alice] of alice" || labels["/account"] != verdictSignedIn {
		t.Errorf("-refusal: %q", labels)
	}
	if !slices.ContainsFunc(toStrings(sum["notes"]), func(n string) bool { return strings.HasPrefix(n, `-refusal <p>Nope\.</p> matched `) }) {
		t.Errorf("notes %q", toStrings(sum["notes"]))
	}
	if err := cmdRoles([]string{"-refusal", "(", "-role", "anon", "-role", "a=A: 1", "--", "-url", site.URL + "/"}); exitCode(err) != exitUsage {
		t.Errorf("a bad -refusal: %v", err)
	}
}

// expiringApp issues tokens that die after life object requests each:
// alice-1, alice-2, … from a -role-cmd that counts, and a fixed one.
func expiringApp(t *testing.T, life int) *httptest.Server {
	t.Helper()
	var mu sync.Mutex
	used := map[string]int{}
	spec := `{"openapi":"3.0.0","info":{"title":"items","version":"1"},"paths":{"/api/me":{"get":{}},"/api/items":{"get":{}},
		"/api/items/{id}":{"get":{"parameters":[{"name":"id","in":"path","required":true}]}}}}`
	ownerOf := func(id int) string {
		switch {
		case id >= 1 && id <= 5:
			return "alice"
		case id >= 6 && id <= 10:
			return "bob"
		}
		return ""
	}
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		user, _, _ := strings.Cut(tok, "-")
		p := r.URL.Path
		mu.Lock()
		alive := (user == "alice" || user == "bob") && used[tok] < life
		id, err := strconv.Atoi(strings.TrimPrefix(p, "/api/items/"))
		if alive && strings.HasPrefix(p, "/api/items/") {
			used[tok]++
		}
		mu.Unlock()
		switch {
		case p == "/":
			fmt.Fprint(w, `{"name":"items"}`)
		case p == "/openapi.json":
			fmt.Fprint(w, spec)
		case !alive && strings.HasPrefix(p, "/api/"):
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"token expired"}`)
		case p == "/api/me":
			fmt.Fprintf(w, `{"user":{"name":%q}}`, user)
		case p == "/api/items":
			var items []string
			for i := 1; i <= 10; i++ {
				if ownerOf(i) == user {
					items = append(items, fmt.Sprintf(`{"id":%d}`, i))
				}
			}
			fmt.Fprintf(w, `{"items":[%s]}`, strings.Join(items, ","))
		case err == nil && ownerOf(id) != "":
			fmt.Fprintf(w, `{"id":%d,"owner":%q,"text":"note %d"}`, id, ownerOf(id), id)
		default:
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"error":"not found"}`)
		}
	}))
	t.Cleanup(site.Close)
	return site
}

// counter is a -role-cmd that prints a new token each time it runs.
func counter(t *testing.T, user string) string {
	f := filepath.Join(t.TempDir(), "n")
	return fmt.Sprintf(`n=$(cat %s 2>/dev/null || echo 0); n=$((n+1)); echo $n > %s; echo %s-$n`, f, f, user)
}

// TestRolesCanaryRenews: a session that dies during the replay is seen
// dying by its canary (/api/me), renewed with its -role-cmd, and what was
// asked since its last good check is asked again: nothing is suspect, and
// the cross reads stand.
func TestRolesCanaryRenews(t *testing.T) {
	site := expiringApp(t, 4)
	labels, rows, sum, err := rolesJSON(t, site.URL, "-canary-every", "3", "-role", "anon", "-role-cmd", "alice="+counter(t, "alice"), "-role-cmd", "bob="+counter(t, "bob"),
		"--", "-url", site.URL+"/")
	if err != nil {
		t.Fatalf("%v %v", err, sum)
	}
	if labels["/api/items/1"] != verdictCross+" [bob] of alice" || labels["/api/items/6"] != verdictCross+" [alice] of bob" {
		t.Errorf("rows %q", labels)
	}
	for p, row := range rows {
		if row.SessionSuspect {
			t.Errorf("%s: suspect after the session was renewed", p)
		}
	}
	var renewed []string
	for _, n := range toStrings(sum["notes"]) {
		if strings.Contains(n, "'s session failed its check (/api/me → 401) during the replay; its -role-cmd gave a new one") {
			renewed = append(renewed, n)
		}
	}
	if len(renewed) != 2 {
		t.Errorf("notes %q", toStrings(sum["notes"]))
	}
}

// TestRolesCanarySuspect: a session given with -role cannot be renewed:
// what it was asked after its last good check is marked session_suspect,
// on the answer and the row, with a note.
func TestRolesCanarySuspect(t *testing.T) {
	site := expiringApp(t, 4)
	_, rows, sum, _ := rolesJSON(t, site.URL, "-canary-every", "3", "-role", "anon", "-role-cmd", "alice="+counter(t, "alice"), "-role", "bob=Authorization: Bearer bob-fixed",
		"--", "-url", site.URL+"/")
	suspect := 0
	for p, row := range rows {
		if !row.SessionSuspect {
			continue
		}
		suspect++
		if !row.Answers["bob"].SessionSuspect || row.Answers["alice"].SessionSuspect {
			t.Errorf("%s: %+v", p, row.Answers)
		}
	}
	all := strings.Join(toStrings(sum["notes"]), "\n")
	if suspect == 0 || !strings.Contains(all, "role bob: its session could not be renewed during the replay: its session was given with -role") ||
		!regexp.MustCompile(`role bob's session failed its check \(/api/me → 401\) during the replay and did not come back: \d+ answers asked after it was last seen alive \(session_suspect\)`).MatchString(all) {
		t.Errorf("%d suspect rows; notes %s", suspect, all)
	}
}

// TestReplayCanaryRetries: one role asked 9 URLs, its session checked
// every 3 requests, dies after 4: renewed, the stretch since its last good
// check is asked again.
func TestReplayCanaryRetries(t *testing.T) {
	var mu sync.Mutex
	var asked []string
	n := 0
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		tok := r.Header.Get("Authorization")
		if r.URL.Path != "/me" {
			asked = append(asked, r.URL.Path+" "+tok)
			if tok == "t1" {
				n++
			}
		}
		if tok != "t2" && (tok != "t1" || n > 4) {
			w.WriteHeader(401)
			fmt.Fprint(w, `{"error":"expired"}`)
			return
		}
		if r.URL.Path == "/me" {
			fmt.Fprint(w, `{"name":"alice"}`)
			return
		}
		fmt.Fprintf(w, `{"path":%q}`, r.URL.Path)
	}))
	defer site.Close()
	me, _ := readAnswer(200, []byte(`{"name":"alice"}`), "application/json")
	roles := []role{{name: "alice", headers: []string{"Authorization: t1"}, session: http.Header{"Authorization": {"t1"}}}}
	answers := map[string]map[string]answer{"alice": {}}
	found := map[string][]string{}
	for i := 1; i <= 9; i++ {
		found[fmt.Sprintf("%s/o/%d", site.URL, i)] = []string{"bob"}
	}
	w := &replayWatch{every: 3, canaries: map[string]*canary{"alice": {url: site.URL + "/me", want: me}}, renew: func(i int) error {
		roles[i].session = http.Header{"Authorization": {"t2"}}
		return nil
	}}
	sent, err := replayAll(roles, answers, found, nil, map[string]bool{"127.0.0.1": true}, 0, 100, w)
	if err != nil {
		t.Fatal(err)
	}
	// /o/5 and /o/6 failed with t1, and /o/4, asked since the last good
	// check, is asked again with t2.
	want := "/o/1 t1|/o/2 t1|/o/3 t1|/o/4 t1|/o/5 t1|/o/6 t1|/o/4 t2|/o/5 t2|/o/6 t2|/o/7 t2|/o/8 t2|/o/9 t2"
	if got := strings.Join(asked, "|"); got != want {
		t.Errorf("asked %s\nwant  %s", got, want)
	}
	for u, a := range answers["alice"] {
		if a.Status != 200 || a.SessionSuspect {
			t.Errorf("%s: %+v", u, a)
		}
	}
	// 12 objects, and the checks: before, after 3, after 6 (failed), the
	// new session's, after the retry, after 9.
	if sent != 18 || len(w.notes) != 1 || !strings.Contains(w.notes[0], "the 3 requests asked since the last good check were asked again") {
		t.Errorf("sent %d, notes %q", sent, w.notes)
	}
}

func TestParseCanaries(t *testing.T) {
	roles := []role{{name: "anon"}, {name: "alice", headers: []string{"A: 1"}}}
	got, err := parseCanaries([]string{`alice:https://app/api/me="name":"alice"`, "https://app/x?a=1&b=2", "https://app/x?a=1&b=2=ok", "https://app/me=^\\{"}, roles)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{`alice https://app/api/me "name":"alice"`, ` https://app/x?a=1&b=2 `, ` https://app/x?a=1&b=2 ok`, ` https://app/me ^\{`}
	for i, c := range got {
		re := ""
		if c.re != nil {
			re = c.re.String()
		}
		if s := c.role + " " + c.url + " " + re; s != want[i] {
			t.Errorf("%d: %q, want %q", i, s, want[i])
		}
	}
	for _, bad := range []string{"anon:https://app/me", "bob:https://app/me", "/me", "https://app/me=("} {
		if _, err := parseCanaries([]string{bad}, roles); exitCode(err) != exitUsage {
			t.Errorf("%q: %v", bad, err)
		}
	}
}

func TestPickCanaries(t *testing.T) {
	roles := []role{{name: "anon"}, {name: "alice", headers: []string{"A: 1"}}, {name: "bob", headers: []string{"A: 2"}}}
	j := func(status int, body string) answer {
		a, _ := readAnswer(status, []byte(body), "application/json")
		return a
	}
	answers := map[string]map[string]answer{
		"anon":  {"http://h/api/me": j(200, `{"user":{}}`), "http://h/api/cards": j(401, `{"error":"sign in"}`), "http://h/api/logout-all": j(401, `{}`)},
		"alice": {"http://h/api/me": j(200, `{"user":{"id":1}}`), "http://h/api/cards": j(200, `{"data":[]}`), "http://h/api/logout-all": j(200, `{"ok":1}`)},
		"bob":   {"http://h/api/me": j(200, `{"user":{}}`), "http://h/api/cards": j(200, `{"data":[]}`), "http://h/rest/basket/6": j(200, `{"data":{"id":6}}`)},
	}
	made := map[string]instance{"http://h/rest/basket/6": {owner: "bob"}}
	got := pickCanaries(roles, answers, made, nil, map[string]bool{"h": true})
	// alice's /me says who she is; bob's says what the anonymous role's
	// does, and his own basket tells his session apart.
	if got["alice"].url != "http://h/api/me" || got["bob"].url != "http://h/rest/basket/6" || got["anon"] != nil {
		t.Errorf("%+v %+v", got["alice"], got["bob"])
	}
	given, _ := parseCanaries([]string{"http://h/ping=pong", "bob:http://h/api/cards"}, roles)
	got = pickCanaries(roles, answers, made, given, map[string]bool{"h": true})
	if got["alice"].url != "http://h/ping" || got["alice"].re.String() != "pong" || got["bob"].url != "http://h/api/cards" {
		t.Errorf("given: %+v %+v", got["alice"], got["bob"])
	}
}

// TestRolesShowEvidence: the answers behind a listed row are kept in -dir,
// their secrets taken out, and roles show prints them side by side with
// curl lines that name each session as a shell variable, never its value.
func TestRolesShowEvidence(t *testing.T) {
	alice, bob := jwt(`{"sub":"alice"}`), jwt(`{"sub":"bob"}`)
	site := objectApp(t, map[string]string{alice: "alice", bob: "bob"})
	dir := t.TempDir()
	if _, _, err := captureBoth(t, func() error {
		return cmdRoles([]string{"-json", "-dir", dir, "-role", "anon", "-role", "alice=Authorization: Bearer " + alice, "-role", "bob=Authorization: Bearer " + bob,
			"--", "-url", site.URL + "/"})
	}); err != nil {
		t.Fatal(err)
	}
	out, err := captureStdout(t, func() error { return cmdRolesShow([]string{"-dir", dir, site.URL + "/api/notes/21"}) })
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"[bob reads alice's object] proved",
		"anon  401",
		"curl -sS -i '" + site.URL + "/api/notes/21'\n",
		"alice (owner)  200",
		`-H "Authorization: Bearer $ALICE_TOKEN"`,
		"the same body as alice's",
		"bob (made-up identifier)  404",
		"curl -sS -i '" + site.URL + `/api/notes/1000024' -H "Authorization: Bearer $BOB_TOKEN"`,
		"- secret  \"[redacted ",
		"set ALICE_TOKEN, BOB_TOKEN to the sessions the roles sent",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("no %q in\n%s", want, out)
		}
	}
	if strings.Contains(out, alice) || strings.Contains(out, "s3cr3t") {
		t.Errorf("a secret in\n%s", out)
	}
	body, err := captureStdout(t, func() error { return cmdRolesShow([]string{"-dir", dir, "-body", "bob", site.URL + "/api/notes/21"}) })
	if err != nil || !strings.Contains(body, `"secret":"[redacted `) || strings.Contains(body, "s3cr3t") {
		t.Errorf("bob's body %q %v", body, err)
	}
	// -json: the row, and each answer with its curl and differences.
	raw, _ := captureStdout(t, func() error { return cmdRolesShow([]string{"-dir", dir, "-json", site.URL + "/api/me"}) })
	var shown struct {
		Row     roleRow `json:"row"`
		Answers []struct {
			Role string     `json:"role"`
			Curl string     `json:"curl"`
			Diff []diffLine `json:"diff"`
		} `json:"answers"`
	}
	if err := json.Unmarshal([]byte(raw), &shown); err != nil || shown.Row.Verdict != verdictSignedIn || len(shown.Answers) != 3 {
		t.Fatalf("%v: %s", err, raw)
	}
	if d := shown.Answers[2].Diff; shown.Answers[2].Role != "bob" || len(d) != 1 || d[0].String() != `~ user.name  "alice" → "bob"` {
		t.Errorf("bob against alice: %+v", shown.Answers[2])
	}
	if err := cmdRolesShow([]string{"-dir", dir, site.URL + "/nothing"}); err == nil || !strings.Contains(err.Error(), "no row for GET "+site.URL+"/nothing") {
		t.Errorf("an unknown row: %v", err)
	}
	if err := cmdRolesShow([]string{"-dir", t.TempDir(), site.URL + "/api/me"}); exitCode(err) != exitUsage {
		t.Errorf("a -dir without evidence: %v", err)
	}
	if err := cmdRoles([]string{"-role", "anon", "-role", "roles=A: 1", "--", "-url", site.URL + "/"}); exitCode(err) != exitUsage {
		t.Errorf("a role named roles: %v", err)
	}
}

// A write row keeps its body and method in its curl lines.
func TestWriteEvidence(t *testing.T) {
	dir := t.TempDir()
	bodies = newBodyKeep()
	defer func() { bodies = nil }()
	roles := []role{{name: "anon"}, {name: "alice", session: http.Header{"Cookie": {"sid=alice-secret-cookie"}}},
		{name: "bob", session: http.Header{"Cookie": {"sid=bob-secret-cookie"}, "X-Api-Key": {"bob-key-123456"}}}}
	a, _ := readAnswer(200, []byte(`{"ok":true,"by":"bob-secret-cookie"}`), "application/json")
	keepBody(a.Hash, "application/json", []byte(`{"ok":true,"by":"bob-secret-cookie"}`))
	row := roleRow{URL: "http://h/api/items/3", Method: "PUT", Owner: "alice", OwnerBy: "PUT /api/items/{id} with an empty body", Verdict: verdictWriteCross,
		Readers: []string{"bob"}, Answers: map[string]answer{"alice": {Status: 200}, "bob": a}, Status: map[string]int{}, reqBody: []byte(`{}`), reqType: "application/json"}
	rows := []roleRow{row}
	explain(rows, nil, roles, nil)
	if rows[0].Evidence != "bob got 200:36, as alice did (200); PUT /api/items/{id} with an empty body" {
		t.Errorf("evidence %q", rows[0].Evidence)
	}
	if err := saveEvidence(dir, roles, rows); err != nil {
		t.Fatal(err)
	}
	ev, err := store.OpenEvidenceExisting(filepath.Join(dir, evidenceFile))
	if err != nil {
		t.Fatal(err)
	}
	er, ok, err := ev.Row("http://h/api/items/3", "PUT")
	ev.Close()
	if err != nil || !ok || len(er.Answers) != 2 {
		t.Fatalf("%v %v %+v", ok, err, er)
	}
	want := `curl -sS -i -X PUT 'http://h/api/items/3' -b "$BOB_COOKIE" -H "X-Api-Key: $BOB_X_API_KEY" -H 'Content-Type: application/json' --data-raw '{}'`
	if got := er.Answers[1].Curl; got != want {
		t.Errorf("curl %s\nwant %s", got, want)
	}
	if b := string(er.Answers[1].Body); strings.Contains(b, "bob-secret-cookie") || !strings.Contains(b, `"by":"[redacted `) {
		t.Errorf("body %s", b)
	}
	out, err := captureStdout(t, func() error { return cmdRolesShow([]string{"-dir", dir, "http://h/api/items/3", "-method", "put"}) })
	if err != nil || !strings.HasPrefix(out, "PUT http://h/api/items/3\n  [bob writes alice's object] guess") {
		t.Errorf("%v\n%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(dir, evidenceFile)); err != nil {
		t.Error(err)
	}
}

func TestCurlLine(t *testing.T) {
	for _, c := range []struct {
		r    role
		want string
	}{
		{role{name: "anon"}, `curl -sS -i 'http://h/x'`},
		{role{name: "admin-2", headers: []string{"Authorization: Basic YTpi"}}, `curl -sS -i 'http://h/x' -H "Authorization: Basic $ADMIN_2_BASIC"`},
		{role{name: "2fa", session: http.Header{"Authorization": {"Token abc"}, "Accept-Language": {"vi"}}},
			`curl -sS -i 'http://h/x' -H 'Accept-Language: vi' -H "Authorization: $ROLE_2FA_AUTHORIZATION"`},
	} {
		if got, _ := curlLine("", "http://h/x", c.r, "", nil); got != c.want {
			t.Errorf("%s: %s\nwant %s", c.r.name, got, c.want)
		}
	}
}

func TestConfidence(t *testing.T) {
	for _, c := range []struct {
		in   instance
		want string
	}{
		{instance{sure: proved, told: toldConfirms}, confProved},
		{instance{given: true, told: toldConfirms}, confProved},
		{instance{sure: hinted, by: "item of /books/v1: user alice names alice", told: toldConfirms}, confProved},
		{instance{sure: proved}, confLikely},
		{instance{given: true}, confLikely},
		{instance{sure: shortName, told: toldConfirms}, confLikely},
		{instance{sure: proved, told: toldNames}, confLikely},
		{instance{sure: hinted, by: "in alice's answers alone"}, confGuess},
		{instance{sure: shortName}, confGuess},
	} {
		if got := confidenceOf(c.in); got != c.want {
			t.Errorf("%+v: %s, want %s", c.in, got, c.want)
		}
	}
}
