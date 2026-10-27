package main

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Tokens copied at the same time expire together: with every session
// dead, nobody reads what the visitor is refused, and each role is
// judged alone.
func TestRoleAllSessionsDead(t *testing.T) {
	roles := []role{{name: "anon"}, {name: "alice", headers: []string{"A: 1"}}, {name: "bob", headers: []string{"A: 2"}}}
	ok := answer{Status: 200, Length: 10, Hash: "h"}
	no := answer{Status: 401, Length: 30, Hash: "x"}
	rows := []roleRow{
		{URL: "http://h/", Answers: map[string]answer{"anon": ok, "alice": ok, "bob": ok}},
		{URL: "http://h/me", Answers: map[string]answer{"anon": no, "alice": no, "bob": no}},
		{URL: "http://h/books/b1", Answers: map[string]answer{"anon": no, "alice": no, "bob": no}},
	}
	if got := deadRoles(roles, rows); !reflect.DeepEqual(got, []string{"alice", "bob"}) {
		t.Errorf("dead %v, want both", got)
	}
	// One of them alive: the other is judged against it, as before.
	rows[1].Answers["alice"] = answer{Status: 200, Length: 12, Hash: "me", Keys: []string{"user"}}
	if got := deadRoles(roles, rows); !reflect.DeepEqual(got, []string{"bob"}) {
		t.Errorf("dead %v, want bob", got)
	}
}

func TestTokenExpiry(t *testing.T) {
	h := headerOf([]string{"Authorization: Bearer " + jwt(`{"sub":"a","exp":2000000000}`), "Cookie: x=1; t=" + jwt(`{"exp":1700000000}`)})
	if got := tokenExpiry(h); !got.Equal(time.Unix(1700000000, 0)) {
		t.Errorf("earliest expiry %v", got)
	}
	if got := tokenExpiry(headerOf([]string{"Authorization: Bearer " + jwt(`{"sub":"a"}`)})); !got.IsZero() {
		t.Errorf("a token without exp expires %v", got)
	}
	now := time.Unix(1700000000+3600, 0)
	roles := []role{{name: "anon"}, {name: "old", headers: []string{"Authorization: Bearer " + jwt(`{"exp":1700000000}`)}},
		{name: "soon", headers: []string{"Authorization: Bearer " + jwt(`{"exp":1700003900}`)}},
		{name: "fresh", headers: []string{"Authorization: Bearer " + jwt(`{"exp":1800000000}`)}}}
	stale, soon, expired := expiryNotes(roles, now)
	if len(stale) != 1 || !strings.Contains(stale[0], "role old carries a token that expired 1h0m ago") {
		t.Errorf("stale %q", stale)
	}
	if len(soon) != 1 || !strings.Contains(soon[0], "role soon carries a token that expires in 5m") {
		t.Errorf("soon %q", soon)
	}
	if len(expired) != 1 || expired["old"].IsZero() {
		t.Errorf("expired %v", expired)
	}
}

func TestSessionNotes(t *testing.T) {
	var asked int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked++
		if r.Header.Get("A") == "" {
			t.Errorf("asked without the role's session")
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(401)
		w.Write([]byte(`{"status":"fail","message":"Signature expired. Please log in again.","token":"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhIn0.abc"}`))
	}))
	defer srv.Close()
	exp := time.Unix(1700000000, 0)
	h := http.Header{}
	h.Set("A", "1")
	roles := []role{{name: "anon"}, {name: "alice", headers: []string{"A: 1"}, session: h}, {name: "bob", headers: []string{"A: 2"}, session: h}}
	ok := answer{Status: 200, Length: 10, Hash: "h"}
	no := answer{Status: 401, Length: 30, Hash: "x"}
	rows := []roleRow{
		{URL: srv.URL + "/", Answers: map[string]answer{"anon": ok, "alice": ok, "bob": ok}},
		{URL: srv.URL + "/books/b1", Answers: map[string]answer{"anon": no, "alice": no, "bob": ok}},
	}
	// alice is dead with an expired token; bob's expired token is still taken.
	notes, warn, n := sessionNotes(roles, rows, map[string]time.Time{"alice": exp, "bob": exp}, map[string]bool{"127.0.0.1": true})
	if !warn || n != 1 || asked != 1 || len(notes) != 2 {
		t.Fatalf("warn %v asked %d/%d notes %q", warn, n, asked, notes)
	}
	if want := `role alice was refused wherever a session matters (the site said "Signature expired. Please log in again."): its token expired at 2023-11-14T22:13:20Z`; !strings.HasPrefix(notes[0], want) {
		t.Errorf("dead note %q\nwant %q", notes[0], want)
	}
	if !strings.Contains(notes[1], "role bob's token expired at 2023-11-14T22:13:20Z, yet the site still let it read 1 endpoint the") {
		t.Errorf("accepted note %q", notes[1])
	}
}

func TestReasonText(t *testing.T) {
	for _, c := range []struct{ body, ctype, want string }{
		{`{"error":{"code":401,"message":"jwt expired"}}`, "application/json", "jwt expired"},
		{`{"errors":[{"detail":"Invalid token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhIn0.abc"}]}`, "application/json", "Invalid token …"},
		{"<html><head><title>\n Sign in \n</title>", "text/html", "Sign in"},
		{"Unauthorized\n", "text/plain", "Unauthorized"},
		{`{"id":5}`, "application/json", ""},
	} {
		if got := reasonText([]byte(c.body), c.ctype); got != c.want {
			t.Errorf("%s: %q, want %q", c.body, got, c.want)
		}
	}
}

func TestRoleCmd(t *testing.T) {
	roles, err := addCmds([]role{{name: "anon"}}, []string{"alice=printf 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhIn0.c2ln\\n'", "bob=printf 'Authorization: Bearer b\\nX-Tenant: 7\\n'"})
	if err != nil || len(roles) != 3 || roles[1].anonymous() {
		t.Fatalf("roles %+v err %v", roles, err)
	}
	if h, err := cmdHeaders(roles[1]); err != nil || !reflect.DeepEqual(h, []string{"Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhIn0.c2ln"}) {
		t.Errorf("a bare token: %q %v", h, err)
	}
	if h, err := cmdHeaders(roles[2]); err != nil || !reflect.DeepEqual(h, []string{"Authorization: Bearer b", "X-Tenant: 7"}) {
		t.Errorf("header lines: %q %v", h, err)
	}
	for _, bad := range []string{"exit 3", "true", "echo 'not a header line'"} {
		if _, err := cmdHeaders(role{name: "x", cmd: bad}); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if _, err := addCmds(roles, []string{"alice=true"}); err == nil {
		t.Error("a second role named alice accepted")
	}
}
