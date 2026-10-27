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
	now := time.Unix(1700000000+3600, 0)
	h := headerOf([]string{"Authorization: Bearer " + jwt(`{"sub":"a","exp":2000000000}`), "Cookie: x=1; token=" + jwt(`{"exp":1700000000}`)})
	if got, sole := tokenExpiry(h, now); !got.Equal(time.Unix(1700000000, 0)) || sole {
		t.Errorf("earliest expiry %v, sole %v", got, sole)
	}
	if got, _ := tokenExpiry(headerOf([]string{"Authorization: Bearer " + jwt(`{"sub":"a"}`)}), now); !got.IsZero() {
		t.Errorf("a token without exp expires %v", got)
	}
	// An analytics cookie's token is no credential; an opaque session
	// cookie is one, so an expired token beside it is not the only one.
	if got, _ := tokenExpiry(headerOf([]string{"Cookie: session=4f9a; _ga_id=" + jwt(`{"exp":1700000000}`)}), now); !got.IsZero() {
		t.Errorf("an analytics cookie's token expires %v", got)
	}
	if got, sole := tokenExpiry(headerOf([]string{"Cookie: session=4f9a; jwt=" + jwt(`{"exp":1700000000}`)}), now); got.IsZero() || sole {
		t.Errorf("beside an opaque session: %v, sole %v", got, sole)
	}
	if _, sole := tokenExpiry(headerOf([]string{"Authorization: Bearer " + jwt(`{"exp":1700000000}`)}), now); !sole {
		t.Error("an expired bearer token alone is not the only credential")
	}
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
	if len(expired) != 1 || expired["old"].at.IsZero() || !expired["old"].sole {
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
	notes, warn, n := sessionNotes(roles, rows, map[string]expiry{"alice": {exp, true}, "bob": {exp, true}}, map[string]bool{"127.0.0.1": true})
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

// Users refused an admin area, with objects of their own and no "/me":
// alive, though no signed-in role reads what the visitor is refused.
func TestRoleUsersBesideAnAdminArea(t *testing.T) {
	roles := []role{{name: "anon"}, {name: "alice", headers: []string{"A: 1"}}, {name: "bob", headers: []string{"A: 2"}}}
	ok := func(h string) answer { return answer{Status: 200, Length: 10, Hash: h} }
	rows := []roleRow{
		{URL: "http://h/", Answers: map[string]answer{"anon": ok("h"), "alice": ok("h"), "bob": ok("h")}},
		{URL: "http://h/notes/1", Answers: map[string]answer{"anon": {Status: 404}, "alice": ok("n1"), "bob": {Status: 404}}},
		{URL: "http://h/admin", Answers: map[string]answer{"anon": {Status: 401}, "alice": {Status: 403}, "bob": {Status: 403}}},
	}
	if got := deadRoles(roles, rows); len(got) != 0 {
		t.Errorf("live users called dead: %v", got)
	}
}

func TestRefusalHidesWhatWasSent(t *testing.T) {
	h := http.Header{}
	h.Set("Cookie", "PHPSESSID=9f2kq0v8m3l1; connect.sid=s%3Aabc")
	h.Set("Authorization", "Basic YWxpY2U6aHVudGVyMg==")
	got := hideSent("Session 9f2kq0v8m3l1 has expired; Basic YWxpY2U6aHVudGVyMg== refused; s%3Aabc", h)
	if strings.Contains(got, "9f2kq0v8m3l1") || strings.Contains(got, "YWxpY2U6") || strings.Contains(got, "s%3Aabc") {
		t.Errorf("sent values left in %q", got)
	}
	for in, want := range map[string]string{
		"key AKIAIOSFODNN7EXAMPLE is not valid":          "key … is not valid",
		"token a1b2c3d4e5f6.g7h8i9j0k1l2.m3n4o5p6 stale": "token … stale",
		"Authentication credentials were not provided":   "Authentication credentials were not provided",
	} {
		if got := hideCredentials(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}
