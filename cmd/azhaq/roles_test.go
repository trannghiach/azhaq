package main

import (
	"reflect"
	"testing"
)

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
		"/api/settings":  verdictRoleGated,
		"/api/users":     verdictSignedIn,
		"/rest/basket/6": verdictStatus,
	}
	// bob gets alice's basket; the anonymous visitor does not.
	want["/rest/basket/6"] = verdictSignedIn
	if !reflect.DeepEqual(got, want) {
		t.Errorf("verdicts %v\nwant %v", got, want)
	}
	answers["anon"]["/rest/basket/6"] = ok("b6", "items")
	for _, r := range roleRows(roles, answers, found, nil) {
		if r.URL == "/rest/basket/6" && r.Verdict != verdictShared {
			t.Errorf("alice's basket answers everyone the same: %s", r.Verdict)
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
