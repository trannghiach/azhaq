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

func TestRoleDiff(t *testing.T) {
	roles := []role{{name: "anon"}, {name: "member"}, {name: "owner"}}
	rows := roleDiff(roles, map[string]map[string]int{
		"anon":   {"/": 200, "/api/me": 401, "/api/settings": 401},
		"member": {"/": 200, "/api/me": 200, "/api/settings": 403},
		"owner":  {"/": 200, "/api/me": 200, "/api/settings": 200, "/api/billing": 200},
	})
	want := []roleRow{
		{URL: "/api/billing", Status: map[string]int{"anon": 0, "member": 0, "owner": 200}},
		{URL: "/api/me", Status: map[string]int{"anon": 401, "member": 200, "owner": 200}},
		{URL: "/api/settings", Status: map[string]int{"anon": 401, "member": 403, "owner": 200}},
	}
	if !reflect.DeepEqual(rows, want) {
		t.Errorf("rows %+v", rows)
	}
}
