package engine

import (
	"reflect"
	"testing"
)

func TestWatch(t *testing.T) {
	r := MapEntry{Params: []string{"q", "page", "returnUrl"}, Body: []string{"isAdmin", "email"},
		Ops:   []Op{{Method: "GET", Query: []string{"file", "to"}}},
		Forms: []MapForm{{Fields: []string{"cmd", "Submit"}}}}
	want := []string{"cmd (command)", "file (file)", "isAdmin (debug)", "returnUrl (redirect)", "to (redirect)"}
	if got := Watch(r); !reflect.DeepEqual(got, want) {
		t.Errorf("%q, want %q", got, want)
	}
}
