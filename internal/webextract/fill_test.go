package webextract

import (
	"net/url"
	"testing"
)

func TestFilledGet(t *testing.T) {
	page := &url.URL{Scheme: "http", Host: "h", Path: "/p"}
	forms := Forms([]byte(`<form action="/search"><input name=q><input type=hidden name=tok value=t1><input type=checkbox name=a><input type=checkbox name=b checked value=yes><select name=s><option value=x>X<option value=y selected>Y</select><input type=email name=e><input type=submit name=go value=Go></form>`), page)
	if len(forms) != 1 {
		t.Fatalf("%v", forms)
	}
	got, ok := FilledGet(forms[0])
	want := "http://h/search?q=azhaq&tok=t1&b=yes&s=y&e=azhaq%40example.org"
	if !ok || got != want {
		t.Errorf("%q, want %q", got, want)
	}
	post := Forms([]byte(`<form action="/x" method=post><input name=q></form>`), page)
	if _, ok := FilledGet(post[0]); ok {
		t.Error("a POST form has no filled GET")
	}
	if _, ok := FilledGet(Forms([]byte(`<form action="/x"><input type=submit></form>`), page)[0]); ok {
		t.Error("a form with nothing to send is not filled")
	}
}
