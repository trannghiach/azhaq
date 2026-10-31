package fetch

import (
	"net/http"
	"testing"
)

// A response ends the session when it expires a cookie the run sends, and
// only then: another cookie, or one set to a value, does not.
func TestClearsSession(t *testing.T) {
	Reset()
	defer Reset()
	Extra = http.Header{"Cookie": {"sid=abc; theme=dark"}}
	for set, want := range map[string]bool{
		"sid=; Max-Age=0; Path=/":                      true,
		"sid=x; Expires=Thu, 01 Jan 1970 00:00:00 GMT": true,
		"sid=; Path=/":                                 true,
		"sid=newvalue; Path=/":                         false,
		"other=; Max-Age=0":                            false,
		"theme=light":                                  false,
	} {
		if got := clearsSession(http.Header{"Set-Cookie": {set}}); got != want {
			t.Errorf("%q: %v, want %v", set, got, want)
		}
	}
	Extra = http.Header{"Authorization": {"Bearer x"}}
	if clearsSession(http.Header{"Set-Cookie": {"sid=; Max-Age=0"}}) {
		t.Error("a run with no cookie has none to lose")
	}
}
