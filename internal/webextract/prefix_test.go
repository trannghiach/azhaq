package webextract

import (
	"net/url"
	"testing"
)

func TestHeadAt(t *testing.T) {
	for _, c := range []struct {
		src  string
		head bool
	}{
		{`x = "/rest/user/" + id`, true},
		{`x = "/rest/user"+id`, true},
		{"x = `/rest/user/` + id", true},
		{`x = "/api/x".concat(id)`, true},
		{`x = "/api/x" + "/" + id`, true},
		{"x = \"/api/a/\" +\n  id", true},
		{`x = "/search?q=" + q`, false},
		{`x = "/api/export" + "?id=" + id`, false},
		{`x = "/img/logo" + ".png"`, false},
		{`x = "/login"`, false},
		{`x = "/login";y="/a"+b`, false},
		{`n = "/a" ++ b`, false},
		{`n += "/a" + b`, true},
		{`x = "/a" == y`, false},
	} {
		start := indexQuoted(c.src, "/")
		end := indexAfterClose(c.src, start)
		if got := HeadAt(c.src, start, end); got != c.head {
			t.Errorf("%s: head %v, want %v", c.src, got, c.head)
		}
	}
}

// indexQuoted is the index of the quote that opens the first string that
// starts with prefix.
func indexQuoted(s, prefix string) int {
	for i := 0; i+1 < len(s); i++ {
		if (s[i] == '"' || s[i] == '\'' || s[i] == '`') && s[i+1:i+2] == prefix {
			return i
		}
	}
	return -1
}

func indexAfterClose(s string, open int) int {
	for i := open + 1; i < len(s); i++ {
		if s[i] == s[open] {
			return i + 1
		}
	}
	return -1
}

func TestRefsMarkTheStartsOfJoinedPaths(t *testing.T) {
	base, _ := url.Parse("http://h/app")
	script := `fetch("/api/admin/users/" + userId + "/reset"); var q = "/rest/products/search?q=" + q; var l = "/login"; go("/api/items".concat(x))`
	head := map[string]bool{}
	for _, r := range JSURLRefs(script, base) {
		head[r.URL] = r.Head
	}
	for u, want := range map[string]bool{
		"http://h/api/admin/users/": true, "http://h/rest/products/search?q=": false, "http://h/login": false, "http://h/api/items": true,
	} {
		if got, ok := head[u]; !ok || got != want {
			t.Errorf("%s: head %v (found %v), want %v in %v", u, got, ok, want, head)
		}
	}
}

func TestCandidatesRejectAPrefix(t *testing.T) {
	page, _ := url.Parse("http://h/")
	script := `var a = "/rest/web/things/" + id; var b = "/rest/web/stuff"; go(b);`
	got := map[string]string{}
	for _, c := range Candidates(script, page, page, true) {
		got[c.Text] = c.Reason
	}
	if got["/rest/web/things/"] != ReasonPrefix || got["/rest/web/stuff"] != "" {
		t.Errorf("%v", got)
	}
}
