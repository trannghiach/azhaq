package webextract

import (
	"net/url"
	"strings"
	"testing"
)

func TestLocator(t *testing.T) {
	src := "var a=1;\nfunction go(){\n  fetch('/api/x')\n}"
	loc := NewLocator(src)
	at := strings.Index(src, "fetch")
	if line, col := loc.LineCol(at); line != 3 || col != 3 {
		t.Errorf("LineCol = %d:%d, want 3:3", line, col)
	}
	if line, col := loc.LineCol(0); line != 1 || col != 1 {
		t.Errorf("LineCol(0) = %d:%d", line, col)
	}
	end := strings.Index(src, ")\n}") + 1
	if s := loc.CallSite("http://a.test/m.js", at, end); s.Snippet != "fetch('/api/x')" || s.Line != 3 {
		t.Errorf("CallSite = %+v", s)
	}
	if s := loc.Site("http://a.test/m.js", at+7, at+13); s.Snippet != "fetch('/api/x')" {
		t.Errorf("Site keeps to its line: %q", s.Snippet)
	}
	if got := (Site{Script: "http://a.test/m.js", Line: 3, Col: 3, Snippet: "fetch('/api/x')"}).String(); got != "http://a.test/m.js:3:3  fetch('/api/x')" {
		t.Errorf("String = %q", got)
	}
}

func TestSnippetBounds(t *testing.T) {
	// A minified bundle: one long line.
	long := strings.Repeat("abcdefghij;", 40) + `this.http.post("/rest/2fa/verify",{tmpToken:t})` + strings.Repeat(";klmnopqrst", 40)
	loc := NewLocator(long)
	at := strings.Index(long, `"/rest`)
	s := loc.Snippet(at, at+len(`"/rest/2fa/verify"`))
	if len(s) > MaxSnippet || !strings.Contains(s, `"/rest/2fa/verify"`) {
		t.Errorf("snippet %d bytes: %q", len(s), s)
	}
	if strings.HasPrefix(s, "bcdefghij") || strings.HasPrefix(s, "cdefghij") {
		t.Errorf("snippet starts inside a word: %q", s)
	}
	call := loc.Span(0, len(long))
	if len(call) > MaxSnippet+len("…") || !strings.HasSuffix(call, "…") {
		t.Errorf("long span %q", call)
	}
	// Multibyte text is cut on a rune, never inside one.
	uni := strings.Repeat("é", 200)
	if got := NewLocator(uni).Span(0, len(uni)); !strings.HasSuffix(got, "…") || strings.ContainsRune(got, '�') {
		t.Errorf("multibyte span %q", got)
	}
}

// A signed-in page's inline script can hold its session: what a snippet
// carries out of it has its credentials blanked, and a route's words kept.
func TestSnippetsRedactCredentials(t *testing.T) {
	jwt := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.c2lnbmF0dXJlX2hlcmVfYWJj"
	for src, want := range map[string]string{
		`fetch("/api/me",{headers:{Authorization:"Bearer ` + jwt + `"}})`:      `fetch("/api/me",{headers:{Authorization:"Bearer [redacted]"}})`,
		`var t="` + jwt + `";$.get("/rest/user/whoami")`:                       `var t="[redacted]";$.get("/rest/user/whoami")`,
		`login({user:"admin",password:"hunter2!"});fetch("/api/login")`:        `login({user:"admin",password:"[redacted]"});fetch("/api/login")`,
		`fetch("/resetpw?login=user&token=ee11cbb19052e40b07aac0ca060c23ee")`:  `fetch("/resetpw?login=user&token=[redacted]")`,
		`const k="AKfycbx9QzP2mW7rT4uVn8bLs3dH6jE1";fetch("/api/data")`:        `const k="[redacted]";fetch("/api/data")`,
		`this.http.post("/api/Challenges/continueCodeFindIt/applyNow2",{a:b})`: `this.http.post("/api/Challenges/continueCodeFindIt/applyNow2",{a:b})`,
		`{tmpToken:localStorage.getItem("totp_tmp_token"),totpToken:t}`:        `{tmpToken:localStorage.getItem("totp_tmp_token"),totpToken:t}`,
	} {
		if got := NewLocator(src).Span(0, len(src)); got != want {
			t.Errorf("Span(%s)\n got %s\nwant %s", src, got, want)
		}
	}
}

// A minified bundle is one line of megabytes: a snippet looks no further
// than it can show, wherever the line starts.
func TestSnippetOnOneLongLine(t *testing.T) {
	src := strings.Repeat("x=1;", 1<<18) + `fetch("/api/far")` + strings.Repeat(";y=2", 1<<18)
	at := strings.Index(src, `"/api/far"`)
	s := NewLocator(src).Site("m.js", at, at+len(`"/api/far"`))
	if s.Line != 1 || s.Col != at+1 || !strings.Contains(s.Snippet, `fetch("/api/far")`) || len(s.Snippet) > MaxSnippet {
		t.Errorf("site %+v", s)
	}
}

func TestInlineScriptsAt(t *testing.T) {
	page := "<html>\n<head><title>x</title></head>\n<body>\n<script>\nfetch('/api/a')</script>\n  <script src=/x.js></script><script>var b=2</script>\n</body>"
	got := InlineScriptsAt([]byte(page))
	if len(got) != 2 {
		t.Fatalf("inline scripts %+v", got)
	}
	if got[0].Line != 4 || got[0].Col != 9 || !strings.Contains(got[0].Text, "fetch") {
		t.Errorf("first %+v", got[0])
	}
	if got[1].Line != 6 || got[1].Col != 38 || got[1].Text != "var b=2" {
		t.Errorf("second %+v", got[1])
	}
}

func TestJSURLRefs(t *testing.T) {
	base, _ := url.Parse("http://a.test/")
	script := `a="/api/users";b='/pQ';c="/api/users";d="/juice-shop/juice-shop";e="/v1"`
	var got []string
	for _, r := range JSURLRefs(script, base) {
		got = append(got, r.URL+" "+script[r.Start:r.End])
	}
	want := []string{`http://a.test/api/users "/api/users"`, `http://a.test/api/users "/api/users"`, `http://a.test/v1 "/v1"`}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("got  %q\nwant %q", got, want)
	}
	if urls := JSURLs(script, base); len(urls) != 2 {
		t.Errorf("JSURLs lists each once: %q", urls)
	}
}

func TestAssembledRefs(t *testing.T) {
	script := `og="identity/",sg={LOGIN:"api/auth/login"};fetch(og+sg.LOGIN)`
	refs := AssembledRefs(script)
	if len(refs) != 1 || refs[0].URL != "identity/api/auth/login" || script[refs[0].Start:refs[0].End] != "og+sg.LOGIN" {
		t.Fatalf("refs %+v", refs)
	}
}
