package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestImportRawRequest(t *testing.T) {
	raw := "POST /api/login?next=1 HTTP/1.1\r\nHost: app.test:8080\r\nContent-Type: application/json\r\nCookie: s=1\r\nContent-Length: 12\r\n\r\n{\"keep\":\"1\"}"
	pg, err := importRaw([]byte(raw), "")
	if err != nil {
		t.Fatal(err)
	}
	if pg.URL != "http://app.test:8080/api/login?next=1" || pg.Target.Method != "JSON" || pg.Target.Include != `{"keep":"1"}` {
		t.Errorf("%+v", pg)
	}
	if len(pg.Target.Header) != 1 || pg.Target.Header[0] != "Cookie: s=1" {
		t.Errorf("headers %v", pg.Target.Header)
	}
	if _, err := importRaw([]byte("DELETE /x HTTP/1.1\r\nHost: a\r\n\r\n"), ""); err == nil {
		t.Error("a DELETE is not searched")
	}
}

func TestImportBurpExport(t *testing.T) {
	req := base64.StdEncoding.EncodeToString([]byte("GET /a?x=1 HTTP/1.1\r\nHost: app.test\r\n\r\n"))
	xml := `<?xml version="1.1"?><items>
<item><url><![CDATA[http://app.test/a?x=1]]></url><method>GET</method><request base64="true"><![CDATA[` + req + `]]></request><mimetype>HTML</mimetype></item>
<item><url><![CDATA[http://app.test/a?x=2]]></url><method>GET</method><mimetype>HTML</mimetype></item>
<item><url><![CDATA[http://app.test/app.js]]></url><method>GET</method><mimetype>script</mimetype></item>
<item><url><![CDATA[http://app.test/b]]></url><method>PUT</method><mimetype>JSON</mimetype></item>
</items>`
	f := filepath.Join(t.TempDir(), "burp.xml")
	if err := os.WriteFile(f, []byte(xml), 0o644); err != nil {
		t.Fatal(err)
	}
	got, notes, err := importPages(f)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].URL != "http://app.test/a?x=1" {
		t.Errorf("pages %+v", got)
	}
	joined := strings.Join(notes, "; ")
	for _, want := range []string{"1 Burp items were not HTML", "repeated a page", "left out"} {
		if !strings.Contains(joined, want) {
			t.Errorf("notes %q lack %q", joined, want)
		}
	}
}

func TestImportURLList(t *testing.T) {
	f := filepath.Join(t.TempDir(), "urls.txt")
	_ = os.WriteFile(f, []byte("http://a.test/x\n# no\nhttp://a.test/y\n"), 0o644)
	got, _, err := importPages(f)
	if err != nil || len(got) != 2 {
		t.Fatalf("%v %v", got, err)
	}
}

func TestParamsFiles(t *testing.T) {
	rows := []paramsRow{{URL: "http://a.test/s", Method: "GET", Params: []string{"q", "page"}}, {URL: "http://a.test/p", Method: "JSON", Params: []string{"isAdmin"}}}
	dir := t.TempDir()
	if err := writeParamsJSON(filepath.Join(dir, "o.json"), rows, map[string]string{"Cookie": "s=1"}); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "o.json"))
	var got map[string]struct {
		Params  []string
		Method  string
		Headers map[string]string
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if g := got["http://a.test/s"]; len(g.Params) != 2 || g.Method != "GET" || g.Headers["Cookie"] != "s=1" {
		t.Errorf("%s", raw)
	}
	if err := writeParamsText(filepath.Join(dir, "o.txt"), rows); err != nil {
		t.Fatal(err)
	}
	txt, _ := os.ReadFile(filepath.Join(dir, "o.txt"))
	want := "http://a.test/s?q=1234&page=1235\nhttp://a.test/p\t{\"isAdmin\":\"1234\"}\n"
	if string(txt) != want {
		t.Errorf("text %q, want %q", txt, want)
	}
}

func TestCheckInclude(t *testing.T) {
	for _, tc := range []struct {
		method, inc string
		ok          bool
	}{
		{"JSON", `{"a":1}`, true}, {"JSON", `{"a":1,$arjun$}`, true}, {"JSON", `a=1`, false},
		{"XML", `<r><a>1</a></r>`, true}, {"XML", `<r>$arjun$</r>`, true}, {"XML", `<r><a>`, false},
		{"POST", `a=1`, true},
	} {
		if err := checkInclude(tc.method, tc.inc); (err == nil) != tc.ok {
			t.Errorf("%s %q: %v", tc.method, tc.inc, err)
		}
	}
}

// A body method is refused without a named target when there are several.
func TestParamsBodyNeedsScope(t *testing.T) {
	err := cmdParams([]string{"-X", "POST", "-u", "http://127.0.0.1:1/a", "-u", "http://127.0.0.1:1/b"})
	if err == nil || !strings.Contains(err.Error(), "-allow or -scope") {
		t.Errorf("err %v", err)
	}
	err = cmdParams([]string{"-X", "PUT", "-u", "http://127.0.0.1:1/a"})
	if err == nil || !strings.Contains(err.Error(), "use GET, POST, JSON or XML") {
		t.Errorf("err %v", err)
	}
}
