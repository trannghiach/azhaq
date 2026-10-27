package connector

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadAnyFormats(t *testing.T) {
	in := strings.Join([]string{
		`{"host":"api.example.com","input":"example.com","source":"crtsh"}`,
		`{"host":"www.example.com","a":["192.0.2.1"],"cname":["edge.cdn.test"]}`,
		`{"timestamp":"2026-10-26T00:00:00Z","url":"https://www.example.com","input":"www.example.com","host":"www.example.com","host_ip":"192.0.2.1","a":["192.0.2.1"],"status_code":200,"title":"Home","webserver":"nginx","tech":["Nginx"]}`,
		`{"timestamp":"2026-10-26T00:00:00Z","request":{"method":"POST","endpoint":"https://www.example.com/api/login"},"response":{"status_code":401}}`,
		`{"host":"www.example.com","ip":"192.0.2.1","port":8443,"protocol":"tcp"}`,
		`{"template-id":"exposed-git","info":{"name":"Git config","severity":"medium"},"matched-at":"https://www.example.com/.git/config","host":"www.example.com"}`,
		`{"url":"https://www.example.com/old/page?id=1"}`,
		`https://www.example.com/robots.txt`,
		`legacy.example.com`,
		`192.0.2.9`,
	}, "\n")
	facts, formats, err := ReadAny([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{FormatSubfinder, FormatDNSX, FormatHTTPX, FormatKatana, FormatNaabu, FormatNuclei, FormatURLs} {
		if formats[f] != 1 {
			t.Errorf("%s read %d times: %v", f, formats[f], formats)
		}
	}
	if formats[FormatLines] != 3 {
		t.Errorf("plain lines %v", formats)
	}
	var keys []string
	for _, f := range facts {
		t, k := f.Entity()
		keys = append(keys, string(t)+" "+k+" "+f.ObsKind)
	}
	want := []string{
		"Hostname api.example.com hostname",
		"Hostname www.example.com dns",
		"URL https://www.example.com/ application",
		"Hostname www.example.com dns",
		"URL https://www.example.com/api/login url", // a POST is what the route takes, not its answer
		"Hostname www.example.com ports",
		"URL https://www.example.com/.git/config finding",
		"URL https://www.example.com/old/page?id=1 url",
		"URL https://www.example.com/robots.txt ",
		"Hostname legacy.example.com ",
		"IPAddress 192.0.2.9 ",
	}
	if strings.Join(keys, "\n") != strings.Join(want, "\n") {
		t.Errorf("facts\n%s\nwant\n%s", strings.Join(keys, "\n"), strings.Join(want, "\n"))
	}
}

func TestReadAnyFFUFAndExport(t *testing.T) {
	facts, formats, err := ReadAny([]byte(`{"commandline":"ffuf …","results":[{"url":"https://app.test/admin","status":403,"length":10,"words":2,"lines":1}]}`))
	if err != nil || formats[FormatFFUF] != 1 || len(facts) != 1 {
		t.Fatalf("ffuf %v %v %v", facts, formats, err)
	}
	export := `{"kind":"entity","entity":{"id":"e1","type":"URL","key":"https://app.test/"},"scope":"target"}
{"kind":"observation","observation":{"id":"o1","entity_id":"e1","collector":"azhaq-http","kind":"application","payload":{"status":200}}}
{"kind":"edge","edge":{"from":"e1","to":"e2","type":"ON_HOST"}}`
	facts, formats, err = ReadAny([]byte(export))
	if err != nil || formats[FormatExport] != 3 || len(facts) != 2 || facts[1].Collector != "azhaq-http" {
		t.Fatalf("export %+v %v %v", facts, formats, err)
	}
	if _, _, err := ReadAny([]byte("{\n  \"openapi\": \"3.0.0\"\n}\n")); err == nil || !strings.Contains(err.Error(), "not JSON lines") {
		t.Errorf("a pretty-printed document: %v", err)
	}
}

// payloads reads a fixture and indexes each fact's payload by its entity
// and kind.
func payloads(t *testing.T, name string) map[string]map[string]any {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "fixtures", name))
	if err != nil {
		t.Fatal(err)
	}
	facts, _, err := ReadAny(raw)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]map[string]any{}
	for _, f := range facts {
		var p map[string]any
		if err := json.Unmarshal(f.Payload, &p); err != nil {
			t.Fatal(err)
		}
		out[f.EntityKey+" "+f.ObsKind] = p
	}
	return out
}

// httpx's fields are taken in under azhaq-http's names and meanings:
// status is the first answer, the URL the service's.
func TestReadAnyHTTPXFields(t *testing.T) {
	got := payloads(t, "httpx.jsonl")
	www := got["https://www.example.com/ application"]
	want := map[string]any{"url": "https://www.example.com/", "status": 200.0, "title": "Example Store", "server": "nginx/1.25.3",
		"content_type": "text/html", "length": 5120.0, "words": 412.0, "lines": 63.0, "ms": 152.0, "ip": "192.0.2.10", "favicon": "-1840324437"}
	for k, v := range want {
		if www[k] != v {
			t.Errorf("www %s = %v, want %v (%v)", k, www[k], v, www)
		}
	}
	if api := got["https://api.example.com:8443/ application"]; api["ip"] != "192.0.2.11" || api["status"] != 401.0 {
		t.Errorf("an address written as host: %v", api)
	}
	old := got["https://old.example.com/ application"]
	if old["status"] != 301.0 || old["final_status"] != 200.0 || old["final_url"] != "https://www.example.com/" || old["cdn"] != "cloudflare" || old["location"] != "https://www.example.com/" {
		t.Errorf("-fr redirect: %v", old)
	}
	if legacy := got["http://legacy.example.com/ error"]; legacy["error"] != `cause="context deadline exceeded"` || got["http://legacy.example.com/ application"] != nil {
		t.Errorf("a failed probe is no answer: %v", got)
	}
}

// A GET katana sent is the URL's answer; a POST (a filled form, a call a
// script made) says what the route takes, its method and body fields; the
// forms katana read are the page's.
func TestReadAnyKatanaFields(t *testing.T) {
	got := payloads(t, "katana.jsonl")
	root := got["https://shop.example.com/ application"]
	if root["status"] != 200.0 || root["content_type"] != "text/html; charset=utf-8" || root["server"] != "nginx" || root["length"] != 2048.0 {
		t.Errorf("root answer %v", root)
	}
	if tech, _ := root["tech"].([]any); len(tech) != 2 {
		t.Errorf("technologies %v", root)
	}
	if p := got["https://shop.example.com/api/products?page=2 application"]; p["status"] != 200.0 || p["length"] != 11.0 {
		t.Errorf("api answer %v", p)
	}
	for route, op := range map[string]string{
		"https://shop.example.com/rest/user/login": `{"body":["email","password"],"body_type":"application/json","method":"POST"}`,
		"https://shop.example.com/login":           `{"body":["csrf","email","password"],"body_type":"application/x-www-form-urlencoded","method":"POST"}`,
		"https://shop.example.com/profile/avatar":  `{"body":["avatar","note"],"body_type":"multipart/form-data","method":"POST"}`,
	} {
		if got[route+" application"] != nil {
			t.Errorf("a POST is not the URL's answer: %s", route)
		}
		raw, _ := json.Marshal(got[route+" url"])
		if s := string(raw); !strings.Contains(s, `"methods":["POST"]`) || !strings.Contains(s, `"ops":[`+op+`]`) {
			t.Errorf("%s: %s", route, s)
		}
	}
	raw, _ := json.Marshal(got["https://shop.example.com/ form"])
	if !strings.Contains(string(raw), `"action":"https://shop.example.com/login","fields":["email","password","csrf"],"method":"POST"`) {
		t.Errorf("form %s", raw)
	}
	if backup := got["https://shop.example.com/backup/ url"]; backup == nil || backup["status"] != nil {
		t.Errorf("a request with no answer is a found URL: %v", got)
	}
}

// ffuf's report and its -json lines are the same hits: answers to a GET,
// unless -X asked with another method.
func TestReadAnyFFUFFields(t *testing.T) {
	got := payloads(t, "ffuf.json")
	admin := got["https://shop.example.com/admin application"]
	if admin["status"] != 301.0 || admin["length"] != 169.0 || admin["location"] != "https://shop.example.com/admin/" || admin["content_type"] != "text/html" || admin["ms"] != 41.0 {
		t.Errorf("admin %v", admin)
	}
	line := `{"input":{"FFUFHASH":"5d2a91","FUZZ":"admin"},"position":12,"status":301,"length":169,"words":5,"lines":8,"content-type":"text/html","redirectlocation":"https://shop.example.com/admin/","scraper":{},"duration":41823456,"resultfile":"","url":"https://shop.example.com/admin","host":"shop.example.com"}`
	facts, formats, err := ReadAny([]byte(line + "\n"))
	if err != nil || formats[FormatFFUF] != 1 || len(facts) != 1 || facts[0].ObsKind != "application" {
		t.Fatalf("ffuf -json %v %v %v", facts, formats, err)
	}
	post := `{"commandline":"ffuf -X POST","results":[{"status":200,"url":"https://shop.example.com/api/x"},{"status":405,"url":"https://shop.example.com/api/y"},{"status":404,"url":"https://shop.example.com/api/z"}],"config":{"method":"POST"}}`
	if facts, _, _ := ReadAny([]byte(post)); len(facts) != 1 || facts[0].ObsKind != "url" || !strings.Contains(string(facts[0].Payload), `"methods":["POST"]`) || !strings.Contains(string(facts[0].Payload), "/api/x") {
		t.Errorf("ffuf -X POST: only the route that took it %+v", facts)
	}
	fuzz := `{"commandline":"ffuf -X FUZZ","results":[{"input":{"FUZZ":"PUT"},"status":201,"url":"https://shop.example.com/api/x"}],"config":{"method":"FUZZ"}}`
	if facts, _, _ := ReadAny([]byte(fuzz)); len(facts) != 1 || !strings.Contains(string(facts[0].Payload), `"methods":["PUT"]`) {
		t.Errorf("ffuf -X FUZZ: the method is the input %+v", facts)
	}
}

// httpx -irr writes the request as a string: still httpx, not katana.
func TestReadAnyHTTPXWithRequest(t *testing.T) {
	line := `{"timestamp":"2026-10-27T10:00:00Z","url":"https://www.example.com","host":"www.example.com","status_code":200,"request":"GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n","response":"HTTP/1.1 200 OK\r\n\r\n"}`
	facts, formats, err := ReadAny([]byte(line + "\n"))
	if err != nil || formats[FormatHTTPX] != 1 || len(facts) == 0 {
		t.Fatalf("httpx -irr %v %v %v", facts, formats, err)
	}
}

// One record shape ingest does not know does not lose the rest; katana's
// request-only records (headless, no answer) are URLs.
func TestReadLinesSkips(t *testing.T) {
	in := `{"request":{"endpoint":"http://a.test/x","method":"GET"}}
{"what":"no idea"}
not a url at all
{"timestamp":"2026-10-27T10:00:00Z","request":{"method":"GET","endpoint":"http://a.test/y"},"response":{"status_code":200}}
`
	facts, formats, skipped, err := ReadLines([]byte(in))
	if err != nil || formats[FormatKatana] != 2 || formats["skipped"] != 2 || len(skipped) != 2 || !strings.HasPrefix(skipped[0], "line 2: ") || len(facts) < 2 {
		t.Fatalf("facts %d formats %v skipped %q err %v", len(facts), formats, skipped, err)
	}
	if _, _, _, err := ReadLines([]byte("{\"what\":1}\nnot a url\n")); err == nil {
		t.Error("a file with nothing readable ingested")
	}
}
