package connector

import (
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
		"URL https://www.example.com/api/login application",
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
