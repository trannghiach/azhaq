package httpcol

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/trannghiach/azhaq/internal/fetch"
	"github.com/trannghiach/azhaq/types"
)

func TestParsePorts(t *testing.T) {
	got, err := ParsePorts("http:80,https:443, 8000-8002,https:9000-9001")
	if err != nil {
		t.Fatal(err)
	}
	want := []PortSpec{{80, "http"}, {443, "https"}, {8000, ""}, {8001, ""}, {8002, ""}, {9000, "https"}, {9001, "https"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v", got)
	}
	for _, bad := range []string{"x", "0", "70000", "80-70", "ftp:21", "8o"} {
		if _, err := ParsePorts(bad); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
}

func TestParseRawRequest(t *testing.T) {
	rr, err := ParseRawRequest([]byte("POST /api/x?y=1 HTTP/1.1\r\nHost: app.example\r\nContent-Type: application/json\r\nX-A: b\r\n\r\n{\"a\":1}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if rr.Method != "POST" || rr.Path != "/api/x?y=1" || rr.Host != "app.example" || rr.Header.Get("X-A") != "b" || rr.Header.Get("Host") != "" || string(rr.Body) != `{"a":1}` {
		t.Errorf("parsed %+v body %q", rr, rr.Body)
	}
	if _, err := ParseRawRequest([]byte("nonsense")); err == nil {
		t.Error("a request line needs a path")
	}
}

func TestTargetsUnderSpec(t *testing.T) {
	host := types.Seed{Type: types.TypeHostname, Keys: map[string]string{"fqdn": "app.example.org"}}
	ip := types.Seed{Type: types.TypeIPAddress, Keys: map[string]string{"ip": "10.0.0.5"}}
	c := &Collector{Spec: &Spec{Ports: []PortSpec{{80, ""}, {8080, ""}, {8443, "https"}, {9001, ""}, {443, ""}}}}
	want := [][]string{
		{"http://app.example.org/", "https://app.example.org:80/"},
		{"http://app.example.org:8080/", "https://app.example.org:8080/"}, // httpx asks 8080 over plain HTTP first
		{"https://app.example.org:8443/"},
		{"http://app.example.org:9001/", "https://app.example.org:9001/"}, // so does any port above 1024
		{"https://app.example.org/", "http://app.example.org:443/"},
	}
	if got := c.targets(host); !reflect.DeepEqual(got, want) {
		t.Errorf("ports %v", got)
	}
	// -p applies to an address too, which -web-ports never did.
	if got := c.targets(ip); len(got) != 5 || got[2][0] != "https://10.0.0.5:8443/" {
		t.Errorf("address %v", got)
	}
	nf := &Collector{Spec: &Spec{NoFallback: true}}
	if got := nf.targets(host); !reflect.DeepEqual(got, [][]string{{"https://app.example.org/"}, {"http://app.example.org/"}}) {
		t.Errorf("-nf %v", got)
	}
	paths := &Collector{Spec: &Spec{Paths: []string{"/a", "b?x=1"}}}
	if got := paths.targets(host); !reflect.DeepEqual(got, [][]string{{"https://app.example.org/a", "http://app.example.org/a"}, {"https://app.example.org/b?x=1", "http://app.example.org/b?x=1"}}) {
		t.Errorf("-path %v", got)
	}
	// Without a Spec the targets are what a run always asked.
	if got := (&Collector{}).targets(host); !reflect.DeepEqual(got, [][]string{{"https://app.example.org/", "http://app.example.org/"}}) {
		t.Errorf("run %v", got)
	}
}

func TestMethodsBodyAndRows(t *testing.T) {
	fetch.Reset()
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		seen = append(seen, r.Method+" "+string(b)+" "+r.Header.Get("Accept"))
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<html><title>\n Spaced   Title\n</title><body>b</body></html>"))
	}))
	defer srv.Close()
	spec := &Spec{Methods: []string{"GET", "POST"}, Body: "a=1", Hashes: []string{"md5"}, Preview: 10, Evidence: true}
	if err := spec.Apply(); err != nil {
		t.Fatal(err)
	}
	c := New(srv.Client())
	c.NoFavicon, c.Probe, c.Spec = true, true, spec
	var rows []map[string]any
	meta, err := c.Run(context.Background(), types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": srv.URL + "/"}}, func(o types.Observation) error {
		var m map[string]any
		_ = json.Unmarshal(o.Payload, &m)
		rows = append(rows, m)
		if ev, ok := TakeEvidence(o.Source); !ok || ev.Method == "" || !strings.HasPrefix(ev.Head, "HTTP/1.1 200") {
			t.Errorf("evidence for %s: %v %+v", o.Source, ok, ev)
		}
		return nil
	})
	if err != nil || meta.EmitCount != 2 || len(rows) != 2 {
		t.Fatalf("meta %+v err %v rows %d", meta, err, len(rows))
	}
	if rows[0]["method"] != "GET" || rows[1]["method"] != "POST" {
		t.Errorf("methods %v %v", rows[0]["method"], rows[1]["method"])
	}
	// httpx's title keeps the spaces inside and drops the newlines.
	if rows[0]["title"] != "Spaced   Title" {
		t.Errorf("title %q", rows[0]["title"])
	}
	// The preview has its tags stripped, and a title's text goes with them, as httpx's.
	if rows[0]["body_preview"] != "b" {
		t.Errorf("preview %q", rows[0]["body_preview"])
	}
	if h, _ := rows[0]["hash"].(map[string]any); h["body_md5"] == nil || h["header_md5"] == nil {
		t.Errorf("hash %v", rows[0]["hash"])
	}
	// -body goes with every method, as httpx sends it; no Accept goes with any.
	if len(seen) != 2 || seen[0] != "GET a=1 " || seen[1] != "POST a=1 " {
		t.Errorf("server saw %q", seen)
	}
}

func TestFollowSettings(t *testing.T) {
	fetch.Reset()
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		switch r.URL.Path {
		case "/":
			http.Redirect(w, r, "/a", http.StatusFound)
		case "/a":
			http.Redirect(w, r, "/b", http.StatusFound)
		default:
			_, _ = w.Write([]byte("<title>end</title>"))
		}
	}))
	defer srv.Close()
	for _, c := range []struct {
		spec     Spec
		hits     int
		status   float64
		finalURL bool
	}{
		{Spec{}, 1, 302, false}, // no -fr: one request, the first answer
		{Spec{Follow: true, MaxRedirects: 10}, 3, 200, true},
		{Spec{Follow: true, MaxRedirects: 2}, 2, 302, true}, // httpx's -maxr 2 stops at the second redirect
	} {
		fetch.Reset()
		hits = 0
		spec := c.spec
		if err := spec.Apply(); err != nil {
			t.Fatal(err)
		}
		col := New(srv.Client())
		col.NoFavicon, col.Probe, col.Spec = true, true, &spec
		p := payloadOf(t, col, types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": srv.URL + "/"}})
		if hits != c.hits {
			t.Errorf("%+v: %d requests, want %d", c.spec, hits, c.hits)
		}
		last := p["hops"].([]any)
		if got := last[len(last)-1].(map[string]any)["status"]; got != c.status {
			t.Errorf("%+v: last status %v", c.spec, got)
		}
	}
}
