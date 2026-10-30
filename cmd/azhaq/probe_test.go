package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// probeSite is a server with a few pages, counting what it is sent.
type probeSite struct {
	*httptest.Server
	mu   sync.Mutex
	seen []string
}

func newProbeSite(t *testing.T) *probeSite {
	t.Helper()
	s := &probeSite{}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.seen = append(s.seen, r.Method+" "+r.URL.RequestURI())
		s.mu.Unlock()
		switch r.URL.Path {
		case "/":
			http.Redirect(w, r, "/home", http.StatusFound)
		case "/home":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("<title>Home</title><p>welcome admin</p>"))
		case "/api":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"ok":true}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *probeSite) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.seen)
}

func probeRows(t *testing.T, out string) []map[string]any {
	t.Helper()
	var rows []map[string]any
	for _, l := range lines(out) {
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("row %q: %v", l, err)
		}
		rows = append(rows, m)
	}
	return rows
}

// probe follows no redirect unless asked: a row's status, title and length
// all come from the same answer.
func TestProbeFollowsNothingByDefault(t *testing.T) {
	t.Chdir(t.TempDir())
	site := newProbeSite(t)
	out, rep, code := runContract(t, "probe", "-u", site.URL+"/")
	rows := probeRows(t, out)
	if code != exitOK || len(rows) != 1 || site.count() != 1 {
		t.Fatalf("exit %d, %d rows, %d requests: %s", code, len(rows), site.count(), out)
	}
	r := rows[0]
	if r["status_code"] != float64(302) || r["title"] != nil || r["location"] != "/home" || r["chain_status_codes"] != nil {
		t.Errorf("row %v", r)
	}
	if rep.Requests != 1 {
		t.Errorf("summary counts %d requests", rep.Requests)
	}
	out, _, _ = runContract(t, "probe", "-u", site.URL+"/", "-fr")
	r = probeRows(t, out)[0]
	codes, _ := r["chain_status_codes"].([]any)
	if r["status_code"] != float64(200) || r["title"] != "Home" || len(codes) != 2 || r["final_url"] == nil {
		t.Errorf("with -fr: %v", r)
	}
}

// Matchers and filters keep httpx's semantics, over the response as sent.
func TestProbeMatchersAndFilters(t *testing.T) {
	t.Chdir(t.TempDir())
	site := newProbeSite(t)
	targets := []string{"-u", site.URL + "/home", "-u", site.URL + "/api", "-u", site.URL + "/missing"}
	for _, c := range []struct {
		flags []string
		want  int
	}{
		{nil, 3},
		{[]string{"-mc", "200"}, 2},
		{[]string{"-fc", "200"}, 1},
		{[]string{"-mc", "2xx", "-ms", "ADMIN"}, 1}, // a string matches in any case
		{[]string{"-mr", "welcome", "-mr", "admin"}, 1},
		{[]string{"-fe", "^HTTP/1.1 404"}, 2}, // the head is part of the response
		{[]string{"-mdc", `status_code == 200 && contains(body, "ok")`}, 1},
		{[]string{"-fdc", `contains(raw_header, "json")`}, 2},
		{[]string{"-mwc", "2"}, 1},
	} {
		out, rep, code := runContract(t, append(append([]string{"probe"}, targets...), c.flags...)...)
		if got := len(probeRows(t, out)); got != c.want || code != exitOK {
			t.Errorf("%v: %d rows, want %d (exit %d)\n%s", c.flags, got, c.want, code, out)
		}
		if c.want < 3 && !strings.Contains(strings.Join(rep.Notes, " "), "left out") {
			t.Errorf("%v: the summary does not say rows were left out: %v", c.flags, rep.Notes)
		}
	}
	// A condition that cannot be judged is said, not a silent miss.
	_, rep, _ := runContract(t, "probe", "-u", site.URL+"/home", "-mdc", "no_such_field == 1")
	if !strings.Contains(strings.Join(rep.Notes, " "), "could not be judged") {
		t.Errorf("notes %v", rep.Notes)
	}
	// A bad flag is a usage error before anything is sent.
	n := site.count()
	for _, bad := range [][]string{{"-mc", "x"}, {"-mr", "("}, {"-mrt", "fast"}, {"-mdc", "contains("}, {"-hash", "crc"}, {"-p", "99999"}} {
		_, _, code := runContract(t, append([]string{"probe", "-u", site.URL + "/home"}, bad...)...)
		if code != exitUsage {
			t.Errorf("%v: exit %d", bad, code)
		}
	}
	if site.count() != n {
		t.Errorf("a usage error sent requests")
	}
}

// A target that gets no answer is a row with failed:true, and the summary says so.
func TestProbeFailureRows(t *testing.T) {
	t.Chdir(t.TempDir())
	site := newProbeSite(t)
	dead := "127.0.0.1:1" // nothing listens
	out, rep, code := runContract(t, "probe", "-u", site.URL+"/home", "-u", dead)
	rows := probeRows(t, out)
	if len(rows) != 2 {
		t.Fatalf("rows %s", out)
	}
	var failed map[string]any
	for _, r := range rows {
		if r["failed"] == true {
			failed = r
		}
	}
	if failed == nil || failed["input"] != dead || failed["error"] == nil {
		t.Errorf("failed row %v", failed)
	}
	if code != exitPartial || rep.Counts["without an answer"] != 1 {
		t.Errorf("exit %d, counts %v, summary %+v", code, rep.Counts, rep)
	}
	// The text form prints [FAILED] with -probe.
	text, _, _ := captureBoth(t, func() error { return run([]string{"probe", "-u", dead, "-probe", "-silent"}) })
	if !strings.Contains(text, "[FAILED]") {
		t.Errorf("text %q", text)
	}
}

// -x, -body and -rr send what is asked, to the targets given: counted,
// and said in the summary.
func TestProbeSendsWhatIsAsked(t *testing.T) {
	t.Chdir(t.TempDir())
	site := newProbeSite(t)
	_, rep, _ := runContract(t, "probe", "-u", site.URL+"/api", "-x", "GET,POST,DELETE", "-body", "a=1", "-ledger", "led.jsonl")
	got := strings.Join(site.seen, ";")
	if site.count() != 3 || !strings.Contains(got, "POST /api") || !strings.Contains(got, "DELETE /api") {
		t.Errorf("server saw %v", site.seen)
	}
	if rep.Requests != 3 || !strings.Contains(strings.Join(rep.Notes, " "), "requests other than GET were sent") {
		t.Errorf("requests %d, notes %v", rep.Requests, rep.Notes)
	}
	raw, _ := os.ReadFile("led.jsonl")
	if n := strings.Count(string(raw), `"method":"POST"`) + strings.Count(string(raw), `"method":"DELETE"`); n != 2 {
		t.Errorf("the ledger holds %d writes:\n%s", n, raw)
	}
	// A raw request file.
	site.seen = nil
	file := filepath.Join(t.TempDir(), "req.txt")
	_ = os.WriteFile(file, []byte("PUT /api HTTP/1.1\r\nHost: x\r\nX-K: v\r\n\r\nbody"), 0o644)
	_, rep, _ = runContract(t, "probe", "-u", site.URL, "-rr", file)
	if len(site.seen) != 1 || site.seen[0] != "PUT /api" || !strings.Contains(strings.Join(rep.Notes, " "), "can change data") {
		t.Errorf("server saw %v, notes %v", site.seen, rep.Notes)
	}
}

// -sr stores the request and the response as sent, with an index.
func TestProbeStoresResponses(t *testing.T) {
	t.Chdir(t.TempDir())
	site := newProbeSite(t)
	out, _, _ := runContract(t, "probe", "-u", site.URL+"/home", "-sr", "-srd", "out", "-irr")
	r := probeRows(t, out)[0]
	path, _ := r["stored_response_path"].(string)
	data, err := os.ReadFile(path)
	if err != nil || !strings.HasPrefix(string(data), "GET /home HTTP/1.1\r\n") || !strings.Contains(string(data), "HTTP/1.1 200 OK") || !strings.Contains(string(data), "welcome admin") {
		t.Errorf("stored %q: %v", data, err)
	}
	idx, _ := os.ReadFile("out/response/index.txt")
	if !strings.Contains(string(idx), path+" "+site.URL+"/home (200 OK)") {
		t.Errorf("index %q", idx)
	}
	if r["request"] == nil || r["body"] == nil || r["raw_header"] == nil {
		t.Errorf("-irr fields %v", r)
	}
}

func TestProbeInputs(t *testing.T) {
	var rep report
	pf := &probeFlags{}
	got, _, err := probeInputs([]string{"a.example,b.example:8080", "*.c.example", "192.0.2.0/30"}, "", pf, nil, 4096, &rep)
	if err != nil {
		t.Fatal(err)
	}
	var in []string
	for _, g := range got {
		in = append(in, g.given)
	}
	want := "a.example b.example:8080 c.example 192.0.2.0 192.0.2.1 192.0.2.2 192.0.2.3"
	if strings.Join(in, " ") != want {
		t.Errorf("inputs %v", in)
	}
	// A range past -max-ips is cut, and the summary says so.
	rep = report{}
	got, _, _ = probeInputs([]string{"10.0.0.0/24"}, "", pf, nil, 10, &rep)
	if len(got) != 10 || len(rep.Notes) != 1 || !strings.Contains(rep.Notes[0], "246 addresses") {
		t.Errorf("%d targets, notes %v", len(got), rep.Notes)
	}
	if _, _, err := probeInputs([]string{"10.0.0.0/33"}, "", pf, nil, 10, &rep); err == nil {
		t.Error("a bad range is an error")
	}
}
