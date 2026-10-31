package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
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

// A raw request's credentials stay out of the workspace, as -header's do.
func TestKeptArgsRedactsRawRequestSecrets(t *testing.T) {
	raw := `{"raw":{"method":"GET","path":"/","header":{"Authorization":["Bearer x"],"X-A":["b"]}}}`
	got := keptArgs([]string{"-probe-opts", raw, "-db", "w.db"})
	if len(got) != 1 || strings.Contains(got[0], "Bearer") || !strings.Contains(got[0], `"X-A"`) {
		t.Errorf("kept %v", got)
	}
}

// A name that does not resolve is one row, its URL's, with what DNS said;
// not a second row for the bare name, and not "no failure recorded".
func TestProbeUnresolvedNameIsOneRow(t *testing.T) {
	t.Chdir(t.TempDir())
	out, rep, _ := runContract(t, "probe", "-u", "http://nosuch-zq81x.invalid")
	rows := probeRows(t, out)
	if len(rows) != 1 || rows[0]["failed"] != true || !strings.Contains(fmt.Sprint(rows[0]["error"]), "special-use name") {
		t.Fatalf("rows %s", out)
	}
	for _, f := range rep.Failed {
		if f.Error == "no answer and no failure recorded" {
			t.Errorf("gap %+v", f)
		}
	}
}

// -rl paces services, as httpx -rl: four services at 4 a second take three
// turns; each one's favicon does not wait for one.
func TestProbeRLPacesServices(t *testing.T) {
	t.Chdir(t.TempDir())
	var args []string
	for i := 0; i < 4; i++ {
		args = append(args, "-u", newProbeSite(t).URL)
	}
	t0 := time.Now()
	out, _, code := runContract(t, append([]string{"probe"}, append(args, "-rl", "4", "-favicon")...)...)
	if el := time.Since(t0); el < 700*time.Millisecond || el > 3*time.Second {
		t.Errorf("4 services at -rl 4 took %v", el)
	}
	if rows := probeRows(t, out); len(rows) != 4 || code != exitOK {
		t.Errorf("exit %d rows %s", code, out)
	}
}

// A URL or a host:port is asked as given, once: the name in it is not asked
// on the web ports nobody named (an extra GET to a public host otherwise).
func TestProbeAsksOnlyWhatIsGiven(t *testing.T) {
	t.Chdir(t.TempDir())
	site := newProbeSite(t)
	hp := strings.TrimPrefix(site.URL, "http://")
	port := hp[strings.LastIndex(hp, ":")+1:]
	for _, in := range []string{site.URL + "/home", "localhost:" + port} {
		out, rep, _ := runContract(t, "probe", "-u", in)
		if rows := probeRows(t, out); len(rows) != 1 {
			t.Errorf("%s: rows %s", in, out)
		}
		if rep.Requests != 1 {
			t.Errorf("%s: %d requests, want 1", in, rep.Requests)
		}
	}
}

// Every input line has one row, its own: a URL and a name that reach one
// page, or two spellings of a URL, are not left with a "no answer" while
// the other gets the answer.
func TestProbeOneRowPerInput(t *testing.T) {
	t.Chdir(t.TempDir())
	site := newProbeSite(t)
	hp := strings.TrimPrefix(site.URL, "http://")
	port := hp[strings.LastIndex(hp, ":")+1:]
	local := "http://localhost:" + port + "/"
	for _, tc := range []struct {
		name     string
		inputs   []string
		flags    []string
		failed   string // the input whose own request fails
		requests int
	}{
		{"two spellings of a URL", []string{site.URL, site.URL + "/"}, nil, "", 1},
		{"host:port and its URL", []string{"localhost:" + port, "http://localhost:" + port}, nil, "", 1},
		{"a URL and a name, in two cases", []string{local, "localhost", "LOCALHOST"}, []string{"-p", port}, "", 1},
		{"a URL that fails and a name that answers", []string{"https://localhost:" + port + "/", "localhost"}, []string{"-p", port}, "https://localhost:" + port + "/", 2},
		{"a line twice", []string{site.URL + "/home", site.URL + "/home"}, nil, "", 1},
	} {
		args := []string{"probe"}
		for _, in := range tc.inputs {
			args = append(args, "-u", in)
		}
		out, rep, code := runContract(t, append(args, tc.flags...)...)
		got := map[string]map[string]any{}
		for _, r := range probeRows(t, out) {
			in, _ := r["input"].(string)
			if got[in] != nil {
				t.Errorf("%s: two rows for %q\n%s", tc.name, in, out)
			}
			got[in] = r
		}
		distinct := map[string]bool{}
		for _, in := range tc.inputs {
			distinct[in] = true
		}
		if len(got) != len(distinct) {
			t.Errorf("%s: %d rows for %d inputs\n%s", tc.name, len(got), len(distinct), out)
		}
		for in, r := range got {
			failed, _ := r["failed"].(bool)
			if failed != (in == tc.failed) {
				t.Errorf("%s: %q failed %v\n%s", tc.name, in, failed, out)
			}
			if failed && strings.Contains(fmt.Sprint(r["error"]), "no answer") {
				t.Errorf("%s: %q failed with %v, not with what its request got", tc.name, in, r["error"])
			}
		}
		if wantCode := map[bool]int{true: exitPartial, false: exitOK}[tc.failed != ""]; code != wantCode || rep.Requests != int64(tc.requests) {
			t.Errorf("%s: exit %d with %d requests, want %d with %d", tc.name, code, rep.Requests, wantCode, tc.requests)
		}
	}
}

// tunnel is a proxy that carries every CONNECT to target, so a name asked
// on port 443 reaches a test server.
func tunnel(t *testing.T, target string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		up, err := net.Dial("tcp", target)
		if r.Method != http.MethodConnect || err != nil {
			http.Error(w, "no tunnel", http.StatusBadGateway)
			return
		}
		conn, _, _ := w.(http.Hijacker).Hijack()
		_, _ = conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
		go func() { _, _ = io.Copy(up, conn); up.Close() }()
		go func() { _, _ = io.Copy(conn, up); conn.Close() }()
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

// A bare name is asked over HTTPS, and over HTTP only when that fails:
// two names that answer on the first try spend two requests and end the
// run complete under -max-requests 2, not stopped with tasks left.
func TestProbeBoundedRunThatAnsweredEverythingIsComplete(t *testing.T) {
	t.Chdir(t.TempDir())
	site := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<title>ok</title>"))
	}))
	t.Cleanup(site.Close)
	resolvers := serveZone(t, fakeZone{a: map[string]string{"a.labtest.com": "192.0.2.1", "b.labtest.org": "192.0.2.2"}})
	out, rep, code := runContract(t, "probe", "-u", "a.labtest.com", "-u", "b.labtest.org", "-max-requests", "2",
		"-resolvers", resolvers, "-proxy", tunnel(t, strings.TrimPrefix(site.URL, "https://")))
	if rows := probeRows(t, out); len(rows) != 2 || code != exitOK || rep.Requests != 2 || rep.Stopped != "" || !rep.Complete {
		t.Errorf("exit %d, %d requests, stopped %q: %s", code, rep.Requests, rep.Stopped, out)
	}
}

// The url of a row is the URL input as it was given, slash, query and
// fragment included, and a bare host's front page has no slash, as in httpx.
func TestProbeURLFieldIsTheInputAsGiven(t *testing.T) {
	t.Chdir(t.TempDir())
	site := newProbeSite(t)
	bare := strings.TrimPrefix(site.URL, "http://")
	want := map[string]string{
		site.URL + "/":        site.URL + "/",
		site.URL + "/#x":      site.URL + "/#x",
		site.URL + "/api?a=1": site.URL + "/api?a=1",
		site.URL + "/api#y":   site.URL + "/api#y",
		bare:                  site.URL,
	}
	args := []string{"probe"}
	for in := range want {
		args = append(args, "-u", in)
	}
	out, _, _ := runContract(t, args...)
	rows := probeRows(t, out)
	if len(rows) != len(want) {
		t.Fatalf("%d rows for %d inputs\n%s", len(rows), len(want), out)
	}
	for _, r := range rows {
		in, _ := r["input"].(string)
		if r["url"] != want[in] {
			t.Errorf("input %q: url %v, want %q", in, r["url"], want[in])
		}
		if in == site.URL+"/#x" && r["path"] != "/" {
			t.Errorf("path %v, want /", r["path"])
		}
	}
}

// As httpx, -p replaces the port of a host:port or URL input: the row is the
// service on the port asked, and its input is the line as given. Without -p
// the input's own port is the one asked.
func TestProbePortsReplaceTheInputsPort(t *testing.T) {
	t.Chdir(t.TempDir())
	one, other := newProbeSite(t), newProbeSite(t)
	port := func(s *probeSite) string { return s.URL[strings.LastIndex(s.URL, ":")+1:] }
	for _, in := range []string{"127.0.0.1:" + port(one), "http://127.0.0.1:" + port(one) + "/"} {
		out, rep, code := runContract(t, "probe", "-u", in, "-p", port(other))
		rows := probeRows(t, out)
		if len(rows) != 1 || rows[0]["input"] != in || rows[0]["port"] != port(other) || rows[0]["failed"] == true || code != exitOK {
			t.Errorf("-p %s on %s: exit %d rows %s", port(other), in, code, out)
		}
		if one.count() != 0 || other.count() != 1 || rep.Requests != 1 {
			t.Errorf("%s: asked %d on its own port, %d on -p, %d requests", in, one.count(), other.count(), rep.Requests)
		}
		other.mu.Lock()
		other.seen = nil
		other.mu.Unlock()
	}
	// A path stays; every port of -p is asked; no -p asks the input's own port.
	out, _, _ := runContract(t, "probe", "-u", "http://127.0.0.1:"+port(one)+"/api", "-p", "http:"+port(other)+","+port(one))
	if rows := probeRows(t, out); len(rows) != 2 {
		t.Errorf("two ports of -p: %s", out)
	}
	if other.seen[0] != "GET /api" {
		t.Errorf("the path is not kept: %v", other.seen)
	}
	one.mu.Lock()
	one.seen = nil
	one.mu.Unlock()
	out, _, _ = runContract(t, "probe", "-u", "127.0.0.1:"+port(one))
	if rows := probeRows(t, out); len(rows) != 1 || rows[0]["port"] != port(one) || one.count() != 1 {
		t.Errorf("without -p: %s", out)
	}
}
