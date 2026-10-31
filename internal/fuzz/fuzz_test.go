package fuzz

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/trannghiach/azhaq/internal/egress"
	"github.com/trannghiach/azhaq/internal/fetch"
	"github.com/trannghiach/azhaq/internal/neterr"
)

func TestExpandPutsKeywordsEverywhere(t *testing.T) {
	tmpl, err := NewTemplate("FUZZM", "http://FUZZ.lab.test/a/FUZZ?q=FUZZ", `{"u":"FUZZ"}`,
		[]string{"X-FUZZ: v-FUZZ", "content-type: application/json", "Host: FUZZ.lab.test"}, []string{"a=1", "b=2"})
	if err != nil {
		t.Fatal(err)
	}
	req := tmpl.Expand(map[string]string{"FUZZ": "adm"})
	if req.Method != "admM" || req.URL != "http://adm.lab.test/a/adm?q=adm" || req.Data != `{"u":"adm"}` {
		t.Fatalf("method, url or body: %+v", req)
	}
	got := map[string]string{}
	for _, h := range req.Headers {
		got[h.Name] = h.Value
	}
	want := map[string]string{"X-Adm": "v-adm", "Content-Type": "application/json", "Host": "adm.lab.test", "Cookie": "a=1; b=2"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("headers %v, want %v", got, want)
	}
	if !tmpl.Has("FUZZ") || tmpl.Has("USER") {
		t.Error("Has")
	}
}

func TestTemplateDefaults(t *testing.T) {
	a, _ := NewTemplate("", "http://x/", "", nil, nil)
	b, _ := NewTemplate("", "http://x/", "k=v", nil, nil)
	c, _ := NewTemplate("PUT", "http://x/", "k=v", nil, nil)
	if a.Method != "GET" || b.Method != "POST" || c.Method != "PUT" {
		t.Errorf("methods %s %s %s", a.Method, b.Method, c.Method)
	}
	if _, err := NewTemplate("", "http://x/", "", []string{"no colon"}, nil); err == nil {
		t.Error("a header without a colon was accepted")
	}
	// The last value for a name wins, as in ffuf.
	d, _ := NewTemplate("", "http://x/", "", []string{"A: 1", "a: 2"}, nil)
	if r := d.Expand(nil); len(r.Headers) != 1 || r.Headers[0].Value != "2" {
		t.Errorf("duplicate header: %+v", r.Headers)
	}
}

func TestCounts(t *testing.T) {
	users := List{Keyword: "USER", Words: []string{"a", "b", "c", "d"}}
	pass := List{Keyword: "PASS", Words: []string{"1", "2", "3"}}
	if n := Total(Clusterbomb, []List{users, pass}); n != 12 {
		t.Errorf("clusterbomb 4x3 = %d", n)
	}
	// ffuf's pitchfork runs as long as its longest list; the shorter start over.
	if n := Total(Pitchfork, []List{users, pass}); n != 4 {
		t.Errorf("pitchfork 4,3 = %d", n)
	}
	if n := Total(Pitchfork, []List{{Keyword: "A", Words: []string{"x", "y"}}, {Keyword: "B", Words: []string{"1", "2"}}}); n != 2 {
		t.Errorf("pitchfork 2,2 = %d", n)
	}
	seen := map[string]bool{}
	for i := 0; i < 12; i++ {
		in := At(Clusterbomb, []List{users, pass}, i)
		seen[in["USER"]+in["PASS"]] = true
	}
	if len(seen) != 12 {
		t.Errorf("clusterbomb gave %d different pairs of 12", len(seen))
	}
	for i, want := range []string{"a1", "b2", "c3", "d1"} {
		in := At(Pitchfork, []List{users, pass}, i)
		if in["USER"]+in["PASS"] != want {
			t.Errorf("pitchfork %d: %v", i, in)
		}
	}
}

func TestReadList(t *testing.T) {
	p := filepath.Join(t.TempDir(), "w.txt")
	os.WriteFile(p, []byte("admin\n# note\n\nlogin # tail\r\nlast"), 0o644)
	l, err := ReadList(p, "FUZZ", ListOptions{Exts: []string{".php", ".bak"}})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"admin", "admin.php", "admin.bak", "# note", "# note.php", "# note.bak", "", ".php", ".bak", "login # tail", "login # tail.php", "login # tail.bak", "last", "last.php", "last.bak"}
	if !reflect.DeepEqual(l.Words, want) {
		t.Errorf("words %q", l.Words)
	}
	l, _ = ReadList(p, "USER", ListOptions{Exts: []string{".php"}, IgnoreComments: true})
	if !reflect.DeepEqual(l.Words, []string{"admin", "", "login", "last"}) {
		t.Errorf("a list of another keyword, comments dropped: %q", l.Words)
	}
	if path, kw := ParseWordlist(p + ":USER"); path != p || kw != "USER" {
		t.Errorf("-w FILE:KEYWORD: %s %s", path, kw)
	}
	if path, kw := ParseWordlist(p); path != p || kw != "FUZZ" {
		t.Errorf("-w FILE: %s %s", path, kw)
	}
}

func resp(status int, length, words, lines int64, body string) *Response {
	return &Response{Status: status, Length: length, Words: words, Lines: lines, Body: []byte(body), Header: http.Header{"Server": {"x"}}, Request: &Request{Input: map[string]string{"FUZZ": "adm.in"}}}
}

func TestMatchersAndFilters(t *testing.T) {
	set := NewSet([]string{"FUZZ"})
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(set.AddMatcher("status", "200-299,301,500"))
	for status, want := range map[int]bool{200: true, 299: true, 301: true, 500: true, 404: false, 302: false} {
		if got := set.Matches(resp(status, 1, 1, 1, "")); got != want {
			t.Errorf("-mc: %d is %v", status, got)
		}
	}
	// A filter drops what a matcher took; a second value joins the first.
	must(set.AddFilter("size", "10"))
	must(set.AddFilter("size", "20-30"))
	must(set.AddFilter("word", "7"))
	for _, c := range []struct {
		size, words int64
		want        bool
	}{{10, 1, false}, {25, 1, false}, {31, 1, true}, {5, 7, false}, {5, 8, true}} {
		if got := set.Matches(resp(200, c.size, c.words, 1, "")); got != c.want {
			t.Errorf("size %d words %d: %v", c.size, c.words, got)
		}
	}
	must(set.AddFilter("line", "3"))
	must(set.AddFilter("status", "301"))
	if set.Matches(resp(200, 1, 1, 3, "")) || set.Matches(resp(301, 1, 1, 1, "")) {
		t.Error("-fl or -fc let an answer through")
	}
	for _, bad := range []string{"x", "5-3", "5-5", "1,,2"} {
		if err := NewSet(nil).AddFilter("size", bad); err == nil {
			t.Errorf("-fs %q was accepted", bad)
		}
	}
	if err := NewSet(nil).AddMatcher("status", "all,200"); err != nil {
		t.Errorf("-mc all: %v", err)
	}
}

func TestMatcherDefaultsAndModes(t *testing.T) {
	// No matcher: nothing is shown. Any matcher is enough, or all with and.
	if NewSet(nil).Matches(resp(200, 1, 1, 1, "")) {
		t.Error("no matcher, yet a match")
	}
	set := NewSet(nil)
	set.AddMatcher("status", "200")
	set.AddMatcher("size", "5")
	if !set.Matches(resp(200, 1, 1, 1, "")) || !set.Matches(resp(404, 5, 1, 1, "")) || set.Matches(resp(404, 1, 1, 1, "")) {
		t.Error("matchers are any of them by default")
	}
	set.MatcherAnd = true
	if set.Matches(resp(200, 1, 1, 1, "")) || !set.Matches(resp(200, 5, 1, 1, "")) {
		t.Error("-mmode and wants every matcher")
	}
	set.AddFilter("word", "9")
	set.AddFilter("line", "9")
	set.FilterAnd = true
	if !set.Matches(resp(200, 5, 9, 1, "")) || set.Matches(resp(200, 5, 9, 9, "")) {
		t.Error("-fmode and drops only what every filter holds")
	}
}

func TestRegexpReadsHeadersAndBodyAndTheInput(t *testing.T) {
	set := NewSet([]string{"FUZZ"})
	set.AddMatcher("status", "all")
	set.AddFilter("regexp", "Password is not correct")
	if set.Matches(resp(200, 1, 1, 1, `{"x":"Password is not correct"}`)) || !set.Matches(resp(200, 1, 1, 1, `{"x":"ok"}`)) {
		t.Error("-fr on the body")
	}
	hdr := NewSet(nil)
	hdr.AddMatcher("regexp", `(?i)server: x`)
	if !hdr.Matches(resp(200, 1, 1, 1, "")) {
		t.Error("-mr does not read the headers")
	}
	// The keyword in the pattern is the input, quoted.
	echo := NewSet([]string{"FUZZ"})
	echo.AddMatcher("regexp", `hello FUZZ!`)
	if echo.Matches(resp(200, 1, 1, 1, "hello admXin!")) || !echo.Matches(resp(200, 1, 1, 1, "hello adm.in!")) {
		t.Error("the keyword is not the quoted input")
	}
	if err := NewSet(nil).AddMatcher("regexp", "("); err == nil {
		t.Error("a bad regexp was accepted")
	}
}

// fake answers from a function of the request, and counts what it got.
type fake struct {
	mu   sync.Mutex
	got  []string
	hook func(*Request) (*Response, error)
}

func (f *fake) Send(_ context.Context, req *Request, _ bool) (*Response, error) {
	f.mu.Lock()
	f.got = append(f.got, req.Method+" "+req.URL)
	f.mu.Unlock()
	r, err := f.hook(req)
	if r != nil {
		r.Request = req
	}
	return r, err
}

func runFake(t *testing.T, f *fake, mut func(*Config)) (Stats, []Result) {
	t.Helper()
	tmpl, _ := NewTemplate("", "http://h.test/FUZZ", "", nil, nil)
	set := NewSet([]string{"FUZZ"})
	set.AddMatcher("status", "200-299,301,302,307,401,403,405,500")
	cfg := Config{Template: tmpl, Mode: Clusterbomb, Set: set, Sender: f, Threads: 4,
		Lists: []List{{Keyword: "FUZZ", Words: []string{"admin", "login", "static", "x", "y", "z"}}}}
	var mu sync.Mutex
	var out []Result
	cfg.OnResult = func(r Result) { mu.Lock(); out = append(out, r); mu.Unlock() }
	if mut != nil {
		mut(&cfg)
	}
	return Run(context.Background(), cfg), out
}

func TestCalibrationFiltersWhatACatchAllAnswers(t *testing.T) {
	f := &fake{hook: func(r *Request) (*Response, error) {
		if strings.HasSuffix(r.URL, "/admin") {
			return &Response{Status: 200, Length: 500, Words: 50, Lines: 9, Header: http.Header{}}, nil
		}
		return &Response{Status: 200, Length: 9984, Words: 800, Lines: 90, Header: http.Header{}}, nil
	}}
	st, out := runFake(t, f, func(c *Config) { c.Calibrate = true })
	if len(out) != 1 || out[0].URL != "http://h.test/admin" {
		t.Fatalf("results %+v", out)
	}
	if !reflect.DeepEqual(st.Filters, []string{"size 9984"}) {
		t.Errorf("filters %v", st.Filters)
	}
	if len(f.got) != 6+6 { // the words, and two names in each of three shapes
		t.Errorf("%d requests", len(f.got))
	}
	// Without it every answer is a result.
	_, out = runFake(t, &fake{hook: f.hook}, nil)
	if len(out) != 6 {
		t.Errorf("without calibration %d results", len(out))
	}
}

func TestCalibrationFallsBackToWordsThenLines(t *testing.T) {
	// The answers to made-up names differ in size (they echo the name) but
	// not in words: the filter is on the words.
	f := &fake{hook: func(r *Request) (*Response, error) {
		if strings.HasSuffix(r.URL, "/admin") {
			return &Response{Status: 200, Length: 500, Words: 50, Lines: 9, Header: http.Header{}}, nil
		}
		return &Response{Status: 200, Length: int64(100 + len(r.URL)), Words: 80, Lines: 9, Header: http.Header{}}, nil
	}}
	st, out := runFake(t, f, func(c *Config) { c.Calibrate = true })
	if len(out) != 1 || !reflect.DeepEqual(st.Filters, []string{"word 80"}) {
		t.Errorf("results %+v filters %v", out, st.Filters)
	}
}

func TestCalibrationIgnoresAnswersTheFiltersAlreadyDrop(t *testing.T) {
	f := &fake{hook: func(r *Request) (*Response, error) {
		return &Response{Status: 200, Length: 30, Words: 1, Lines: 1, Header: http.Header{}}, nil
	}}
	st, _ := runFake(t, f, func(c *Config) { c.Calibrate = true; c.Set.AddFilter("size", "30") })
	if len(st.Filters) != 0 {
		t.Errorf("added %v on top of -fs 30", st.Filters)
	}
}

func TestCalibrationNeedsItsKeyword(t *testing.T) {
	f := &fake{hook: func(r *Request) (*Response, error) {
		return &Response{Status: 200, Header: http.Header{}}, nil
	}}
	st, _ := runFake(t, f, func(c *Config) {
		c.Calibrate, c.CalKeyword = true, "USER"
		c.Lists[0].Keyword = "FUZZ"
	})
	if len(st.Notes) != 1 || len(f.got) != 6 {
		t.Errorf("notes %v, %d requests", st.Notes, len(f.got))
	}
}

func redirectTo(loc string) *Response {
	return &Response{Status: 301, Header: http.Header{"Location": {loc}}}
}

func TestRecursionFollowsDirectoriesToTheDepth(t *testing.T) {
	f := &fake{hook: func(r *Request) (*Response, error) {
		switch r.URL {
		case "http://h.test/admin": // a directory: redirected to itself with a slash
			return redirectTo("/admin/"), nil
		case "http://h.test/admin/login":
			return redirectTo("http://h.test/admin/login/"), nil
		case "http://h.test/admin/login/x":
			return redirectTo("/admin/login/x/"), nil
		case "http://h.test/static": // redirected elsewhere: not a directory
			return redirectTo("/new"), nil
		}
		return &Response{Status: 404, Header: http.Header{}}, nil
	}}
	_, out := runFake(t, f, func(c *Config) { c.Recursion, c.Depth = true, 2 })
	var urls []string
	for _, r := range out {
		urls = append(urls, r.URL)
	}
	sort.Strings(urls)
	// Two levels below the start: admin, admin/login, admin/login/x. The
	// sweep of admin/login/ is the third level and is not made.
	want := []string{"http://h.test/admin", "http://h.test/admin/login", "http://h.test/admin/login/x", "http://h.test/static"}
	if !reflect.DeepEqual(urls, want) {
		t.Errorf("urls %v", urls)
	}
	for _, g := range f.got {
		if strings.Contains(g, "/admin/login/FUZZ") || strings.HasPrefix(g, "GET http://h.test/admin/login/x/") {
			t.Errorf("sent past the depth: %s", g)
		}
	}
	// No depth: the sweep of admin/login/ is made too.
	f2 := &fake{hook: f.hook}
	runFake(t, f2, func(c *Config) { c.Recursion = true })
	found := false
	for _, g := range f2.got {
		found = found || g == "GET http://h.test/admin/login/x/admin"
	}
	if !found {
		t.Error("unlimited recursion did not go below the second level")
	}
	// Off: only the start.
	f3 := &fake{hook: f.hook}
	runFake(t, f3, nil)
	if len(f3.got) != 6 {
		t.Errorf("without -recursion %d requests", len(f3.got))
	}
}

func TestRecursionTakesFilteredAnswersToo(t *testing.T) {
	f := &fake{hook: func(r *Request) (*Response, error) {
		if r.URL == "http://h.test/admin" {
			return redirectTo("/admin/"), nil
		}
		return &Response{Status: 404, Header: http.Header{}}, nil
	}}
	_, out := runFake(t, f, func(c *Config) {
		c.Recursion, c.Depth = true, 1
		c.Set.AddFilter("status", "301")
	})
	if len(out) != 0 {
		t.Errorf("a filtered answer was shown: %+v", out)
	}
	found := false
	for _, g := range f.got {
		found = found || g == "GET http://h.test/admin/x"
	}
	if !found {
		t.Error("ffuf recurses on every redirect to the same directory, shown or not")
	}
}

func TestScopeKeepsRequestsToHosts(t *testing.T) {
	f := &fake{hook: func(r *Request) (*Response, error) {
		return &Response{Status: 200, Header: http.Header{}}, nil
	}}
	st, out := runFake(t, f, func(c *Config) {
		c.Template, _ = NewTemplate("", "http://FUZZ.lab.test/", "", nil, nil)
		c.Allow = func(h string) bool { return h != "x.lab.test" && h != "y.lab.test" }
	})
	if st.OutOfScope != 2 || len(out) != 4 || len(f.got) != 4 {
		t.Errorf("out of scope %d, results %d, sent %d", st.OutOfScope, len(out), len(f.got))
	}
}

func TestRunStopsWhenTheBudgetIsSpent(t *testing.T) {
	var n int
	var mu sync.Mutex
	f := &fake{hook: func(r *Request) (*Response, error) {
		mu.Lock()
		defer mu.Unlock()
		if n++; n > 2 {
			return nil, neterr.ErrBudget
		}
		return &Response{Status: 200, Header: http.Header{}}, nil
	}}
	st, out := runFake(t, f, func(c *Config) { c.Threads = 1 })
	if !st.Spent || len(out) != 2 {
		t.Errorf("spent %v, results %d", st.Spent, len(out))
	}
}

func TestRunStopsWhenTheTargetDoesNotAnswer(t *testing.T) {
	f := &fake{hook: func(r *Request) (*Response, error) {
		return nil, context.DeadlineExceeded
	}}
	st, _ := runFake(t, f, func(c *Config) { c.Threads = 1; c.OriginTrips = 3 })
	if len(st.Down) != 1 || st.Down[0] != "http://h.test" || st.Errors != 3 {
		t.Errorf("down %v errors %d", st.Down, st.Errors)
	}
	// A failed request is tried once more.
	if len(f.got) != 6 {
		t.Errorf("%d requests", len(f.got))
	}
}

func TestSenderCountsLikeFfuf(t *testing.T) {
	var host, accept, method, body, ctype string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, accept, method, ctype = r.Host, r.Header.Get("Accept"), r.Method, r.Header.Get("Content-Type")
		b := make([]byte, 100)
		n, _ := r.Body.Read(b)
		body = string(b[:n])
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Location", "/a/")
		w.WriteHeader(http.StatusMovedPermanently)
		fmt.Fprint(w, "one two  three\nfour\n")
	}))
	defer srv.Close()
	fetch.Reset()
	s := mustSender(t, HTTPOptions{Timeout: 5 * time.Second, Threads: 2})
	tmpl, _ := NewTemplate("POST", srv.URL+"/a", `{"k":"FUZZ"}`, []string{"Host: FUZZ.lab.test", "Content-Type: application/json"}, nil)
	req := tmpl.Expand(map[string]string{"FUZZ": "v"})
	r, err := s.Send(context.Background(), &req, true)
	if err != nil {
		t.Fatal(err)
	}
	// "one two  three\nfour\n": 3 spaces plus one, 2 newlines plus one.
	if r.Status != 301 || r.Length != 20 || r.Words != 4 || r.Lines != 3 || string(r.Body) != "one two  three\nfour\n" {
		t.Errorf("answer %+v", r)
	}
	if host != "v.lab.test" || method != "POST" || body != `{"k":"v"}` || ctype != "application/json" || accept != "" {
		t.Errorf("sent host %q method %q body %q type %q accept %q", host, method, body, ctype, accept)
	}
	if loc := RedirectLocation(r, false); loc != "/a/" {
		t.Errorf("location %q", loc)
	}
	if loc := RedirectLocation(r, true); loc != srv.URL+"/a/" {
		t.Errorf("absolute location %q", loc)
	}
	if r2, _ := s.Send(context.Background(), &req, false); r2.Body != nil || r2.Words != 4 {
		t.Errorf("body kept without a regexp: %+v", r2)
	}
}

// express answers a redirect with a body that depends on Accept, as
// Express's res.redirect does: a page for a browser's, a line for none.
func express(seen *atomic.Value) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if seen != nil {
			seen.Store(r.Header.Clone())
		}
		w.Header().Set("Location", r.URL.Path+"/")
		w.WriteHeader(http.StatusMovedPermanently)
		if strings.Contains(r.Header.Get("Accept"), "text/html") {
			fmt.Fprint(w, "<p>Moved Permanently. Redirecting to <a>/app/</a></p>")
			return
		}
		fmt.Fprint(w, "Moved Permanently. Redirecting to /app/")
	})
}

func TestSenderAsksAsFfufDoes(t *testing.T) {
	var seen atomic.Value
	srv := httptest.NewServer(express(&seen))
	defer srv.Close()
	fetch.Reset()
	s := mustSender(t, HTTPOptions{Timeout: 5 * time.Second, Threads: 1})
	tmpl, _ := NewTemplate("", srv.URL+"/FUZZ", "", nil, nil)
	req := tmpl.Expand(map[string]string{"FUZZ": "app"})
	r, err := s.Send(context.Background(), &req, false)
	if err != nil {
		t.Fatal(err)
	}
	// The body a ffuf-style request (no Accept) is answered with.
	want := len("Moved Permanently. Redirecting to /app/")
	if r.Length != int64(want) || r.Words != 5 || r.Lines != 1 {
		t.Errorf("size %d words %d lines %d, want %d 5 1", r.Length, r.Words, r.Lines, want)
	}
	h := seen.Load().(http.Header)
	if _, ok := h["Accept"]; ok || h.Get("Accept-Encoding") != "gzip" {
		t.Errorf("sent Accept %q, Accept-Encoding %q", h.Values("Accept"), h.Get("Accept-Encoding"))
	}
	// A header the user gives wins.
	tmpl, _ = NewTemplate("", srv.URL+"/FUZZ", "", []string{"Accept: text/html"}, nil)
	req = tmpl.Expand(map[string]string{"FUZZ": "app"})
	if r, _ = s.Send(context.Background(), &req, false); r.Length == int64(want) {
		t.Errorf("-H Accept did not reach the server: size %d", r.Length)
	}
}

func TestSenderSpendsTheBudget(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	fetch.Reset()
	egress.SetMaxRequests(2)
	defer fetch.Reset()
	s := mustSender(t, HTTPOptions{Timeout: time.Second, Threads: 1})
	tmpl, _ := NewTemplate("", srv.URL+"/", "", nil, nil)
	req := tmpl.Expand(nil)
	var errs []error
	for i := 0; i < 3; i++ {
		_, err := s.Send(context.Background(), &req, false)
		errs = append(errs, err)
	}
	if errs[0] != nil || errs[1] != nil || errs[2] == nil || egress.Sent() != 2 {
		t.Errorf("errors %v, sent %d", errs, egress.Sent())
	}
}

// An answer cut off mid-body is an error, not a short page that a size
// filter calibrated on the whole one would let through.
func TestSenderRefusesACutOffAnswer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "9984")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "<html>")
		conn, _, _ := w.(http.Hijacker).Hijack()
		conn.Close()
	}))
	defer srv.Close()
	fetch.Reset()
	s := mustSender(t, HTTPOptions{Timeout: time.Second, Threads: 1})
	tmpl, _ := NewTemplate("", srv.URL+"/FUZZ", "", nil, nil)
	req := tmpl.Expand(map[string]string{"FUZZ": "zh-cn"})
	if r, err := s.Send(context.Background(), &req, false); err == nil {
		t.Errorf("cut-off answer taken: %+v", r)
	}
}

func mustSender(t *testing.T, o HTTPOptions) Sender {
	t.Helper()
	s, err := NewSender(o)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
