package fuzz

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/andybalholm/brotli"

	"github.com/trannghiach/azhaq/internal/egress"
	"github.com/trannghiach/azhaq/internal/fetch"
)

func TestEncodersMatchFfuf(t *testing.T) {
	for chain, want := range map[string]string{
		"b64encode":                      "YSBiPmM=",
		"urlencode":                      "a+b%3Ec",
		"urlencodeall":                   "%61%20%62%3E%63",
		"hexencode":                      "6120623e63",
		"md5":                            "5d41402abc4b2a76b9719d911017c592",
		"urlencode b64encode":            "YSUyQmJjJTNEYw==",
		"upper":                          "A B>C",
		"unicodeencodeall":               "\\u0061\\u0020\\u0062\\u003e\\u0063",
		"xmlescape":                      "a b&gt;c",
		"jsonescape upper":               "A B>C",
		"utf16 hexencode":                "6100200062003e006300",
		"b64encode b64decode":            "a b>c",
		"unicodeencodeall unicodedecode": "a b>c",
	} {
		c, err := ParseChain(chain)
		if err != nil {
			t.Fatal(chain, err)
		}
		in := "a b>c"
		if chain == "md5" {
			in = "hello"
		}
		if chain == "urlencode b64encode" {
			in = "a+bc=c"
		}
		got, err := c.Apply(in)
		if err != nil || got != want {
			t.Errorf("%s: %q %v, want %q", chain, got, err, want)
		}
	}
	if _, err := ParseChain("nope"); err == nil {
		t.Error("unknown encoder accepted")
	}
	dir := t.TempDir()
	tmpl := filepath.Join(dir, "p.tmpl")
	os.WriteFile(tmpl, []byte("<<#PAYLOAD#>>"), 0o644)
	if c, err := ParseChain(tmpl); err != nil {
		t.Fatal(err)
	} else if got, _ := c.Apply("x"); got != "<<x>>" {
		t.Errorf("template %q", got)
	}
}

func TestSniperTemplates(t *testing.T) {
	tm, _ := NewTemplate("", "http://h/§a§/§b§?q=§c§", "d=§e§", []string{"X-§n§: §v§"}, nil)
	ok, err := HasSniperMarks(tm)
	if !ok || err != nil {
		t.Fatal(ok, err)
	}
	var urls, bodies, hdrs []string
	for _, s := range SniperTemplates(tm) {
		r := s.Expand(map[string]string{"FUZZ": "W"})
		urls = append(urls, r.URL)
		bodies = append(bodies, r.Data)
		for _, h := range r.Headers {
			hdrs = append(hdrs, h.Name+"="+h.Value)
		}
	}
	// 3 URL places, 1 body, header name, header value
	if len(urls) != 6 || urls[0] != "http://h/W/b?q=c" || urls[2] != "http://h/a/b?q=W" || bodies[3] != "d=W" {
		t.Errorf("urls %v bodies %v", urls, bodies)
	}
	if !reflect.DeepEqual(hdrs[len(hdrs)-2:], []string{"X-W=v", "X-N=W"}) {
		t.Errorf("headers %v", hdrs)
	}
	odd, _ := NewTemplate("", "http://h/§a", "", nil, nil)
	if _, err := HasSniperMarks(odd); err == nil {
		t.Error("odd marks accepted")
	}
}

func TestRequestFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "r.txt")
	os.WriteFile(p, []byte("POST /login?x=1 HTTP/1.1\r\nHost: app.test:8443\r\nContent-Length: 5\r\nX-A: b\r\n\r\nu=FUZZ\r\n"), 0o644)
	tm, err := ParseRequestFile(p, "https")
	if err != nil {
		t.Fatal(err)
	}
	r := tm.Expand(map[string]string{"FUZZ": "z"})
	if r.Method != "POST" || r.URL != "https://app.test:8443/login?x=1" || r.Data != "u=z" {
		t.Errorf("%+v", r)
	}
	for _, h := range r.Headers {
		if h.Name == "Content-Length" {
			t.Error("Content-Length kept")
		}
	}
	os.WriteFile(p, []byte("GET http://other.test/a HTTP/1.1\nHost: ignored\n\n"), 0o644)
	tm, _ = ParseRequestFile(p, "https")
	if tm.URL != "http://other.test/a" || tm.Headers[0].Value != "other.test" {
		t.Errorf("full URL line: %+v", tm)
	}
	os.WriteFile(p, []byte("garbage\n"), 0o644)
	if _, err := ParseRequestFile(p, "https"); err == nil {
		t.Error("malformed accepted")
	}
}

func TestTimeMatcher(t *testing.T) {
	s := NewSet([]string{"FUZZ"})
	if err := s.AddMatcher("time", ">100"); err != nil {
		t.Fatal(err)
	}
	if s.AddMatcher("time", "100") == nil || s.AddMatcher("time", "<x") == nil || s.AddMatcher("time", "><1") == nil {
		t.Error("bad time value accepted")
	}
	if !s.Matches(&Response{Duration: int64(150 * time.Millisecond)}) || s.Matches(&Response{Duration: int64(50 * time.Millisecond)}) {
		t.Error("time matcher")
	}
	s.AddFilter("time", "<10")
	if s.Matches(&Response{Duration: int64(5 * time.Millisecond)}) {
		t.Error("time filter")
	}
}

func TestSenderDecodesWhateverTheServerCompressed(t *testing.T) {
	body := strings.Repeat("one two three\n", 100)
	enc := map[string]func(*bytes.Buffer) interface {
		Write([]byte) (int, error)
		Close() error
	}{
		"gzip": func(b *bytes.Buffer) interface {
			Write([]byte) (int, error)
			Close() error
		} {
			return gzip.NewWriter(b)
		},
		"deflate": func(b *bytes.Buffer) interface {
			Write([]byte) (int, error)
			Close() error
		} {
			return zlib.NewWriter(b)
		},
		"br": func(b *bytes.Buffer) interface {
			Write([]byte) (int, error)
			Close() error
		} {
			return brotli.NewWriter(b)
		},
		"raw": func(b *bytes.Buffer) interface {
			Write([]byte) (int, error)
			Close() error
		} {
			w, _ := flate.NewWriter(b, 6)
			return w
		},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		kind := strings.TrimPrefix(r.URL.Path, "/")
		var buf bytes.Buffer
		cw := enc[kind](&buf)
		cw.Write([]byte(body))
		cw.Close()
		ce := kind
		if kind == "raw" {
			ce = "deflate"
		}
		w.Header().Set("Content-Encoding", ce)
		w.Write(buf.Bytes())
	}))
	defer srv.Close()
	fetch.Reset()
	s := mustSender(t, HTTPOptions{Timeout: 5 * time.Second, Threads: 1})
	for kind := range enc {
		tm, _ := NewTemplate("", srv.URL+"/"+kind, "", []string{"Accept-Encoding: gzip, deflate, br"}, nil)
		req := tm.Expand(nil)
		r, err := s.Send(context.Background(), &req, false)
		if err != nil || r.Length != int64(len(body)) || r.Lines != 101 {
			t.Errorf("%s: %+v %v", kind, r, err)
		}
	}
}

func TestIgnoreBodyAndRaw(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.RequestURI
		w.Header().Set("Content-Length", "11")
		fmt.Fprint(w, "hello world")
	}))
	defer srv.Close()
	fetch.Reset()
	s := mustSender(t, HTTPOptions{Timeout: 5 * time.Second, Threads: 1, IgnoreBody: true, Raw: true})
	tm, _ := NewTemplate("", srv.URL+"/FUZZ", "", nil, nil)
	req := tm.Expand(map[string]string{"FUZZ": "%2e%2e/a"})
	r, err := s.Send(context.Background(), &req, true)
	if err != nil || r.Length != 11 || r.Words != 0 {
		t.Errorf("%+v %v", r, err)
	}
	if got != "/%2e%2e/a" {
		t.Errorf("request URI %q", got)
	}
}

func TestReplayProxyGetsMatchesOnly(t *testing.T) {
	var seen []string
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { seen = append(seen, r.URL.String()) }))
	defer proxy.Close()
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/yes" {
			fmt.Fprint(w, "x")
			return
		}
		http.NotFound(w, r)
	}))
	defer target.Close()
	fetch.Reset()
	s := mustSender(t, HTTPOptions{Timeout: 5 * time.Second, Threads: 1, ReplayProxy: proxy.URL})
	tm, _ := NewTemplate("", target.URL+"/FUZZ", "", nil, nil)
	set := NewSet([]string{"FUZZ"})
	set.AddMatcher("status", "200")
	st := Run(context.Background(), Config{Template: tm, Mode: Clusterbomb, Set: set, Sender: s, Replay: s.(Replayer), Threads: 1,
		Lists: []List{{Keyword: "FUZZ", Words: []string{"yes", "no"}}}})
	if st.Replayed != 1 || len(seen) != 1 || !strings.HasSuffix(seen[0], "/yes") || egress.Sent() != 2 {
		t.Errorf("replayed %d seen %v sent %d", st.Replayed, seen, egress.Sent())
	}
}

func TestGreedyRecursionAndPitfalls(t *testing.T) {
	f := &fake{hook: func(r *Request) (*Response, error) {
		switch r.URL {
		case "http://h.test/admin", "http://h.test/admin/login":
			return &Response{Status: 200, Header: http.Header{}}, nil
		}
		return &Response{Status: 404, Header: http.Header{}}, nil
	}}
	st, out := runFake(t, f, func(c *Config) {
		c.Recursion, c.Strategy, c.Threads = true, "greedy", 1
	})
	var urls []string
	for _, r := range out {
		urls = append(urls, r.URL)
	}
	if st.Jobs != 3 || len(out) != 2 || !contains(urls, "http://h.test/admin/login") {
		t.Errorf("jobs %d results %v", st.Jobs, urls)
	}
}

func TestStopOn403(t *testing.T) {
	f := &fake{hook: func(r *Request) (*Response, error) { return &Response{Status: 403, Header: http.Header{}}, nil }}
	words := make([]string, 300)
	for i := range words {
		words[i] = fmt.Sprint("w", i)
	}
	st, _ := runFake(t, f, func(c *Config) { c.StopOn403, c.Threads = true, 1; c.Lists[0].Words = words })
	if st.StoppedBy == "" || len(f.got) > 60 || len(f.got) < 51 {
		t.Errorf("stopped %q after %d", st.StoppedBy, len(f.got))
	}
}

func TestMaxTimeJobAndDelay(t *testing.T) {
	f := &fake{hook: func(r *Request) (*Response, error) { return &Response{Status: 200, Header: http.Header{}}, nil }}
	t0 := time.Now()
	st, _ := runFake(t, f, func(c *Config) {
		c.Threads = 1
		c.DelayMin = 50 * time.Millisecond
		c.MaxTimeJob = 120 * time.Millisecond
	})
	if len(st.CutJobs) != 1 || len(f.got) >= 6 || time.Since(t0) > time.Second {
		t.Errorf("cut %v after %d requests in %v", st.CutJobs, len(f.got), time.Since(t0))
	}
}

func TestTrackerKeepsTheExactSetAnswered(t *testing.T) {
	tr := &tracker{low: 5}
	for _, i := range []int{7, 8, 5, 10} {
		tr.done(i)
	}
	if tr.first() != 6 || !reflect.DeepEqual(tr.set(), Spans{{5, 6}, {7, 9}, {10, 11}}) {
		t.Errorf("first %d set %v", tr.first(), tr.set())
	}
	tr.done(6)
	if tr.first() != 9 || !reflect.DeepEqual(tr.set(), Spans{{5, 9}, {10, 11}}) {
		t.Errorf("first %d set %v", tr.first(), tr.set())
	}
	// Answers that came out of order from 0 leave a hole, not a lost prefix.
	tr = &tracker{}
	for _, i := range []int{9, 3, 0} {
		tr.done(i)
	}
	if tr.first() != 1 || !tr.set().Has(9) || tr.set().Has(4) {
		t.Errorf("first %d set %v", tr.first(), tr.set())
	}
}

func TestCalibrationStrategies(t *testing.T) {
	g, _ := CalibrationGroups(nil, nil)
	if len(g) != 3 {
		t.Errorf("basic %d groups", len(g))
	}
	g, _ = CalibrationGroups([]string{"advanced"}, nil)
	if len(g) != 5 || !strings.HasSuffix(g[3][0], "/") {
		t.Errorf("advanced %v", g)
	}
	g, _ = CalibrationGroups([]string{"advanced"}, []string{"zzz", "admin"})
	if !reflect.DeepEqual(g, [][]string{{"zzz", "admin"}}) {
		t.Errorf("custom %v", g)
	}
	if _, err := CalibrationGroups([]string{"nonesuch"}, nil); err == nil {
		t.Error("unknown strategy")
	}
}

func TestPerHostCalibration(t *testing.T) {
	f := &fake{hook: func(r *Request) (*Response, error) {
		if strings.Contains(r.URL, "one.test") {
			return &Response{Status: 200, Length: 10, Words: 1, Lines: 1, Header: http.Header{}}, nil
		}
		return &Response{Status: 200, Length: 20, Words: 2, Lines: 1, Header: http.Header{}}, nil
	}}
	tm, _ := NewTemplate("", "http://HOST/FUZZ", "", nil, nil)
	set := NewSet([]string{"HOST", "FUZZ"})
	set.PerHost = true
	set.AddMatcher("status", "200")
	st := Run(context.Background(), Config{Template: tm, Mode: Clusterbomb, Set: set, Sender: f, Threads: 1, Calibrate: true,
		Lists: []List{{Keyword: "HOST", Words: []string{"one.test", "two.test"}}, {Keyword: "FUZZ", Words: []string{"a", "b"}}}})
	// One filter per host, each its own size.
	if !reflect.DeepEqual(st.Filters, []string{"size 10 for one.test", "size 20 for two.test"}) && !reflect.DeepEqual(st.Filters, []string{"size 20 for two.test", "size 10 for one.test"}) {
		t.Errorf("per-host filters %v", st.Filters)
	}
}

func TestCommandListRunsPerInput(t *testing.T) {
	l := CommandList("/bin/sh", `printf "n$FFUF_NUM"`, "FUZZ", 3, nil)
	if Total(Clusterbomb, []List{l}) != 3 || At(Clusterbomb, []List{l}, 2)["FUZZ"] != "n2" {
		t.Error("command input")
	}
	bad := CommandList("/bin/sh", "exit 3", "FUZZ", 2, nil)
	bad.Word(0)
	if bad.Failed.Load() != 1 {
		t.Error("failure not counted")
	}
}

// A sweep reads thousands of small answers: the buffers that read them are
// reused, not made for each. Each answer used to cost a 32 KiB read buffer
// and a 4 KiB reader, and the collector's work on them slowed the sweep
// (and the server it shares a machine with) against ffuf's.
func TestReadingAnAnswerReusesItsBuffers(t *testing.T) {
	if raceOn {
		t.Skip("the race detector makes sync.Pool drop items")
	}
	body := strings.Repeat("word ", 41) // 205 bytes
	resp := &http.Response{Header: http.Header{}}
	const n = 500
	read := func() {
		resp.Body = io.NopCloser(strings.NewReader(body))
		dec, release := decoded(resp)
		_, length, words, _, ok, err := readCounting(dec, false)
		release()
		if err != nil || !ok || length != 205 || words != 42 {
			t.Fatalf("read %d bytes, %d words, ok %v, err %v", length, words, ok, err)
		}
	}
	read() // fills the pools
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for i := 0; i < n; i++ {
		read()
	}
	runtime.ReadMemStats(&after)
	if per := (after.TotalAlloc - before.TotalAlloc) / n; per > 2048 {
		t.Errorf("each answer allocates %d bytes to be read; its buffers are not reused", per)
	}
}
