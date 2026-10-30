package paramcol

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/trannghiach/azhaq/internal/fetch"
	"github.com/trannghiach/azhaq/types"
)

func noise(n int) []string {
	var w []string
	for i := 0; i < n; i++ {
		w = append(w, fmt.Sprintf("noise%d", i))
	}
	return w
}

func found(got map[string]any) []string {
	var out []string
	for _, n := range got["params"].([]any) {
		out = append(out, n.(string))
	}
	return out
}

// A header, a redirect, a name printed back and a line count each give a
// parameter away without a status or a size change.
func TestOtherChannels(t *testing.T) {
	fetch.Reset()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		switch r.URL.Path {
		case "/hdr":
			if q.Has("trace") {
				w.Header().Set("X-Trace-Id", "1")
			}
			fmt.Fprint(w, "same body")
		case "/loc":
			to := "/home"
			if q.Has("next") {
				to = "/other"
			}
			w.Header().Set("Location", to)
			w.WriteHeader(http.StatusFound)
		case "/named":
			body := "<p>colours</p>"
			if q.Has("colour") {
				body += `<p>filter "colour" applied</p>`
			}
			fmt.Fprint(w, body)
		case "/lines":
			if q.Has("wrap") {
				fmt.Fprint(w, "aaa bbb\nccc\n")
			} else {
				fmt.Fprint(w, "aaa\nbbb\nccc\n")
			}
		}
	}))
	defer srv.Close()
	for path, want := range map[string]string{"/hdr": "trace", "/loc": "next", "/named": "colour", "/lines": "wrap"} {
		words := append(noise(80), want)
		got := runOn(t, New(srv.Client(), Options{Words: words, Rate: 10000}), srv.URL+path)
		if !slices.Equal(found(got), []string{want}) {
			t.Errorf("%s: found %v, want %s", path, got, want)
		}
	}
}

// A page that prints any name between quotes is no evidence for names.
func TestPrintedNamesOfAnyNameAreNoEvidence(t *testing.T) {
	fetch.Reset()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<p>")
		for k := range r.URL.Query() {
			fmt.Fprintf(w, "got param %q; ", k)
		}
		fmt.Fprint(w, "</p>")
	}))
	defer srv.Close()
	got := runOn(t, New(srv.Client(), Options{Words: noise(300), Rate: 10000}), srv.URL+"/")
	if len(found(got)) != 0 {
		t.Errorf("reported %v", got)
	}
}

// Names the page's own form and scripts hold are searched first, and found
// when the list lacks them.
func TestHarvestedNames(t *testing.T) {
	fetch.Reset()
	var reqs atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqs.Add(1)
		body := `<form><input name="secret_code"><input id="csrf_field"><textarea name=memo></textarea></form><script>var voucher = '';</script>`
		if r.URL.Query().Has("secret_code") {
			body += strings.Repeat("<li>x</li>", 30)
		}
		if r.URL.Query().Has("voucher") {
			body += strings.Repeat("<li>y</li>", 60)
		}
		fmt.Fprint(w, body)
	}))
	defer srv.Close()
	got := runOn(t, New(srv.Client(), Options{Words: noise(400), Rate: 10000}), srv.URL+"/f")
	if !slices.Equal(found(got), []string{"secret_code", "voucher"}) {
		t.Errorf("found %v", got)
	}
}

// debug answers only when it is true.
func TestValueSensitiveToggle(t *testing.T) {
	fetch.Reset()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := "<p>site</p>"
		if r.URL.Query().Get("debug") == "true" {
			body += strings.Repeat("<li>trace</li>", 20)
		}
		fmt.Fprint(w, body)
	}))
	defer srv.Close()
	got := runOn(t, New(srv.Client(), Options{Words: noise(200), Rate: 10000}), srv.URL+"/")
	vals, _ := got["values"].(map[string]any)
	if !slices.Equal(found(got), []string{"debug"}) || vals["debug"] != "true" {
		t.Errorf("found %v", got)
	}
}

// A server that refuses long queries: the group size is found by asking,
// and the names are searched in groups it takes.
func TestFindsLargestQuery(t *testing.T) {
	fetch.Reset()
	var biggest atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if n := int64(len(r.URL.RawQuery)); n > 1500 {
			http.Error(w, "too long", http.StatusBadRequest)
			return
		} else if n > biggest.Load() {
			biggest.Store(n)
		}
		body := "<p>catalog</p>"
		if r.URL.Query().Has("category") {
			body += strings.Repeat("<li>p</li>", 20)
		}
		fmt.Fprint(w, body)
	}))
	defer srv.Close()
	words := append(noise(1500), "category")
	got := runOn(t, New(srv.Client(), Options{Words: words, Rate: 10000}), srv.URL+"/c")
	if !slices.Equal(found(got), []string{"category"}) {
		t.Fatalf("found %v", got)
	}
	if biggest.Load() < 900 {
		t.Errorf("the largest query sent was %d bytes: the server took 1500", biggest.Load())
	}
	if n := got["requests"].(float64); n > 80 {
		t.Errorf("%v requests", n)
	}
}

type recorded struct {
	method, ctype, body string
}

func bodyServer(t *testing.T, seen *[]recorded, mu *sync.Mutex) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		mu.Lock()
		*seen = append(*seen, recorded{r.Method, r.Header.Get("Content-Type"), string(raw)})
		mu.Unlock()
		body := "<p>handler</p>"
		if strings.Contains(string(raw), "role") {
			body += strings.Repeat("<li>r</li>", 30)
		}
		fmt.Fprint(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestBodiesNeedWrites(t *testing.T) {
	fetch.Reset()
	var seen []recorded
	var mu sync.Mutex
	srv := bodyServer(t, &seen, &mu)
	c := New(srv.Client(), Options{Words: []string{"role"}, Method: POST, Rate: 10000})
	got := runOn(t, c, srv.URL+"/x")
	if note, _ := got["note"].(string); !strings.Contains(note, "not searched") || len(seen) != 0 {
		t.Errorf("a body was sent without writes being allowed: %v, %d requests", got, len(seen))
	}
}

func TestPostJSONAndXML(t *testing.T) {
	for _, tc := range []struct {
		method, ctype, include string
		check                  func(body string) bool
	}{
		{POST, "application/x-www-form-urlencoded", "csrf=1", func(b string) bool { return strings.Contains(b, "csrf=1&") && strings.Contains(b, "role=") }},
		{JSON, "application/json", `{"csrf":"1"}`, func(b string) bool {
			var m map[string]string
			return json.Unmarshal([]byte(b), &m) == nil && m["csrf"] == "1" && len(m) > 1
		}},
		{JSON, "application/json", `{"wrap":{"a":1},$arjun$}`, func(b string) bool { return strings.HasPrefix(b, `{"wrap":{"a":1},"`) }},
		{XML, "application/xml", "", func(b string) bool { return strings.HasPrefix(b, "<?xml") && strings.Contains(b, "<role>") }},
	} {
		fetch.Reset()
		var seen []recorded
		var mu sync.Mutex
		srv := bodyServer(t, &seen, &mu)
		c := New(srv.Client(), Options{Words: append(noise(120), "role"), Method: tc.method, Writes: true, Include: tc.include, Rate: 10000})
		got := runOn(t, c, srv.URL+"/x")
		if !slices.Equal(found(got), []string{"role"}) {
			t.Errorf("%s: found %v", tc.method, got)
		}
		if note, _ := got["note"].(string); !strings.Contains(note, "may have changed data") {
			t.Errorf("%s: no note that writes were sent: %v", tc.method, got["note"])
		}
		ok := false
		for _, r := range seen {
			if r.method != http.MethodPost || r.ctype != tc.ctype {
				t.Errorf("%s: sent %s with %s", tc.method, r.method, r.ctype)
			}
			ok = ok || tc.check(r.body)
		}
		if !ok {
			t.Errorf("%s: no body looked right: %v", tc.method, seen[:min(3, len(seen))])
		}
		if int(got["writes"].(float64)) != len(seen) {
			t.Errorf("%s: %v writes counted, %d sent", tc.method, got["writes"], len(seen))
		}
	}
}

// Ten names that are not XML elements are said, not sent.
func TestXMLNamesAreChecked(t *testing.T) {
	fetch.Reset()
	var seen []recorded
	var mu sync.Mutex
	srv := bodyServer(t, &seen, &mu)
	c := New(srv.Client(), Options{Words: []string{"role", "1bad", "a b", "xmlfoo"}, Method: XML, Writes: true, Rate: 10000})
	got := runOn(t, c, srv.URL+"/x")
	if note, _ := got["note"].(string); !strings.Contains(note, "3 names are not valid XML") {
		t.Errorf("note %v", got["note"])
	}
}

// Without -t the groups of a list go side by side: a slow page takes
// about a fifth of the time.
func TestGroupsRunSideBySide(t *testing.T) {
	fetch.Reset()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(20 * time.Millisecond)
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()
	run := func(threads int) time.Duration {
		fetch.Reset()
		c := New(srv.Client(), Options{Words: noise(2000), Chunk: 50, Rate: 10000, Threads: threads})
		start := time.Now()
		_, err := c.Run(context.Background(), types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": srv.URL + "/p"}}, func(types.Observation) error { return nil })
		if err != nil {
			t.Fatal(err)
		}
		return time.Since(start)
	}
	one, five := run(1), run(5)
	if five*3 > one*2 {
		t.Errorf("5 threads took %v, 1 thread %v", five, one)
	}
}

func TestBuiltinLists(t *testing.T) {
	small, ok1 := Builtin("small")
	medium, ok2 := Builtin("medium")
	large, ok3 := Builtin("large")
	if !ok1 || !ok2 || !ok3 || len(small) != 1000 || len(medium) != 3000 || len(large) < 6000 {
		t.Fatalf("sizes %d %d %d", len(small), len(medium), len(large))
	}
	if !slices.Equal(large[:1000], small) {
		t.Error("small is the first of large")
	}
	for _, w := range []string{"id", "q", "redirect_uri", "callback"} {
		if !slices.Contains(large, w) {
			t.Errorf("no %s in the list", w)
		}
	}
	if _, ok := Builtin("huge"); ok {
		t.Error("huge is not a list")
	}
}

func TestRecase(t *testing.T) {
	in := []string{"user_id", "userId", "user-id", "USER", "page"}
	for style, want := range map[string][]string{
		"snake": {"user_id", "user", "page"}, "like_this": {"user_id", "user", "page"},
		"camel": {"userId", "user", "page"}, "likeThis": {"userId", "user", "page"},
		"lower": {"userid", "user", "page"}, "likethis": {"userid", "user", "page"},
	} {
		got, err := Recase(in, style)
		if err != nil || !slices.Equal(got, want) {
			t.Errorf("%s: %v %v, want %v", style, got, err, want)
		}
	}
	if _, err := Recase(in, "title"); err == nil {
		t.Error("unknown style accepted")
	}
}

// A page that answers each way with one short message: a one-byte change
// is a change when the page never varies by itself, and a name another name
// hides is found once the groups are small.
func TestOneByteChange(t *testing.T) {
	fetch.Reset()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		w.WriteHeader(http.StatusBadRequest)
		switch {
		case q.Has("variables"):
			fmt.Fprint(w, `{"errors":["Variables are invalid JSON."]}`)
		case q.Has("query"):
			fmt.Fprint(w, `{"errors":["Syntax Error here"]}`)
		default:
			fmt.Fprint(w, `{"errors":["Must provide query string."]}`)
		}
	}))
	defer srv.Close()
	words := append(noise(60), "variables", "query")
	got := runOn(t, New(srv.Client(), Options{Words: words, Rate: 10000}), srv.URL+"/graphql")
	if !slices.Equal(found(got), []string{"query", "variables"}) {
		t.Errorf("found %v", got)
	}
}
