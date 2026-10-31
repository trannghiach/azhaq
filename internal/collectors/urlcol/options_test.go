package urlcol

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/trannghiach/azhaq/types"
)

// mirror is a fake archive for every source that records each request and
// answers from rows: wayback rows per page, common crawl, otx, urlscan and
// arquivo each a fixed answer.
type mirror struct {
	*httptest.Server
	mu   sync.Mutex
	reqs []string
	// wayback maps a page number to the CDX JSON rows; a page it lacks is a 400.
	wayback map[string][]string
	status  map[string]int    // path → status to answer instead
	text    map[string]string // path → a 200 body to answer instead
	slow    map[string]time.Duration
}

func newMirror(t *testing.T, wayback map[string][]string) *mirror {
	m := &mirror{wayback: wayback, status: map[string]int{}, text: map[string]string{}, slow: map[string]time.Duration{}}
	m.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		m.reqs = append(m.reqs, r.URL.RequestURI())
		code, delay := m.status[r.URL.Path], m.slow[r.URL.Path+"?"+r.URL.Query().Get("page")]
		m.mu.Unlock()
		if delay > 0 {
			select {
			case <-time.After(delay):
			case <-r.Context().Done():
				return
			}
		}
		if code != 0 {
			w.WriteHeader(code)
			return
		}
		if body, ok := m.text[r.URL.Path]; ok {
			fmt.Fprint(w, body)
			return
		}
		q := r.URL.Query()
		switch {
		case r.URL.Path == "/wayback":
			rows, ok := m.wayback[q.Get("page")]
			if !ok {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			out := [][]string{{"original"}}
			for _, u := range rows {
				out = append(out, []string{u})
			}
			_ = json.NewEncoder(w).Encode(out)
		case r.URL.Path == "/cc/collinfo.json":
			fmt.Fprintf(w, `[{"cdx-api":"http://%s/cc/idx"}]`, r.Host)
		case r.URL.Path == "/cc/idx":
			if q.Get("showNumPages") != "" {
				fmt.Fprint(w, `{"pages":1}`)
				return
			}
			fmt.Fprint(w, `{"url":"http://example.org/cc"}`+"\n")
		case strings.HasPrefix(r.URL.Path, "/otx/"):
			fmt.Fprint(w, `{"has_next":false,"url_list":[{"url":"http://example.org/otx"},{"url":"http://api.example.org/otx"}]}`)
		case r.URL.Path == "/urlscan":
			fmt.Fprint(w, `{"has_more":false,"results":[{"page":{"url":"http://example.org/us"},"task":{"url":"http://example.org/us-task"},"sort":[1,"a"]}]}`)
		case r.URL.Path == "/arquivo":
			fmt.Fprint(w, `{"url":"http://example.org/arq"}`+"\n")
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(m.Close)
	return m
}

func (m *mirror) bases() map[string]string {
	return map[string]string{
		"wayback": m.URL + "/wayback", "commoncrawl": m.URL + "/cc/collinfo.json", "otx": m.URL + "/otx",
		"urlscan": m.URL + "/urlscan", "arquivo": m.URL + "/arquivo",
	}
}

// asked returns the parameters of each request to path.
func (m *mirror) asked(path string) []url.Values {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []url.Values
	for _, r := range m.reqs {
		u, _ := url.Parse(r)
		if u.Path == path || strings.HasPrefix(u.Path, path+"/") {
			out = append(out, u.Query())
		}
	}
	return out
}

func run(t *testing.T, o Options, ctx context.Context) (summary map[string]any, rows []map[string]any, meta types.RunMeta, err error) {
	t.Helper()
	if o.Bases == nil {
		t.Fatal("no archive addresses")
	}
	c := New(o)
	c.pauses = nil
	meta, err = c.Run(ctx, types.Seed{Type: types.TypeDomain, Keys: map[string]string{"domain": "example.org"}}, func(ob types.Observation) error {
		var m map[string]any
		_ = json.Unmarshal(ob.Payload, &m)
		if ob.Kind == "urls" {
			summary = m
		} else {
			rows = append(rows, m)
		}
		return nil
	})
	return
}

var pages = map[string][]string{
	"0": {"http://example.org/a?x=1", "http://example.org/a?x=2", "http://example.org/img/logo.PNG", "http://www.example.org/w", "http://example.org/page"},
	"1": {"http://example.org/b", "http://example.org/a?x=3", "http://example.org/page"},
}

func TestApexAsksTheHostAlone(t *testing.T) {
	m := newMirror(t, pages)
	var got []string
	_, _, _, err := run(t, Options{Bases: m.bases(), Client: m.Client(), Apex: true, OnURL: func(u, _ string) { got = append(got, u) }}, context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if q := m.asked("/wayback")[0]; q.Get("url") != "example.org/*" {
		t.Errorf("wayback url=%q, want the host alone as gau asks without --subs", q.Get("url"))
	}
	if q := m.asked("/cc/idx")[0]; q.Get("url") != "example.org/*" {
		t.Errorf("common crawl url=%q", q.Get("url"))
	}
	if q := m.asked("/arquivo")[0]; q.Get("url") != "example.org/*" {
		t.Errorf("arquivo url=%q", q.Get("url"))
	}
	// The mirror's wayback answers www. whatever it is asked: the host alone
	// is kept from the archives asked for it. otx and urlscan answer for the
	// domain, and their subdomain URLs are kept, as gau prints them.
	for _, u := range got {
		if strings.Contains(u, "www.") {
			t.Errorf("%s is on a subdomain", u)
		}
	}
	slices.Sort(got)
	want := []string{"http://api.example.org/otx", "http://example.org/a?x=1", "http://example.org/a?x=2", "http://example.org/a?x=3", "http://example.org/arq", "http://example.org/b",
		"http://example.org/cc", "http://example.org/img/logo.PNG", "http://example.org/otx", "http://example.org/page", "http://example.org/us", "http://example.org/us-task"}
	if !slices.Equal(got, want) {
		t.Errorf("apex URLs %v, want %v", got, want)
	}
	// With subdomains the same archives are asked for *.domain and keep them.
	m2 := newMirror(t, pages)
	var all []string
	if _, _, _, err := run(t, Options{Bases: m2.bases(), Client: m2.Client(), OnURL: func(u, _ string) { all = append(all, u) }}, context.Background()); err != nil {
		t.Fatal(err)
	}
	if q := m2.asked("/wayback")[0]; q.Get("url") != "*.example.org/*" {
		t.Errorf("wayback with subdomains: url=%q", q.Get("url"))
	}
	if !slices.Contains(all, "http://www.example.org/w") || !slices.Contains(all, "http://api.example.org/otx") {
		t.Errorf("subdomain URLs missing: %v", all)
	}
}

// The OTX category follows gau: a name with a subdomain is a hostname, or
// its registered domain when the subdomains are wanted.
func TestOTXTarget(t *testing.T) {
	for _, c := range []struct {
		domain string
		apex   bool
		cat    string
		name   string
	}{
		{"example.org", true, "domain", "example.org"},
		{"example.org", false, "domain", "example.org"},
		{"www.example.org", true, "hostname", "www.example.org"},
		{"www.example.org", false, "domain", "example.org"},
		{"a.b.example.co.uk", true, "hostname", "a.b.example.co.uk"},
	} {
		if cat, name := otxTarget(c.domain, c.apex); cat != c.cat || name != c.name {
			t.Errorf("%s apex=%v: %s/%s, want %s/%s", c.domain, c.apex, cat, name, c.cat, c.name)
		}
	}
}

// The filters reach the archives as gau sends them, and the sources that
// keep no status or type are asked all the same: their URLs are kept
// unfiltered and their rows say what they lack.
func TestFiltersAreSentAndTheRestAreUnfiltered(t *testing.T) {
	m := newMirror(t, pages)
	f := Filters{MatchStatus: []string{"200"}, DropStatus: []string{"404"}, MatchMime: []string{"text/html"}, DropMime: []string{"image/png"}, From: "202401", To: "202412"}
	summary, rows, _, err := run(t, Options{Bases: m.bases(), Client: m.Client(), Filters: f}, context.Background())
	if err != nil {
		t.Fatal(err)
	}
	wb := m.asked("/wayback")[0]
	want := []string{"mimetype:text/html", "statuscode:200", "!statuscode:404", "!mimetype:image/png"}
	got := wb["filter"]
	slices.Sort(want)
	slices.Sort(got)
	if !slices.Equal(got, want) || wb.Get("from") != "202401" || wb.Get("to") != "202412" {
		t.Errorf("wayback filters %v from=%s to=%s", wb["filter"], wb.Get("from"), wb.Get("to"))
	}
	cc := m.asked("/cc/idx")[0]
	got = cc["filter"]
	want = []string{"mime:text/html", "status:200", "!=status:404", "!=mime:image/png"}
	slices.Sort(want)
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Errorf("common crawl filters %v", cc["filter"])
	}
	if n := len(m.asked("/otx")); n == 0 {
		t.Error("otx holds no status, yet gau asks it: it was not asked")
	}
	if n := len(m.asked("/urlscan")); n == 0 {
		t.Error("urlscan was not asked")
	}
	srcs := summary["sources"].(map[string]any)
	for name, c := range map[string]struct{ what, by string }{
		"otx":     {"status, type or date", "-mc, -fc, -mt, -ft, -from, -to"},
		"urlscan": {"status or type", "-mc, -fc, -mt, -ft"},
	} {
		row := srcs[name].(map[string]any)
		if row["unfiltered"] != c.what || row["unfiltered_by"] != c.by || row["skipped"] != nil || row["count"].(float64) == 0 {
			t.Errorf("%s row: %v", name, row)
		}
	}
	for _, name := range []string{"wayback", "commoncrawl", "arquivo"} {
		if row := srcs[name].(map[string]any); row["unfiltered"] != nil {
			t.Errorf("%s applies every filter, its row says %v", name, row)
		}
	}
	var otx bool
	for _, r := range rows {
		if strings.Contains(fmt.Sprint(r), "example.org/otx") {
			otx = true
		}
	}
	if !otx {
		t.Errorf("the URLs of otx are not in the rows: %v", rows)
	}
	if summary["degraded"] == true {
		t.Error("an archive that cannot filter is not a failure")
	}
}

func TestSeveralStatusesAreAlternatives(t *testing.T) {
	q := url.Values{}
	Filters{MatchStatus: []string{"200", "301"}, DropMime: []string{"image/png", "image/gif"}}.params(q, cdxWayback)
	got := q["filter"]
	slices.Sort(got)
	if want := []string{"!mimetype:image/gif", "!mimetype:image/png", "statuscode:200|301"}; !slices.Equal(got, want) {
		t.Errorf("%v", got)
	}
}

// A date filter reaches urlscan.io as its own date range.
func TestUrlscanTakesDates(t *testing.T) {
	m := newMirror(t, pages)
	if _, _, _, err := run(t, Options{Bases: m.bases(), Client: m.Client(), Filters: Filters{From: "2024", To: "202402"}}, context.Background()); err != nil {
		t.Fatal(err)
	}
	if q := m.asked("/urlscan"); len(q) != 1 || q[0].Get("q") != "domain:example.org AND date:>=2024-01-01 AND date:<=2024-02-29" {
		t.Errorf("urlscan asked %v", q)
	}
	if n := len(m.asked("/otx")); n != 1 {
		t.Errorf("otx dates no capture: it is asked all the same, once, not %d times", n)
	}
}

func TestFiltersValidate(t *testing.T) {
	for _, f := range []Filters{{MatchStatus: []string{"20"}}, {DropStatus: []string{"ok"}}, {MatchMime: []string{"text html"}}, {From: "2024-01"}, {From: "202413"}, {To: "20241"}, {From: "202406", To: "202401"}} {
		if err := f.Validate(); err == nil {
			t.Errorf("%+v passed", f)
		}
	}
	for _, f := range []Filters{{}, {MatchStatus: []string{"200", "404"}, MatchMime: []string{"text/html"}, From: "2024", To: "20241231"}} {
		if err := f.Validate(); err != nil {
			t.Errorf("%+v: %v", f, err)
		}
	}
}

func TestOnlyTheChosenArchives(t *testing.T) {
	m := newMirror(t, pages)
	if _, _, _, err := run(t, Options{Bases: m.bases(), Client: m.Client(), Only: []string{"wayback"}}, context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(m.asked("/wayback")) == 0 || len(m.asked("/cc"))+len(m.asked("/otx"))+len(m.asked("/urlscan"))+len(m.asked("/arquivo")) != 0 {
		t.Errorf("requests %v", m.reqs)
	}
	if err := CheckSources([]string{"wayback", "gau"}); err == nil {
		t.Error("gau is not an archive")
	}
}

func TestBlacklistAndFirstPerPath(t *testing.T) {
	m := newMirror(t, pages)
	var got []string
	o := Options{Bases: m.bases(), Client: m.Client(), Only: []string{"wayback"}, Blacklist: []string{"png", ".JPG"}, FirstPath: true,
		OnURL: func(u, _ string) { got = append(got, u) }}
	if _, _, _, err := run(t, o, context.Background()); err != nil {
		t.Fatal(err)
	}
	slices.Sort(got)
	want := []string{"http://example.org/a?x=1", "http://example.org/b", "http://example.org/page", "http://www.example.org/w"}
	if !slices.Equal(got, want) {
		t.Errorf("streamed %v, want %v", got, want)
	}
	// Sorted output (no OnURL) keeps the first in order, whatever arrived first.
	file := filepath.Join(t.TempDir(), "u.txt")
	o.OnURL, o.Out = nil, file
	if _, _, _, err := run(t, o, context.Background()); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(file)
	if got := strings.Fields(string(raw)); !slices.Equal(got, want) {
		t.Errorf("file %v, want %v", got, want)
	}
}

// Raw prints every row on the domain as the archive gave it: no
// normalising, no junk filter, no deduplication.
func TestRawIsWhatTheArchiveSaid(t *testing.T) {
	m := newMirror(t, map[string][]string{
		"0": {"HTTP://Example.ORG/A#frag", "http://example.org/page", "http://example.org/page", "http://example.org/x/..", "http://other.test/x", "http://example.org:80/p"},
	})
	var got []string
	o := Options{Bases: m.bases(), Client: m.Client(), Only: []string{"wayback"}, Raw: true, OnURL: func(u, _ string) { got = append(got, u) }}
	if _, _, _, err := run(t, o, context.Background()); err != nil {
		t.Fatal(err)
	}
	want := []string{"HTTP://Example.ORG/A#frag", "http://example.org/page", "http://example.org/page", "http://example.org/x/..", "http://example.org:80/p"}
	if !slices.Equal(got, want) {
		t.Errorf("raw %v, want %v", got, want)
	}
}

func TestPageCapIsSaid(t *testing.T) {
	m := newMirror(t, map[string][]string{"0": {"http://example.org/1"}, "1": {"http://example.org/2"}, "2": {"http://example.org/3"}})
	summary, _, _, err := run(t, Options{Bases: m.bases(), Client: m.Client(), Only: []string{"wayback"}, MaxPages: 2}, context.Background())
	if err != nil {
		t.Fatal(err)
	}
	row := summary["sources"].(map[string]any)["wayback"].(map[string]any)
	if row["capped"] != true || row["pages"].(float64) != 2 || fmt.Sprint(summary["capped"]) != "[wayback]" {
		t.Errorf("row %v, summary capped %v", row, summary["capped"])
	}
	m2 := newMirror(t, map[string][]string{"0": {"http://example.org/1"}})
	summary, _, _, _ = run(t, Options{Bases: m2.bases(), Client: m2.Client(), Only: []string{"wayback"}, MaxPages: 2}, context.Background())
	if row := summary["sources"].(map[string]any)["wayback"].(map[string]any); row["capped"] != nil {
		t.Errorf("a source that read everything is not capped: %v", row)
	}
}

func TestURLsPastTheCapAreCounted(t *testing.T) {
	m := newMirror(t, pages)
	summary, _, _, err := run(t, Options{Bases: m.bases(), Client: m.Client(), Only: []string{"wayback"}, MaxURLs: 3}, context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if summary["count"].(float64) != 3 || summary["truncated"] == nil {
		t.Errorf("%v", summary)
	}
}

func TestRetriesZeroMakesARefusalFinal(t *testing.T) {
	m := newMirror(t, pages)
	m.status["/wayback"] = http.StatusTooManyRequests
	zero := 0
	t0 := time.Now()
	summary, _, _, err := run(t, Options{Bases: m.bases(), Client: m.Client(), Only: []string{"wayback"}, Retries: &zero}, context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if n := len(m.asked("/wayback")); n != 1 || time.Since(t0) > time.Second {
		t.Errorf("%d requests in %v with -retries 0", n, time.Since(t0))
	}
	if row := summary["sources"].(map[string]any)["wayback"].(map[string]any); fmt.Sprint(row["error"]) != "failed after 1 try, 429 Too Many Requests" {
		t.Errorf("%v", row)
	}
	// More retries than the table has repeat its last wait.
	old := backoff
	backoff = []time.Duration{time.Millisecond}
	defer func() { backoff = old }()
	five := 5
	m2 := newMirror(t, pages)
	m2.status["/wayback"] = http.StatusServiceUnavailable
	if _, _, _, err := run(t, Options{Bases: m2.bases(), Client: m2.Client(), Only: []string{"wayback"}, Retries: &five}, context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := len(m2.asked("/wayback")); n != 6 {
		t.Errorf("%d requests with -retries 5", n)
	}
}

// A run that is stopped keeps what the archives had given: the file is
// written whatever ended the run.
func TestStopKeepsTheFile(t *testing.T) {
	m := newMirror(t, pages)
	m.slow["/wayback?1"] = time.Minute
	file := filepath.Join(t.TempDir(), "u.txt")
	ctx, cancel := context.WithCancel(context.Background())
	var once sync.Once
	o := Options{Bases: m.bases(), Client: m.Client(), Only: []string{"wayback"}, Out: file,
		OnURL: func(string, string) { once.Do(func() { time.AfterFunc(100*time.Millisecond, cancel) }) }}
	_, _, meta, err := run(t, o, ctx)
	if !errors.Is(err, context.Canceled) || meta.Status != types.StatusCancelled {
		t.Fatalf("%v %v", meta.Status, err)
	}
	raw, _ := os.ReadFile(file)
	if n := len(strings.Fields(string(raw))); n != 5 {
		t.Errorf("file holds %d URLs: %q", n, raw)
	}
}

// The run's own time limit ends the sources a little before it, so the
// summary can still say which were cut short.
func TestTimeoutCutsTheSourcesAndSaysSo(t *testing.T) {
	m := newMirror(t, pages)
	m.slow["/wayback?1"] = time.Minute
	ctx, cancel := context.WithTimeout(context.Background(), 1200*time.Millisecond)
	defer cancel()
	summary, _, meta, err := run(t, Options{Bases: m.bases(), Client: m.Client(), Only: []string{"wayback"}}, ctx)
	if err != nil || summary == nil {
		t.Fatalf("%v %v", err, summary)
	}
	row := summary["sources"].(map[string]any)["wayback"].(map[string]any)
	if row["error"] != types.CutShort || row["count"].(float64) != 5 || meta.Status != types.StatusDegraded {
		t.Errorf("row %v status %s", row, meta.Status)
	}
}

func TestProxyCarriesEveryRequest(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.URL.String())
		mu.Unlock()
		fmt.Fprint(w, `[["original"],["http://example.org/via-proxy"]]`)
	}))
	defer proxy.Close()
	var got []string
	o := Options{Proxy: proxy.URL, Only: []string{"wayback"}, Bases: map[string]string{"wayback": "http://archive.test/cdx"}, Apex: true,
		OnURL: func(u, _ string) { got = append(got, u) }}
	if _, _, _, err := run(t, o, context.Background()); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) == 0 || !strings.HasPrefix(seen[0], "http://archive.test/cdx?") || !slices.Contains(got, "http://example.org/via-proxy") {
		t.Errorf("proxy saw %v, got %v", seen, got)
	}
	for _, bad := range []string{"ftp://x", "nonsense", "http://"} {
		if _, err := ParseProxy(bad); err == nil {
			t.Errorf("%q passed", bad)
		}
	}
	if _, err := ParseProxy("socks5://127.0.0.1:9050"); err != nil {
		t.Error(err)
	}
}

// Common Crawl answers 404 for a name it holds nothing under: an empty
// answer, not a failure.
func TestCommonCrawlWithoutCapturesIsNotAFailure(t *testing.T) {
	m := newMirror(t, pages)
	m.status["/cc/idx"] = http.StatusNotFound
	summary, _, _, err := run(t, Options{Bases: m.bases(), Client: m.Client(), Only: []string{"commoncrawl"}}, context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if row := summary["sources"].(map[string]any)["commoncrawl"].(map[string]any); row["error"] != nil {
		t.Errorf("%v", row)
	}
}

func TestPauseOverride(t *testing.T) {
	none := time.Duration(0)
	c := New(Options{Pause: &none})
	for name, p := range c.pauses {
		if p != 0 {
			t.Errorf("%s still pauses %v", name, p)
		}
	}
	if c := New(Options{}); c.pauses["urlscan"] != 2*time.Second {
		t.Error("default pause changed")
	}
}

func TestDateBound(t *testing.T) {
	for _, c := range []struct {
		in   string
		last bool
		want string
	}{{"2024", false, "2024-01-01"}, {"2024", true, "2024-12-31"}, {"202402", true, "2024-02-29"}, {"202302", true, "2023-02-28"}, {"20240315", false, "2024-03-15"}, {"20240315120000", true, "2024-03-15"}} {
		if got := dateBound(c.in, c.last); got != c.want {
			t.Errorf("%s last=%v: %s, want %s", c.in, c.last, got, c.want)
		}
	}
}

// An archive may hold a scheme in capitals; the URL is the same page.
func TestCleanKeepsAnUppercaseScheme(t *testing.T) {
	got, ok := clean("HTTP://Example.ORG/Upper#frag", "example.org", true)
	if !ok || got != "http://example.org/Upper" {
		t.Errorf("%q %v", got, ok)
	}
	if _, ok := clean("ftp://example.org/x", "example.org", true); ok {
		t.Error("ftp kept")
	}
}

// socks5 serves one no-auth CONNECT at a time and relays it to target,
// whatever name the client asked for; asked lists the names.
func socks5(t *testing.T, target string, asked *[]string, mu *sync.Mutex) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 262)
				if _, err := io.ReadFull(c, buf[:2]); err != nil {
					return
				}
				if _, err := io.ReadFull(c, buf[:buf[1]]); err != nil {
					return
				}
				c.Write([]byte{5, 0})
				if _, err := io.ReadFull(c, buf[:5]); err != nil || buf[3] != 3 {
					return
				}
				n := int(buf[4])
				if _, err := io.ReadFull(c, buf[:n+2]); err != nil {
					return
				}
				mu.Lock()
				*asked = append(*asked, string(buf[:n]))
				mu.Unlock()
				up, err := net.Dial("tcp", target)
				if err != nil {
					return
				}
				defer up.Close()
				c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
				go io.Copy(up, c)
				io.Copy(c, up)
			}(c)
		}
	}()
	return ln.Addr().String()
}

func TestSocks5Proxy(t *testing.T) {
	m := newMirror(t, pages)
	var mu sync.Mutex
	var asked []string
	addr := socks5(t, strings.TrimPrefix(m.URL, "http://"), &asked, &mu)
	var got []string
	o := Options{Proxy: "socks5://" + addr, Only: []string{"wayback"}, Bases: map[string]string{"wayback": "http://archive.test/wayback"}, Apex: true,
		OnURL: func(u, _ string) { got = append(got, u) }}
	if _, _, _, err := run(t, o, context.Background()); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(asked) == 0 || asked[0] != "archive.test" || len(got) == 0 {
		t.Errorf("socks5 server asked for %v, got %v", asked, got)
	}
}

// Raw is what gau prints: urlscan's page URLs, without the task URLs
// azhaq otherwise adds.
func TestRawLeavesUrlscanTaskURLsOut(t *testing.T) {
	for raw, want := range map[bool]int{false: 2, true: 1} {
		m := newMirror(t, pages)
		var got []string
		o := Options{Bases: m.bases(), Client: m.Client(), Only: []string{"urlscan"}, Raw: raw, OnURL: func(u, _ string) { got = append(got, u) }}
		if _, _, _, err := run(t, o, context.Background()); err != nil {
			t.Fatal(err)
		}
		if len(got) != want {
			t.Errorf("raw=%v: %v", raw, got)
		}
	}
}

// An archive that answers 200 with a quota page or a JSON error has not
// answered: the source failed, with the archive's words.
func TestAnErrorAnswerIsAFailedArchive(t *testing.T) {
	for name, path := range map[string]string{"wayback": "/wayback", "commoncrawl": "/cc/idx", "otx": "/otx/domain/example.org/url_list", "urlscan": "/urlscan", "arquivo": "/arquivo"} {
		for _, body := range []string{`{"error":"quota exceeded"}`, `{"message":"Too Many Requests"}`, "error: slow down", `<html><title>Attention Required! | Cloudflare</title></html>`} {
			m := newMirror(t, pages)
			m.text[path] = body
			summary, _, _, err := run(t, Options{Bases: m.bases(), Client: m.Client(), Only: []string{name}}, context.Background())
			if err != nil {
				t.Fatal(err)
			}
			row := summary["sources"].(map[string]any)[name].(map[string]any)
			if e := fmt.Sprint(row["error"]); !strings.Contains(e, "answered 200 with an error, not URLs") || row["count"].(float64) != 0 {
				t.Errorf("%s given %q: %v", name, body, row)
			}
			if summary["degraded"] != true {
				t.Errorf("%s given %q: not degraded: %v", name, body, summary)
			}
		}
	}
}

// What is not an error is not a failure: Common Crawl's "No Captures found"
// object, and an empty answer.
func TestAnEmptyAnswerIsNotAFailedArchive(t *testing.T) {
	for name, path := range map[string]string{"commoncrawl": "/cc/idx", "arquivo": "/arquivo", "otx": "/otx/domain/example.org/url_list"} {
		for _, body := range []string{`{"error": "No Captures found for: example.org/*"}`, `{"has_next":false,"url_list":[]}`, ""} {
			if name == "otx" && body == "" {
				continue // not JSON: the source's own decoder fails it
			}
			m := newMirror(t, pages)
			m.text[path] = body
			summary, _, _, err := run(t, Options{Bases: m.bases(), Client: m.Client(), Only: []string{name}}, context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if row := summary["sources"].(map[string]any)[name].(map[string]any); row["error"] != nil {
				t.Errorf("%s given %q: %v", name, body, row)
			}
		}
	}
}

// An OTX URL cut at the end of its sentence, or shortened to "...", is junk
// like any other source's: left out and counted, and kept by -raw.
func TestOTXJunkIsDroppedAndCounted(t *testing.T) {
	otx := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"has_next":false,"url_list":[{"url":"https://example.org/reports/2307813."},{"url":"https://example.org/reports/..."},{"url":"https://example.org/reports/2307814"}]}`)
	}))
	defer otx.Close()
	m := newMirror(t, pages)
	bases := m.bases()
	bases["otx"] = otx.URL
	var got []string
	summary, _, _, err := run(t, Options{Bases: bases, Client: otx.Client(), Only: []string{"otx"}, OnURL: func(u, _ string) { got = append(got, u) }}, context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"https://example.org/reports/2307814"}; !slices.Equal(got, want) {
		t.Errorf("urls %v, want %v", got, want)
	}
	junk, _ := summary["junk"].(map[string]any)
	if junk["link cut at the end of its sentence"] != 1.0 || junk["malformed link (wildcard, quote, bracket, ellipsis)"] != 1.0 {
		t.Errorf("junk %v", junk)
	}
	got = nil
	if _, _, _, err := run(t, Options{Bases: bases, Client: otx.Client(), Only: []string{"otx"}, Raw: true, OnURL: func(u, _ string) { got = append(got, u) }}, context.Background()); err != nil || len(got) != 3 {
		t.Errorf("raw keeps them: %v (%v)", got, err)
	}
}
