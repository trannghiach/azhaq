package main

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
)

// archiveMirror answers every archive of azhaq urls for example.org from
// one server and records what was asked.
func archiveMirror(t *testing.T) (flags []string, asked func() []string) {
	var mu sync.Mutex
	var reqs []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		reqs = append(reqs, r.URL.RequestURI())
		mu.Unlock()
		q := r.URL.Query()
		switch {
		case r.URL.Path == "/wayback" && q.Get("page") == "0":
			fmt.Fprint(w, `[["original"],["http://example.org/a?x=1"],["http://example.org/a?x=2"],["http://example.org/logo.png"],["http://www.example.org/w"],["http://api.example.org/s"],["http://example.org/b"]]`)
		case r.URL.Path == "/wayback":
			w.WriteHeader(http.StatusBadRequest)
		case r.URL.Path == "/cc/collinfo.json":
			fmt.Fprintf(w, `[{"cdx-api":"http://%s/cc/idx"}]`, r.Host)
		case r.URL.Path == "/cc/idx" && q.Get("showNumPages") != "":
			fmt.Fprint(w, `{"pages":1}`)
		case r.URL.Path == "/cc/idx":
			fmt.Fprint(w, `{"url":"http://example.org/cc"}`+"\n")
		case strings.HasPrefix(r.URL.Path, "/otx/"):
			fmt.Fprint(w, `{"has_next":false,"url_list":[{"url":"http://example.org/otx"}]}`)
		case r.URL.Path == "/urlscan":
			fmt.Fprint(w, `{"has_more":false,"results":[{"page":{"url":"http://example.org/us"},"task":{"url":"http://example.org/us"},"sort":[1,"a"]}]}`)
		case r.URL.Path == "/arquivo":
			fmt.Fprint(w, `{"url":"http://example.org/arq"}`+"\n")
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	for name, path := range map[string]string{"wayback": "/wayback", "commoncrawl": "/cc/collinfo.json", "otx": "/otx", "urlscan": "/urlscan", "arquivo": "/arquivo"} {
		flags = append(flags, "-archive", name+"="+srv.URL+path)
	}
	return flags, func() []string { mu.Lock(); defer mu.Unlock(); return slices.Clone(reqs) }
}

func urlsRun(t *testing.T, args ...string) (lines []string, errOut string, err error) {
	t.Helper()
	out, errOut, err := captureBoth(t, func() error { return run(append([]string{"urls"}, args...)) })
	return strings.Fields(out), errOut, err
}

var apexURLs = []string{"http://example.org/a?x=1", "http://example.org/a?x=2", "http://example.org/arq", "http://example.org/b", "http://example.org/cc",
	"http://example.org/logo.png", "http://example.org/otx", "http://example.org/us", "http://www.example.org/w"}

// Into a pipe the URLs come as they arrive, each once; -sort holds them
// until every archive has answered and sorts them. The domain alone is the
// default, www. being the domain itself; -subs adds its subdomains.
func TestURLsApexStreamAndSort(t *testing.T) {
	flags, asked := archiveMirror(t)
	args := append([]string{"-d", "example.org", "-silent", "-urls-pause", "0"}, flags...)
	got, _, err := urlsRun(t, args...)
	if err != nil {
		t.Fatal(err)
	}
	sorted := slices.Clone(got)
	slices.Sort(sorted)
	if !slices.Equal(sorted, apexURLs) {
		t.Errorf("streamed %v", got)
	}
	got, _, err = urlsRun(t, append(args, "-sort")...)
	if err != nil || !slices.Equal(got, apexURLs) {
		t.Errorf("sorted %v %v", got, err)
	}
	for _, r := range asked() {
		if strings.HasPrefix(r, "/wayback") && !strings.Contains(r, "url=example.org%2F%2A") {
			t.Errorf("wayback asked %s: the host alone is the default", r)
		}
	}
	got, _, err = urlsRun(t, append(args, "-subs", "-sort")...)
	if err != nil || len(got) != len(apexURLs)+1 || !slices.Contains(got, "http://api.example.org/s") {
		t.Errorf("-subs %v %v", got, err)
	}
}

func TestURLsJSONAndPositionalDomains(t *testing.T) {
	flags, _ := archiveMirror(t)
	got, errOut, err := urlsRun(t, append([]string{"example.org", "-json", "-urls-pause", "0", "-providers", "wayback"}, flags...)...)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 5 {
		t.Fatalf("%v", got)
	}
	out := strings.Join(got, "")
	if !strings.Contains(out, `"url":"http://example.org/a?x=1"`) || !strings.Contains(out, `"source":"wayback"`) {
		t.Errorf("%s", out)
	}
	if r := lastReport(t, errOut); r.Results != 5 {
		t.Errorf("summary %+v", r)
	}
}

// -o adds to the file, as gau's does; the other commands still replace it.
func TestURLsOutputAppends(t *testing.T) {
	flags, _ := archiveMirror(t)
	file := filepath.Join(t.TempDir(), "all.txt")
	for i := 0; i < 2; i++ {
		if _, _, err := urlsRun(t, append([]string{"-d", "example.org", "-silent", "-urls-pause", "0", "-providers", "arquivo", "-o", file}, flags...)...); err != nil {
			t.Fatal(err)
		}
	}
	raw, _ := os.ReadFile(file)
	if got := strings.Fields(string(raw)); len(got) != 2 || got[0] != got[1] {
		t.Errorf("file %q", raw)
	}
}

// -providers is a list of archives; a file, or a value with a slash, is
// the key file it used to be; -provider-config says so without doubt.
func TestURLsProvidersFlag(t *testing.T) {
	flags, asked := archiveMirror(t)
	base := append([]string{"-d", "example.org", "-silent", "-urls-pause", "0"}, flags...)
	if _, _, err := urlsRun(t, append(base, "-providers", "wayback,otx")...); err != nil {
		t.Fatal(err)
	}
	for _, r := range asked() {
		if !strings.HasPrefix(r, "/wayback") && !strings.HasPrefix(r, "/otx") {
			t.Errorf("-providers wayback,otx asked %s", r)
		}
	}
	_, _, err := urlsRun(t, append(base, "-providers", "wayback,gau")...)
	var ue usageErr
	if !errors.As(err, &ue) || !strings.Contains(err.Error(), "-provider-config") {
		t.Errorf("an unknown archive: %v", err)
	}
	keys := filepath.Join(t.TempDir(), "keys.yaml")
	if err := os.WriteFile(keys, []byte("urlscan:\n  - k\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, f := range [][]string{{"-providers", keys}, {"-provider-config", keys}} {
		if got, _, err := urlsRun(t, append(base, f...)...); err != nil || len(got) != len(apexURLs) {
			t.Errorf("%v: %v %v", f, got, err)
		}
	}
}

func TestURLsFiltersAndNotes(t *testing.T) {
	flags, asked := archiveMirror(t)
	base := append([]string{"-d", "example.org", "-urls-pause", "0"}, flags...)
	got, errOut, err := urlsRun(t, append(base, "-mc", "200", "-ft", "image/png", "-from", "202401", "-sort")...)
	if err != nil {
		t.Fatalf("%v\n%s", err, errOut)
	}
	if !slices.Equal(got, []string{"http://example.org/a?x=1", "http://example.org/a?x=2", "http://example.org/arq", "http://example.org/b", "http://example.org/cc", "http://example.org/logo.png", "http://example.org/otx", "http://example.org/us", "http://www.example.org/w"}) {
		t.Errorf("%v", got)
	}
	for _, note := range []string{
		"otx has no status, type or date of its captures: its 1 URL is not filtered by -mc, -ft, -from",
		"urlscan has no status or type of its captures: its 2 URLs are not filtered by -mc, -ft",
	} {
		if !strings.Contains(errOut, note) {
			t.Errorf("the archives that cannot filter are not said (%q):\n%s", note, errOut)
		}
	}
	n := 0
	for _, r := range asked() {
		if strings.HasPrefix(r, "/wayback") && strings.Contains(r, "filter=statuscode%3A200") && strings.Contains(r, "filter=%21mimetype%3Aimage%2Fpng") && strings.Contains(r, "from=202401") {
			n++
		}
	}
	if n == 0 {
		t.Errorf("the filters did not reach wayback: %v", asked())
	}
	for _, bad := range [][]string{{"-from", "2024-01"}, {"-mc", "ok"}, {"-urls-pause", "0", "-proxy", "ftp://x"}, {"-archive", "wayback"}, {"-stream", "-sort"}, {"-raw", "-sort"}} {
		_, _, err := urlsRun(t, append(base, bad...)...)
		var ue usageErr
		if !errors.As(err, &ue) {
			t.Errorf("%v: %v", bad, err)
		}
	}
}

// gau's --mc filters where an archive has a status and prints the URLs of one
// that has none: -mc with only OTX lists OTX's URLs, unfiltered, and says so.
func TestURLsStatuslessArchiveKeepsItsURLsUnderMC(t *testing.T) {
	flags, _ := archiveMirror(t)
	base := append([]string{"-d", "example.org", "-urls-pause", "0", "-providers", "otx"}, flags...)
	got, errOut, err := urlsRun(t, append(base, "-mc", "200", "-json")...)
	if err != nil {
		t.Fatalf("%v\n%s", err, errOut)
	}
	if len(got) != 1 || got[0] != `{"source":"otx","url":"http://example.org/otx"}` && got[0] != `{"url":"http://example.org/otx","source":"otx"}` {
		t.Errorf("rows %q: no status, no invented one", got)
	}
	if !strings.Contains(errOut, "otx has no status of its captures: its 1 URL is not filtered by -mc") {
		t.Errorf("no note:\n%s", errOut)
	}
	if rep := lastReport(t, errOut); rep.Results != 1 || rep.Exit != 0 || rep.Stopped != "" {
		t.Errorf("summary %+v", rep)
	}
	for _, f := range []string{"-fc", "-ft", "-mt"} {
		v := "404"
		if f != "-fc" {
			v = "image/png"
		}
		got, errOut, err = urlsRun(t, append(base, f, v, "-silent")...)
		if err != nil || len(got) != 1 {
			t.Errorf("%s: %v %v", f, got, err)
		}
	}
	// Run apart from the stream: the same with the archives together.
	got, errOut, err = urlsRun(t, append([]string{"-d", "example.org", "-urls-pause", "0", "-mc", "200", "-sort", "-silent"}, flags...)...)
	if err != nil || !slices.Contains(got, "http://example.org/otx") || !slices.Contains(got, "http://example.org/us") {
		t.Errorf("%v %v\n%s", got, err, errOut)
	}
}

func TestURLsBlacklistRawAndFirstPath(t *testing.T) {
	flags, _ := archiveMirror(t)
	base := append([]string{"-d", "example.org", "-silent", "-urls-pause", "0", "-providers", "wayback", "-sort"}, flags...)
	got, _, err := urlsRun(t, append(base, "-blacklist", "png,jpg", "-fp")...)
	if err != nil || !slices.Equal(got, []string{"http://example.org/a?x=1", "http://example.org/b", "http://www.example.org/w"}) {
		t.Errorf("%v %v", got, err)
	}
	got, _, err = urlsRun(t, append([]string{"-d", "example.org", "-silent", "-urls-pause", "0", "-providers", "wayback", "-raw", "-blacklist", ".png"}, flags...)...)
	if err != nil || len(got) != 4 {
		t.Errorf("raw %v %v", got, err)
	}
}

// A gau config file sets what the command line leaves unset.
func TestURLsReadsAGauConfig(t *testing.T) {
	flags, _ := archiveMirror(t)
	cfg := filepath.Join(t.TempDir(), "gau.toml")
	body := "threads = 2\nretries = 1\nproviders = [\"wayback\", \"otx\"]\nblacklist = [\"png\"]  # images\nparameters = false\n\n[filters]\n  matchstatuscodes = []\n  filtermimetypes = []\n\n[urlscan]\n  apikey = \"\"\n"
	if err := os.WriteFile(cfg, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	got, errOut, err := urlsRun(t, append([]string{"-d", "example.org", "-urls-pause", "0", "-config", cfg, "-sort"}, flags...)...)
	if err != nil {
		t.Fatalf("%v\n%s", err, errOut)
	}
	want := []string{"http://example.org/a?x=1", "http://example.org/a?x=2", "http://example.org/b", "http://example.org/otx", "http://www.example.org/w"}
	if !slices.Equal(got, want) || !strings.Contains(errOut, "read "+cfg) {
		t.Errorf("%v\n%s", got, errOut)
	}
	// The command line wins.
	got, _, err = urlsRun(t, append([]string{"-d", "example.org", "-silent", "-urls-pause", "0", "-config", cfg, "-sort", "-providers", "arquivo"}, flags...)...)
	if err != nil || !slices.Equal(got, []string{"http://example.org/arq"}) {
		t.Errorf("%v %v", got, err)
	}
	if _, _, err := urlsRun(t, "-d", "example.org", "-config", filepath.Join(t.TempDir(), "none.toml")); err == nil {
		t.Error("a config that is not there passed")
	}
}

func TestReadGauConfig(t *testing.T) {
	f := filepath.Join(t.TempDir(), "c.toml")
	_ = os.WriteFile(f, []byte("threads = 3\nverbose = true\nproviders = [\n \"wayback\", # one\n \"otx\"\n]\notx = \"http://x.test/\"\n[urlscan]\nhost = \"http://u.test\"\napikey = \"a#b\"\n"), 0o644)
	cfg, err := readGauConfig(f)
	if err != nil {
		t.Fatal(err)
	}
	if cfg["threads"] != 3 || cfg["verbose"] != true || cfg["otx"] != "http://x.test/" || cfg["urlscan.host"] != "http://u.test" || cfg["urlscan.apikey"] != "a#b" {
		t.Errorf("%v", cfg)
	}
	if p, _ := cfg["providers"].([]string); !slices.Equal(p, []string{"wayback", "otx"}) {
		t.Errorf("%v", cfg["providers"])
	}
	_ = os.WriteFile(f, []byte("threads\n"), 0o644)
	if _, err := readGauConfig(f); err == nil {
		t.Error("a line without = passed")
	}
}

// The probes a scanner leaves beside a clean URL in an archive (?., ?.tst,
// ?%00) are dropped as junk and counted; a query with a name and value, or a
// dotted value, stays. -raw keeps them all.
func TestURLsDropsScannerProbeVariants(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"has_next":false,"url_list":[`+
			`{"url":"http://example.org/t/fit.txt"},`+
			`{"url":"http://example.org/t/fit.txt?."},`+
			`{"url":"http://example.org/t/fit.txt?.tst"},`+
			`{"url":"http://example.org/t/fit.txt?%00"},`+
			`{"url":"http://example.org/p?v=1.2"},`+
			`{"url":"http://example.org/q?id=3"}]}`)
	}))
	defer srv.Close()
	args := []string{"-d", "example.org", "-providers", "otx", "-urls-pause", "0", "-archive", "otx=" + srv.URL}
	got, _, err := urlsRun(t, args...)
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(got)
	if want := []string{"http://example.org/p?v=1.2", "http://example.org/q?id=3", "http://example.org/t/fit.txt"}; !reflect.DeepEqual(got, want) {
		t.Errorf("urls %v, want %v", got, want)
	}
	_, errOut, err := urlsRun(t, append(args, "-json")...)
	if err != nil {
		t.Fatal(err)
	}
	rep := lastReport(t, errOut)
	if want := map[string]int{"scanner probe": 3}; !reflect.DeepEqual(rep.Junk, want) || rep.Counts["dropped as junk"] != 3 {
		t.Errorf("junk %v counts %v", rep.Junk, rep.Counts)
	}
	_, errOut, err = urlsRun(t, args...)
	if err != nil || !strings.Contains(errOut, "3 URLs dropped as junk (3 scanner probe; -raw keeps them)") {
		t.Errorf("%v\n%s", err, errOut)
	}
	raw, _, err := urlsRun(t, append(args, "-raw")...)
	if err != nil || len(raw) != 6 {
		t.Errorf("-raw: %d lines %v", len(raw), err)
	}
}

// A page cap that cut an archive short is a note, and exit 4 when asked.
func TestURLsPageCapIsSaid(t *testing.T) {
	flags, _ := archiveMirror(t)
	args := append([]string{"-d", "example.org", "-urls-pause", "0", "-providers", "wayback", "-urls-pages", "1"}, flags...)
	_, errOut, err := urlsRun(t, args...)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(errOut, "wayback stopped at its page cap") {
		t.Errorf("%s", errOut)
	}
	_, _, err = urlsRun(t, append(args, "-fail-on-capped")...)
	var ee exitErr
	if !errors.As(err, &ee) || ee.code != exitLimit {
		t.Errorf("-fail-on-capped: %v", err)
	}
}

// URLs left out as junk are counted, by reason, in the summary; -raw keeps
// them and says nothing was dropped.
func TestURLsSaysHowManyWereDroppedAsJunk(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"has_next":false,"url_list":[`+
			`{"url":"http://example.org/ok?id=1"},`+
			`{"url":"http://example.org/x?q=<script>alert(1)</script>"},`+
			`{"url":"http://example.org/y?q=../../../../etc/passwd"},`+
			`{"url":"http://example.org/acunetix_xsl_inclusion_test.xsl"},`+
			`{"url":"http://example.org/rest/basket/NaN"},`+
			`{"url":"http://example.org/rest/basket/NaN"},`+
			`{"url":"http://other.test/<script>alert(1)</script>"}]}`)
	}))
	defer srv.Close()
	args := []string{"-d", "example.org", "-providers", "otx", "-urls-pause", "0", "-archive", "otx=" + srv.URL}
	lines, errOut, err := urlsRun(t, append(args, "-json")...)
	if err != nil || len(lines) != 1 {
		t.Fatalf("%v %v", lines, err)
	}
	rep := lastReport(t, errOut)
	want := map[string]int{"scanner payload": 2, "scanner probe": 1, "script placeholder (NaN, undefined, null)": 1}
	if !reflect.DeepEqual(rep.Junk, want) || rep.Counts["dropped as junk"] != 4 {
		t.Errorf("junk %v counts %v", rep.Junk, rep.Counts)
	}
	_, errOut, err = urlsRun(t, args...)
	if err != nil || !strings.Contains(errOut, "4 URLs dropped as junk (2 scanner payload, 1 scanner probe, 1 script placeholder (NaN, undefined, null); -raw keeps them)") {
		t.Errorf("%v\n%s", err, errOut)
	}
	lines, errOut, err = urlsRun(t, append(args, "-raw")...)
	if err != nil || len(lines) != 6 || strings.Contains(errOut, "dropped as junk") {
		t.Errorf("-raw: %d lines %v\n%s", len(lines), err, errOut)
	}
}

// The summary's requests count is what reached the targets, and urls sends
// none; the archives' own requests, retries included, are in the sources
// block and in a note.
func TestURLsSummaryCountsTheArchiveRequests(t *testing.T) {
	var mu sync.Mutex
	var n int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		n++
		first := n == 1
		mu.Unlock()
		if first {
			w.WriteHeader(http.StatusServiceUnavailable) // asked again
			return
		}
		fmt.Fprint(w, `{"has_next":false,"url_list":[{"url":"http://example.org/otx"}]}`)
	}))
	defer srv.Close()
	_, errOut, err := urlsRun(t, "-d", "example.org", "-json", "-urls-pause", "0", "-providers", "otx", "-archive", "otx="+srv.URL+"/otx")
	if err != nil {
		t.Fatal(err)
	}
	r := lastReport(t, errOut)
	mu.Lock()
	sent := n
	mu.Unlock()
	if sent != 2 || r.Sources == nil || r.Sources.Requests["otx"] != sent {
		t.Fatalf("server saw %d requests, sources block %+v", sent, r.Sources)
	}
	if r.Requests != 0 || !strings.Contains(strings.Join(r.Notes, "\n"), "2 requests to archives, retries included (otx 2)") {
		t.Errorf("requests %d, notes %v", r.Requests, r.Notes)
	}
}
