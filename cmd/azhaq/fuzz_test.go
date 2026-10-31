package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/trannghiach/azhaq/internal/fuzz"
	"github.com/trannghiach/azhaq/store"
)

func fuzzServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "POST" && r.URL.Path == "/login":
			b := make([]byte, 200)
			n, _ := r.Body.Read(b)
			if strings.Contains(string(b[:n]), `"admin"`) {
				fmt.Fprint(w, `{"token":"t"}`)
				return
			}
			http.Error(w, "Password is not correct", 400)
		case r.URL.Path == "/admin":
			fmt.Fprint(w, "the admin page")
		case r.URL.Path == "/docs":
			http.Redirect(w, r, "/docs/", http.StatusMovedPermanently)
		case r.URL.Path == "/docs/guide":
			fmt.Fprint(w, "a guide inside docs")
		case r.Host == "dev.lab.test":
			fmt.Fprint(w, "the dev virtual host")
		default:
			fmt.Fprint(w, "the front page for everything else")
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func wlist(t *testing.T, lines ...string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "w.txt")
	if err := os.WriteFile(p, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// fuzzRows runs fuzz -json and gives the results as (status, url, input).
func fuzzRows(t *testing.T, args ...string) ([]string, report, error) {
	t.Helper()
	out, errOut, err := captureBoth(t, func() error { return cmdFuzz(append(args, "-json")) })
	var rows []string
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if json.Unmarshal([]byte(line), &m) != nil {
			t.Fatalf("not JSON: %q", line)
		}
		in := map[string]string{}
		for k, v := range m["input"].(map[string]any) {
			if k == "FFUFHASH" { // ffuf's name for the request; differs each run
				continue
			}
			raw, _ := base64.StdEncoding.DecodeString(v.(string))
			in[k] = string(raw)
		}
		keys := make([]string, 0, len(in))
		for k := range in {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var parts []string
		for _, k := range keys {
			parts = append(parts, k+"="+in[k])
		}
		rows = append(rows, fmt.Sprintf("%v %s %s", m["status"], m["url"], strings.Join(parts, ",")))
	}
	sort.Strings(rows)
	if exitCode(err) == exitUsage {
		return rows, report{}, err // a refused command prints no summary
	}
	return rows, lastReport(t, errOut), err
}

// fuzz is ffuf: it calibrates only when -ac (or -acs, -acc, -ach) is given.
func TestFuzzCalibratesOnlyWithAC(t *testing.T) {
	srv := fuzzServer(t)
	words := wlist(t, "admin", "nothing", "docs", "x")
	rows, rep, err := fuzzRows(t, "-u", srv.URL+"/FUZZ", "-w", words)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 4 || rep.Requests != 4 || rep.Exit != 0 || rep.Command != "fuzz" || !rep.Complete {
		t.Errorf("by default (ffuf's): %q, summary %+v", rows, rep)
	}
	for _, n := range rep.Notes {
		if strings.Contains(n, "calibration") {
			t.Errorf("a note about calibration without -ac: %s", n)
		}
	}
	want := []string{"200 " + srv.URL + "/admin FUZZ=admin", "301 " + srv.URL + "/docs FUZZ=docs"}
	for _, args := range [][]string{{"-ac"}, {"-acs", "basic"}, {"-ach"}, {"-acc", "zzqq"}} {
		rows, rep, err = fuzzRows(t, append([]string{"-u", srv.URL + "/FUZZ", "-w", words}, args...)...)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Join(rows, "|") != strings.Join(want, "|") || rep.Requests <= 4 {
			t.Errorf("%v: rows %q, %d requests", args, rows, rep.Requests)
		}
	}
	// An explicit -ac=false stays off, whatever else is given.
	rows, rep, _ = fuzzRows(t, "-u", srv.URL+"/FUZZ", "-w", words, "-acs", "basic", "-ac=false")
	if len(rows) != 4 || rep.Requests != 4 {
		t.Errorf("-ac=false -acs: %q, %d requests", rows, rep.Requests)
	}
}

// Two keywords, as in ffuf's clusterbomb: every answer that matches -mc is
// listed, the short ones too (calibration would drop answers of one size).
func TestFuzzClusterbombKeepsEveryMatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("q") == "apple" {
			fmt.Fprint(w, strings.Repeat("a product ", 40))
			return
		}
		fmt.Fprint(w, `{"status":"success","data":[]}`)
	}))
	t.Cleanup(srv.Close)
	rows, rep, err := fuzzRows(t, "-u", srv.URL+"/search?q=FUZZ&x=BAR", "-w", wlist(t, "apple", "zzzzzz")+":FUZZ", "-w", wlist(t, "1", "2")+":BAR",
		"-mode", "clusterbomb", "-mc", "200")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 4 || rep.Requests != 4 {
		t.Errorf("%d results, %d requests: %q", len(rows), rep.Requests, rows)
	}
}

func TestFuzzRecursion(t *testing.T) {
	srv := fuzzServer(t)
	rows, _, err := fuzzRows(t, "-u", srv.URL+"/FUZZ", "-w", wlist(t, "docs", "guide", "x"), "-recursion", "-recursion-depth", "2", "-ac")
	if err != nil {
		t.Fatal(err)
	}
	want := "200 " + srv.URL + "/docs/guide FUZZ=guide|301 " + srv.URL + "/docs FUZZ=docs"
	if strings.Join(rows, "|") != want {
		t.Errorf("rows %q", rows)
	}
	if _, _, err := fuzzRows(t, "-u", srv.URL+"/FUZZ/x", "-w", wlist(t, "a"), "-recursion"); exitCode(err) != exitUsage {
		t.Errorf("-recursion with the keyword not last: %v", err)
	}
}

func TestFuzzHostHeaderAndBody(t *testing.T) {
	srv := fuzzServer(t)
	rows, _, err := fuzzRows(t, "-u", srv.URL+"/", "-H", "Host: FUZZ.lab.test", "-w", wlist(t, "www", "dev", "mail"), "-mc", "200", "-fs", "35", "-ac")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || !strings.HasSuffix(rows[0], "FUZZ=dev") {
		t.Errorf("virtual hosts: %q", rows)
	}
	rows, _, _ = fuzzRows(t, "-u", srv.URL+"/login", "-X", "POST", "-H", "Content-Type: application/json", "-d", `{"username":"FUZZ"}`,
		"-w", wlist(t, "bob", "admin", "eve"), "-mr", `"token"`)
	if len(rows) != 1 || !strings.HasSuffix(rows[0], "FUZZ=admin") {
		t.Errorf("json body: %q", rows)
	}
	rows, _, _ = fuzzRows(t, "-u", srv.URL+"/login", "-d", `{"username":"FUZZ"}`, "-w", wlist(t, "bob", "admin"), "-mr", `"token"`)
	if len(rows) != 1 {
		t.Errorf("-d alone makes it a POST: %q", rows)
	}
}

func TestFuzzTwoWordlists(t *testing.T) {
	srv := fuzzServer(t)
	u, p := wlist(t, "bob", "admin", "eve"), wlist(t, "1", "2")
	for mode, requests := range map[string]int{"clusterbomb": 6, "pitchfork": 3} {
		rows, rep, err := fuzzRows(t, "-u", srv.URL+"/login", "-X", "POST", "-d", `{"username":"USER","password":"PASS"}`,
			"-w", u+":USER", "-w", p+":PASS", "-mode", mode, "-mr", `"token"`)
		if err != nil {
			t.Fatal(err)
		}
		if rep.Requests != int64(requests) || len(rows) != map[string]int{"clusterbomb": 2, "pitchfork": 1}[mode] {
			t.Errorf("%s: %d requests, rows %q", mode, rep.Requests, rows)
		}
	}
	// A keyword in no part of the request is dropped; none left is a usage error.
	_, _, err := fuzzRows(t, "-u", srv.URL+"/", "-w", u)
	if exitCode(err) != exitUsage {
		t.Errorf("no keyword in the request: %v", err)
	}
}

func TestFuzzOutputForms(t *testing.T) {
	srv := fuzzServer(t)
	w := wlist(t, "admin")
	out, _, _ := captureBoth(t, func() error { return cmdFuzz([]string{"-u", srv.URL + "/FUZZ", "-w", w, "-ac=false", "-mc", "200"}) })
	if !strings.HasPrefix(out, "admin ") || !strings.Contains(out, "[Status: 200, Size: 14, Words: 3, Lines: 1, Duration: ") {
		t.Errorf("default line %q", out)
	}
	out, _, _ = captureBoth(t, func() error {
		return cmdFuzz([]string{"-u", srv.URL + "/FUZZ", "-w", w, "-ac=false", "-mc", "200", "-s"})
	})
	if out != "admin\n" {
		t.Errorf("-s %q", out)
	}
	out, _, _ = captureBoth(t, func() error {
		return cmdFuzz([]string{"-u", srv.URL + "/FUZZ", "-w", w, "-ac=false", "-mc", "200", "-v"})
	})
	if !strings.Contains(out, "| URL | "+srv.URL+"/admin") || !strings.Contains(out, "    * FUZZ: admin") {
		t.Errorf("-v %q", out)
	}
	out, errOut, _ := captureBoth(t, func() error { return cmdFuzz([]string{"-u", srv.URL + "/FUZZ", "-w", w, "-ac=false", "-mc", "200"}) })
	if strings.Contains(out, "azhaq fuzz:") || !strings.Contains(errOut, "azhaq fuzz: 1 matches") {
		t.Errorf("the summary is on stderr: %q / %q", out, errOut)
	}
}

func TestFuzzScopeAndLimits(t *testing.T) {
	srv := fuzzServer(t)
	w := wlist(t, "a", "b", "c")
	// The host of -u is the scope: a word cannot take the request to another host.
	_, _, err := fuzzRows(t, "-u", srv.URL+"/FUZZ", "-w", w, "-deny", "127.0.0.1")
	if exitCode(err) != exitUsage {
		t.Errorf("a denied target: %v", err)
	}
	_, _, err = fuzzRows(t, "-u", "http://a-FUZZ.lab.test/", "-w", w)
	if exitCode(err) != exitUsage {
		t.Errorf("a keyword for a host without -allow: %v", err)
	}
	rows, rep, err := fuzzRows(t, "-u", "http://FUZZ.127.0.0.1.nip.invalid/", "-w", w, "-allow", "other.test")
	if err == nil && (len(rows) != 0 || rep.Requests != 0 || len(rep.Skipped) != 1) {
		t.Errorf("hosts outside -allow were requested: %+v", rep)
	}
	// The request budget stops the run with exit 4.
	_, rep, err = fuzzRows(t, "-u", srv.URL+"/FUZZ", "-w", w, "-ac=false", "-max-requests", "2", "-t", "1")
	if exitCode(err) != exitLimit || rep.Stopped == "" || rep.Requests != 2 {
		t.Errorf("budget: exit %d, %+v", exitCode(err), rep)
	}
}

func TestFuzzDBKeepsTheHits(t *testing.T) {
	srv := fuzzServer(t)
	db := filepath.Join(t.TempDir(), "f.db")
	if _, _, err := fuzzRows(t, "-u", srv.URL+"/FUZZ", "-w", wlist(t, "admin", "x"), "-db", db); err != nil {
		t.Fatal(err)
	}
	st, err := store.OpenExisting(db)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ents, _ := st.Entities()
	found := false
	for _, e := range ents {
		found = found || e.Key == srv.URL+"/admin"
	}
	if !found {
		t.Errorf("the hit is not in the workspace: %v", ents)
	}
}

func TestFuzzScopeRules(t *testing.T) {
	tm, _ := fuzz.NewTemplate("", "http://FUZZ.example.com/", "", nil, nil)
	r, _, err := fuzzScope(tm, nil, []string{"FUZZ"}, "", "", nil, nil)
	if err != nil || !r.Allows("a.example.com") || r.Allows("example.org") {
		t.Errorf("%+v %v", r, err)
	}
	tm, _ = fuzz.NewTemplate("", "http://app.example.com/FUZZ", "", nil, nil)
	r, _, err = fuzzScope(tm, nil, []string{"FUZZ"}, "", "", nil, []string{"app.example.com"})
	if err == nil || !errors.As(err, new(usageErr)) {
		t.Errorf("a denied host: %+v %v", r, err)
	}
}

func TestFuzzIsInTheCommandTable(t *testing.T) {
	c, ok := lookup("fuzz")
	if !ok || c.group != groupDropIn || c.like != "ffuf" || len(c.examples) != 5 || c.usage == "" || c.output == "" {
		t.Errorf("registry entry %+v", c)
	}
}

func TestFuzzResumeArgs(t *testing.T) {
	got := withoutFlag([]string{"-u", "http://h/FUZZ", "-start", "5", "-w", "w.txt", "-start=9", "-t", "10"}, "start")
	if strings.Join(got, " ") != "-u http://h/FUZZ -w w.txt -t 10" {
		t.Fatalf("%v", got)
	}
	if s := shellJoin([]string{"-H", "Host: FUZZ.x", "-mr", "it's"}); s != `-H 'Host: FUZZ.x' -mr 'it'\''s'` {
		t.Fatalf("%s", s)
	}
}

// A filter of the command's own sends no calibration request; -ac with it does.
func TestFuzzOwnFilterAndAC(t *testing.T) {
	srv := fuzzServer(t)
	_, rep, err := fuzzRows(t, "-u", srv.URL+"/FUZZ", "-w", wlist(t, "admin", "nothing"), "-mc", "all", "-fs", "4242")
	if err != nil {
		t.Fatal(err)
	}
	if rep.Requests != 2 {
		t.Errorf("%d requests, want 2 (no calibration)", rep.Requests)
	}
	_, rep, _ = fuzzRows(t, "-u", srv.URL+"/FUZZ", "-w", wlist(t, "admin", "nothing"), "-mc", "all", "-fs", "4242", "-ac")
	if rep.Requests != 8 {
		t.Errorf("%d requests with -ac, want 8", rep.Requests)
	}
}

func TestFuzzReportFiles(t *testing.T) {
	srv := fuzzServer(t)
	dir := t.TempDir()
	for _, f := range []string{"json", "ejson", "csv", "ecsv", "md", "html"} {
		p := filepath.Join(dir, "r."+f)
		if _, _, err := fuzzRows(t, "-u", srv.URL+"/FUZZ", "-w", wlist(t, "admin", "docs"), "-ac=false", "-o", p, "-of", f); err != nil {
			t.Fatal(f, err)
		}
		raw, err := os.ReadFile(p)
		if err != nil || !strings.Contains(string(raw), "admin") && !strings.Contains(string(raw), "YWRtaW4=") {
			t.Errorf("%s report: %v %.80q", f, err, raw)
		}
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "r.json"))
	var rep struct {
		Results []struct{ Input map[string]string }
		Config  map[string]any
	}
	if json.Unmarshal(raw, &rep) != nil || len(rep.Results) != 2 || rep.Results[0].Input["FUZZ"] != "admin" || rep.Config["threads"] == nil {
		t.Errorf("json report %s", raw)
	}
	if _, _, err := fuzzRows(t, "-u", srv.URL+"/FUZZ", "-w", wlist(t, "a"), "-o", filepath.Join(dir, "x"), "-of", "yaml"); exitCode(err) != exitUsage {
		t.Errorf("-of yaml: %v", err)
	}
	// -or: no file for no matches.
	p := filepath.Join(dir, "none.json")
	fuzzRows(t, "-u", srv.URL+"/FUZZ", "-w", wlist(t, "zzz"), "-ac=false", "-fc", "200", "-o", p, "-or")
	if _, err := os.Stat(p); err == nil {
		t.Error("-or wrote an empty report")
	}
}

// A preflight reads a one-use token the login needs: each request gets its
// own, the flight requests are counted, and a captured value cannot choose
// the host.
func TestFuzzPreflightCarriesATokenAndKeepsTheHost(t *testing.T) {
	var mu sync.Mutex
	issued := map[string]bool{}
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.URL.Path == "/form" {
			n++
			tok := fmt.Sprintf("t%d", n)
			issued[tok] = true
			fmt.Fprintf(w, `<input type="hidden" name="csrf" value="%s">`, tok)
			return
		}
		b, _ := io.ReadAll(r.Body)
		tok := strings.TrimPrefix(string(b), "csrf=")
		tok, _, _ = strings.Cut(tok, "&")
		if !issued[tok] {
			http.Error(w, "bad token", 403)
			return
		}
		delete(issued, tok)
		fmt.Fprint(w, "ok "+string(b))
	}))
	defer srv.Close()
	dir := t.TempDir()
	pre := filepath.Join(dir, "pre.req")
	os.WriteFile(pre, []byte("GET /form HTTP/1.1\n\n"), 0o644)
	rows, rep, err := fuzzRows(t, "-u", srv.URL+"/login", "-X", "POST", "-d", "csrf=TOKEN&p=FUZZ", "-w", wlist(t, "a", "b", "c"), "-ac=false", "-mc", "200",
		"-preflight", pre, "-preflight-var", `TOKEN:name="csrf" value="([^"]+)"`)
	if err != nil || len(rows) != 3 || rep.Requests != 6 {
		t.Errorf("rows %q requests %d err %v", rows, rep.Requests, err)
	}
	// A value taken from the answer that would be a host is refused.
	pre2 := filepath.Join(dir, "pre2.req")
	os.WriteFile(pre2, []byte("GET /form HTTP/1.1\nHost: HOSTX\n\n"), 0o644)
	_, rep, err = fuzzRows(t, "-u", srv.URL+"/login", "-X", "POST", "-d", "p=FUZZ", "-w", wlist(t, "a"), "-ac=false", "-mc", "all",
		"-preflight", pre, "-preflight-var", `HOSTX:name="csrf" value="([^"]+)"`, "-preflight", pre2)
	if exitCode(err) != exitPartial || len(rep.Failed) == 0 || !strings.Contains(fmt.Sprint(rep.Failed), "cannot choose where requests go") {
		t.Errorf("host change: exit %d, failed %+v", exitCode(err), rep.Failed)
	}
	if _, _, err := fuzzRows(t, "-u", srv.URL+"/FUZZ", "-w", wlist(t, "a"), "-preflight-var", "X:(y)"); exitCode(err) != exitUsage {
		t.Errorf("a variable before any -preflight: %v", err)
	}
}

func TestFuzzRequestFile(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = r.Method + " " + r.URL.String() + " " + r.Header.Get("X-A") + " " + string(b)
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()
	p := filepath.Join(t.TempDir(), "r.req")
	os.WriteFile(p, []byte("PUT /x?y=1 HTTP/1.1\r\nHost: "+strings.TrimPrefix(srv.URL, "http://")+"\r\nX-A: 1\r\nContent-Length: 3\r\n\r\nk=FUZZ\r\n"), 0o644)
	rows, _, err := fuzzRows(t, "-request", p, "-request-proto", "http", "-w", wlist(t, "v"), "-ac=false")
	if err != nil || len(rows) != 1 || got != "PUT /x?y=1 1 k=v" {
		t.Errorf("rows %q got %q err %v", rows, got, err)
	}
}

// -rate holds the calibration's guesses as it holds every request: the whole
// sweep, calibration included, keeps to the user's rate (ffuf's calibration
// is unpaced; the docs say so). The pace lets a burst of rate/5 through.
func TestFuzzRatePacesCalibration(t *testing.T) {
	srv := fuzzServer(t)
	start := time.Now()
	_, rep, err := fuzzRows(t, "-u", srv.URL+"/FUZZ", "-w", wlist(t, "admin", "nothing", "x"), "-ac", "-rate", "20", "-t", "1")
	took := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Requests <= 3 {
		t.Fatalf("%d requests: no calibration went out", rep.Requests)
	}
	if min := time.Duration(float64(rep.Requests-4) / 20 * 0.9 * float64(time.Second)); took < min {
		t.Errorf("%d requests at -rate 20 took %s, under %s: the calibration was not paced", rep.Requests, took, min)
	}
}

// The docs say what -rate does to calibration, and how it differs from ffuf.
func TestDocsSayRatePacesCalibration(t *testing.T) {
	for _, f := range []string{"../../docs/commands/dirs.md"} {
		doc := readDoc(t, f)
		if !strings.Contains(doc, "`-rate` paces every request, the calibration guesses included; ffuf sends its calibration unpaced") ||
			!strings.Contains(doc, "(guesses ÷ rate) seconds longer than ffuf's") && !strings.Contains(doc, "(guesses ÷ 5) seconds longer") {
			t.Errorf("%s does not say that -rate paces the calibration", f)
		}
	}
}

// An empty line of the wordlist is a word: FUZZ is replaced by nothing.
func TestFuzzBlankWordIsAsked(t *testing.T) {
	srv := fuzzServer(t)
	words := wlist(t, "", "admin")
	rows, rep, err := fuzzRows(t, "-u", srv.URL+"/FUZZ", "-w", words)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rep.Requests != 2 || !strings.Contains(strings.Join(rows, "\n"), srv.URL+"/ ") {
		t.Errorf("rows %q, summary %+v", rows, rep)
	}
}

// A budget stops a run with its 40 workers' answers out of order: the
// resume must ask only inputs not asked, and say only what it newly did.
func TestFuzzResumeAsksNothingTwice(t *testing.T) {
	var mu sync.Mutex
	seen := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen[r.URL.Path]++
		mu.Unlock()
		fmt.Fprint(w, "ok "+r.URL.Path)
	}))
	defer srv.Close()
	words := strings.Fields("a b c d e f g h i j")
	db := filepath.Join(t.TempDir(), "r.db")
	fz := []string{"-u", srv.URL + "/FUZZ", "-w", wlist(t, words...), "-db", db, "-ledger", "off", "-json", "-max-requests", "3"}
	_, errOut, err := captureBoth(t, func() error { return cmdFuzz(fz) })
	if exitCode(err) != exitLimit {
		t.Fatalf("first run: %v", err)
	}
	got := []int{lastReport(t, errOut).Results}
	for _, budget := range []string{"3", "20"} {
		_, errOut, err = captureBoth(t, func() error { return cmdResume([]string{"-db", db, "-max-requests", budget}) })
		if budget == "3" && exitCode(err) != exitLimit || budget == "20" && err != nil {
			t.Fatalf("resume %s: %v", budget, err)
		}
		got = append(got, lastReport(t, errOut).Results)
	}
	if fmt.Sprint(got) != "[3 3 4]" {
		t.Errorf("results per run %v, want [3 3 4]", got)
	}
	for _, w := range words {
		if seen["/"+w] != 1 {
			t.Errorf("/%s asked %d times: %v", w, seen["/"+w], seen)
		}
	}
}

// -maxtime that falls while the run waits for -rate is a stop: exit 4 with
// the words not asked left to the resume.
func TestFuzzMaxtimeInThePaceStops(t *testing.T) {
	srv := fuzzServer(t)
	var words []string
	for i := range 50 {
		words = append(words, fmt.Sprintf("w%d", i))
	}
	_, rep, err := fuzzRows(t, "-u", srv.URL+"/FUZZ", "-w", wlist(t, words...), "-ac=false", "-rate", "5", "-maxtime", "1", "-t", "1")
	if exitCode(err) != exitLimit || rep.Stopped == "" || rep.Complete || rep.Requests >= 50 || rep.Resume == "" {
		t.Errorf("exit %d, %+v", exitCode(err), rep)
	}
}
