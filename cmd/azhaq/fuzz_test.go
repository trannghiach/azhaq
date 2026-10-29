package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

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

func TestFuzzPathsCalibratedByDefault(t *testing.T) {
	srv := fuzzServer(t)
	rows, rep, err := fuzzRows(t, "-u", srv.URL+"/FUZZ", "-w", wlist(t, "admin", "nothing", "docs", "x"))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"200 " + srv.URL + "/admin FUZZ=admin", "301 " + srv.URL + "/docs FUZZ=docs"}
	if strings.Join(rows, "|") != strings.Join(want, "|") {
		t.Errorf("rows %q", rows)
	}
	if rep.Command != "fuzz" || rep.Results != 2 || !rep.Complete || rep.Exit != 0 || rep.Requests != 10 {
		t.Errorf("summary %+v", rep)
	}
	// -ac=false shows the catch-all page too.
	rows, rep, _ = fuzzRows(t, "-u", srv.URL+"/FUZZ", "-w", wlist(t, "admin", "nothing", "docs", "x"), "-ac=false")
	if len(rows) != 4 || rep.Requests != 4 {
		t.Errorf("without calibration: %q, %d requests", rows, rep.Requests)
	}
}

func TestFuzzRecursion(t *testing.T) {
	srv := fuzzServer(t)
	rows, _, err := fuzzRows(t, "-u", srv.URL+"/FUZZ", "-w", wlist(t, "docs", "guide", "x"), "-recursion", "-recursion-depth", "2")
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
	rows, _, err := fuzzRows(t, "-u", srv.URL+"/", "-H", "Host: FUZZ.lab.test", "-w", wlist(t, "www", "dev", "mail"), "-mc", "200", "-fs", "35")
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
	r, err := fuzzScope(tm, []string{"FUZZ"}, "", "", nil, nil)
	if err != nil || !r.Allows("a.example.com") || r.Allows("example.org") {
		t.Errorf("%+v %v", r, err)
	}
	tm, _ = fuzz.NewTemplate("", "http://app.example.com/FUZZ", "", nil, nil)
	r, err = fuzzScope(tm, []string{"FUZZ"}, "", "", nil, []string{"app.example.com"})
	if err == nil || !errors.As(err, new(usageErr)) {
		t.Errorf("a denied host: %+v %v", r, err)
	}
}

func TestFuzzIsInTheCommandTable(t *testing.T) {
	c, ok := lookup("fuzz")
	if !ok || c.group != groupDropIn || c.like != "ffuf" || len(c.examples) != 3 || c.usage == "" || c.output == "" {
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
