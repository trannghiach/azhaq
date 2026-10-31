package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBenignExitAndRefused(t *testing.T) {
	if !benignExit("exit status 3 x") || !benignExit("exit status 4") || benignExit("exit status 2 flag provided but not defined") {
		t.Fatal("benignExit")
	}
	if !refused(runMeasure{Error: "exit status 2 usage"}) || refused(runMeasure{Error: "exit status 3"}) || refused(runMeasure{}) {
		t.Fatal("refused")
	}
}

func TestBarChecksNameTheProfileAndFailARunThatFailed(t *testing.T) {
	old, oldProf := rec, prof
	defer func() { rec, prof = old, oldProf }()
	rec = record{}
	prof = profPolite
	barOne("dirs", 5, 5, 10, 9.6, "a server", "azhaq dirs vs ffuf", "")
	barOne("dirs", 5, 4, 10, 9.6, "a server", "azhaq dirs vs ffuf", "[azhaq: exit status 2]")
	got := map[string]bool{}
	for _, c := range rec.Checks {
		if !strings.HasPrefix(c.Name, "[polite] dirs: ") {
			t.Fatalf("check %q has no profile", c.Name)
		}
		got[c.Name] = got[c.Name] || c.Pass
	}
	want := []struct {
		i    int
		pass bool
	}{{0, true}, {1, true}, {2, true}, {3, false}}
	// 10 s against 9.6 s is within 1.05; the second row's run failed, so no time to compare.
	for _, w := range want {
		if rec.Checks[w.i].Pass != w.pass {
			t.Fatalf("check %d (%s): pass %v, want %v", w.i, rec.Checks[w.i].Name, rec.Checks[w.i].Pass, w.pass)
		}
	}
}

func TestBarTimeIsFivePercent(t *testing.T) {
	old, oldProf := rec, prof
	defer func() { rec, prof = old, oldProf }()
	rec = record{}
	prof = ""
	barOne("x", 1, 1, 10.5, 10, "e", "c", "")
	barOne("x", 1, 1, 10.6, 10, "e", "c", "")
	if !rec.Checks[1].Pass || rec.Checks[3].Pass {
		t.Fatalf("1.05× is the line: %v", rec.Checks)
	}
}

func TestValidateOpenAPI(t *testing.T) {
	good := `{"openapi":"3.0.3","info":{"title":"t","version":"1"},"paths":{"/blog":{"get":{"operationId":"a","responses":{"200":{"description":"ok"}}}},
	"/users/{id}":{"get":{"operationId":"b","parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"string"}}],"responses":{"200":{"description":"ok"}}}}}}`
	var doc map[string]any
	if err := json.Unmarshal([]byte(good), &doc); err != nil {
		t.Fatal(err)
	}
	if bad := validateOpenAPI(doc); len(bad) != 0 {
		t.Fatalf("a valid document has problems: %v", bad)
	}
	for name, mut := range map[string]string{
		"duplicate operationId": `{"openapi":"3.0.3","info":{"title":"t","version":"1"},"paths":{"/blog":{"get":{"operationId":"a","responses":{"200":{"description":"ok"}}}},"/blog/":{"get":{"operationId":"a","responses":{"200":{"description":"ok"}}}}}}`,
		"undeclared path param": `{"openapi":"3.0.3","info":{"title":"t","version":"1"},"paths":{"/u/{id}":{"get":{"responses":{"200":{"description":"ok"}}}}}}`,
		"no responses":          `{"openapi":"3.0.3","info":{"title":"t","version":"1"},"paths":{"/u":{"get":{}}}}`,
		"bad ref":               `{"openapi":"3.0.3","info":{"title":"t","version":"1"},"paths":{"/u":{"get":{"responses":{"200":{"$ref":"#/components/responses/x"}}}}}}`,
		"swagger 2":             `{"swagger":"2.0","info":{"title":"t","version":"1"},"paths":{}}`,
	} {
		var d map[string]any
		if err := json.Unmarshal([]byte(mut), &d); err != nil {
			t.Fatal(err)
		}
		if len(validateOpenAPI(d)) == 0 {
			t.Errorf("%s: no problem found", name)
		}
	}
}

func TestNormalizedResultsDropsDuration(t *testing.T) {
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a.json"), filepath.Join(dir, "b.json")
	os.WriteFile(a, []byte(`{"results":[{"input":{"FUZZ":"YQ=="},"status":200,"duration":123,"position":2},{"input":{"FUZZ":"Yg=="},"status":301,"duration":9,"position":1}]}`), 0o644)
	os.WriteFile(b, []byte(`{"results":[{"position":1,"status":301,"input":{"FUZZ":"Yg=="},"duration":777},{"duration":5,"position":2,"input":{"FUZZ":"YQ=="},"status":200}]}`), 0o644)
	ra, err1 := normalizedResults(a)
	rb, err2 := normalizedResults(b)
	if err1 != nil || err2 != nil || strings.Join(ra, "\n") != strings.Join(rb, "\n") || len(ra) != 2 {
		t.Fatalf("%v %v %v %v", ra, rb, err1, err2)
	}
}

func TestHostPortKey(t *testing.T) {
	for in, want := range map[string]string{
		"127.0.0.1:8080":            "127.0.0.1:8080",
		"http://127.0.0.1:8080/x":   "127.0.0.1:8080",
		"https://www.example.com/":  "www.example.com",
		"www.example.com":           "www.example.com",
		"http://www.example.com:80": "www.example.com",
	} {
		if got := hostPortKey(in); got != want {
			t.Errorf("hostPortKey(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSweepListPoliteIsShortAndKeepsRealPaths(t *testing.T) {
	old, oldW, oldWork := prof, politeWords, work
	defer func() { prof, politeWords, work = old, oldW, oldWork }()
	work = t.TempDir()
	var words []string
	for i := 0; i < 4750; i++ {
		words = append(words, "w"+string(rune('a'+i%26))+strings.Repeat("x", i%7)+string(rune('a'+(i/26)%26))+string(rune('a'+(i/676)%26)))
	}
	src := filepath.Join(work, "src.txt")
	os.WriteFile(src, []byte(strings.Join(words, "\n")+"\n"), 0o644)
	prof, politeWords = profDefault, 250
	if p, n := sweepList(src, "t"); p != src || n != 4750 {
		t.Fatalf("default: %s %d", p, n)
	}
	prof = profPolite
	p, n := sweepList(src, "t")
	if n < 200 || n > 300 {
		t.Fatalf("polite list has %d words", n)
	}
	got := lines(must1(os.ReadFile(p)))
	has := map[string]bool{}
	for _, w := range got {
		has[w] = true
	}
	for _, w := range realPaths {
		if !has[w] {
			t.Fatalf("polite list lacks %q", w)
		}
	}
}

func TestSemverGE(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{{"0.10.0", "0.9.1", true}, {"0.9.0", "0.9.1", false}, {"0.9.1", "0.9.1", true}, {"1.0.0", "", true}, {"0.9.0", "0.9.0-rc1", true}} {
		if got := semverGE(c.a, c.b); got != c.want {
			t.Errorf("semverGE(%q, %q) = %v", c.a, c.b, got)
		}
	}
}

func TestReadmeBlockCarriesTheLabelTheDriftCheckReads(t *testing.T) {
	r := &record{Date: "2026-11-01T10:00:00Z", Commit: "abc1234", Profile: "both"}
	r.Dirs = &dirsRow{Words: 4750, AzhaqHits: 22, FfufHits: 22, AzhaqSecs: 30, FfufSecs: 31}
	r.Polite = &profileSet{Dirs: &dirsRow{Words: 250, AzhaqHits: 22, FfufHits: 22, AzhaqSecs: 60, FfufSecs: 61}}
	r.Checks = []check{{Pass: true}, {Pass: false}}
	b := readmeBlock(r, "0.10.0")
	m := latestRun.FindStringSubmatch(b)
	if m == nil || m[1] != "2026-11-01" || m[2] != "0.10.0" {
		t.Fatalf("label: %v in %q", m, b[:80])
	}
	if !strings.Contains(b, "| default |") || !strings.Contains(b, "| polite |") || !strings.Contains(b, "1 of 2 checks pass") {
		t.Fatal(b)
	}
}

// Two tools are timed in turn, so a target that drifts costs both the same.
func TestTimedPairTakesTheRunsInTurn(t *testing.T) {
	oldRec, oldFresh, oldWork := rec, fresh, work
	defer func() { rec, fresh, work = oldRec, oldFresh, oldWork }()
	rec, fresh, work = record{}, true, t.TempDir() // fresh: nothing replayed from a cache
	order := filepath.Join(t.TempDir(), "order")
	say := func(who string) []string { return []string{"-c", "echo " + who + " >> " + order + "; echo out-" + who} }
	aOut, am, bOut, bm := timedPair("t", time.Minute, t.TempDir(), "sh", "sh", say("a"), say("b"))
	got, _ := os.ReadFile(order)
	if string(got) != "a\nb\na\nb\na\nb\n" {
		t.Errorf("runs in this order: %q", got)
	}
	if string(aOut) != "out-a\n" || string(bOut) != "out-b\n" || am.Seconds <= 0 || bm.Seconds <= 0 {
		t.Errorf("outputs %q %q, seconds %v %v", aOut, bOut, am.Seconds, bm.Seconds)
	}
	if noCache {
		t.Error("the cache is left off")
	}

	// A run that failed is its tool's only measure; the other tool goes on.
	os.Remove(order)
	_, am, _, _ = timedPair("t", time.Minute, t.TempDir(), "sh", "sh", []string{"-c", "echo a >> " + order + "; exit 2"}, say("b"))
	got, _ = os.ReadFile(order)
	if string(got) != "a\nb\nb\nb\n" || am.Error == "" {
		t.Errorf("a failed tool is run once: %q, error %q", got, am.Error)
	}
}

// A reference that could not start has no time and no results: the
// comparison fails and says so, instead of finding azhaq within 5% of 0.0 s.
func TestBarFailsWhenTheReferenceDidNotRun(t *testing.T) {
	oldRec, oldProf, oldFresh, oldWork, oldGone := rec, prof, fresh, work, refGone
	defer func() { rec, prof, fresh, work, refGone = oldRec, oldProf, oldFresh, oldWork, oldGone }()
	rec, prof, fresh, work, refGone = record{}, profDefault, true, t.TempDir(), map[string]string{}

	// The tool is not there: run() notes it.
	_, m := run("notify", time.Second, t.TempDir(), filepath.Join(t.TempDir(), "notify"), "-i", "x")
	if m.Error == "" || refGone["notify"] == "" {
		t.Fatalf("a tool that cannot start is not marked: error %q, gone %v", m.Error, refGone)
	}
	barOne("notify", 6, 0, 5.0, 0.0, "the stub's own log", "azhaq notify -i x vs notify -i x -duc", "")
	for _, c := range rec.Checks {
		if c.Pass || !strings.Contains(c.Detail, "the reference did not run") {
			t.Errorf("%s: pass %v, detail %q", c.Name, c.Pass, c.Detail)
		}
	}
	if len(rec.Checks) != 2 || rec.Checks[1].Name != "[default] notify: time ≤ 1.05× the reference's" {
		t.Errorf("checks %+v", rec.Checks)
	}

	// A reference that ran is compared as before.
	rec.Checks = nil
	refGone = map[string]string{}
	barOne("notify", 6, 6, 5.0, 4.9, "the stub's own log", "azhaq notify -i x vs notify -i x -duc", "")
	if !rec.Checks[0].Pass || !rec.Checks[1].Pass {
		t.Errorf("checks %+v", rec.Checks)
	}
	if got := vsTool("azhaq dirs -u x vs /home/r/ffuf -u y"); got != "ffuf" {
		t.Errorf("vsTool %q", got)
	}
}
