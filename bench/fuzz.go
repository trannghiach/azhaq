package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// fuzzRow compares `azhaq fuzz` with ffuf on the bench apps: the same
// wordlist, matchers and filters, the hits, and the JSON report.
type fuzzRow struct {
	Profile  string    `json:"profile,omitempty"`
	AppDowns int       `json:"app_down_during_sweep,omitempty"` // an app crashed under the sweeps: the rows are not a measure
	Words    int       `json:"words"`
	Legs     []fuzzLeg `json:"legs"`
}

type fuzzLeg struct {
	App           string   `json:"app"`
	Variant       string   `json:"variant"` // calibrated (-ac) or filtered (-fs)
	AzhaqHits     int      `json:"azhaq_hits"`
	FfufHits      int      `json:"ffuf_hits"`
	Shared        int      `json:"shared"`
	AzhaqOK       int      `json:"azhaq_confirmed"`
	FfufOK        int      `json:"ffuf_confirmed"`
	AzhaqSecs     float64  `json:"azhaq_seconds"`
	FfufSecs      float64  `json:"ffuf_seconds"`
	ReportEqual   *bool    `json:"report_equal,omitempty"`
	ReportProblem string   `json:"report_problem,omitempty"`
	FfufOnly      []string `json:"ffuf_only,omitempty"`
}

func benchFuzz(apps []string) *fuzzRow {
	src, err := fetchWordlist(webWords)
	must(err)
	words, n := sweepList(src, "fuzz")
	row := &fuzzRow{Profile: prof, Words: n}
	downs0 := appRestarts
	defer func() { row.AppDowns = appRestarts - downs0 }()
	rate := pick([]string(nil), []string{"-rate", politeHTTP})
	for _, app := range apps {
		u := app + "FUZZ"
		// -ac on both sides: fuzz calibrates only when asked, as ffuf does.
		legs := []struct {
			name   string
			az, ff []string
		}{{"calibrated (-ac)", []string{"-ac"}, []string{"-ac"}}}
		if !polite() {
			// A matcher and a filter, no calibration: a ported ffuf line.
			fs := strconv.Itoa(missingSize(app))
			legs = append(legs, struct {
				name   string
				az, ff []string
			}{"filtered (-fs " + fs + ")", []string{"-fs", fs}, []string{"-fs", fs}})
		}
		for _, lg := range legs {
			leg := fuzzLeg{App: app, Variant: lg.name}
			aa := append(append([]string{"fuzz", "-u", u, "-w", words, "-s"}, lg.az...), rate...)
			fa := append(append([]string{"-u", u, "-w", words, "-s"}, lg.ff...), rate...)
			var az, ff map[string]bool
			var am, fm runMeasure
			beforeEach = func() { freshApp(app) }
			legWithApp(app, func() {
				var out []byte
				out, am = timed(app, 40*time.Minute, work, azhaq, aa...)
				az = fuzzHits(out, app)
				out, fm = timed(app, 40*time.Minute, work, ref("ffuf"), fa...)
				ff = fuzzHits(out, app)
			})
			beforeEach = nil
			leg.AzhaqSecs, leg.FfufSecs = am.Seconds, fm.Seconds
			leg.AzhaqHits, leg.FfufHits, leg.Shared = len(az), len(ff), overlap(az, ff)
			for h := range az {
				if !softHit(h) {
					leg.AzhaqOK++
				}
			}
			for h := range ff {
				if !softHit(h) {
					leg.FfufOK++
				}
				if !az[h] {
					leg.FfufOnly = append(leg.FfufOnly, h)
				}
			}
			sort.Strings(leg.FfufOnly)
			// The JSON report, once per app, outside the timing.
			if !polite() && lg.name[0] == 'c' {
				leg.reportEqual(u, words)
			}
			row.Legs = append(row.Legs, leg)
			cmds := cmdLine(azhaq, aa...) + " vs " + cmdLine("ffuf", fa...)
			name := "fuzz " + filepath.Base(strings.TrimSuffix(strings.TrimPrefix(app, "http://"), "/")) + " " + lg.name
			barOne(name, leg.AzhaqOK, leg.FfufOK, leg.AzhaqSecs, leg.FfufSecs, "a request that is not the app's catch-all answer",
				cmds, fmt.Sprintf("%s; hits azhaq %d, ffuf %d, shared %d; %d words; %s; ffuf only %v%s", share(leg.Shared, leg.FfufHits), leg.AzhaqHits,
					leg.FfufHits, leg.Shared, n, ratio(leg.AzhaqSecs, leg.FfufSecs), clipList(leg.FfufOnly, 5), azErr(am))+downNote(appRestarts-downs0))
			if leg.ReportEqual != nil {
				addCheck("fuzz "+app+": the JSON report equals ffuf's (duration dropped)", *leg.ReportEqual, "%s", leg.ReportProblem)
			}
		}
	}
	return row
}

// fuzzHits reads a -s listing (the words) as URLs on app.
func fuzzHits(out []byte, app string) map[string]bool {
	set := map[string]bool{}
	for _, l := range lines(out) {
		set[app+strings.TrimPrefix(firstField(l), "/")] = true
	}
	return set
}

// missingSize is the length of the answer to a path that cannot exist.
func missingSize(app string) int {
	_, body := getBody(app + "azhaq-bench-" + fmt.Sprint(time.Now().UnixNano()))
	return len(body)
}

// reportEqual runs both tools with a JSON report file and compares the
// results as ffuf prints them, without the durations.
func (l *fuzzLeg) reportEqual(u, words string) {
	dir := filepath.Join(work, "fuzz-reports")
	must(os.MkdirAll(dir, 0o755))
	tag := strings.NewReplacer("http://", "", "/", "", ":", "-").Replace(u)
	af, ff := filepath.Join(dir, tag+"-azhaq.json"), filepath.Join(dir, tag+"-ffuf.json")
	_ = os.Remove(af)
	freshApp(u)
	_, am := run(u, 20*time.Minute, work, azhaq, "fuzz", "-u", u, "-w", words, "-s", "-ac", "-of", "json", "-o", af)
	freshApp(u)
	run(u, 20*time.Minute, work, ref("ffuf"), "-u", u, "-w", words, "-s", "-ac", "-of", "json", "-o", ff)
	a, aerr := normalizedResults(af)
	f, ferr := normalizedResults(ff)
	ok := aerr == nil && ferr == nil && len(a) == len(f)
	var problem string
	switch {
	case ferr != nil:
		problem = "ffuf's report: " + ferr.Error()
	case aerr != nil:
		problem = "azhaq's report: " + aerr.Error() + azErr(am) + " (stream F1: -o/-of report formats)"
	case len(a) != len(f):
		problem = fmt.Sprintf("azhaq %d results, ffuf %d", len(a), len(f))
	default:
		for i := range a {
			if a[i] != f[i] {
				ok = false
				problem = fmt.Sprintf("result %d differs: azhaq %s, ffuf %s", i+1, clip(a[i], 200), clip(f[i], 200))
				break
			}
		}
	}
	if ok {
		problem = fmt.Sprintf("%d results equal", len(a))
	}
	l.ReportEqual, l.ReportProblem = &ok, problem
}

// normalizedResults is a ffuf JSON report's results, one canonical line
// each, sorted by input, with the fields that vary left out.
func normalizedResults(path string) ([]string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Results []map[string]any `json:"results"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("not a ffuf report: %v", err)
	}
	var out []string
	for _, r := range doc.Results {
		delete(r, "duration")
		delete(r, "resultfile")
		if in, ok := r["input"].(map[string]any); ok {
			delete(in, "FFUFHASH") // a random prefix per run, in ffuf's own reports too
		}
		b, _ := json.Marshal(r) // map keys marshal sorted
		out = append(out, string(b))
	}
	sort.Strings(out)
	return out, nil
}
