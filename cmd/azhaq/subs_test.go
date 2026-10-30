package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/trannghiach/azhaq/internal/collectors/subcol"
)

func jsonRows(t *testing.T, stdout string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, l := range lines(stdout) {
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("%q: %v", l, err)
		}
		out = append(out, m)
	}
	return out
}

// The counts of a subs -live run add up: what the sources gave, less what
// did not resolve, plus the CNAME target, is what was printed.
func TestSubsLiveCountsAddUp(t *testing.T) {
	t.Chdir(t.TempDir())
	resolvers := serveZone(t, fakeZone{
		a:     map[string]string{"www.example.org": "192.0.2.10", "app.example.org": "192.0.2.11", "real.example.org": "192.0.2.12"},
		cname: map[string]string{"api.example.org": "www.example.org"},
	})
	defer subcol.UseTestSources(
		subcol.TestSource{Name: "s", Default: true, Names: []string{"api.example.org", "app.example.org", "stale.example.org"}},
		subcol.TestSource{Name: "pad", Default: true, Padding: true, Names: []string{"real.example.org", "junk1.example.org", "junk2.example.org", "app.example.org"}},
	)()
	out, rep, code := runContract(t, "subs", "-d", "example.org", "-live", "-resolvers", resolvers, "-no-history")
	if code != exitOK {
		t.Fatalf("exit %d %+v", code, rep)
	}
	c := rep.Counts
	if got := c["from sources"] - c["did not resolve"] + c["found as CNAME targets"]; got != rep.Results {
		t.Errorf("from sources %d - did not resolve %d + CNAME %d = %d, printed %d\n%v", c["from sources"], c["did not resolve"], c["found as CNAME targets"], got, rep.Results, c)
	}
	if c["from sources"] != 6 || c["did not resolve"] != 3 || c["resolved from sources"] != 3 || c["found as CNAME targets"] != 1 || rep.Results != 4 {
		t.Errorf("counts %v results %d", c, rep.Results)
	}
	if want := []string{"api.example.org", "app.example.org", "real.example.org", "www.example.org"}; !reflect.DeepEqual(hosts(t, out), want) {
		t.Errorf("printed %v", hosts(t, out))
	}
	found := false
	for _, n := range rep.Notes {
		if strings.HasPrefix(n, "count: 6 from the sources − 3 did not resolve + 1 found as CNAME targets = 4 printed") {
			found = true
		}
	}
	if !found {
		t.Errorf("no count note in %q", rep.Notes)
	}
}

// Without -live a guess is not looked up: it is listed, unverified, and
// counted; the names add up here too.
func TestSubsWithoutLiveListsGuessesUnverified(t *testing.T) {
	t.Chdir(t.TempDir())
	defer subcol.UseTestSources(
		subcol.TestSource{Name: "s", Default: true, Names: []string{"www.example.org"}},
		subcol.TestSource{Name: "pad", Default: true, Padding: true, Names: []string{"guess1.example.org", "guess2.example.org", "www.example.org"}},
	)()
	out, rep, code := runContract(t, "subs", "-d", "example.org", "-no-history")
	if code != exitOK {
		t.Fatalf("exit %d %+v", code, rep)
	}
	rows := jsonRows(t, out)
	got := map[string]bool{}
	for _, r := range rows {
		got[r["host"].(string)] = r["unverified"] == true
	}
	want := map[string]bool{"www.example.org": false, "guess1.example.org": true, "guess2.example.org": true}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("rows %v, want %v", got, want)
	}
	if rep.Counts["unverified"] != 2 || rep.Counts["from sources"] != 3 || rep.Results != 3 {
		t.Errorf("counts %v results %d", rep.Counts, rep.Results)
	}
}

func TestSubsDomainsAreCleaned(t *testing.T) {
	ds, notes := subsDomains([]string{"tesla.com,vulnweb.com", "https://HackerOne.com/x.", `"Example.org."  # note`, "1.2.3.4", "*.corp.example.net", "nodot", "TESLA.com"})
	want := []string{"tesla.com", "vulnweb.com", "hackerone.com", "example.org", "corp.example.net"}
	if !reflect.DeepEqual(ds, want) {
		t.Errorf("domains %v", ds)
	}
	if len(notes) != 2 || !strings.Contains(notes[0], "1.2.3.4 is an IP address") {
		t.Errorf("notes %q", notes)
	}
}

func TestSubsFlagsAsSubfinder(t *testing.T) {
	t.Chdir(t.TempDir())
	defer subcol.UseTestSources(
		subcol.TestSource{Name: "a", Default: true, Recursive: true, Names: []string{"www.example.org", "api.example.org", "cdn.example.org", "dev.api.example.org"}},
		subcol.TestSource{Name: "b", Default: true, Names: []string{"www.example.org", "mail.example.org"}},
	)()
	sub := func(args ...string) (string, report, int) {
		return runContract(t, append([]string{"subs", "-no-history"}, args...)...)
	}
	// Several domains in one -d, a URL, a trailing dot.
	out, rep, code := sub("-d", "example.org,https://Example.net/x.")
	if code != exitOK || len(jsonRows(t, out)) == 0 {
		t.Fatalf("exit %d %+v", code, rep)
	}
	inputs := map[any]bool{}
	for _, r := range jsonRows(t, out) {
		inputs[r["input"]] = true
	}
	if len(inputs) != 1 { // the test sources answer only for example.org names
		t.Errorf("inputs %v", inputs)
	}
	// -m and -f, with a glob; a filtered name is counted.
	out, rep, _ = sub("-d", "example.org", "-m", "*.example.org", "-f", "www.*,*.api.*")
	if got := hosts(t, out); !reflect.DeepEqual(got, []string{"api.example.org", "cdn.example.org", "mail.example.org"}) {
		t.Errorf("-m -f: %v", got)
	}
	if rep.Counts["left out by -m/-f"] != 2 || rep.Counts["from sources"]-rep.Counts["left out by -m/-f"] != rep.Results {
		t.Errorf("counts %v", rep.Counts)
	}
	out, _, _ = sub("-d", "example.org", "-match-regex", "^(api|mail)", "-filter-regex", `\.api\.`)
	if got := hosts(t, out); !reflect.DeepEqual(got, []string{"api.example.org", "mail.example.org"}) {
		t.Errorf("regex: %v", got)
	}
	// -recursive runs only the recursive source.
	out, rep, _ = sub("-d", "example.org", "-recursive")
	if got := hosts(t, out); len(got) != 4 || rep.Counts["sources asked"] != 1 {
		t.Errorf("-recursive: %v %v", got, rep.Counts)
	}
	// -cs text form.
	stdout, _, err := captureBoth(t, func() error { return runArgs("subs", "-d", "example.org", "-no-history", "-cs", "-silent") })
	if err != nil && exitCode(err) != exitPartial {
		t.Fatal(err)
	}
	if !strings.Contains(stdout, "www.example.org,[a,b]\n") || !strings.Contains(stdout, "mail.example.org,[b]\n") {
		t.Errorf("-cs: %q", stdout)
	}
	// -o appends, -oD writes a file per domain.
	f := filepath.Join(t.TempDir(), "sub", "out.txt")
	d := filepath.Join(t.TempDir(), "per")
	for range 2 {
		if _, _, err := captureBoth(t, func() error {
			return runArgs("subs", "-d", "example.org", "-no-history", "-silent", "-o", f, "-oD", d)
		}); err != nil {
			t.Fatal(err)
		}
	}
	raw, _ := os.ReadFile(f)
	if n := len(lines(string(raw))); n != 10 {
		t.Errorf("-o twice: %d lines, want 10", n)
	}
	if raw, _ := os.ReadFile(filepath.Join(d, "example.org.txt")); len(lines(string(raw))) != 5 {
		t.Errorf("-oD: %q", raw)
	}
}

// An unknown -sources name is said; alone it is a usage error.
func TestSubsUnknownSource(t *testing.T) {
	t.Chdir(t.TempDir())
	defer subcol.UseTestSources(subcol.TestSource{Name: "a", Default: true, Names: []string{"www.example.org"}})()
	out, rep, code := runContract(t, "subs", "-d", "example.org", "-no-history", "-sources", "a,nosuch")
	if code != exitOK || len(hosts(t, out)) != 1 || !strings.Contains(strings.Join(rep.Notes, "|"), "no source named nosuch") {
		t.Errorf("exit %d notes %q", code, rep.Notes)
	}
	_, _, code = runContract(t, "subs", "-d", "example.org", "-no-history", "-sources", "nosuch")
	if code != exitUsage {
		t.Errorf("alone: exit %d", code)
	}
	// none asks no source (a DNS-only run), as before sources were checked.
	out, _, code = runContract(t, "subs", "-d", "example.org", "-no-history", "-sources", "none")
	if code == exitUsage || len(hosts(t, out)) != 0 {
		t.Errorf("none: exit %d, %s", code, out)
	}
}

func TestSubsListSources(t *testing.T) {
	out, _, err := captureBoth(t, func() error { return runArgs("subs", "-ls", "-json") })
	if err != nil {
		t.Fatal(err)
	}
	rows := jsonRows(t, out)
	byName := map[string]map[string]any{}
	for _, r := range rows {
		byName[r["name"].(string)] = r
	}
	if len(rows) < 54 || byName["crtsh"]["recursive"] != true || byName["crtsh"]["keyRequirement"] != "none" || byName["chaos"]["keyRequirement"] != "required" || byName["certspotter"]["keyRequirement"] != "optional" {
		t.Errorf("%d rows, crtsh %v chaos %v", len(rows), byName["crtsh"], byName["chaos"])
	}
	out, _, _ = captureBoth(t, func() error { return runArgs("subs", "-ls") })
	if !strings.Contains(out, "chaos *\n") || !strings.Contains(out, "certspotter ~\n") || !strings.Contains(out, "crtsh\n") {
		t.Errorf("text list: %q", out[:min(len(out), 200)])
	}
}

func TestSourceRatesParse(t *testing.T) {
	got, err := parseSourceRates("hackertarget=10/m,crtsh=2/s, github=60/h")
	if err != nil || got["crtsh"] != 2 || got["github"] != 1.0/60 || got["hackertarget"] < 0.16 || got["hackertarget"] > 0.17 {
		t.Errorf("%v %v", got, err)
	}
	for _, bad := range []string{"crtsh", "crtsh=2", "crtsh=x/s", "crtsh=2/d", "=2/s"} {
		if _, err := parseSourceRates(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func runArgs(args ...string) error { return run(args) }

// A name that is only a CNAME exists in DNS and is a live name, as dnsx
// -a -cname lists it, whether its target answers or not.
func TestSubsLiveListsCNAMEOnlyNames(t *testing.T) {
	t.Chdir(t.TempDir())
	resolvers := serveZone(t, fakeZone{
		a:     map[string]string{"www.example.org": "192.0.2.10"},
		cname: map[string]string{"go.example.org": "www.example.org", "cdn.example.org": "gone.example.net"},
	})
	// cdn is only guessed (a padding source): the guess check keeps it too.
	defer subcol.UseTestSources(
		subcol.TestSource{Name: "s", Default: true, Names: []string{"go.example.org", "dead.example.org", "www.example.org"}},
		subcol.TestSource{Name: "pad", Default: true, Padding: true, Names: []string{"cdn.example.org", "junk.example.org"}},
	)()
	out, rep, code := runContract(t, "subs", "-d", "example.org", "-live", "-resolvers", resolvers, "-no-history")
	if code != exitOK {
		t.Fatalf("exit %d %+v", code, rep)
	}
	rows := map[string]map[string]any{}
	for _, r := range jsonRows(t, out) {
		rows[r["host"].(string)] = r
	}
	if len(rows) != 3 || rows["dead.example.org"] != nil {
		t.Fatalf("printed %v", hosts(t, out))
	}
	if cdn := rows["cdn.example.org"]; cdn["a"] != nil || cdn["cname"] == nil {
		t.Errorf("a CNAME to nowhere: %v", cdn)
	}
	if rep.Counts["CNAME only"] != 1 {
		t.Errorf("counts %v", rep.Counts)
	}
}

// Without -live a domain's names are printed when its sources have
// answered, not when the last domain does.
func TestSubsPrintsADomainWhenItsSourcesAnswered(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("AZHAQ_DATA_DIR", t.TempDir())
	defer subcol.UseTestSources(subcol.TestSource{Name: "s", Default: true, Delay: 1500 * time.Millisecond, DelayDomain: "example.net",
		Names: []string{"www.example.org", "www.example.net"}})()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	start := time.Now()
	firstAt := make(chan time.Duration, 1)
	got := make(chan string, 1)
	go func() {
		var all strings.Builder
		buf := make([]byte, 4096)
		sent := false
		for {
			n, err := r.Read(buf)
			if n > 0 && !sent {
				firstAt <- time.Since(start)
				sent = true
			}
			all.Write(buf[:n])
			if err != nil {
				got <- all.String()
				return
			}
		}
	}()
	done := make(chan error, 1)
	go func() {
		done <- run([]string{"subs", "-d", "example.org", "-d", "example.net", "-silent", "-no-history"})
	}()
	err = <-done
	end := time.Since(start)
	w.Close()
	os.Stdout = old
	out := <-got
	if err != nil {
		t.Fatal(err)
	}
	if first := <-firstAt; first > time.Second || end < 1400*time.Millisecond {
		t.Errorf("first line after %s, run took %s: the fast domain should not wait for the slow one", first, end)
	}
	if !strings.Contains(out, "www.example.org\n") || !strings.Contains(out, "www.example.net\n") {
		t.Errorf("output %q", out)
	}
}

// A domain keeps 200,000 names, not 20,000; a smaller -max-names cuts, says
// how many, and the exit is 3.
func TestSubsMaxNamesCutIsSaid(t *testing.T) {
	t.Chdir(t.TempDir())
	var names []string
	for i := range 30 {
		names = append(names, fmt.Sprintf("n%02d.example.org", i))
	}
	defer subcol.UseTestSources(subcol.TestSource{Name: "s", Default: true, Names: names})()
	out, rep, code := runContract(t, "subs", "-d", "example.org", "-no-history")
	if code != exitOK || len(hosts(t, out)) != 30 {
		t.Fatalf("uncut: exit %d, %d names", code, len(hosts(t, out)))
	}
	out, rep, code = runContract(t, "subs", "-d", "example.org", "-no-history", "-max-names", "10")
	if code != exitPartial || len(hosts(t, out)) != 10 || rep.Counts["cut by -max-names"] != 20 || rep.Counts["from sources"] != 10 {
		t.Errorf("cut: exit %d, %d names, counts %v", code, len(hosts(t, out)), rep.Counts)
	}
}

func TestNameSumAndRateLimitNote(t *testing.T) {
	c := map[string]int{"from sources": 2638, "did not resolve": 2096, "not checked": 1, "found as CNAME targets": 10}
	if got, want := nameSum(c, 551, false), "count: 2638 from the sources − 2096 did not resolve − 1 not checked + 10 found as CNAME targets = 551 printed"; got != want {
		t.Errorf("%q", got)
	}
	if nameSum(map[string]int{}, 0, false) != "" {
		t.Error("a sum with no names")
	}
	row := map[string]any{"rate_limited": true, "retried_429": 2.0, "waited_seconds": 6.0}
	if got := rateLimitNote("a.com", "crtname", row); !strings.Contains(got, "asked again 2 times after 6 s") {
		t.Errorf("%q", got)
	}
	row["gave_up_429"] = true
	if got := rateLimitNote("a.com", "crtname", row); !strings.Contains(got, "kept answering 429 after 2 retries") {
		t.Errorf("%q", got)
	}
	if got := rateLimitNote("a.com", "x", map[string]any{"gave_up_429": true, "retry_after_seconds": 120.0}); !strings.Contains(got, "asked for 120 s") {
		t.Errorf("%q", got)
	}
}
