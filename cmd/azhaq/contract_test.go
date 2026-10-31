package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/trannghiach/azhaq/internal/collectors/subcol"
	"github.com/trannghiach/azhaq/store"
)

// The contract tests encode bench/truth/contract/cases.md: the exit code,
// the summary and the rows a command wrote must agree. Every case runs
// with no network: local listeners, httptest and fake passive sources.

// fakeZone is a DNS zone: A records, CNAMEs, and NXDOMAIN for the rest.
type fakeZone struct {
	a     map[string]string // name → IPv4
	cname map[string]string // name → target
	// nxGone: a CNAME whose target is in no zone answers NXDOMAIN with the
	// chain, as a recursive resolver does, instead of NOERROR.
	nxGone bool
}

func (z fakeZone) handle(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	q := r.Question[0]
	name := strings.TrimSuffix(strings.ToLower(q.Name), ".")
	rr := func(s string) dns.RR { x, _ := dns.NewRR(s); return x }
	target, isAlias := z.cname[name]
	_, isHost := z.a[name]
	switch {
	case !isAlias && !isHost:
		m.Rcode = dns.RcodeNameError
	case q.Qtype == dns.TypeA:
		if isAlias {
			m.Answer = append(m.Answer, rr(name+". 60 IN CNAME "+target+"."))
			name = target
			_, inA := z.a[target]
			_, inC := z.cname[target]
			if z.nxGone && !inA && !inC {
				m.Rcode = dns.RcodeNameError
			}
		}
		if ip, ok := z.a[name]; ok {
			m.Answer = append(m.Answer, rr(name+". 60 IN A "+ip))
		}
	case q.Qtype == dns.TypeCNAME && isAlias:
		m.Answer = append(m.Answer, rr(name+". 60 IN CNAME "+target+"."))
	}
	_ = w.WriteMsg(m)
}

// serveZone starts the zone on 127.0.0.1 and returns a -resolvers file.
func serveZone(t *testing.T, z fakeZone) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no UDP: %v", err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(z.handle)}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	path := filepath.Join(t.TempDir(), "resolvers.txt")
	if err := os.WriteFile(path, []byte(pc.LocalAddr().String()+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

var dataDirs sync.Map // test name → its own data directory

// runContract runs one command line as main does, with -json, and
// checks the invariants I1 to I5 on what it printed.
func runContract(t *testing.T, args ...string) (stdout string, rep report, code int) {
	t.Helper()
	dir, _ := dataDirs.LoadOrStore(t.Name(), t.TempDir())
	t.Setenv("AZHAQ_DATA_DIR", dir.(string)) // subs keeps a name history there
	if !wantsJSON(args) {
		args = append(args, "-json")
	}
	out, errOut, err := captureBoth(t, func() error {
		err := run(args)
		reportError(args, err) // a usage error's summary is printed by main
		return err
	})
	code = exitCode(err)
	rep = lastReport(t, errOut)
	checkInvariants(t, strings.Join(args, " "), out, rep, code)
	return out, rep, code
}

func checkInvariants(t *testing.T, what, stdout string, rep report, code int) {
	t.Helper()
	// I1
	if rep.Exit != code {
		t.Errorf("I1 %s: summary exit %d, process exit %d", what, rep.Exit, code)
	}
	// I2
	if (rep.Stopped != "") != (code == exitLimit) {
		t.Errorf("I2 %s: stopped %q with exit %d", what, rep.Stopped, code)
	}
	// I3
	if rep.Complete != (code == exitOK) {
		t.Errorf("I3 %s: complete %v with exit %d", what, rep.Complete, code)
	}
	// I4
	if code == exitPartial && len(rep.Failed) == 0 && len(rep.Unreachable) == 0 && len(rep.Notes) == 0 {
		t.Errorf("I4 %s: exit 3 and nothing says why: %+v", what, rep)
	}
	// I5: run prints the map, not its results.
	if rep.Command != "run" {
		if n := len(lines(stdout)); n != rep.Results {
			t.Errorf("I5 %s: results %d, result lines on stdout %d\n%s", what, rep.Results, n, stdout)
		}
	}
}

func lines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

// hosts reads the "host" of each JSONL result line, sorted.
func hosts(t *testing.T, stdout string) []string {
	t.Helper()
	var out []string
	for _, l := range lines(stdout) {
		var row struct {
			Host string `json:"host"`
		}
		if err := json.Unmarshal([]byte(l), &row); err != nil || row.Host == "" {
			t.Fatalf("not a result line: %q (%v)", l, err)
		}
		out = append(out, row.Host)
	}
	sort.Strings(out)
	return out
}

// rowKeys reads the "key" of each map row, sorted.
func rowKeys(t *testing.T, stdout string) []string {
	t.Helper()
	var out []string
	for _, l := range lines(stdout) {
		var row struct {
			Key string `json:"key"`
		}
		if err := json.Unmarshal([]byte(l), &row); err != nil {
			t.Fatalf("not a map row: %q (%v)", l, err)
		}
		out = append(out, row.Key)
	}
	sort.Strings(out)
	return out
}

func failedSource(rep report, source string) (bool, bool) {
	for _, f := range rep.Failed {
		if f.Source == source {
			return true, f.Partial
		}
	}
	return false, false
}

// contract C2: -timeout cuts a source short: exit 4, resumable, and the
// resume gives the names of the source that was cut.
func TestContractTimeoutCutsASourceAndResumeFinishes(t *testing.T) {
	t.Chdir(t.TempDir())
	defer subcol.UseTestSources(
		subcol.TestSource{Name: "fast", Default: true, Names: []string{"a.example.org"}},
		subcol.TestSource{Name: "slow", Default: true, Names: []string{"b.example.org"}, Delay: 2 * time.Second},
	)()
	out, rep, code := runContract(t, "subs", "-d", "example.org", "-timeout", "800ms", "-db", "cut.db")
	if code != exitLimit || !strings.Contains(rep.Stopped, "-timeout") {
		t.Fatalf("exit %d stopped %q\n%+v", code, rep.Stopped, rep)
	}
	if !strings.Contains(rep.Resume, "azhaq resume -db cut.db") {
		t.Fatalf("resume %q", rep.Resume)
	}
	if got := hosts(t, out); !reflect.DeepEqual(got, []string{"a.example.org"}) {
		t.Fatalf("the names the first run had: %v", got)
	}
	_, rep, code = runContract(t, strings.Fields(rep.Resume)[1:]...) // as the summary says
	if code != exitOK {
		t.Fatalf("resume: exit %d\n%+v", code, rep)
	}
	st, err := store.OpenExisting("cut.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	names := map[string]bool{}
	for _, p := range payloads(st, "azhaq-subdomains") {
		for _, n := range strs(p["names"]) {
			names[n] = true
		}
	}
	if !names["a.example.org"] || !names["b.example.org"] {
		t.Fatalf("after the resume the db holds %v", names)
	}
}

// liveRows lists the Hostname rows with role live in a database.
func liveRows(t *testing.T, db string) []string {
	t.Helper()
	out, _, err := captureBoth(t, func() error {
		return run([]string{"query", "-db", db, "-type", "Hostname", "-role", "live", "-json", "-fields", "key"})
	})
	if err != nil {
		t.Fatal(err)
	}
	return rowKeys(t, out)
}

// contract C3: a live name that DNS met only as a CNAME target is a
// result, and the counts add up.
func TestContractLiveNameFoundAsCNAMETarget(t *testing.T) {
	t.Chdir(t.TempDir())
	resolvers := serveZone(t, fakeZone{
		a:     map[string]string{"www.example.org": "192.0.2.10", "app.example.org": "192.0.2.11"},
		cname: map[string]string{"api.example.org": "www.example.org"},
	})
	defer subcol.UseTestSources(subcol.TestSource{Name: "s", Default: true,
		Names: []string{"api.example.org", "app.example.org", "dead.example.org"}})()
	out, rep, code := runContract(t, "subs", "-d", "example.org", "-live", "-resolvers", resolvers, "-db", "live.db")
	if code != exitOK {
		t.Fatalf("exit %d\n%+v", code, rep)
	}
	printed := hosts(t, out)
	want := []string{"api.example.org", "app.example.org", "www.example.org"}
	if !reflect.DeepEqual(printed, want) {
		t.Fatalf("printed %v, want %v (www is only api's CNAME target)", printed, want)
	}
	if rep.Results != len(printed) {
		t.Errorf("results %d, printed %d", rep.Results, len(printed))
	}
	c := rep.Counts
	if c["collected"]-c["did not resolve"]+c["found as CNAME targets"] != rep.Results || c["found as CNAME targets"] != 1 {
		t.Errorf("collected %d - did not resolve %d + CNAME targets %d != results %d", c["collected"], c["did not resolve"], c["found as CNAME targets"], rep.Results)
	}
	if got := liveRows(t, "live.db"); !reflect.DeepEqual(got, want) {
		t.Errorf("live Hostname rows in the db: %v, want %v", got, want)
	}
}

// contract C4: dns asks each distinct name once. -json gives a row for
// each name with an address (A is the default type, as in dnsx); the one
// that does not exist is counted as not resolved and has no row, unless
// -rcode asks for it.
func TestContractDNSCountsDistinctNames(t *testing.T) {
	t.Chdir(t.TempDir())
	resolvers := serveZone(t, fakeZone{a: map[string]string{"a.example.org": "192.0.2.1", "c.example.org": "192.0.2.3"}})
	list := filepath.Join(t.TempDir(), "names.txt")
	if err := os.WriteFile(list, []byte("a.example.org\nA.example.org\nb.example.org\na.example.org\nc.example.org\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, rep, code := runContract(t, "dns", "-l", list, "-resolvers", resolvers)
	if code != exitOK {
		t.Fatalf("exit %d\n%+v", code, rep)
	}
	if rep.Counts["asked"] != 3 || rep.Results != 2 || rep.Counts["did not resolve"] != 1 {
		t.Errorf("results %d, counts %v: want 3 asked, 2 rows, 1 that did not resolve", rep.Results, rep.Counts)
	}
	if strings.Contains(out, `"host":"b.example.org"`) {
		t.Errorf("a row for a name with no address:\n%s", out)
	}
	out, rep, code = runContract(t, "dns", "-l", list, "-resolvers", resolvers, "-rcode", "nxdomain")
	if code != exitOK || rep.Results != 1 || !strings.Contains(out, `"host":"b.example.org"`) || !strings.Contains(out, `"status_code":"NXDOMAIN"`) {
		t.Errorf("-rcode nxdomain: exit %d results %d\n%s", code, rep.Results, out)
	}
	out, rep, code = runContract(t, "dns", "-l", list, "-resolvers", resolvers, "-a")
	if code != exitOK || rep.Results != 2 || rep.Counts["asked"] != 3 || rep.Counts["did not resolve"] != 1 {
		t.Errorf("-a: exit %d results %d counts %v\n%s", code, rep.Results, rep.Counts, out)
	}
}

// pageSite serves n pages linking to each other, and a templated family
// of /item?id=N pages when items > 0.
func pageSite(t *testing.T, chain, items int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		var links []string
		var n int
		switch {
		case r.URL.Path == "/":
			links = append(links, "/p1")
			for i := 1; i <= items; i++ {
				links = append(links, fmt.Sprintf("/item?id=%d", i))
			}
		case r.URL.Path == "/item":
		default:
			if _, err := fmt.Sscanf(r.URL.Path, "/p%d", &n); err != nil || n > chain {
				http.NotFound(w, r)
				return
			}
			if n < chain {
				links = append(links, fmt.Sprintf("/p%d", n+1))
			}
		}
		fmt.Fprint(w, "<html><title>t</title><body>")
		for _, l := range links {
			fmt.Fprintf(w, `<a href="%s">x</a>`, l)
		}
		fmt.Fprint(w, "</body></html>")
	}))
	t.Cleanup(srv.Close)
	return srv
}

// contract C5: results are the map rows; URLs folded into a template are
// labelled as folded when they outnumber the rows.
func TestContractFoldedURLsAreLabelled(t *testing.T) {
	t.Chdir(t.TempDir())
	srv := pageSite(t, 0, 8)
	flags := []string{"-no-paths", "-no-favicon", "-no-tech", "-depth", "2"}
	out, rep, code := runContract(t, append([]string{"run", "-url", srv.URL + "/", "-db", "fold.db"}, flags...)...)
	if code != exitOK {
		t.Fatalf("exit %d\n%+v", code, rep)
	}
	if rows := len(lines(out)); rep.Results != rows {
		t.Errorf("results %d, map rows %d", rep.Results, rows)
	}
	if rep.Counts["URLs"] <= rep.Results {
		t.Fatalf("the site was meant to fold URLs into rows: %d URLs, %d rows", rep.Counts["URLs"], rep.Results)
	}
	_, errOut, err := captureBoth(t, func() error {
		return run(append([]string{"run", "-url", srv.URL + "/", "-quiet", "-db", "fold-text.db"}, flags...))
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(errOut, "folded into templated rows") {
		t.Errorf("the text summary does not say the URLs are folded:\n%s", errOut)
	}
}

// contract C6: a request budget stops the run with work left; resumes
// finish it, and the rows are those of a run with no cap.
func TestContractRequestBudgetResumesToTheSameMap(t *testing.T) {
	t.Chdir(t.TempDir())
	srv := pageSite(t, 6, 0)
	flags := []string{"-no-paths", "-no-favicon", "-no-tech", "-depth", "8"}
	full, rep, code := runContract(t, append([]string{"run", "-url", srv.URL + "/", "-db", "full.db"}, flags...)...)
	if code != exitOK || rep.Requests <= 3 {
		t.Fatalf("uncapped run: exit %d, %d requests", code, rep.Requests)
	}
	_, rep, code = runContract(t, append([]string{"run", "-url", srv.URL + "/", "-db", "cap.db", "-max-requests", "3"}, flags...)...)
	if code != exitLimit || !strings.Contains(rep.Stopped, "request budget") || !strings.Contains(rep.Resume, "azhaq resume -db cap.db") {
		t.Fatalf("exit %d stopped %q resume %q", code, rep.Stopped, rep.Resume)
	}
	var last string
	for i := 0; code != exitOK; i++ {
		if i == 30 {
			t.Fatalf("still stopped after %d resumes: %+v", i, rep)
		}
		last, rep, code = runContract(t, "resume", "-db", "cap.db")
		if code != exitOK && code != exitLimit {
			t.Fatalf("resume: exit %d\n%+v", code, rep)
		}
	}
	if got, want := rowKeys(t, last), rowKeys(t, full); !reflect.DeepEqual(got, want) {
		t.Errorf("rows after the resumes\n%v\nrows of an uncapped run\n%v", got, want)
	}
}

// contract C7: a sampled source refused with 429 on every call is a
// failure, not a clean zero.
func TestContractSampledSourceRefusedIsFailed(t *testing.T) {
	t.Chdir(t.TempDir())
	defer subcol.UseTestSources(subcol.TestSource{Name: "refused", Default: true, Sampled: true,
		Err: errors.New("unexpected status code 429 received from refused")})()
	_, rep, code := runContract(t, "subs", "-d", "example.org", "-source-timeout", "2s")
	if code != exitPartial {
		t.Fatalf("exit %d\n%+v", code, rep)
	}
	if failed, partial := failedSource(rep, "refused"); !failed || partial {
		t.Fatalf("the refused source is not listed as failed: %+v", rep.Failed)
	}
	if rep.Counts["sources failed"] != 1 || !rep.Degraded {
		t.Errorf("counts %v degraded %v", rep.Counts, rep.Degraded)
	}
}

// contract C8: -all-sources says how many sources answered out of how
// many were asked, and counts the off-by-default failures apart.
func TestContractAllSourcesCountsOffByDefaultApart(t *testing.T) {
	t.Chdir(t.TempDir())
	sources := func(defaultErr error) []subcol.TestSource {
		return []subcol.TestSource{
			{Name: "main", Default: true, Names: []string{"a.example.org"}, Err: defaultErr},
			{Name: "extra1", Names: []string{"b.example.org"}},
			{Name: "extra2", Err: errors.New("boom")},
		}
	}
	restore := subcol.UseTestSources(sources(nil)...)
	defer restore()
	_, rep, code := runContract(t, "subs", "-d", "example.org", "-all-sources")
	want := map[string]int{"sources asked": 3, "sources answered": 2, "sources failed": 0, "off-by-default failed": 1, "from sources": 2}
	if code != exitOK || !reflect.DeepEqual(rep.Counts, want) || rep.Degraded {
		t.Errorf("exit %d degraded %v counts %v, want %v and not degraded", code, rep.Degraded, rep.Counts, want)
	}
	// Named with -sources, the same source is not off-by-default.
	_, rep, _ = runContract(t, "subs", "-d", "example.org", "-sources", "main,extra2")
	if rep.Counts["sources failed"] != 1 || rep.Counts["off-by-default failed"] != 0 || !rep.Degraded {
		t.Errorf("a source named with -sources: counts %v degraded %v", rep.Counts, rep.Degraded)
	}
	// A default source that fails is the run's failure.
	restore()
	defer subcol.UseTestSources(sources(errors.New("down"))...)()
	_, rep, code = runContract(t, "subs", "-d", "example.org", "-all-sources")
	want = map[string]int{"sources asked": 3, "sources answered": 1, "sources failed": 1, "off-by-default failed": 1, "from sources": 2}
	if !reflect.DeepEqual(rep.Counts, want) || !rep.Degraded {
		t.Errorf("exit %d degraded %v counts %v, want %v and degraded", code, rep.Degraded, rep.Counts, want)
	}
	// The text summary shows the counts.
	_, errOut, err := captureBoth(t, func() error {
		return run([]string{"subs", "-d", "example.org", "-all-sources"})
	})
	if err != nil && exitCode(err) != exitPartial {
		t.Fatal(err)
	}
	for _, s := range []string{"1 sources answered", "3 sources asked", "1 off-by-default failed"} {
		if !strings.Contains(errOut, s) {
			t.Errorf("the text summary lacks %q:\n%s", s, errOut)
		}
	}
}

// contract C9: an unknown flag is a usage error, in the summary too.
func TestContractUnknownFlagIsUsage(t *testing.T) {
	t.Chdir(t.TempDir())
	for _, cmd := range []string{"run", "subs", "dns", "probe", "ports", "query", "export", "resume", "roles"} {
		_, rep, code := runContract(t, cmd, "-no-such-flag")
		if code != exitUsage || rep.Exit != exitUsage || rep.Command != cmd {
			t.Errorf("%s: exit %d, summary %+v", cmd, code, rep)
		}
	}
}

// contract C11: -fail-on-errors makes a failed source exit 3 even when
// the others answered; without it the failure is listed as partial.
func TestContractFailOnErrors(t *testing.T) {
	t.Chdir(t.TempDir())
	defer subcol.UseTestSources(
		subcol.TestSource{Name: "good", Default: true, Names: []string{"a.example.org"}},
		subcol.TestSource{Name: "bad", Default: true, Err: errors.New("boom")},
	)()
	_, rep, code := runContract(t, "subs", "-d", "example.org")
	if failed, partial := failedSource(rep, "bad"); code != exitOK || !failed || !partial {
		t.Errorf("without the flag: exit %d, failed %+v", code, rep.Failed)
	}
	_, rep, code = runContract(t, "subs", "-d", "example.org", "-fail-on-errors")
	if failed, partial := failedSource(rep, "bad"); code != exitPartial || !failed || partial {
		t.Errorf("with -fail-on-errors: exit %d, failed %+v", code, rep.Failed)
	}
}

// The exit code follows what the report holds, for every combination.
func TestContractSettleKeepsTheInvariants(t *testing.T) {
	for _, c := range []struct {
		name string
		set  func(*report)
		exit int
	}{
		{"clean", func(*report) {}, exitOK},
		{"stopped", func(r *report) { r.Stopped = "x" }, exitLimit},
		{"stopped and failed", func(r *report) { r.Stopped = "x"; r.Unreachable = []string{"h"} }, exitLimit},
		{"unreachable", func(r *report) { r.Unreachable = []string{"h"} }, exitPartial},
		{"warned", func(r *report) { r.warned = true; r.Notes = []string{"dead session"} }, exitPartial},
	} {
		rep := newReport("roles")
		c.set(rep)
		rep.settle()
		out := ""
		if err := rep.err(); exitCode(err) != c.exit {
			t.Errorf("%s: exit %d, want %d", c.name, exitCode(err), c.exit)
		}
		checkInvariants(t, c.name, out, *rep, rep.Exit)
	}
}

// Commands built on run keep the invariants on the built-in site.
func TestContractInvariantsOnDemo(t *testing.T) {
	t.Chdir(t.TempDir())
	for _, args := range [][]string{
		{"run", "-demo", "-db", "demo.db"},
		{"run", "-demo", "-db", "items.db", "-max-items", "1"},
		{"run", "-demo", "-db", "conn.db", "-exec", "/bin/false"},
	} {
		runContract(t, args...)
	}
}

// A private suffix (github.io) sits under a public TLD: its names are in
// the sources, which are asked. Only a TLD no registry runs skips them.
func TestContractSubsAsksSourcesUnderAPrivateSuffix(t *testing.T) {
	t.Chdir(t.TempDir())
	defer subcol.UseTestSources(subcol.TestSource{Name: "s", Default: true, Names: []string{"docs.acme.github.io"}})()
	out, rep, code := runContract(t, "subs", "-d", "acme.github.io", "-no-history")
	if code != exitOK || !reflect.DeepEqual(hosts(t, out), []string{"docs.acme.github.io"}) {
		t.Fatalf("exit %d, printed %v\n%+v", code, hosts(t, out), rep)
	}
	out, rep, _ = runContract(t, "subs", "-d", "azqlab.lan", "-no-history")
	if len(hosts(t, out)) != 0 || !strings.Contains(strings.Join(rep.Notes, " "), "not a public domain") {
		t.Errorf("azqlab.lan: printed %v, notes %v", hosts(t, out), rep.Notes)
	}
}
