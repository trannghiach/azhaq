package subcol

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"

	"github.com/trannghiach/azhaq/catalog"
	"github.com/trannghiach/azhaq/internal/limit"
	"github.com/trannghiach/azhaq/types"
)

func fake(name string, need keyNeed, deflt bool, names []string, err error) source {
	return source{name: name, need: need, deflt: deflt, collect: func(context.Context, string, []string, *subscraping.Session) ([]string, error) {
		return names, err
	}}
}

func collector(o Options, srcs ...source) *Collector {
	c := New(o)
	c.sources = srcs
	c.limiter = limit.New(0, 1)
	return c
}

func run(t *testing.T, c *Collector, ctx context.Context) (map[string]any, types.RunMeta) {
	t.Helper()
	var payload map[string]any
	meta, err := c.Run(ctx, types.Seed{Type: types.TypeDomain, Keys: map[string]string{"domain": "example.org"}}, func(o types.Observation) error {
		return json.Unmarshal(o.Payload, &payload)
	})
	if err != nil {
		t.Fatal(err)
	}
	return payload, meta
}

func TestPlanKeysAndSelection(t *testing.T) {
	srcs := []source{
		fake("free", noKey, true, nil, nil),
		fake("slow", noKey, false, nil, nil),
		fake("paid", requiredKey, true, nil, nil),
		fake("better-with-key", optionalKey, true, nil, nil),
	}
	names := func(c *Collector) (string, map[string]string) {
		run, skipped := c.plan()
		var out []string
		for _, s := range run {
			out = append(out, s.name)
		}
		return strings.Join(out, ","), skipped
	}
	got, skipped := names(collector(Options{}, srcs...))
	if got != "free,better-with-key" || skipped["paid"] != "needs a key" {
		t.Errorf("default: %s %v", got, skipped)
	}
	if got, _ = names(collector(Options{All: true, Keys: map[string][]string{"paid": {"k"}}}, srcs...)); got != "free,slow,paid,better-with-key" {
		t.Errorf("all with key: %s", got)
	}
	if got, _ = names(collector(Options{Only: []string{"slow"}}, srcs...)); got != "slow" {
		t.Errorf("only: %s", got)
	}
	if got, _ = names(collector(Options{Exclude: []string{"FREE"}}, srcs...)); got != "better-with-key" {
		t.Errorf("exclude: %s", got)
	}
}

func TestMergeAndEarlyHints(t *testing.T) {
	c := collector(Options{},
		fake("a", noKey, true, []string{"www.example.org", "*.api.example.org", "evil.test", "example.org"}, nil),
		fake("b", noKey, true, []string{"WWW.example.org.", "mail.example.org"}, errors.New("partial page")),
		fake("c", noKey, true, nil, errors.New("down")),
	)
	var mu sync.Mutex
	var early []string
	ctx := catalog.WithHints(context.Background(), func(seeds []types.Seed) {
		mu.Lock()
		defer mu.Unlock()
		for _, s := range seeds {
			early = append(early, s.Keys["fqdn"])
		}
	})
	payload, meta := run(t, c, ctx)
	sort.Strings(early)
	if strings.Join(early, ",") != "api.example.org,example.org,mail.example.org,www.example.org" {
		t.Errorf("early hints %v", early)
	}
	if len(meta.NextHints) != 0 {
		t.Errorf("names hinted early came back again: %v", meta.NextHints)
	}
	if payload["count"].(float64) != 4 || payload["degraded"] != nil {
		t.Errorf("payload %v", payload)
	}
	srcs := payload["sources"].(map[string]any)
	if srcs["c"].(map[string]any)["error"] != "down" || srcs["b"].(map[string]any)["count"].(float64) != 2 {
		t.Errorf("per-source %v", srcs)
	}
	if !strings.Contains(payload["warning"].(string), "b, c") {
		t.Errorf("warning %v", payload["warning"])
	}
}

func TestNothingFoundAndBrokenIsDegraded(t *testing.T) {
	c := collector(Options{}, fake("a", noKey, true, nil, errors.New("429")))
	payload, meta := run(t, c, context.Background())
	if payload["degraded"] != true || meta.Status != types.StatusDegraded {
		t.Fatalf("payload %v meta %+v", payload, meta)
	}
	if c2 := collector(Options{}, fake("a", noKey, true, nil, nil)); true {
		payload, _ = run(t, c2, context.Background())
		if payload["degraded"] != nil {
			t.Fatalf("an answered zero is not degraded: %v", payload)
		}
	}
}

func TestLoadProviders(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "providers.yaml")
	if err := os.WriteFile(p, []byte("securitytrails: [k1, ' k2 ']\nCensys:\n  - id:secret\nvirustotal: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	keys, used, err := LoadProviders(filepath.Join(dir, "missing.yaml"), p)
	if err != nil || used != p {
		t.Fatal(used, err)
	}
	if strings.Join(keys["securitytrails"], ",") != "k1,k2" || keys["censys"][0] != "id:secret" {
		t.Errorf("keys %v", keys)
	}
	if _, ok := keys["virustotal"]; ok {
		t.Errorf("empty list kept")
	}
	if k, used, err := LoadProviders(filepath.Join(dir, "none.yaml")); err != nil || used != "" || len(k) != 0 {
		t.Errorf("missing file: %v %q %v", k, used, err)
	}
}

func TestDerivedDomainWaitsLess(t *testing.T) {
	defer func(d time.Duration) { fanoutTimeout = d }(fanoutTimeout)
	fanoutTimeout = 50 * time.Millisecond
	slow := source{name: "slow", deflt: true, collect: func(ctx context.Context, _ string, _ []string, _ *subscraping.Session) ([]string, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	c := collector(Options{SourceTimeout: time.Minute}, slow)
	t0 := time.Now()
	var payload map[string]any
	_, err := c.Run(context.Background(), types.Seed{Type: types.TypeDomain, Keys: map[string]string{"domain": "example.org", types.DerivedKey: "1"}}, func(o types.Observation) error {
		return json.Unmarshal(o.Payload, &payload)
	})
	if err != nil || time.Since(t0) > 5*time.Second {
		t.Fatalf("derived domain took %s (%v)", time.Since(t0), err)
	}
	if payload["degraded"] != true {
		t.Errorf("a source cut short must be reported: %v", payload)
	}
}

// hang is a source that never answers until its context ends (crt.sh on a
// bad day), or at all when it ignores the context (release closes it).
func hang(name string, release <-chan struct{}) source {
	return source{name: name, deflt: true, collect: func(ctx context.Context, _ string, _ []string, _ *subscraping.Session) ([]string, error) {
		if release != nil {
			<-release
			return nil, nil
		}
		<-ctx.Done()
		return nil, ctx.Err()
	}}
}

func TestRunDeadlineKeepsWhatSourcesGave(t *testing.T) {
	stuck := make(chan struct{})
	defer close(stuck)
	c := collector(Options{SourceTimeout: time.Minute},
		fake("fast", noKey, true, []string{"www.example.org", "api.example.org"}, nil),
		fake("other", noKey, true, []string{"mail.example.org"}, nil),
		hang("slow", nil),
		hang("deaf", stuck),
	)
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	t0 := time.Now()
	var payload map[string]any
	meta, err := c.Run(ctx, types.Seed{Type: types.TypeDomain, Keys: map[string]string{"domain": "example.org"}}, func(o types.Observation) error {
		if ctx.Err() != nil {
			return ctx.Err() // as the engine does: nothing is taken after the run ends
		}
		return json.Unmarshal(o.Payload, &payload)
	})
	if err != nil || ctx.Err() != nil {
		t.Fatalf("not emitted before the run's deadline (%s): %v", time.Since(t0), err)
	}
	if meta.Status != types.StatusDegraded || payload["degraded"] != true || payload["partial"] != true {
		t.Errorf("a result cut short by -timeout is partial: %+v %v", meta, payload)
	}
	if got := strings.Join(strs(payload["names"]), ","); got != "api.example.org,mail.example.org,www.example.org" {
		t.Errorf("names the sources gave were thrown away: %q", got)
	}
	srcs := payload["sources"].(map[string]any)
	for _, name := range []string{"slow", "deaf"} {
		msg, _ := srcs[name].(map[string]any)["error"].(string)
		if !strings.Contains(msg, "-timeout") {
			t.Errorf("%s: %q should say the run cut it short", name, msg)
		}
	}
	if srcs["fast"].(map[string]any)["error"] != nil || srcs["fast"].(map[string]any)["count"].(float64) != 2 {
		t.Errorf("fast: %v", srcs["fast"])
	}
	if len(meta.NextHints) != 3 {
		t.Errorf("hints %v", meta.NextHints)
	}
}

func TestSourceTimeoutAbandonsOneSourceOnly(t *testing.T) {
	stuck := make(chan struct{})
	defer close(stuck)
	c := collector(Options{SourceTimeout: 50 * time.Millisecond},
		fake("fast", noKey, true, []string{"www.example.org"}, nil),
		hang("slow", nil),
		hang("deaf", stuck),
	)
	t0 := time.Now()
	payload, meta := run(t, c, context.Background())
	if time.Since(t0) > 5*time.Second {
		t.Fatalf("waited %s on a source past -source-timeout", time.Since(t0))
	}
	if meta.Status != types.StatusOK || payload["degraded"] != nil || payload["partial"] != nil {
		t.Errorf("one slow source among answers is a warning, not a partial result: %+v %v", meta, payload)
	}
	if got := strings.Join(strs(payload["names"]), ","); got != "www.example.org" {
		t.Errorf("names %q", got)
	}
	srcs := payload["sources"].(map[string]any)
	for _, name := range []string{"slow", "deaf"} {
		msg, _ := srcs[name].(map[string]any)["error"].(string)
		if !strings.Contains(msg, "50ms (-source-timeout)") {
			t.Errorf("%s: %q should name -source-timeout", name, msg)
		}
	}
	if payload["warning"] != "failed: deaf, slow" {
		t.Errorf("warning %v", payload["warning"])
	}
}

func TestCancelledRunStillEmitsWhatItHas(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	// A source's names are hinted once its answer is recorded: the signal
	// that fast is in before slow pulls the plug.
	answered := make(chan struct{})
	var once sync.Once
	ctx = catalog.WithHints(ctx, func([]types.Seed) { once.Do(func() { close(answered) }) })
	c := collector(Options{SourceTimeout: time.Minute},
		fake("fast", noKey, true, []string{"www.example.org"}, nil),
		source{name: "slow", deflt: true, collect: func(ctx context.Context, _ string, _ []string, _ *subscraping.Session) ([]string, error) {
			<-answered
			cancel() // Ctrl-C while it is still working
			<-ctx.Done()
			return nil, ctx.Err()
		}},
	)
	payload, meta := run(t, c, ctx)
	if meta.Status != types.StatusDegraded || payload["degraded"] != true || payload["count"].(float64) != 1 {
		t.Errorf("%+v %v", meta, payload)
	}
	msg, _ := payload["sources"].(map[string]any)["slow"].(map[string]any)["error"].(string)
	if !strings.Contains(msg, "stopped with the run") {
		t.Errorf("slow: %q", msg)
	}
	// An emit the run's end refuses (the engine's) makes the task cancelled.
	meta, err := c.Run(ctx, types.Seed{Type: types.TypeDomain, Keys: map[string]string{"domain": "example.org"}}, func(types.Observation) error { return ctx.Err() })
	if meta.Status != types.StatusCancelled || !errors.Is(err, context.Canceled) {
		t.Errorf("%+v %v", meta, err)
	}
}

func strs(v any) []string {
	xs, _ := v.([]any)
	out := make([]string, 0, len(xs))
	for _, x := range xs {
		out = append(out, x.(string))
	}
	return out
}

// A padding source's names need a DNS check (Options.Verify). Under a tight
// -timeout that check cannot finish, and running it anyway would blow the
// deadline so the engine stores nothing — the v0.8 "0 names on -timeout"
// bug. The collector must emit the real names and drop the unchecked
// padding name instead.
func TestRunDeadlineSkipsSlowPaddingVerify(t *testing.T) {
	pad := fake("pad", noKey, true, []string{"junk.example.org"}, nil)
	pad.verify = true
	stuck := make(chan struct{})
	defer close(stuck)
	c := collector(Options{SourceTimeout: time.Minute, Verify: func(ctx context.Context, _ string, names []string) ([]string, []string) {
		<-ctx.Done() // the DNS check never answers in time
		return nil, names
	}},
		fake("fast", noKey, true, []string{"www.example.org"}, nil),
		pad,
		hang("deaf", stuck), // keeps a source running so the -timeout cuts the wait
	)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	t0 := time.Now()
	var payload map[string]any
	_, err := c.Run(ctx, types.Seed{Type: types.TypeDomain, Keys: map[string]string{"domain": "example.org"}}, func(o types.Observation) error {
		if ctx.Err() != nil {
			return ctx.Err() // as the engine does: nothing is taken after the run ends
		}
		return json.Unmarshal(o.Payload, &payload)
	})
	if err != nil || ctx.Err() != nil {
		t.Fatalf("emitted nothing before the deadline (%s): %v", time.Since(t0), err)
	}
	if got := strings.Join(strs(payload["names"]), ","); got != "junk.example.org,www.example.org" || strings.Join(strs(payload["unverified"]), ",") != "junk.example.org" {
		t.Errorf("want the real name kept and the unchecked padding name listed unverified, got %q", got)
	}
	if payload["partial"] != true {
		t.Errorf("a cut-short result is partial: %+v", payload)
	}
	if msg, _ := payload["sources"].(map[string]any)["pad"].(map[string]any)["error"].(string); !strings.Contains(msg, "not checked") {
		t.Errorf("padding source should say its names were not checked: %q", msg)
	}
}

// allLive is a Verify that finds every name live.
func allLive(_ context.Context, _ string, names []string) ([]string, []string) { return names, nil }

func TestSampledGathersUntilSaturated(t *testing.T) {
	answers := []struct {
		names []string
		err   error
	}{
		{[]string{"a.example.org", "b.example.org", "c.example.org", "d.example.org"}, nil},
		{[]string{"c.example.org", "d.example.org", "e.example.org", "f.example.org"}, nil},
		{[]string{"a.example.org", "b.example.org", "c.example.org", "d.example.org", "e.example.org", "f.example.org"}, nil}, // nothing new: stop
		{[]string{"never"}, nil},
	}
	calls := 0
	s := sampled(source{name: "s", collect: func(_ context.Context, _ string, keys []string, _ *subscraping.Session) ([]string, error) {
		if len(keys) > 0 {
			return []string{"keyed"}, nil
		}
		a := answers[calls]
		calls++
		return a.names, a.err
	}})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	chk := newChecker(ctx, "example.org", allLive, nil)
	ctx = context.WithValue(ctx, checkerKey{}, chk)
	got, err := s.collect(ctx, "example.org", nil, nil)
	if err != nil || calls != 3 || strings.Join(got, ",") != "a.example.org,b.example.org,c.example.org,d.example.org,e.example.org,f.example.org" {
		t.Fatalf("got %v %v after %d calls", got, err, calls)
	}
	if got, _ := s.collect(ctx, "example.org", []string{"k"}, nil); len(got) != 1 || got[0] != "keyed" {
		t.Fatalf("a key should page once: %v", got)
	}
	// A failed first call is the source's failure; a later one ends the
	// asking and keeps what the rounds gave.
	fail := errors.New("unexpected status code 500 received from x")
	calls = 0
	bad := sampled(source{name: "b.example.org", collect: func(context.Context, string, []string, *subscraping.Session) ([]string, error) {
		calls++
		if calls == 1 {
			return []string{"a.example.org"}, nil
		}
		return nil, fail
	}})
	if got, err := bad.collect(ctx, "example.org", nil, nil); err != nil || len(got) != 1 {
		t.Fatalf("a later round refused: %v %v", got, err)
	}
	first := sampled(source{name: "f.example.org", collect: func(context.Context, string, []string, *subscraping.Session) ([]string, error) {
		return nil, fail
	}})
	if _, err := first.collect(ctx, "example.org", nil, nil); err == nil {
		t.Fatal("first-round error swallowed")
	}
}

// subdomain.center answers a random sample per call. With resolvers, a
// round's new names are resolved before the next round is asked, a name is
// resolved once, and the asking stops at the first round that adds no name
// that resolves.
func TestSampledStopsWhenARoundAddsNoLiveName(t *testing.T) {
	rounds := [][]string{
		{"a.example.org", "b.example.org", "c.example.org"},
		{"b.example.org", "d.example.org", "e.example.org"}, // d is live
		{"a.example.org", "f.example.org", "g.example.org"}, // nothing live: stop
		{"h.example.org"},
	}
	var mu sync.Mutex
	var log []string
	asked := 0
	pad := sampled(verified(source{name: "pad", deflt: true, collect: func(context.Context, string, []string, *subscraping.Session) ([]string, error) {
		mu.Lock()
		defer mu.Unlock()
		log = append(log, "ask")
		r := rounds[min(asked, len(rounds)-1)]
		asked++
		return r, nil
	}}))
	live := map[string]bool{"a.example.org": true, "d.example.org": true}
	sent := map[string]int{}
	c := collector(Options{SourceTimeout: 5 * time.Second, NoHistory: true, Verify: func(_ context.Context, _ string, names []string) ([]string, []string) {
		mu.Lock()
		defer mu.Unlock()
		var out []string
		for _, n := range names {
			sent[n]++
			if live[n] {
				out = append(out, n)
			}
		}
		log = append(log, "check")
		return out, nil
	}}, pad, fake("real", noKey, true, []string{"www.example.org"}, nil))
	payload, _ := run(t, c, context.Background())
	// Each round's names are looked up once, and the next call is made
	// while they are: three rounds, and a fourth call made ahead.
	checks, asks := 0, 0
	for _, l := range log {
		if l == "check" {
			checks++
		} else {
			asks++
		}
	}
	if checks != 3 || asks < 3 || asks > 4 {
		t.Errorf("%d checks and %d calls: %q", checks, asks, log)
	}
	for n, k := range sent {
		if k != 1 {
			t.Errorf("%s resolved %d times", n, k)
		}
	}
	if got := strings.Join(strs(payload["names"]), ","); got != "a.example.org,d.example.org,www.example.org" {
		t.Errorf("names %s", got)
	}
	if payload["from_sources"] != float64(8) || payload["dropped"] != float64(5) || payload["checked"] != float64(7) {
		t.Errorf("counts %v", payload)
	}
	row := payload["sources"].(map[string]any)["pad"].(map[string]any)
	if c := row["calls"].(float64); c < 3 || c > 4 || row["kept"] != float64(2) || row["error"] != nil {
		t.Errorf("row %v", row)
	}
}

// Without -live nothing is resolved: the guesses are listed, unverified,
// and not kept in the history.
func TestNoCheckListsGuessesUnverified(t *testing.T) {
	t.Setenv("AZHAQ_DATA_DIR", t.TempDir())
	pad := fake("pad", noKey, true, []string{"junk.example.org", "real.example.org"}, nil)
	pad.verify = true
	asked := 0
	c := collector(Options{NoCheck: true, Verify: func(context.Context, string, []string) ([]string, []string) {
		asked++
		return nil, nil
	}}, pad, fake("a", noKey, true, []string{"www.example.org"}, nil))
	payload, _ := run(t, c, context.Background())
	if asked != 0 {
		t.Errorf("%d DNS checks without -live", asked)
	}
	if got := strings.Join(strs(payload["names"]), ","); got != "junk.example.org,real.example.org,www.example.org" {
		t.Errorf("names %s", got)
	}
	if got := strings.Join(strs(payload["unverified"]), ","); got != "junk.example.org,real.example.org" {
		t.Errorf("unverified %s", got)
	}
	if m, _ := loadHistory(historyPath("example.org")); len(m) != 1 || m["www.example.org"].Last == "" {
		t.Errorf("history holds %v", m)
	}
}

// The resolvers failing on a name leaves it listed, unverified, not dropped.
func TestFailedCheckIsUnverifiedNotDropped(t *testing.T) {
	pad := fake("pad", noKey, true, []string{"flaky.example.org", "dead.example.org", "real.example.org"}, nil)
	pad.verify = true
	c := collector(Options{NoHistory: true, Verify: func(_ context.Context, _ string, names []string) ([]string, []string) {
		var live, failed []string
		for _, n := range names {
			switch n {
			case "real.example.org":
				live = append(live, n)
			case "flaky.example.org":
				failed = append(failed, n)
			}
		}
		return live, failed
	}}, pad)
	payload, _ := run(t, c, context.Background())
	if got := strings.Join(strs(payload["names"]), ","); got != "flaky.example.org,real.example.org" {
		t.Errorf("names %s", got)
	}
	if got := strings.Join(strs(payload["unverified"]), ","); got != "flaky.example.org" || payload["dropped"] != float64(1) {
		t.Errorf("unverified %s dropped %v", got, payload["dropped"])
	}
	if e, _ := payload["sources"].(map[string]any)["pad"].(map[string]any)["error"].(string); !strings.Contains(e, "1 of its names not checked") {
		t.Errorf("row error %q", e)
	}
}

func TestSampledRowCountsCalls(t *testing.T) {
	answers := [][]string{{"a.example.org", "b.example.org"}, {"c.example.org", "d.example.org"}, {"a.example.org", "c.example.org"}}
	var mu sync.Mutex
	i := 0
	s := sampled(source{name: "s", deflt: true, collect: func(context.Context, string, []string, *subscraping.Session) ([]string, error) {
		mu.Lock()
		defer mu.Unlock()
		a := answers[min(i, len(answers)-1)]
		i++
		return a, nil
	}})
	c := collector(Options{SourceTimeout: 5 * time.Second, Verify: allLive}, s)
	payload, _ := run(t, c, context.Background())
	row := payload["sources"].(map[string]any)["s"].(map[string]any)
	if row["calls"] != float64(3) || row["count"] != float64(4) {
		t.Fatalf("row %v", row)
	}
}

// With a DNS pace the guesses may cost what the real names did and no less
// than guessFloor; without one only the time bounds them. Each round's
// numbers are in the source's row.
func TestSampledGuessBudgetFollowsThePace(t *testing.T) {
	round := 0
	mk := func() source {
		round = 0
		return sampled(verified(source{name: "pad", deflt: true, collect: func(context.Context, string, []string, *subscraping.Session) ([]string, error) {
			round++
			names := make([]string, 500)
			for i := range names {
				names[i] = "g" + strings.Repeat("x", round) + string(rune('a'+i%26)) + string(rune('a'+i/26%26)) + ".example.org"
			}
			return names, nil
		}}))
	}
	for _, tc := range []struct {
		paced  bool
		rounds int
	}{{true, 2}, {false, 12}} {
		c := collector(Options{SourceTimeout: 5 * time.Second, NoHistory: true, DNSPaced: tc.paced, Verify: allLive}, mk(), fake("real", noKey, true, []string{"www.example.org"}, nil))
		payload, _ := run(t, c, context.Background())
		row := payload["sources"].(map[string]any)["pad"].(map[string]any)
		// The next call is made while a round is looked up: the one that
		// follows the last round is a call made ahead, and not used.
		st := row["rounds"].([]any)
		if got := int(row["calls"].(float64)); len(st) != tc.rounds || got < tc.rounds || got > tc.rounds+1 {
			t.Errorf("paced %v: %d rounds and %d calls, want %d rounds (%v)", tc.paced, len(st), got, tc.rounds, row)
		}
		if first := st[0].(map[string]any); first["names"] != float64(500) || first["looked_up"] != float64(500) || first["new_live"] != float64(500) {
			t.Errorf("round stats %v", st)
		}
	}
}

// A source gets 30 seconds by default, subfinder's per-request limit, so a
// run waits no longer for crt.sh than subfinder does.
func TestDefaultSourceTimeoutIsSubfinders(t *testing.T) {
	if got := New(Options{}).opts.SourceTimeout; got != 30*time.Second {
		t.Errorf("default source timeout %s", got)
	}
	if DefaultSourceTimeout != 30*time.Second {
		t.Errorf("DefaultSourceTimeout %s", DefaultSourceTimeout)
	}
}

// A sampled source's next call is made while the last round's names are
// looked up: five rounds of a 300 ms call and a 300 ms check take the longer
// of the two each, 1.8 s, not 3 s.
func TestSampledOverlapsTheCallWithTheCheck(t *testing.T) {
	var mu sync.Mutex
	asked := 0
	pad := sampled(verified(source{name: "pad", deflt: true, collect: func(ctx context.Context, _ string, _ []string, _ *subscraping.Session) ([]string, error) {
		mu.Lock()
		asked++
		n := asked
		mu.Unlock()
		select {
		case <-time.After(300 * time.Millisecond):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return []string{"live" + string(rune('a'+n)) + ".example.org", "dead" + string(rune('a'+n)) + ".example.org"}, nil
	}}))
	c := collector(Options{SourceTimeout: 10 * time.Second, NoHistory: true, Verify: func(_ context.Context, _ string, names []string) ([]string, []string) {
		time.Sleep(300 * time.Millisecond)
		var out []string
		for _, n := range names {
			// the fifth round gives no live name, and ends the asking
			if strings.HasPrefix(n, "live") && !strings.HasPrefix(n, "livef") {
				out = append(out, n)
			}
		}
		return out, nil
	}}, pad, fake("real", noKey, true, []string{"www.example.org"}, nil))
	t0 := time.Now()
	payload, _ := run(t, c, context.Background())
	took := time.Since(t0)
	if got := len(strs(payload["names"])); got != 5 {
		t.Errorf("%d names, want www and four live: %v", got, payload["names"])
	}
	if took > 2400*time.Millisecond {
		t.Errorf("five rounds took %s: the next call waited for the check", took)
	}
}
