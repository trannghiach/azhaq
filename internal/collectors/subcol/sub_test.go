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
	c := collector(Options{SourceTimeout: time.Minute, Verify: func(ctx context.Context, _ string, names []string) ([]string, int) {
		<-ctx.Done() // the DNS check never answers in time
		return nil, len(names)
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
	if got := strings.Join(strs(payload["names"]), ","); got != "www.example.org" {
		t.Errorf("want the real name kept and the unchecked padding name dropped, got %q", got)
	}
	if payload["partial"] != true {
		t.Errorf("a cut-short result is partial: %+v", payload)
	}
	if msg, _ := payload["sources"].(map[string]any)["pad"].(map[string]any)["error"].(string); !strings.Contains(msg, "not checked") {
		t.Errorf("padding source should say its names were not checked: %q", msg)
	}
}

func TestSampledGathersUntilSaturated(t *testing.T) {
	samplePause = 10 * time.Millisecond
	defer func() { samplePause = 12 * time.Second }()
	answers := []struct {
		names []string
		err   error
	}{
		{[]string{"a", "b", "c", "d"}, nil},
		{nil, errors.New("unexpected status code 429 received from x")},
		{[]string{"c", "d", "e", "f"}, nil},
		{[]string{"a", "b", "c", "d", "e", "f"}, nil}, // nothing new: stop
		{[]string{"never"}, nil},
		{nil, errors.New("unexpected status code 500 received from x")},
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
	got, err := s.collect(ctx, "example.org", nil, nil)
	if err != nil || calls != 4 || strings.Join(got, ",") != "a,b,c,d,e,f" {
		t.Fatalf("got %v %v after %d calls", got, err, calls)
	}
	if got, _ := s.collect(ctx, "example.org", []string{"k"}, nil); len(got) != 1 || got[0] != "keyed" {
		t.Fatalf("a key should page once: %v", got)
	}
	calls = 5 // a failed first call is the source's failure
	if _, err := s.collect(ctx, "example.org", nil, nil); err == nil {
		t.Fatal("first-round error swallowed")
	}
	// Refused every time until the time ran out: a failure, not an honest zero.
	refused := sampled(source{name: "r", collect: func(context.Context, string, []string, *subscraping.Session) ([]string, error) {
		return nil, errors.New("unexpected status code 429 received from x")
	}})
	short, cancel2 := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel2()
	if got, err := refused.collect(short, "example.org", nil, nil); err == nil {
		t.Fatalf("a source refused throughout returned %v and no error", got)
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
	c := collector(Options{SourceTimeout: 5 * time.Second}, s)
	payload, _ := run(t, c, context.Background())
	row := payload["sources"].(map[string]any)["s"].(map[string]any)
	if row["calls"] != float64(3) || row["count"] != float64(4) {
		t.Fatalf("row %v", row)
	}
}
