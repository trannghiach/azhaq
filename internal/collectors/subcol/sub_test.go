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
