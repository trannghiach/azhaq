package subcol

import (
	"context"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

const truthDir = "../../../bench/truth/subs"

func fixtureFoundBy(t *testing.T) map[string][]string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(truthDir, "tesla-subs-payload.json"))
	if err != nil {
		t.Fatal(err)
	}
	var p struct {
		FoundBy map[string][]string `json:"found_by"`
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	return p.FoundBy
}

func TestChao1TeslaFixture(t *testing.T) {
	foundBy := fixtureFoundBy(t)
	dep := Dependent()
	if !dep["subdomaincenter"] || !dep["history"] || dep["crtsh"] {
		t.Fatalf("dependent sources: %v", dep)
	}
	s, est, ok := Chao1(foundBy, dep, nil)
	if !ok || s != 1400 || math.Abs(est-1609) > 1 {
		t.Errorf("Chao1 over the payload: S=%d N=%.1f ok=%v, want S=1400 N=1609", s, est, ok)
	}
	raw, err := os.ReadFile(filepath.Join(truthDir, "tesla-live-union.txt"))
	if err != nil {
		t.Fatal(err)
	}
	live := map[string]bool{}
	for _, n := range strings.Fields(string(raw)) {
		live[n] = true
	}
	s, est, ok = Chao1(foundBy, dep, func(n string) bool { return live[n] })
	if !ok || s != 481 || math.Abs(est-485) > 1 {
		t.Errorf("Chao1 over the live names: S=%d N=%.1f ok=%v, want S=481 N=485", s, est, ok)
	}
}

func TestChao1Formula(t *testing.T) {
	dep := map[string]bool{"pad": true}
	fb := map[string][]string{
		"a": {"x"}, "b": {"x"}, "c": {"x", "y"}, "d": {"y"}, "e": {"x", "y", "z"},
		"only-pad": {"pad"}, "pad-and-one": {"pad", "x"},
	}
	// S=6 (the padding-only name is out), f1=4 (pad-and-one has one independent source), f2=1.
	s, est, ok := Chao1(fb, dep, nil)
	if !ok || s != 6 || est != 6+16.0/2 {
		t.Errorf("f2>0: %d %v %v", s, est, ok)
	}
	// No name with two sources: the bias-corrected form.
	s, est, _ = Chao1(map[string][]string{"a": {"x"}, "b": {"y"}, "c": {"x"}}, dep, nil)
	if s != 3 || est != 3+3 {
		t.Errorf("f2=0: %d %v", s, est)
	}
	// One independent source has no overlap to learn from.
	if _, _, ok := Chao1(map[string][]string{"a": {"x"}, "b": {"x"}}, dep, nil); ok {
		t.Error("one source gave an estimate")
	}
}

func TestSchnabelSamples(t *testing.T) {
	var rounds [][]string
	for i := 1; i <= 5; i++ {
		raw, err := os.ReadFile(filepath.Join(truthDir, "subdomaincenter-tesla-sample"+string(rune('0'+i))+".json"))
		if err != nil {
			t.Fatal(err)
		}
		var names []string
		if err := json.Unmarshal(raw, &names); err != nil {
			t.Fatal(err)
		}
		rounds = append(rounds, names)
	}
	est, ok := schnabel(rounds)
	if !ok || math.Abs(est-6321) > 63.21 {
		t.Errorf("Schnabel over the five samples: %.1f ok=%v, want 6321 ±1%%", est, ok)
	}
	if _, ok := schnabel([][]string{{"a", "b"}, {"c", "d"}}); ok {
		t.Error("an estimate without a recapture")
	}
	if _, ok := schnabel([][]string{{"a", "b"}}); ok {
		t.Error("an estimate from one round")
	}
}

func TestSampledRowGivesPopulationEstimate(t *testing.T) {
	answers := [][]string{
		{"a.example.org", "b.example.org", "c.example.org", "d.example.org"},
		{"c.example.org", "d.example.org", "e.example.org", "f.example.org"},
		{"a.example.org", "b.example.org", "c.example.org", "d.example.org", "e.example.org", "f.example.org"},
	}
	i := 0
	s := sampled(source{name: "s", deflt: true, collect: func(context.Context, string, []string, *subscraping.Session) ([]string, error) {
		a := answers[min(i, len(answers)-1)]
		i++
		return a, nil
	}})
	one := fake("once", noKey, true, []string{"www.example.org"}, nil)
	c := collector(Options{SourceTimeout: 5 * time.Second, NoHistory: true, Verify: allLive}, s, one)
	payload, _ := run(t, c, context.Background())
	rows := payload["sources"].(map[string]any)
	// the third round adds nothing, so the source stops: C·M = 0, 4·4, 6·6 over recaptures 0, 2, 6 → 6.5
	if got := rows["s"].(map[string]any)["population_estimate"]; got != float64(7) {
		t.Errorf("sampled row: %v", rows["s"])
	}
	if _, has := rows["once"].(map[string]any)["population_estimate"]; has {
		t.Errorf("a source asked once has no estimate: %v", rows["once"])
	}
}

func TestPayloadCoverage(t *testing.T) {
	pad := fake("pad", noKey, true, []string{"p.example.org", "a.example.org"}, nil)
	pad.verify = true
	c := collector(Options{NoHistory: true},
		fake("x", noKey, true, []string{"a.example.org", "b.example.org", "c.example.org"}, nil),
		fake("y", noKey, true, []string{"b.example.org", "d.example.org"}, nil),
		pad,
	)
	payload, _ := run(t, c, context.Background())
	// independent: a(x) b(x,y) c(x) d(y) → S=4, f1=3, f2=1 → 4+9/2 = 8.5 → 9 (p only has the padding source)
	cov, _ := payload["coverage"].(map[string]any)
	if cov["observed"] != float64(4) || cov["estimated"] != float64(9) || cov["share"] != 0.47 {
		t.Errorf("coverage %v", payload["coverage"])
	}
	one := collector(Options{NoHistory: true}, fake("x", noKey, true, []string{"a.example.org"}, nil))
	payload, _ = run(t, one, context.Background())
	if _, has := payload["coverage"]; has {
		t.Errorf("one source cannot estimate coverage: %v", payload["coverage"])
	}
}
