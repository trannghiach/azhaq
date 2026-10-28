package engine

import (
	"encoding/json"
	"testing"

	"github.com/trannghiach/azhaq/types"
)

// A source that fails while others answered for the domain is partial —
// crt.sh included: a transient crt.sh blip does not make the exit code 3
// when the other sources returned the names. (`-fail-on-errors` still
// treats every failure as exit 3.)
func TestMarkPartialWhenOthersAnswered(t *testing.T) {
	payload, _ := json.Marshal(map[string]any{"domain": "a.test", "sources": map[string]any{
		"crtsh": map[string]any{"error": "timeout"}, "anubis": map[string]any{"error": "HTTP 502"}, "certspotter": map[string]any{"count": 5.0}}})
	obs := []types.StoredObservation{{Observation: types.Observation{Collector: "azhaq-subdomains", Payload: payload}}}
	fs := []Failure{
		{Collector: "azhaq-subdomains", Source: "crtsh", Error: "timeout", Targets: []string{"a.test"}},
		{Collector: "azhaq-subdomains", Source: "anubis", Error: "HTTP 502", Targets: []string{"a.test"}},
	}
	got := MarkPartial(fs, nil, obs)
	if !got[0].Partial || !got[1].Partial {
		t.Errorf("both should be partial (certspotter answered): crtsh %v, anubis %v", got[0].Partial, got[1].Partial)
	}
}

// When no source answered for the domain, a failure is not partial: the
// results are missing, and the run exits 3.
func TestMarkPartialNoneAnswered(t *testing.T) {
	payload, _ := json.Marshal(map[string]any{"domain": "a.test", "sources": map[string]any{
		"crtsh": map[string]any{"error": "timeout"}, "anubis": map[string]any{"error": "HTTP 502"}}})
	obs := []types.StoredObservation{{Observation: types.Observation{Collector: "azhaq-subdomains", Payload: payload}}}
	fs := []Failure{{Collector: "azhaq-subdomains", Source: "crtsh", Error: "timeout", Targets: []string{"a.test"}}}
	got := MarkPartial(fs, nil, obs)
	if got[0].Partial {
		t.Error("no source answered, so the failure is not partial")
	}
}
