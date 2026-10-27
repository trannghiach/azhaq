package engine

import (
	"encoding/json"
	"testing"

	"github.com/trannghiach/azhaq/types"
)

// A source that fails while others answered is partial, except crt.sh:
// the others do not make up for the certificate log with the most names.
func TestMarkPartialCoreSource(t *testing.T) {
	payload, _ := json.Marshal(map[string]any{"domain": "a.test", "sources": map[string]any{
		"crtsh": map[string]any{"error": "timeout"}, "anubis": map[string]any{"error": "HTTP 502"}, "certspotter": map[string]any{"count": 5.0}}})
	obs := []types.StoredObservation{{Observation: types.Observation{Collector: "azhaq-subdomains", Payload: payload}}}
	fs := []Failure{
		{Collector: "azhaq-subdomains", Source: "crtsh", Error: "timeout", Targets: []string{"a.test"}},
		{Collector: "azhaq-subdomains", Source: "anubis", Error: "HTTP 502", Targets: []string{"a.test"}},
	}
	got := MarkPartial(fs, nil, obs)
	if got[0].Partial || !got[1].Partial {
		t.Errorf("crtsh partial %v, anubis partial %v", got[0].Partial, got[1].Partial)
	}
}
