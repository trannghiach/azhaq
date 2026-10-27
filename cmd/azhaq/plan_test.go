package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func planJSON(t *testing.T, args ...string) runPlan {
	t.Helper()
	out, _, err := captureBoth(t, func() error { return cmdPlan(append(args, "-json")) })
	if err != nil {
		t.Fatal(err)
	}
	var p runPlan
	if err := json.Unmarshal([]byte(out), &p); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	return p
}

// A plan for domains counts the source queries it knows it would make and
// bounds the requests to the targets, which depend on what resolves: a
// cost per web service, and the cap that applies. It sends nothing.
func TestPlanRequests(t *testing.T) {
	dir := t.TempDir()
	keys := filepath.Join(dir, "providers.yaml")
	if err := os.WriteFile(keys, []byte("shodan:\n  - k1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	none := filepath.Join(dir, "none.yaml")
	if err := os.WriteFile(none, []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	r := planJSON(t, "-domain", "example.com", "-domain", "example.org", "-providers", none, "-max-requests", "5000").Requests
	if r.Sources["azhaq-rdap"] != 2 || r.Sources["azhaq-urls"] != 10 || r.Total != 12 || r.Sources["azhaq-search"] != 0 {
		t.Errorf("source queries %+v", r)
	}
	if strings.Join(r.NotCounted, ",") != "azhaq-subdomains" || !r.Found || r.MaxNames != 20000 {
		t.Errorf("what is not known before the run %+v", r)
	}
	if r.PerService != 34 || r.Cap != 5000 || r.CapBy != "-max-requests" {
		t.Errorf("bound on the requests to the targets %+v", r)
	}

	// A scan engine with a key is asked; a daily allowance below
	// -max-requests is the cap that applies.
	r = planJSON(t, "-domain", "example.com", "-providers", keys, "-max-requests", "5000", "-daily-requests", "300", "-no-favicon").Requests
	if r.Sources["azhaq-search"] != 1 || r.Total != 7 {
		t.Errorf("keyed engine %+v", r)
	}
	if r.Cap != 300 || !strings.HasPrefix(r.CapBy, "-daily-requests") || r.PerService != 33 {
		t.Errorf("daily cap %+v", r)
	}

	r = planJSON(t, "-domain", "example.com", "-providers", none, "-passive").Requests
	if !r.Passive || r.PerService != 0 || r.Total != 6 {
		t.Errorf("passive %+v", r)
	}

	// A URL's own host is resolved, not enumerated: no source is asked
	// about an address.
	r = planJSON(t, "-url", "http://127.0.0.1:3001/", "-providers", none).Requests
	if r.Total != 0 || len(r.NotCounted) != 0 || r.Found || r.Cap != 0 || r.CapBy != "" || r.PerService != 34 {
		t.Errorf("an address %+v", r)
	}

	out, _, err := captureBoth(t, func() error {
		return cmdPlan([]string{"-domain", "example.com", "-providers", none, "-max-requests", "5000"})
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"source queries: 6 about the targets above (azhaq-rdap 1, azhaq-urls 5)",
		"azhaq-subdomains: not counted",
		"requests to the targets: at most 5000 (-max-requests)",
		"about 34 per web service (its page, the favicon, 32 built-in paths)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
}
