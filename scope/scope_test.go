package scope

import (
	"testing"

	"github.com/trannghiach/azhaq/types"
)

func TestAllowsSuffixAndDeny(t *testing.T) {
	r := Rules{Allow: []string{"example.test"}, Deny: []string{"evil.example.test"}}
	if !r.Allows("www.example.test") {
		t.Fatal("www should be allowed")
	}
	if r.Allows("evil.example.test") {
		t.Fatal("deny should win")
	}
	if r.Allows("other.test") {
		t.Fatal("other eTLD+1 should be out")
	}
	if !r.AllowsSeed(types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": "https://app.example.test/"}}) {
		t.Fatal("in-scope URL")
	}
	if r.AllowsSeed(types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": "https://nope.test/"}}) {
		t.Fatal("out-of-scope URL")
	}
}

func TestEmptyAllowsAll(t *testing.T) {
	var r Rules
	if !r.Allows("anywhere.test") {
		t.Fatal("empty rules allow all")
	}
}

func TestRuleForms(t *testing.T) {
	r := Rules{
		Allow: []string{"*.example.com", "=api.other.org", "10.1.0.0/16", "192.0.2.7"},
		Deny:  []string{"=admin.example.com", "10.1.9.0/24"},
	}
	for host, want := range map[string]bool{
		"example.com": true, "a.b.example.com": true, "admin.example.com": false,
		"api.other.org": true, "x.api.other.org": false, "other.org": false,
		"10.1.2.3": true, "10.1.9.9": false, "10.2.0.1": false,
		"192.0.2.7": true, "192.0.2.70": false,
	} {
		if got := r.Allows(host); got != want {
			t.Errorf("%s: %v, want %v", host, got, want)
		}
	}
}
