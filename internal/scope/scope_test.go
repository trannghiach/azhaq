package scope

import (
	"testing"

	"azhaq/internal/types"
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
