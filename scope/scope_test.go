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

// A port copied into -allow/-deny (from a URL's authority) is ignored:
// scope is matched by host. A bare IPv6 address keeps its colons.
func TestRulePortStripped(t *testing.T) {
	r := Rules{
		Allow: []string{"127.0.0.1:5013", "app.example.com:8443", "[2001:db8::1]:443"},
		Deny:  []string{"admin.example.com:8080"},
	}
	for host, want := range map[string]bool{
		"127.0.0.1":         true,
		"app.example.com":   true,
		"2001:db8::1":       true,
		"admin.example.com": false,
		"other.example.com": false,
	} {
		if got := r.Allows(host); got != want {
			t.Errorf("%s: %v, want %v", host, got, want)
		}
	}
	// A bare IPv6 in -allow (no port) still matches itself.
	if !(Rules{Allow: []string{"::1"}}).Allows("::1") {
		t.Error("bare IPv6 ::1 should match itself")
	}
}

func TestMatchNamesTheAllowRule(t *testing.T) {
	r := Rules{Allow: []string{"*.example.com", "=api.other.test", "10.0.0.0/8"}, Deny: []string{"dev.example.com"}}
	for host, want := range map[string]string{
		"www.example.com":   "*.example.com",
		"example.com":       "*.example.com",
		"api.other.test":    "=api.other.test",
		"www.other.test":    "",
		"10.1.2.3":          "10.0.0.0/8",
		"dev.example.com":   "",
		"x.dev.example.com": "",
		"evil.test":         "",
	} {
		if got := r.Match(host); got != want {
			t.Errorf("Match(%q) = %q, want %q", host, got, want)
		}
	}
	if got := (Rules{}).Match("a.test"); got != "" {
		t.Errorf("no rules: %q", got)
	}
}

// A compiled set of rules answers as the plain one does.
func TestCompileMatchesPlainRules(t *testing.T) {
	r := Rules{
		Allow: []string{"example.com", "*.wild.test", "=api.exact.org", "10.0.0.0/24", "192.0.2.7", "127.0.0.1:8080"},
		Deny:  []string{"admin.example.com", "10.0.0.9"},
	}
	c := r.Compile()
	for _, h := range []string{"example.com", "a.example.com", "admin.example.com", "x.admin.example.com", "wild.test", "q.wild.test",
		"api.exact.org", "x.api.exact.org", "exact.org", "10.0.0.5", "10.0.0.9", "10.0.1.5", "192.0.2.7", "192.0.2.8", "127.0.0.1", "other.net", "", "EXAMPLE.com."} {
		if r.Allows(h) != c.Allows(h) || r.Match(h) != c.Match(h) && c.Match(h) == "" != (r.Match(h) == "") {
			t.Errorf("%q: plain %v %q, compiled %v %q", h, r.Allows(h), r.Match(h), c.Allows(h), c.Match(h))
		}
	}
	if (Rules{}).Compile().Allows("anything") != true {
		t.Error("empty rules refuse")
	}
}
