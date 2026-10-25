package engine_test

import (
	"testing"

	"github.com/trannghiach/azhaq/engine"
	"github.com/trannghiach/azhaq/types"
)

func TestSeedHostPrintsFirst(t *testing.T) {
	ents := []types.Entity{
		{Type: types.TypeHostname, Key: "extra.other.test"},
		{Type: types.TypeHostname, Key: "cdn.example.test"},
		{Type: types.TypeHostname, Key: "app.example.test"},
		{Type: types.TypeDomain, Key: "example.test"},
	}
	seeds := []types.Seed{{
		Type: types.TypeURL,
		Keys: map[string]string{"url": "https://app.example.test/"},
	}}
	got := engine.RankEntities(ents, seeds)
	var firstHost string
	for _, e := range got {
		if e.Type == types.TypeHostname {
			firstHost = e.Key
			break
		}
	}
	if firstHost != "app.example.test" {
		t.Fatalf("first host %q in %+v", firstHost, got)
	}
	if engine.ScopeLabel(got[0], seeds) == "fanout" && got[0].Key == "app.example.test" {
		t.Fatal("seed host should be target")
	}
	if engine.ScopeLabel(types.Entity{Type: types.TypeHostname, Key: "extra.other.test"}, seeds) != "fanout" {
		t.Fatal("other site should be fanout")
	}
}

func TestScopeCloudInventoryIsTarget(t *testing.T) {
	seeds := []types.Seed{{Type: types.TypeCloudAccount, Keys: map[string]string{"id": "inv", "path": "inv.json"}}}
	ents := []types.Entity{
		{Type: types.TypeCloudAccount, Key: "inv"},
		{Type: types.TypeDomain, Key: "example.test"},
		{Type: types.TypeHostname, Key: "www.example.test"},
	}
	scope := engine.ScopeSeeds(seeds, ents)
	if engine.ScopeLabel(ents[1], scope) != "target" {
		t.Fatal("cloud inventory domain should be target")
	}
	if engine.ScopeLabel(ents[2], scope) != "target" {
		t.Fatal("host in inventory domain should be target")
	}
}

func TestExpandSeedsSkipsIPHostname(t *testing.T) {
	got := engine.ExpandSeeds([]types.Seed{{
		Type: types.TypeURL,
		Keys: map[string]string{"url": "http://127.0.0.1:9/"},
	}})
	for _, s := range got {
		if s.Type == types.TypeHostname {
			t.Fatalf("IP should not become Hostname: %+v", got)
		}
		if s.Type == types.TypeIPAddress && s.Key() != "127.0.0.1" {
			t.Fatalf("ip seed %+v", s)
		}
	}
}

func TestScopeIPFromURLIsTarget(t *testing.T) {
	seeds := []types.Seed{{Type: types.TypeURL, Keys: map[string]string{"url": "http://127.0.0.1:8080/"}}}
	ip := types.Entity{Type: types.TypeIPAddress, Key: "127.0.0.1"}
	if engine.ScopeLabel(ip, seeds) != "target" {
		t.Fatal("seed IP should be target")
	}
}

func TestScopeResolvedIPIsTarget(t *testing.T) {
	seeds := []types.Seed{{Type: types.TypeURL, Keys: map[string]string{"url": "https://app.example.test/"}}}
	host := types.Entity{ID: "h1", Type: types.TypeHostname, Key: "app.example.test"}
	ip := types.Entity{ID: "i1", Type: types.TypeIPAddress, Key: "203.0.113.5"}
	scope := engine.ScopeSeeds(seeds, []types.Entity{host, ip}, []types.Edge{{
		From: "h1", To: "i1", Type: "RESOLVES_TO",
	}})
	if engine.ScopeLabel(ip, scope) != "target" {
		t.Fatal("DNS IP of the seed host should be target")
	}
}
