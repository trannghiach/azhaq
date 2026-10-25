package connector

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/trannghiach/azhaq/internal/types"
)

func TestHostIndexFactsFor(t *testing.T) {
	idx, err := LoadHostIndex(filepath.Join("..", "..", "fixtures", "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	facts := idx.FactsFor([]types.Seed{{
		Type: types.TypeDomain,
		Keys: map[string]string{"domain": "example.test"},
	}}, "fixtures/index.json")
	var hosts []string
	for _, f := range facts {
		if f.Kind == "hint" && f.Seed != nil {
			hosts = append(hosts, f.Seed.Keys["fqdn"])
		}
	}
	if len(hosts) != 2 {
		t.Fatalf("want 2 hosts, got %v", hosts)
	}
}

func TestReadWriteSeeds(t *testing.T) {
	var buf bytes.Buffer
	seeds := []types.Seed{{Type: types.TypeDomain, Keys: map[string]string{"domain": "Example.test"}}}
	if err := WriteSeeds(&buf, seeds); err != nil {
		t.Fatal(err)
	}
	facts, err := ReadJSONL(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if len(facts) != 1 || facts[0].Kind != "seed" || facts[0].Seed.Key() != "example.test" {
		t.Fatalf("round-trip: %+v", facts)
	}
}

func TestRejectEmptyAndExport(t *testing.T) {
	if _, err := ReadJSONL(bytes.NewReader([]byte("{}\n"))); err == nil {
		t.Fatal("empty object should fail")
	}
	export := `{"kind":"entity","entity":{"type":"Hostname","key":"x"}}` + "\n"
	if _, err := ReadJSONL(bytes.NewReader([]byte(export))); err == nil {
		t.Fatal("export entity should fail")
	}
}

func TestAcceptsHelloAndMeta(t *testing.T) {
	raw := `{"kind":"hello","protocol":"azhaq.connector.v1"}` + "\n" +
		`{"kind":"meta","items":0,"errors":1}` + "\n"
	facts, err := ReadJSONL(bytes.NewReader([]byte(raw)))
	if err != nil {
		t.Fatal(err)
	}
	if len(facts) != 2 || facts[0].Kind != "hello" || facts[1].Kind != "meta" {
		t.Fatalf("%+v", facts)
	}
}

func TestReadFactsFile(t *testing.T) {
	facts, err := ReadFile(filepath.Join("..", "..", "fixtures", "facts.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if len(facts) != 2 {
		t.Fatalf("want 2 facts, got %d", len(facts))
	}
}
