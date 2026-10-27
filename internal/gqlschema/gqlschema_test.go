package gqlschema

import (
	"flag"
	"os"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite testdata/introspection.sdl")

// testdata/introspection.json is graphql-core's answer to Query for
// testdata/fixture.graphql; introspection.sdl is what SDL prints for it,
// checked to build the same schema with graphql-core.
func fixture(t *testing.T) *Schema {
	t.Helper()
	data, err := os.ReadFile("testdata/introspection.json")
	if err != nil {
		t.Fatal(err)
	}
	raw, s, ok := Read(data)
	if !ok {
		t.Fatal("no schema in the fixture")
	}
	if len(raw) == 0 || raw[0] != '{' || strings.Contains(string(raw), "\n") {
		t.Errorf("the raw schema is not compact JSON: %.80s", raw)
	}
	return s
}

func TestSDL(t *testing.T) {
	got := fixture(t).SDL()
	if *update {
		if err := os.WriteFile("testdata/introspection.sdl", []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile("testdata/introspection.sdl")
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Errorf("SDL differs from testdata/introspection.sdl:\n%s", got)
	}
	for _, s := range []string{"String", "Boolean", "__Type", "directive @deprecated"} {
		if strings.Contains(got, "scalar "+s) || strings.Contains(got, "type "+s+" ") || strings.Contains(got, s+"(") {
			t.Errorf("built-in %s printed", s)
		}
	}
}

func TestOperations(t *testing.T) {
	var got []string
	for _, o := range fixture(t).Operations() {
		got = append(got, o.Kind+" "+o.Signature())
	}
	want := []string{
		"query node(id: ID!): Node",
		"query old: String",
		"query older: String",
		`query search(q: String!, filter: Filter = { kind: "a", tags: ["x"] }): [SearchResult]`,
		"query users(limit: Int = 10, offset: Int, role: Role = ADMIN): [User!]!",
		"mutation deleteUser(id: ID!): Boolean",
		"mutation login(username: String!, password: String!): Token",
		"subscription userAdded: User",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("operations:\n%s", strings.Join(got, "\n"))
	}
}

func TestRead(t *testing.T) {
	for _, answer := range []string{
		`{"errors":[{"message":"GraphQL introspection is not allowed"}]}`,
		`{"data":{"__schema":null}}`,
		`{"data":{"__schema":{"types":[]}}}`,
		`<html>`,
	} {
		if _, _, ok := Read([]byte(answer)); ok {
			t.Errorf("a schema read from %s", answer)
		}
	}
}

// Bound drops descriptions first, then gives up.
func TestBound(t *testing.T) {
	data, _ := os.ReadFile("testdata/introspection.json")
	raw, _, _ := Read(data)
	if got, ok := Bound(raw, len(raw)); !ok || string(got) != string(raw) {
		t.Error("a schema within the bound changed")
	}
	small, ok := Bound(raw, len(raw)-1)
	if !ok || len(small) >= len(raw) || strings.Contains(string(small), "A plain user") {
		t.Fatalf("descriptions kept: %d of %d bytes", len(small), len(raw))
	}
	if s, err := Parse(small); err != nil || len(s.Operations()) != 8 {
		t.Errorf("the bounded schema does not read: %v", err)
	}
	if _, ok := Bound(raw, 100); ok {
		t.Error("a schema far over the bound kept")
	}
}
