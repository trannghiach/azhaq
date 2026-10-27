package engine_test

import (
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/trannghiach/azhaq/engine"
	"github.com/trannghiach/azhaq/internal/gqlschema"
	"github.com/trannghiach/azhaq/types"
)

func schemaObs(id, payload string) types.StoredObservation {
	return types.StoredObservation{EntityID: id, Observation: types.Observation{Collector: "azhaq-graphql-schema", Kind: "graphql", Payload: json.RawMessage(payload)}}
}

func graphqlRow(t *testing.T, payload string) engine.MapEntry {
	t.Helper()
	ents := []types.Entity{{ID: "g", Type: types.TypeURL, Key: "https://api.test/graphql"}}
	obs := []types.StoredObservation{
		httpObs("g", `{"status":400,"url":"https://api.test/graphql"}`),
		schemaObs("g", payload),
	}
	seeds := []types.Seed{{Type: types.TypeURL, Keys: map[string]string{"url": "https://api.test/"}}}
	rows := engine.BuildMap(ents, seeds, obs, nil, false)
	if len(rows) != 1 {
		t.Fatalf("rows %+v", rows)
	}
	return rows[0]
}

// A GraphQL endpoint's row carries its operations from the schema read by
// introspection, and the text map prints their signatures under it.
func TestMapGraphQLOperations(t *testing.T) {
	answer, err := os.ReadFile("../internal/gqlschema/testdata/introspection.json")
	if err != nil {
		t.Fatal(err)
	}
	raw, _, ok := gqlschema.Read(answer)
	if !ok {
		t.Fatal("fixture")
	}
	m := graphqlRow(t, `{"introspection":true,"url":"https://api.test/graphql","role":"graphql","status":200,"schema":`+string(raw)+`}`)
	if len(m.Ops) != 8 || !slices.Contains(m.Methods, "POST") {
		t.Fatalf("ops %+v methods %v", m.Ops, m.Methods)
	}
	login := m.Ops[6]
	if login.Method != "POST" || login.OperationID != "login" || login.Source != "graphql" ||
		login.Summary != "mutation login(username: String!, password: String!): Token" || strings.Join(login.Body, ",") != "username,password" {
		t.Errorf("login %+v", login)
	}
	d := m.Details()
	if !slices.Contains(d, "query users(limit: Int = 10, offset: Int, role: Role = ADMIN): [User!]!") || !slices.Contains(d, "subscription userAdded: User") {
		t.Errorf("details %q", d)
	}
}

// A schema kept by names only (an older run, or a server that refused the
// full query) still lists the operations.
func TestMapGraphQLNames(t *testing.T) {
	m := graphqlRow(t, `{"introspection":true,"url":"https://api.test/graphql","queries":["me","users"],"mutations":["login"]}`)
	var got []string
	for _, op := range m.Ops {
		got = append(got, op.Summary)
	}
	if strings.Join(got, ",") != "query me,query users,mutation login" {
		t.Errorf("ops %q", got)
	}
}

// A long list is cut in the text map, not in the row.
func TestMapGraphQLCap(t *testing.T) {
	var names []string
	for i := range 70 {
		names = append(names, fmt.Sprintf(`"q%02d"`, i))
	}
	m := graphqlRow(t, `{"introspection":true,"queries":[`+strings.Join(names, ",")+`]}`)
	d := m.Details()
	if len(m.Ops) != 70 || len(d) != 51 || d[50] != "… 20 more GraphQL operations (azhaq export -format sdl)" {
		t.Errorf("%d ops, %d lines, last %q", len(m.Ops), len(d), d[len(d)-1])
	}
}
