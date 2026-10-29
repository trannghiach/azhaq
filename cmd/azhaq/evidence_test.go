package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/trannghiach/azhaq/engine"
	"github.com/trannghiach/azhaq/types"
)

func evidenceGraph() *graphView {
	r := urlRow("https://app.test/old", engine.Op{Method: "GET", Source: "openapi"})
	r.Evidence, r.EvidenceFrom = engine.EvDescribed, []string{"azhaq-openapi"}
	return &graphView{path: "x.db", rows: []engine.MapEntry{r}}
}

func TestEvidenceInRowJSONAndExports(t *testing.T) {
	g := evidenceGraph()
	row := mapRowJSON(g.rows[0])
	if row["evidence"] != "described" {
		t.Errorf("row %v", row)
	}
	doc, err := openAPI(g, "")
	if err != nil {
		t.Fatal(err)
	}
	op := doc["paths"].(map[string]any)["/old"].(map[string]any)["get"].(map[string]any)
	if op["x-azhaq-evidence"] != "described" {
		t.Errorf("operation %v", op)
	}
	var page bytes.Buffer
	if err := htmlReport(g, &page); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(page.String(), "<td>described</td>") {
		t.Error("the HTML report does not show the level")
	}
}

// What a recovered schema carries: the mark in the SDL's first line, the
// JSON's x-azhaq, and a note; a whole schema carries no mark.
func recoveredGraph(url string) *graphView {
	payload := `{"url":"` + url + `","role":"graphql","introspection":false,"recovered":"suggestions","errors":12,` +
		`"query_type":"Query","mutation_type":"Mutations","queries":["me","ping"],"mutations":["login"],` +
		`"signatures":{"queries":["me: UserObject","ping"],"mutations":["login(user: String!): [Session!]"]}}`
	ops := `{"url":"https://api.test/app.js","via":"js","graphql_operations":["query getMe","mutation Login"]}`
	return &graphView{path: "x.db", obs: []types.StoredObservation{
		{Observation: types.Observation{Collector: "azhaq-js", Kind: "graphql", Payload: json.RawMessage(ops)}},
		{Observation: types.Observation{Collector: "azhaq-graphql-schema", Kind: "graphql", Payload: json.RawMessage(payload)}},
	}}
}

func TestRecoveredGraphQLSchemaIsMarked(t *testing.T) {
	const u = "https://api.test/graphql"
	g := recoveredGraph(u)
	var sdl bytes.Buffer
	if err := graphqlExport(g, "sdl", "", &sdl); err != nil {
		t.Fatal(err)
	}
	first, _, _ := strings.Cut(sdl.String(), "\n")
	if want := "# introspection disabled on " + u + "; recovered from 12 validation errors and 2 client operations: partial, may lack types and fields"; first != want {
		t.Errorf("first line %q", first)
	}
	for _, want := range []string{"type Query {\n  me: UserObject", "login(user: String!): [Session!]", "left out of Query: ping"} {
		if !strings.Contains(sdl.String(), want) {
			t.Errorf("sdl lacks %q:\n%s", want, sdl.String())
		}
	}

	var out bytes.Buffer
	if err := graphqlExport(g, "graphql", "", &out); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Data map[string]json.RawMessage
		X    map[string]any `json:"x-azhaq"`
	}
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil || doc.Data["__schema"] == nil {
		t.Fatalf("%v %s", err, out.String())
	}
	if doc.X["introspection"] != false || doc.X["recovered"] != "suggestions" || doc.X["partial"] != true {
		t.Errorf("x-azhaq %v", doc.X)
	}

	notes := engine.GraphQLNotes(g.obs)
	if len(notes) != 1 || !strings.Contains(notes[0], "introspection disabled: schema recovered (partial)") {
		t.Errorf("notes %v", notes)
	}
}

func TestWholeGraphQLSchemaIsNotMarkedPartial(t *testing.T) {
	g := schemaGraph(t, "https://api.test/graphql")
	var sdl, out bytes.Buffer
	if err := graphqlExport(g, "sdl", "", &sdl); err != nil {
		t.Fatal(err)
	}
	if err := graphqlExport(g, "graphql", "", &out); err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{sdl.String(), out.String()} {
		if strings.Contains(s, "partial") || strings.Contains(s, "x-azhaq") {
			t.Errorf("a whole schema is marked:\n%.300s", s)
		}
	}
	if notes := engine.GraphQLNotes(g.obs); len(notes) != 1 || !strings.Contains(notes[0], "introspection: full schema") {
		t.Errorf("notes %v", notes)
	}
}

// A page of an MCP export keeps the mark.
func TestRecoveredMarkSurvivesPaging(t *testing.T) {
	var out bytes.Buffer
	if err := graphqlExport(recoveredGraph("https://api.test/graphql"), "graphql", "", &out); err != nil {
		t.Fatal(err)
	}
	u, err := splitExport("graphql", out.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	for i, page := range pageAll(t, u, maxInline) {
		if !strings.Contains(string(page), `"partial":true`) {
			t.Errorf("page %d has no mark: %.200s", i, page)
		}
	}
}

// A served description names every route; an operation of a route the
// run fetched is answered, the others described.
func TestOpenAPIServedOperationsCarryTheRowsLevel(t *testing.T) {
	spec := `{"base":"https://app.test/","document":{"openapi":"3.0.1","info":{"title":"x"},
		"paths":{"/api/users":{"get":{"responses":{"200":{"description":"ok"}}}},
		         "/api/orders":{"get":{"responses":{"200":{"description":"ok"}}}}}}}`
	users := urlRow("https://app.test/api/users", engine.Op{Method: "GET"})
	users.Evidence = engine.EvAnswered
	orders := urlRow("https://app.test/api/orders", engine.Op{Method: "GET"})
	orders.Coverage, orders.Status, orders.Evidence = "hint", 0, engine.EvDescribed
	g := &graphView{path: "x.db",
		obs:  []types.StoredObservation{{Observation: types.Observation{Collector: "azhaq-openapi", Kind: "api", Payload: json.RawMessage(spec)}}},
		rows: []engine.MapEntry{users, orders}}
	doc, err := openAPI(g, "")
	if err != nil {
		t.Fatal(err)
	}
	for p, want := range map[string]string{"/api/users": "answered", "/api/orders": "described"} {
		op := doc["paths"].(map[string]any)[p].(map[string]any)["get"].(map[string]any)
		if op["x-azhaq-evidence"] != want {
			t.Errorf("GET %s: %v, want %s", p, op["x-azhaq-evidence"], want)
		}
	}
}
