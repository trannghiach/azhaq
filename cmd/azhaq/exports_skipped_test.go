package main

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/trannghiach/azhaq/engine"
	"github.com/trannghiach/azhaq/store"
	"github.com/trannghiach/azhaq/types"
)

// A -deny-path rule kept /createdb out of the run; the served description
// lists it like any other route. The export says so on the operation
// (x-azhaq-skipped, and why), and -safe leaves it out, so a tool importing
// the description does not request what the user ruled out. A visited
// route is untouched.
const denyReason = "-deny-path ^/createdb"

func TestOpenAPIFlagsSkippedOperations(t *testing.T) {
	spec := `{"base":"https://app.test/","document":{"openapi":"3.0.1","info":{"title":"VAmPI"},
		"paths":{"/createdb":{"get":{"operationId":"createdb","responses":{"200":{"description":"ok"}}}},
		         "/api/users":{"get":{"operationId":"users","responses":{"200":{"description":"ok"}}}}}}}`
	skip := fmt.Sprintf(`{"skipped":%q}`, denyReason)
	g := &graphView{path: "x.db",
		obs: []types.StoredObservation{
			{Observation: types.Observation{Collector: "azhaq-openapi", Kind: "api", Payload: json.RawMessage(spec)}},
			{EntityID: "e-createdb", Observation: types.Observation{Collector: "azhaq-http", Kind: "skipped", Payload: json.RawMessage(skip)}},
		},
		rows: []engine.MapEntry{
			urlRow("https://app.test/api/users", engine.Op{Method: "GET"}),
			{Entity: types.Entity{ID: "e-createdb", Type: types.TypeURL, Key: "https://app.test/createdb"}, Role: "page", Coverage: "skipped"},
			{Entity: types.Entity{Type: types.TypeURL, Key: "https://app.test/api/reset"}, Role: "api", Coverage: "skipped"},
		}}
	doc, err := openAPI(g, "")
	if err != nil {
		t.Fatal(err)
	}
	op := func(d map[string]any, p, m string) map[string]any {
		item, _ := d["paths"].(map[string]any)[p].(map[string]any)
		o, _ := item[m].(map[string]any)
		return o
	}
	created := op(doc, "/createdb", "get")
	if created == nil || created["x-azhaq-skipped"] != true || created["x-azhaq-skipped-reason"] != denyReason {
		t.Errorf("GET /createdb, kept out by the run, is not flagged: %v", created)
	}
	if x, _ := created["x-azhaq"].(map[string]any); x["source"] != "served description" || x["coverage"] != "skipped" {
		t.Errorf("x-azhaq of GET /createdb: %v", x)
	}
	// No entity to find the reason by: it is only said not to be requested.
	if reset := op(doc, "/api/reset", "post"); reset == nil || reset["x-azhaq-skipped"] != true || reset["x-azhaq-skipped-reason"] != "not requested" {
		t.Errorf("POST /api/reset, skipped with no reason, is not flagged: %v", reset)
	}
	if users := op(doc, "/api/users", "get"); users == nil || users["x-azhaq-skipped"] != nil || users["x-azhaq-skipped-reason"] != nil {
		t.Errorf("GET /api/users, visited, is flagged: %v", users)
	}
	want := []string{"get /api/users users", "get /createdb createdb", "post /api/reset post_api_reset"}
	if got := operations(t, doc); !slices.Equal(got, want) {
		t.Errorf("operations %q, want %q", got, want)
	}
	omitSkipped(doc)
	if got := operations(t, doc); !slices.Equal(got, []string{"get /api/users users"}) {
		t.Errorf("safe: operations %q, want only GET /api/users", got)
	}
	if _, ok := doc["paths"].(map[string]any)["/createdb"]; ok {
		t.Error("safe: /createdb, with no operation left, is still a path")
	}

	// The same through the command, from a database: -safe is the switch.
	db := filepath.Join(t.TempDir(), "x.db")
	st, err := store.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	add := func(key string, o types.Observation) {
		t.Helper()
		e, err := st.UpsertEntity(types.TypeURL, key, now)
		if err != nil {
			t.Fatal(err)
		}
		o.ObservedAt = now
		if _, err := st.AddObservation(e.ID, o); err != nil {
			t.Fatal(err)
		}
	}
	add("https://app.test/", types.Observation{Collector: "azhaq-openapi", Kind: "api", Payload: json.RawMessage(spec)})
	add("https://app.test/api/users", types.Observation{Collector: "azhaq-http", Kind: "http", Payload: json.RawMessage(`{"status":200}`)})
	add("https://app.test/createdb", types.Observation{Collector: "azhaq-http", Kind: "skipped", Payload: json.RawMessage(skip)})
	st.Close()
	export := func(args ...string) map[string]any {
		t.Helper()
		out, err := captureStdout(t, func() error {
			return run(append([]string{"export", "-db", db, "-format", "openapi"}, args...))
		})
		if err != nil {
			t.Fatal(err)
		}
		var d map[string]any
		if err := json.Unmarshal([]byte(out), &d); err != nil {
			t.Fatalf("%v: %s", err, out)
		}
		return d
	}
	if created := op(export(), "/createdb", "get"); created == nil || created["x-azhaq-skipped"] != true || created["x-azhaq-skipped-reason"] != denyReason {
		t.Errorf("export: GET /createdb is not flagged with the run's reason: %v", created)
	}
	safe := export("-safe")
	if _, ok := safe["paths"].(map[string]any)["/createdb"]; ok || op(safe, "/api/users", "get") == nil {
		t.Errorf("export -safe: %v", safe["paths"])
	}
	if err := run([]string{"export", "-db", db, "-format", "urls", "-safe"}); err == nil {
		t.Error("-safe with another format is accepted")
	}
}
