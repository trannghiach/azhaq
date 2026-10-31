package gqlcol

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/trannghiach/azhaq/internal/fetch"
	"github.com/trannghiach/azhaq/internal/gqlschema"
	"github.com/trannghiach/azhaq/types"
)

const schema = `{"data":{"__schema":{"queryType":{"name":"Query"},"mutationType":{"name":"Mutation"},"subscriptionType":null,
"types":[{"name":"Query","kind":"OBJECT","fields":[{"name":"users"},{"name":"me"}]},
{"name":"Mutation","kind":"OBJECT","fields":[{"name":"deleteUser"}]},
{"name":"User","kind":"OBJECT","fields":[{"name":"email"}]},
{"name":"__Type","kind":"OBJECT","fields":[]},{"name":"String","kind":"SCALAR","fields":null}]}}}`

// server is a GraphQL endpoint at /graphql (graphql-express style) and an
// ordinary JSON API at /v1/graphql. The full introspection query is
// answered with full; anything else asking for __schema with schema.
func server(t *testing.T, full string) (*httptest.Server, *int) {
	posts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/graphql" && r.Method == http.MethodGet:
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"errors":[{"message":"Must provide query string."}]}`))
		case r.URL.Path == "/graphql" && r.Method == http.MethodPost:
			posts++
			body, _ := io.ReadAll(r.Body)
			if !strings.Contains(string(body), "__schema") {
				http.Error(w, "bad", http.StatusBadRequest)
				return
			}
			if strings.Contains(string(body), "IntrospectionQuery") {
				_, _ = w.Write([]byte(full))
				return
			}
			_, _ = w.Write([]byte(schema))
		case r.URL.Path == "/v1/graphql":
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &posts
}

func run(t *testing.T, c interface {
	Run(context.Context, types.Seed, func(types.Observation) error) (types.RunMeta, error)
}, u string) (map[string]any, types.RunMeta) {
	t.Helper()
	var got map[string]any
	meta, err := c.Run(context.Background(), types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": u}}, func(o types.Observation) error {
		return json.Unmarshal(o.Payload, &got)
	})
	if err != nil {
		t.Fatal(err)
	}
	return got, meta
}

func TestDetect(t *testing.T) {
	fetch.Reset()
	srv, posts := server(t, schema)
	c := New(srv.Client())
	got, meta := run(t, c, srv.URL+"/graphql")
	if got["role"] != "graphql" || meta.Drop {
		t.Errorf("graphql endpoint: %v %+v", got, meta)
	}
	got, meta = run(t, c, srv.URL+"/v1/graphql")
	if got != nil || !meta.Drop {
		t.Errorf("plain JSON taken for GraphQL: %v", got)
	}
	if !c.Skip(types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": srv.URL + "/api/users"}}) {
		t.Error("an ordinary path should be skipped")
	}
	if *posts != 0 {
		t.Errorf("detection sent %d POSTs", *posts)
	}
}

// The whole schema is kept: types, fields, arguments and their types.
func TestIntrospection(t *testing.T) {
	fetch.Reset()
	full, err := os.ReadFile("../../gqlschema/testdata/introspection.json")
	if err != nil {
		t.Fatal(err)
	}
	srv, posts := server(t, string(full))
	got, _ := run(t, NewSchema(srv.Client()), srv.URL+"/graphql")
	if *posts != 1 {
		t.Fatalf("posts %d", *posts)
	}
	q, _ := got["queries"].([]any)
	m, _ := got["mutations"].([]any)
	if len(q) != 5 || q[0] != "node" || len(m) != 2 || m[0] != "deleteUser" {
		t.Errorf("summary %v %v", q, m)
	}
	raw, _ := json.Marshal(got["schema"])
	sc, err := gqlschema.Parse(raw)
	if err != nil {
		t.Fatalf("no schema kept: %v", err)
	}
	var sigs []string
	for _, o := range sc.Operations() {
		sigs = append(sigs, o.Kind+" "+o.Signature())
	}
	if !slices.Contains(sigs, "mutation login(username: String!, password: String!): Token") {
		t.Errorf("operations %v", sigs)
	}
	if !strings.Contains(sc.SDL(), "input Filter {") {
		t.Error("input objects lost")
	}
}

// A server that refuses the full query for its depth is asked for the
// names; one with introspection off is asked once.
func TestIntrospectionRefused(t *testing.T) {
	fetch.Reset()
	srv, posts := server(t, `{"errors":[{"message":"'IntrospectionQuery' exceeds maximum operation depth of 6"}]}`)
	got, _ := run(t, NewSchema(srv.Client()), srv.URL+"/graphql")
	if *posts != 2 {
		t.Fatalf("posts %d", *posts)
	}
	if q, _ := got["queries"].([]any); len(q) != 2 || got["schema"] != nil {
		t.Errorf("names only: %v", got)
	}

	fetch.Reset()
	srv, posts = server(t, `{"errors":[{"message":"GraphQL introspection is not allowed, but the query contained __schema or __type"}]}`)
	got, _ = run(t, NewSchema(srv.Client()), srv.URL+"/graphql")
	if *posts != 2 || got != nil {
		t.Errorf("introspection off: %d posts, %v", *posts, got) // the full query, and one document to read fields from errors
	}
}

// With introspection off, the root fields are read from the server's
// validation errors; no document asked can pass validation.
func TestSchemaFromSuggestions(t *testing.T) {
	fetch.Reset()
	var docs []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var q struct{ Query string }
		_ = json.NewDecoder(r.Body).Decode(&q)
		docs = append(docs, q.Query)
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(q.Query, "__schema") {
			w.Write([]byte(`{"errors":[{"message":"GraphQL introspection is not allowed"}]}`))
			return
		}
		root, have := "Query", map[string]string{"paste": "PasteObject", "pastes": "[PasteObject]", "systemHealth": ""}
		if strings.HasPrefix(q.Query, "mutation") {
			root, have = "Mutations", map[string]string{"createPaste": "CreatePaste", "deletePaste": "DeletePaste"}
		}
		var errs []map[string]string
		for _, f := range strings.Fields(strings.Trim(strings.SplitN(q.Query, "{", 2)[1], " }")) {
			typ, ok := have[f]
			switch {
			case !ok:
				msg := `Cannot query field "` + f + `" on type "` + root + `".`
				if near := suggest(f, have); len(near) > 0 {
					msg += ` Did you mean "` + strings.Join(near, `" or "`) + `"?`
				}
				errs = append(errs, map[string]string{"message": msg})
			case typ != "":
				errs = append(errs, map[string]string{"message": `Field "` + f + `" of type "` + typ + `" must have a sub selection.`})
			}
			if f == "createPaste" && root == "Mutations" {
				errs = append(errs, map[string]string{"message": `Field "createPaste" argument "title" of type "String!" is required but not provided.`})
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"errors": errs})
	}))
	defer srv.Close()
	got, _ := run(t, NewSchema(srv.Client()), srv.URL+"/graphql")
	if got["recovered"] != "suggestions" || fmt.Sprint(got["queries"]) != "[paste pastes systemHealth]" || fmt.Sprint(got["mutations"]) != "[createPaste deletePaste]" {
		t.Fatalf("recovered %v", got)
	}
	if n, _ := got["errors"].(float64); n < 2 || got["query_type"] != "Query" || got["mutation_type"] != "Mutations" {
		t.Errorf("errors read %v, root types %v and %v", got["errors"], got["query_type"], got["mutation_type"])
	}
	sigs, _ := got["signatures"].(map[string]any)
	if fmt.Sprint(sigs["mutations"]) != "[createPaste(title: String!): CreatePaste deletePaste: DeletePaste]" {
		t.Errorf("signatures %v", sigs)
	}
	for _, d := range docs[1:] {
		if !strings.Contains(d, poison) {
			t.Errorf("a document that could pass validation: %q", d)
		}
	}
}

// Fields neither the built-in wordlist nor a suggestion would reach are
// still recovered: one from a GraphQL operation the map already found in
// a script on the endpoint's origin (vaultBalance, from: client), one
// from words derived from the wordlist's verbs and nouns (deleteAllPastes
// = delete + All + pastes, from: probe). The row reports how many fields
// each root type has, how they were found, and that it may still be
// incomplete.
func TestSchemaRecoversClientAndDerivedWords(t *testing.T) {
	fetch.Reset()
	have := map[string]map[string]bool{
		"Query":     {"pastes": true, "vaultBalance": true},
		"Mutations": {"createPaste": true, "deleteAllPastes": true},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/app.js":
			w.Header().Set("Content-Type", "application/javascript")
			_, _ = w.Write([]byte("const Q = gql`query { vaultBalance pastes { id } }`, M = gql`mutation { createPaste(title: $t) { id } }`;"))
		case "/graphql":
			var q struct{ Query string }
			_ = json.NewDecoder(r.Body).Decode(&q)
			w.Header().Set("Content-Type", "application/json")
			if strings.Contains(q.Query, "__schema") {
				_, _ = w.Write([]byte(`{"errors":[{"message":"GraphQL introspection is not allowed"}]}`))
				return
			}
			root := "Query"
			if strings.HasPrefix(q.Query, "mutation") {
				root = "Mutations"
			}
			var errs []map[string]string
			for _, f := range strings.Fields(strings.Trim(strings.SplitN(q.Query, "{", 2)[1], " }")) {
				if !have[root][f] {
					// No "Did you mean": these two names are reachable only
					// through client-code harvesting or derived words, never
					// a suggestion.
					errs = append(errs, map[string]string{"message": `Cannot query field "` + f + `" on type "` + root + `".`})
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"errors": errs})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	// The map already fetched this script before the schema was recovered.
	if _, _, err := fetch.Do(context.Background(), srv.Client(), srv.URL+"/app.js"); err != nil {
		t.Fatal(err)
	}

	got, _ := run(t, NewSchema(srv.Client()), srv.URL+"/graphql")
	if fmt.Sprint(got["queries"]) != "[pastes vaultBalance]" {
		t.Fatalf("queries %v", got["queries"])
	}
	if fmt.Sprint(got["mutations"]) != "[createPaste deleteAllPastes]" {
		t.Fatalf("mutations %v", got["mutations"])
	}
	if got["complete"] != false {
		t.Errorf("complete %v, want false: recovery never proves there is nothing more", got["complete"])
	}
	if n, _ := got["client_words"].(float64); n < 1 {
		t.Errorf("client_words %v, want at least vaultBalance", got["client_words"])
	}
	recovery, _ := got["recovery"].(map[string]any)
	qr, _ := recovery["queries"].(map[string]any)
	if qr["fields"] != float64(2) {
		t.Errorf("query fields %v, want 2", qr["fields"])
	}
	qby, _ := qr["by"].(map[string]any)
	if qby["client"] != float64(2) {
		t.Errorf("queries by %v, want two client (vaultBalance, pastes)", qby)
	}
	if n, _ := qr["words_tried"].(float64); n == 0 {
		t.Error("words_tried is 0")
	}
	mr, _ := recovery["mutations"].(map[string]any)
	mby, _ := mr["by"].(map[string]any)
	if mby["client"] != float64(1) || mby["probe"] != float64(1) {
		t.Errorf("mutations by %v, want one client (createPaste) and one derived from Query's pastes (deleteAllPastes)", mby)
	}
}

// An endpoint that runs a query sent with GET says so: {__typename}.
func TestGETQueries(t *testing.T) {
	fetch.Reset()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("query") == "{__typename}" {
			w.Write([]byte(`{"data":{"__typename":"Query"}}`))
			return
		}
		w.WriteHeader(400)
		w.Write([]byte(`{"errors":[{"message":"Must provide query string."}]}`))
	}))
	defer srv.Close()
	got, _ := run(t, New(srv.Client()), srv.URL+"/graphql")
	if got["get_queries"] != true {
		t.Errorf("row %v", got)
	}
}

// suggest names the fields a graphql-js server offers for an unknown one:
// those within floor(len*0.4)+1 edits, a case-only difference counting 1.
func suggest(f string, have map[string]string) []string {
	var out []string
	for name := range have {
		if d := lexical(f, name); d <= len(f)*4/10+1 {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// lexical is graphql-js's lexicalDistance (optimal string alignment).
func lexical(a, b string) int {
	if a == b {
		return 0
	}
	a, b = strings.ToLower(a), strings.ToLower(b)
	if a == b {
		return 1
	}
	d := make([][]int, len(a)+1)
	for i := range d {
		d[i] = make([]int, len(b)+1)
		d[i][0] = i
	}
	for j := range d[0] {
		d[0][j] = j
	}
	for i := 1; i <= len(a); i++ {
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			d[i][j] = min(d[i-1][j]+1, d[i][j-1]+1, d[i-1][j-1]+cost)
			if i > 1 && j > 1 && a[i-1] == b[j-2] && a[i-2] == b[j-1] {
				d[i][j] = min(d[i][j], d[i-2][j-2]+1)
			}
		}
	}
	return d[len(a)][len(b)]
}
