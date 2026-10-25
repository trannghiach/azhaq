package gqlcol

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/trannghiach/azhaq/internal/fetch"
	"github.com/trannghiach/azhaq/types"
)

const schema = `{"data":{"__schema":{"queryType":{"name":"Query"},"mutationType":{"name":"Mutation"},"subscriptionType":null,
"types":[{"name":"Query","kind":"OBJECT","fields":[{"name":"users"},{"name":"me"}]},
{"name":"Mutation","kind":"OBJECT","fields":[{"name":"deleteUser"}]},
{"name":"User","kind":"OBJECT","fields":[{"name":"email"}]},
{"name":"__Type","kind":"OBJECT","fields":[]},{"name":"String","kind":"SCALAR","fields":null}]}}}`

// server is a GraphQL endpoint at /graphql (graphql-express style) and an
// ordinary JSON API at /api/graphql-docs.
func server(t *testing.T) (*httptest.Server, *int) {
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
	srv, posts := server(t)
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

func TestIntrospection(t *testing.T) {
	fetch.Reset()
	srv, posts := server(t)
	got, _ := run(t, NewSchema(srv.Client()), srv.URL+"/graphql")
	if *posts != 1 {
		t.Fatalf("posts %d", *posts)
	}
	q, _ := got["queries"].([]any)
	m, _ := got["mutations"].([]any)
	ty, _ := got["types"].([]any)
	if len(q) != 2 || q[0] != "me" || len(m) != 1 || m[0] != "deleteUser" || len(ty) != 1 || ty[0] != "User" {
		t.Errorf("schema %v", got)
	}
}
