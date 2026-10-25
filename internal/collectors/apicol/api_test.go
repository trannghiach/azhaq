package apicol

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/trannghiach/azhaq/internal/fetch"
	"github.com/trannghiach/azhaq/internal/types"
)

const openapi3 = `{
  "openapi": "3.0.1",
  "info": {"title": "VAmPI", "version": "0.1"},
  "servers": [{"url": ""}],
  "paths": {
    "/users/v1": {"get": {}},
    "/users/v1/login": {"post": {"requestBody": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/Login"}}}}}},
    "/users/v1/{username}": {"parameters": [{"name": "username", "in": "path"}], "get": {}, "delete": {}},
    "/createdb": {"get": {}}
  },
  "components": {"schemas": {"Login": {"properties": {"username": {}, "password": {}}}}}
}`

const swagger2 = `swagger: "2.0"
info:
  title: Pets
host: localhost:8080
basePath: /v2
paths:
  /pet/{petId}:
    get:
      parameters:
        - $ref: "#/parameters/petId"
    post:
      parameters:
        - name: name
          in: formData
`

type op struct {
	URL     string   `json:"url"`
	Methods []string `json:"methods"`
	Params  []string `json:"params"`
}

func runSpec(t *testing.T, path, ctype, body string) (map[string]op, types.RunMeta, int) {
	t.Helper()
	fetch.Reset()
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != path {
			calls++
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", ctype)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	ops := map[string]op{}
	emit := func(o types.Observation) error {
		if o.Kind != "url" {
			return nil
		}
		var p op
		if err := json.Unmarshal(o.Payload, &p); err != nil {
			t.Fatal(err)
		}
		ops[strings.TrimPrefix(p.URL, srv.URL)] = p
		return nil
	}
	meta, err := New(srv.Client()).Run(context.Background(), types.Seed{
		Type: types.TypeURL, Keys: map[string]string{"url": srv.URL + path},
	}, emit)
	if err != nil {
		t.Fatal(err)
	}
	return ops, meta, calls
}

func TestOpenAPI3(t *testing.T) {
	ops, meta, calls := runSpec(t, "/openapi.json", "application/json", openapi3)
	if len(ops) != 4 {
		t.Fatalf("ops %v", ops)
	}
	u := ops["/users/v1/{username}"]
	if strings.Join(u.Methods, ",") != "GET,DELETE" || strings.Join(u.Params, ",") != "username" {
		t.Errorf("templated path %+v", u)
	}
	if got := strings.Join(ops["/users/v1/login"].Params, ","); got != "password,username" {
		t.Errorf("body params %q", got)
	}
	if len(meta.NextHints) != 0 || calls != 0 {
		t.Errorf("operations must be mapped, not called: hints=%v calls=%d", meta.NextHints, calls)
	}
}

func TestSwagger2YAML(t *testing.T) {
	ops, _, _ := runSpec(t, "/docs/swagger.yaml", "application/yaml", swagger2)
	p, ok := ops["/v2/pet/{petId}"]
	if !ok {
		t.Fatalf("basePath on the serving origin: %v", ops)
	}
	if strings.Join(p.Methods, ",") != "GET,POST" {
		t.Errorf("methods %v", p.Methods)
	}
}

func TestNotASpec(t *testing.T) {
	ops, meta, _ := runSpec(t, "/assets/i18n/en.json", "application/json", `{"paths": {"/x": {}}, "title": "x"}`)
	if len(ops) != 0 || meta.EmitCount != 0 {
		t.Errorf("plain JSON read as a spec: %v", ops)
	}
	if New(nil).Skip(types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": "http://h/api/Users"}}) == false {
		t.Error("API route should be skipped at plan time")
	}
}
