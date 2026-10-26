package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/trannghiach/azhaq/engine"
	"github.com/trannghiach/azhaq/types"
)

func TestOpenAPIPathNames(t *testing.T) {
	p, names := openAPIPath("/rest/basket/{id}/coupon/{id}/{n}")
	if p != "/rest/basket/{id}/coupon/{id2}/{id3}" || strings.Join(names, ",") != "id,id2,id3" {
		t.Fatalf("%s %v", p, names)
	}
}

// The export describes what was seen: the method a script calls a route
// with and the fields it sends, a served description as it is, and forms.
func TestOpenAPIExport(t *testing.T) {
	spec := `{"base":"https://app.test/","document":{"openapi":"3.0.1","info":{"title":"Shop"},
		"paths":{"/users/v1/login":{"post":{"requestBody":{"content":{"application/json":{"schema":{"properties":{"username":{},"password":{}}}}}},"responses":{}}}},
		"components":{"securitySchemes":{"bearer":{"type":"http","scheme":"bearer"}}}}}`
	g := &graphView{path: "x.db",
		obs: []types.StoredObservation{{Observation: types.Observation{Collector: "azhaq-openapi", Kind: "api", Payload: json.RawMessage(spec)}}},
		rows: []engine.MapEntry{
			{Entity: types.Entity{Type: types.TypeURL, Key: "https://app.test/rest/2fa/verify"}, Role: "api", Coverage: "hint",
				Ops: []engine.Op{{Method: "POST", Body: []string{"tmpToken", "totpToken"}, Source: "js-call"}}},
			{Entity: types.Entity{Type: types.TypeURL, Key: "https://app.test/rest/products/search"}, Role: "api", Coverage: "visited", Status: 200,
				Ops: []engine.Op{{Method: "GET", Query: []string{"q"}, Source: "js-call"}}},
			{Entity: types.Entity{Type: types.TypeURL, Key: "https://app.test/users/v1/{username}"}, Role: "api", Methods: []string{"DELETE"}},
			{Entity: types.Entity{Type: types.TypeURL, Key: "https://app.test/login"}, Role: "page",
				Forms: []engine.MapForm{{Method: "POST", Action: "https://app.test/login", Fields: []string{"csrf", "username"}}}},
		}}
	doc, err := openAPI(g, "")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(doc)
	var d struct {
		Paths map[string]map[string]struct {
			Parameters []struct{ Name, In string }
			Body       *struct {
				Content map[string]struct {
					Schema struct{ Properties map[string]any }
				}
			} `json:"requestBody"`
		}
		Components map[string]any
	}
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatal(err)
	}
	bodyOf := func(path, method, media string) []string {
		op, ok := d.Paths[path][method]
		if !ok || op.Body == nil {
			t.Fatalf("%s %s: no body in %s", method, path, raw)
		}
		var out []string
		for k := range op.Body.Content[media].Schema.Properties {
			out = append(out, k)
		}
		return sortStrings(out)
	}
	if got := bodyOf("/rest/2fa/verify", "post", "application/json"); strings.Join(got, ",") != "tmpToken,totpToken" {
		t.Errorf("script body %v", got)
	}
	if got := bodyOf("/users/v1/login", "post", "application/json"); strings.Join(got, ",") != "password,username" {
		t.Errorf("served description %v", got)
	}
	if got := bodyOf("/login", "post", "application/x-www-form-urlencoded"); strings.Join(got, ",") != "csrf,username" {
		t.Errorf("form %v", got)
	}
	if ps := d.Paths["/rest/products/search"]["get"].Parameters; len(ps) != 1 || ps[0].Name != "q" || ps[0].In != "query" {
		t.Errorf("query %+v", ps)
	}
	if ps := d.Paths["/users/v1/{username}"]["delete"].Parameters; len(ps) != 1 || ps[0].Name != "username" || ps[0].In != "path" {
		t.Errorf("path parameter %+v", ps)
	}
	if _, ok := d.Paths["/rest/2fa/verify"]["get"]; ok {
		t.Error("a POST route got a GET")
	}
	if d.Components["securitySchemes"] == nil {
		t.Error("the served description's security schemes are kept")
	}
}

func sortStrings(xs []string) []string {
	for i := range xs {
		for j := i + 1; j < len(xs); j++ {
			if xs[j] < xs[i] {
				xs[i], xs[j] = xs[j], xs[i]
			}
		}
	}
	return xs
}
