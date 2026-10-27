package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/trannghiach/azhaq/catalog"
	"github.com/trannghiach/azhaq/engine"
	"github.com/trannghiach/azhaq/internal/collectors/crawlcol"
	"github.com/trannghiach/azhaq/internal/collectors/httpcol"
	"github.com/trannghiach/azhaq/internal/fetch"
	"github.com/trannghiach/azhaq/internal/gqlschema"
	"github.com/trannghiach/azhaq/internal/scopefile"
	"github.com/trannghiach/azhaq/scope"
	"github.com/trannghiach/azhaq/store"
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

// A site shaped like DVWA: forms that submit to their own page (action
// "#" or none), a menu linking /fi/?page=include.php from every page, and
// links a GET to which changes something (the run leaves them alone, and
// so must a tool importing the description).
func TestOpenAPIFormsOfAMappedSite(t *testing.T) {
	fetch.Reset()
	menu := `<a href="/sqli/">sqli</a> <a href="/upload/">upload</a> <a href="/security.php">security</a> <a href="/fi/?page=include.php">fi</a>` +
		`<a href="/security.php?phpids=on">enable PHPIDS</a> <a href="/setup.php">setup</a> <a href="/setup.php?action=reset">reset</a>`
	pages := map[string]string{
		"/":             menu,
		"/sqli/":        menu + `<form action="#" method="GET"><input type="text" name="id"><input type="submit" name="Submit" value="Submit"></form>`,
		"/upload/":      menu + `<form enctype="multipart/form-data" action="#" method="POST"><input type="hidden" name="MAX_FILE_SIZE" value="100000"><input name="uploaded" type="file"><input type="submit" name="Upload"></form>`,
		"/security.php": menu + `<form action="#" method="POST"><select name="security"><option>low</option></select><input type="submit" name="seclev_submit"></form>`,
		"/fi/":          menu + `<p>included</p>`,
	}
	var asked sync.Map
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked.Store(r.URL.RequestURI(), true)
		body, ok := pages[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "<html><head><title>%s</title></head><body>%s</body></html>", r.URL.Path, body)
	}))
	defer site.Close()
	db := filepath.Join(t.TempDir(), "x.db")
	st, err := store.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	cat := catalog.New()
	httpcol.Register(cat, site.Client())
	crawlcol.Register(cat, site.Client())
	eng := &engine.Engine{Cat: cat, Store: st}
	seed := types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": site.URL + "/"}}
	if err := eng.RunLocal(context.Background(), []types.Seed{seed}, engine.Budgets{MaxDepth: 3, MaxItems: 64}); err != nil {
		t.Fatal(err)
	}
	st.Close()
	var out bytes.Buffer
	if err := exportAs(db, "openapi", "", &out); err != nil {
		t.Fatal(err)
	}
	var d struct {
		Paths map[string]map[string]struct {
			Parameters []struct{ Name, In string }
			Body       *struct {
				Content map[string]struct {
					Schema struct {
						Properties map[string]struct{ Type, Format string }
					}
				}
			} `json:"requestBody"`
		}
	}
	if err := json.Unmarshal(out.Bytes(), &d); err != nil {
		t.Fatal(err)
	}
	query := func(path string) string {
		var names []string
		for _, p := range d.Paths[path]["get"].Parameters {
			if p.In == "query" {
				names = append(names, p.Name)
			}
		}
		return strings.Join(names, ",")
	}
	if q := query("/sqli/"); q != "id,Submit" {
		t.Errorf("GET /sqli/ query %q, want the form's id,Submit; %s", q, out.Bytes())
	}
	if q := query("/fi/"); q != "page" {
		t.Errorf("GET /fi/ query %q, want page", q)
	}
	for _, p := range []string{"/upload/", "/security.php"} {
		if q := query(p); q != "" {
			t.Errorf("GET %s takes the query of its links: %q", p, q)
		}
	}
	for _, u := range []string{"/security.php?phpids=on", "/setup.php?action=reset"} {
		if _, ok := asked.Load(u); ok {
			t.Errorf("the run requested %s", u)
		}
	}
	if d.Paths["/setup.php"] != nil {
		t.Errorf("/setup.php, never requested, is in the description: %v", d.Paths["/setup.php"])
	}
	up := d.Paths["/upload/"]["post"].Body
	if up == nil || up.Content["multipart/form-data"].Schema.Properties["uploaded"].Format != "binary" ||
		up.Content["multipart/form-data"].Schema.Properties["MAX_FILE_SIZE"].Type != "string" {
		t.Errorf("POST /upload/ body %+v", up)
	}
	sec := d.Paths["/security.php"]["post"].Body
	if sec == nil || len(sec.Content["application/x-www-form-urlencoded"].Schema.Properties) != 2 {
		t.Errorf("POST /security.php body %+v", sec)
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

func urlRow(key string, ops ...engine.Op) engine.MapEntry {
	return engine.MapEntry{Entity: types.Entity{Type: types.TypeURL, Key: key}, Role: "api", Coverage: "visited", Status: 200, Ops: ops}
}

// operations lists "METHOD path operationId" for every operation.
func operations(t *testing.T, doc map[string]any) []string {
	t.Helper()
	var out []string
	for p, v := range doc["paths"].(map[string]any) {
		for m, op := range v.(map[string]any) {
			if o, ok := op.(map[string]any); ok && slices.Contains(opMethods, m) {
				id, _ := o["operationId"].(string)
				out = append(out, m+" "+p+" "+id)
			}
		}
	}
	slices.Sort(out)
	return out
}

// /blog and /blog/ are two paths with one operationId; every operationId
// must be unique, deterministically, and a served description's keep theirs.
func TestOpenAPIUniqueOperationIDs(t *testing.T) {
	spec := `{"base":"https://app.test/","document":{"openapi":"3.0.1","info":{"title":"Blog"},
		"paths":{"/posts":{"get":{"operationId":"get_blog","responses":{"200":{"description":"ok"}}}}}}}`
	g := &graphView{path: "x.db",
		obs: []types.StoredObservation{{Observation: types.Observation{Collector: "azhaq-openapi", Kind: "api", Payload: json.RawMessage(spec)}}},
		rows: []engine.MapEntry{
			urlRow("https://app.test/blog", engine.Op{Method: "GET"}),
			urlRow("https://app.test/blog/", engine.Op{Method: "GET"}),
			urlRow("https://app.test/blog/2", engine.Op{Method: "GET"}),
			urlRow("https://app.test/api/items", engine.Op{Method: "GET", OperationID: "listItems"}, engine.Op{Method: "POST", OperationID: "listItems"}),
		}}
	var first []string
	for range 5 {
		doc, err := openAPI(g, "")
		if err != nil {
			t.Fatal(err)
		}
		got := operations(t, doc)
		ids := map[string]string{}
		for _, o := range got {
			f := strings.Fields(o)
			if prev, ok := ids[f[2]]; ok {
				t.Fatalf("operationId %s on %s and %s", f[2], prev, o)
			}
			ids[f[2]] = o
		}
		if first == nil {
			first = got
		} else if !slices.Equal(first, got) {
			t.Fatalf("not deterministic:\n%v\n%v", first, got)
		}
	}
	want := []string{
		"get /api/items listItems", "get /blog get_blog_3", "get /blog/ get_blog_4", "get /blog/2 get_blog_2",
		"get /posts get_blog", "post /api/items listItems_2",
	}
	if !slices.Equal(first, want) {
		t.Errorf("operations %q", first)
	}
}

// A route the run left alone because a GET there changes something is no
// GET of the export; what a script sends there with another method, and
// what a served description says, stay.
func TestOpenAPISkippedRoutes(t *testing.T) {
	spec := `{"base":"https://app.test/","document":{"openapi":"3.0.1","info":{"title":"Shop"},
		"paths":{"/api/cache/clear":{"get":{"responses":{"200":{"description":"ok"}}}}}}}`
	skipped := func(r engine.MapEntry) engine.MapEntry { r.Coverage, r.Status = "skipped", 0; return r }
	g := &graphView{path: "x.db",
		obs: []types.StoredObservation{{Observation: types.Observation{Collector: "azhaq-openapi", Kind: "api", Payload: json.RawMessage(spec)}}},
		rows: []engine.MapEntry{
			urlRow("https://app.test/api/items", engine.Op{Method: "GET"}),
			skipped(urlRow("https://app.test/api/items?action=delete")),
			skipped(urlRow("https://app.test/api/logout", engine.Op{Method: "GET"}, engine.Op{Method: "POST"})),
			skipped(urlRow("https://app.test/api/reset")),
			skipped(urlRow("https://app.test/api/cache/clear", engine.Op{Method: "GET"})),
			{Entity: types.Entity{Type: types.TypeURL, Key: "https://app.test/admin.php?mode=install"}, Role: "page", Coverage: "skipped", Params: []string{"mode"}},
		}}
	doc, err := openAPI(g, "")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"get /api/cache/clear ", "get /api/items get_api_items", "post /api/logout post_api_logout"}
	if got := operations(t, doc); !slices.Equal(got, want) {
		t.Errorf("operations %q, want %q", got, want)
	}
	if params := doc["paths"].(map[string]any)["/api/items"].(map[string]any)["get"].(map[string]any)["parameters"]; params != nil {
		t.Errorf("GET /api/items takes the names of a link left alone: %v", params)
	}
}

// Templates that differ only by their parameter names are one path, and
// every {name} of a path is a parameter of each of its operations, forms
// included.
func TestOpenAPIPathTemplates(t *testing.T) {
	spec := `{"base":"https://app.test/","document":{"openapi":"3.0.1","info":{"title":"Shop"},
		"paths":{"/users/{username}":{"parameters":[{"name":"username","in":"path","required":true,"schema":{"type":"string"}}],
			"get":{"responses":{"200":{"description":"ok"}}}}}}}`
	g := &graphView{path: "x.db",
		obs: []types.StoredObservation{{Observation: types.Observation{Collector: "azhaq-openapi", Kind: "api", Payload: json.RawMessage(spec)}}},
		rows: []engine.MapEntry{
			urlRow("https://app.test/users/{n}", engine.Op{Method: "DELETE"}),
			urlRow("https://app.test/orders/{id}", engine.Op{Method: "GET", Query: []string{"q", "q", ""}}),
			urlRow("https://app.test/orders/{n}", engine.Op{Method: "PUT"}),
			{Entity: types.Entity{Type: types.TypeURL, Key: "https://app.test/shop"}, Role: "page",
				Forms: []engine.MapForm{{Method: "POST", Action: "https://app.test/product/{n}/review", Fields: []string{"text"}}}},
		}}
	doc, err := openAPI(g, "")
	if err != nil {
		t.Fatal(err)
	}
	paths := doc["paths"].(map[string]any)
	for _, p := range []string{"/users/{id}", "/orders/{n}"} {
		if paths[p] != nil {
			t.Errorf("%s kept beside a path of its shape", p)
		}
	}
	params := func(p, m string) []string {
		op, ok := paths[p].(map[string]any)[m].(map[string]any)
		if !ok {
			t.Fatalf("no %s %s in %v", m, p, paths[p])
		}
		var out []string
		for _, x := range op["parameters"].([]any) {
			out = append(out, x.(map[string]any)["in"].(string)+" "+x.(map[string]any)["name"].(string))
		}
		return out
	}
	if got := params("/users/{username}", "delete"); !slices.Equal(got, []string{"path username"}) {
		t.Errorf("delete /users/{username}: %v", got)
	}
	if got := params("/orders/{id}", "get"); !slices.Equal(got, []string{"path id", "query q"}) {
		t.Errorf("get /orders/{id}: %v", got)
	}
	if got := params("/orders/{id}", "put"); !slices.Equal(got, []string{"path id"}) {
		t.Errorf("put /orders/{id}: %v", got)
	}
	if got := params("/product/{id}/review", "post"); !slices.Equal(got, []string{"path id"}) {
		t.Errorf("form: %v", got)
	}
}

// Component names OpenAPI does not allow are renamed with their
// references.
func TestOpenAPIComponentNames(t *testing.T) {
	spec := `{"base":"https://app.test/","document":{"openapi":"3.0.1","info":{"title":"Shop"},
		"paths":{"/me":{"get":{"responses":{"200":{"description":"ok","content":{"application/json":{"schema":{"$ref":"#/components/schemas/User Info"}}}}}}}},
		"components":{"schemas":{"User Info":{"type":"object"},"Ok.Name-1":{"type":"string"}}}}}`
	g := &graphView{path: "x.db",
		obs:  []types.StoredObservation{{Observation: types.Observation{Collector: "azhaq-openapi", Kind: "api", Payload: json.RawMessage(spec)}}},
		rows: []engine.MapEntry{urlRow("https://app.test/me", engine.Op{Method: "GET"})}}
	doc, err := openAPI(g, "")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(doc)
	if strings.Contains(string(raw), "User Info") || !strings.Contains(string(raw), `"$ref":"#/components/schemas/User_Info"`) || !strings.Contains(string(raw), `"Ok.Name-1"`) {
		t.Errorf("components %s", raw)
	}
}

func schemaGraph(t *testing.T, urls ...string) *graphView {
	t.Helper()
	answer, err := os.ReadFile("../../internal/gqlschema/testdata/introspection.json")
	if err != nil {
		t.Fatal(err)
	}
	raw, _, _ := gqlschema.Read(answer)
	g := &graphView{path: "x.db"}
	for _, u := range urls {
		payload := `{"introspection":true,"url":"` + u + `","role":"graphql","status":200,"schema":` + string(raw) + `}`
		g.obs = append(g.obs, types.StoredObservation{Observation: types.Observation{Collector: "azhaq-graphql-schema", Kind: "graphql", Payload: json.RawMessage(payload)}})
		g.rows = append(g.rows, urlRow(u, engine.Op{Method: "POST", Body: []string{"query", "variables"}, Source: "js-call"},
			engine.Op{Method: "POST", Summary: "query users", OperationID: "users", Source: "graphql"}))
	}
	return g
}

// A GraphQL endpoint is one POST whose x-azhaq-graphql lists the schema's
// operations with their arguments; no REST mapping is made up.
func TestOpenAPIGraphQL(t *testing.T) {
	doc, err := openAPI(schemaGraph(t, "https://api.test/graphql"), "")
	if err != nil {
		t.Fatal(err)
	}
	if got := operations(t, doc); !slices.Equal(got, []string{"post /graphql post_graphql"}) {
		t.Fatalf("operations %v", got)
	}
	post := doc["paths"].(map[string]any)["/graphql"].(map[string]any)["post"].(map[string]any)
	raw, _ := json.Marshal(post)
	var op struct {
		Summary string
		Body    struct {
			Content map[string]struct {
				Schema struct{ Required []string }
			}
		} `json:"requestBody"`
		X struct {
			Operations []struct {
				Type, Name, Returns string
				Arguments           []struct{ Name, Type, Default string }
			}
		} `json:"x-azhaq-graphql"`
	}
	if err := json.Unmarshal(raw, &op); err != nil {
		t.Fatal(err)
	}
	if op.Summary != "GraphQL endpoint: 5 queries, 2 mutations, 1 subscription" || !slices.Equal(op.Body.Content["application/json"].Schema.Required, []string{"query"}) {
		t.Errorf("operation %s", raw)
	}
	if len(op.X.Operations) != 8 {
		t.Fatalf("x-azhaq-graphql %s", raw)
	}
	users := op.X.Operations[4]
	if users.Type != "query" || users.Name != "users" || users.Returns != "[User!]!" || len(users.Arguments) != 3 ||
		users.Arguments[0].Name != "limit" || users.Arguments[0].Type != "Int" || users.Arguments[0].Default != "10" {
		t.Errorf("users %+v", users)
	}
}

// -format graphql writes the introspection result tools read; several
// endpoints are keyed by URL, and -origin picks one. -format sdl writes
// the schema language.
func TestGraphQLExport(t *testing.T) {
	var one bytes.Buffer
	if err := graphqlExport(schemaGraph(t, "https://api.test/graphql"), "graphql", "", &one); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Data struct {
			Schema struct {
				QueryType struct{ Name string }
				Types     []any
			} `json:"__schema"`
		}
	}
	if err := json.Unmarshal(one.Bytes(), &doc); err != nil || doc.Data.Schema.QueryType.Name != "Root" || len(doc.Data.Schema.Types) == 0 {
		t.Errorf("introspection result %v %.200s", err, one.String())
	}

	two := schemaGraph(t, "https://api.test/graphql", "https://api.test/v2/graphql")
	var keyed bytes.Buffer
	if err := graphqlExport(two, "graphql", "", &keyed); err != nil {
		t.Fatal(err)
	}
	var byURL map[string]struct {
		Data map[string]json.RawMessage
	}
	if err := json.Unmarshal(keyed.Bytes(), &byURL); err != nil || len(byURL) != 2 || byURL["https://api.test/v2/graphql"].Data["__schema"] == nil {
		t.Errorf("keyed by endpoint: %v %.200s", err, keyed.String())
	}
	var picked bytes.Buffer
	if err := graphqlExport(two, "graphql", "https://api.test/v2/graphql", &picked); err != nil || !strings.HasPrefix(picked.String(), "{\n  \"data\"") {
		t.Errorf("-origin URL: %v %.80s", err, picked.String())
	}

	var sdl bytes.Buffer
	if err := graphqlExport(schemaGraph(t, "https://api.test/graphql"), "sdl", "", &sdl); err != nil {
		t.Fatal(err)
	}
	want, _ := os.ReadFile("../../internal/gqlschema/testdata/introspection.sdl")
	if !strings.HasPrefix(sdl.String(), "# https://api.test/graphql\n") || !strings.HasSuffix(sdl.String(), string(want)) {
		t.Errorf("sdl:\n%s", sdl.String())
	}

	if err := graphqlExport(&graphView{path: "x.db"}, "sdl", "", &sdl); err == nil || !strings.Contains(err.Error(), "-graphql") {
		t.Errorf("no schema: %v", err)
	}
}

// The Burp scope is the run's: its scope file's and -allow's rules
// included, its deny rules excluded; a run without one lists its hosts.
func TestBurpScopeFromRun(t *testing.T) {
	dir := t.TempDir()
	scopeFile := filepath.Join(dir, "scope.txt")
	if err := os.WriteFile(scopeFile, []byte("*.example.com\napi.example.org\n10.0.0.0/24\n!admin.example.com\n!192.0.2.7\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	db := filepath.Join(dir, "x.db")
	st, err := store.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.BeginRun("r1", 2, 100); err != nil {
		t.Fatal(err)
	}
	if err := st.SetRunArgs(keptArgs([]string{"-scope", scopeFile, "-allow", "127.0.0.1", "-deny==old.example.com", "-graphql"})); err != nil {
		t.Fatal(err)
	}
	st.Close()

	var out bytes.Buffer
	if err := exportAs(db, "burp", "", &out); err != nil {
		t.Fatal(err)
	}
	var f struct {
		Target struct {
			Scope struct {
				Advanced         bool `json:"advanced_mode"`
				Include, Exclude []struct {
					Enabled        bool
					Protocol, Host string
				}
			}
		}
	}
	if err := json.Unmarshal(out.Bytes(), &f); err != nil {
		t.Fatal(err)
	}
	hosts := func(es []struct {
		Enabled        bool
		Protocol, Host string
	}) []string {
		var out []string
		for _, e := range es {
			if !e.Enabled || e.Protocol != "any" {
				t.Errorf("entry %+v", e)
			}
			out = append(out, e.Host)
		}
		return out
	}
	inc, exc := hosts(f.Target.Scope.Include), hosts(f.Target.Scope.Exclude)
	if want := []string{`^127\.0\.0\.1$`, `^(.*\.)?example\.com$`, `10.0.0.0/24`, `^api\.example\.org$`}; !f.Target.Scope.Advanced || !slices.Equal(inc, want) {
		t.Errorf("include %q", inc)
	}
	if want := []string{`^old\.example\.com$`, `^192\.0\.2\.7$`, `^admin\.example\.com$`}; !slices.Equal(exc, want) {
		t.Errorf("exclude %q", exc)
	}
	// Azhaq reads the file back as the same scope.
	sc, err := scopefile.Parse(out.Bytes(), "")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(sc.Allow, " ") != "*.example.com 10.0.0.0/24 127.0.0.1 =api.example.org" || strings.Join(sc.Deny, " ") != "192.0.2.7 =admin.example.com =old.example.com" {
		t.Errorf("read back: allow %v deny %v", sc.Allow, sc.Deny)
	}

	g := &graphView{probe: []engine.ProbeRow{{URL: "https://app.test/"}, {URL: "http://app.test:8080/x"}}}
	none := burpScope(g, runRulesOrEmpty(t, nil))["target"].(map[string]any)["scope"].(map[string]any)
	if inc := none["include"].([]map[string]any); len(inc) != 2 || inc[1]["port"] != "^8080$" || len(none["exclude"].([]map[string]any)) != 0 {
		t.Errorf("observed hosts %v", none)
	}
}

func runRulesOrEmpty(t *testing.T, args []string) scope.Rules {
	t.Helper()
	r, err := runRules(args, func(string, string) (scopefile.Scope, error) {
		t.Fatal("no -scope to load")
		return scopefile.Scope{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// A scope file is stored by its full path, a platform by its name.
func TestKeptArgsScopePath(t *testing.T) {
	got := keptArgs([]string{"-scope", "scope.csv", "-program", "x", "-scope=hackerone"})
	abs, _ := filepath.Abs("scope.csv")
	if !slices.Equal(got, []string{"-scope=" + abs, "-program", "x", "-scope=hackerone"}) {
		t.Errorf("kept %q", got)
	}
}
