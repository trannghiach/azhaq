package main

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"reflect"
	"slices"
	"strings"
	"testing"

	"golang.org/x/net/html"
)

// pageAll pages u from 0 to its end within max bytes, as clients follow
// the offsets: every unit on exactly one page, in order, and a page past
// max only when it holds one unit.
func pageAll(t *testing.T, u *exportUnits, max int) [][]byte {
	t.Helper()
	var pages [][]byte
	for lo := 0; lo < len(u.names); {
		hi, page := u.fit(lo, max)
		if hi <= lo || hi > len(u.names) || len(page) > max && hi-lo > 1 {
			t.Fatalf("page from %d ends at %d with %d bytes (max %d)", lo, hi, len(page), max)
		}
		pages = append(pages, page)
		lo = hi
	}
	return pages
}

// followPages calls exportPart from offset 0 to the end, as a client
// does, and returns the pages without their heads.
func followPages(t *testing.T, format string, raw []byte, unit string, total int) []string {
	t.Helper()
	var pages []string
	for offset := 0; ; {
		head, body, _ := strings.Cut(exportPart("/x/w.export", format, raw, offset), "\n")
		if !strings.Contains(head, fmt.Sprintf("%s: %d %s", format, total, unit)) ||
			!strings.Contains(head, fmt.Sprintf("this page holds %s %d", unit, offset)) && !strings.Contains(head, fmt.Sprintf("this page holds %s %d of", singular[unit], offset)) {
			t.Fatalf("head %s", head)
		}
		pages = append(pages, body)
		i := strings.Index(head, "with offset ")
		if i < 0 {
			return pages
		}
		if _, err := fmt.Sscanf(head[i:], "with offset %d", &offset); err != nil || len(pages) > 100 {
			t.Fatalf("%s: %v", head, err)
		}
	}
}

// An OpenAPI description is paged by whole paths, each page a description
// of its own whose references resolve: the components its paths use,
// through other components too, and no others.
func TestExportPagesOpenAPI(t *testing.T) {
	paths := map[string]any{}
	var all []string
	for i := range 300 {
		p := fmt.Sprintf("/api/items%03d/{id}", i)
		all = append(all, p)
		paths[p] = map[string]any{"get": map[string]any{"operationId": fmt.Sprintf("item%d", i), "responses": map[string]any{"200": map[string]any{
			"description": "an item " + strings.Repeat("·", 40),
			"content":     map[string]any{"application/json": map[string]any{"schema": map[string]any{"$ref": fmt.Sprintf("#/components/schemas/Item%d", i%7)}}}}}}}
	}
	paths["/zoo"] = map[string]any{"post": map[string]any{"requestBody": map[string]any{"$ref": "#/components/requestBodies/Animal"}, "responses": map[string]any{}}}
	all = append(all, "/zoo")
	schemas := map[string]any{
		"User":     map[string]any{"type": "object", "properties": map[string]any{"pet": map[string]any{"$ref": "#/components/schemas/Pet"}}},
		"Pet":      map[string]any{"type": "object", "discriminator": map[string]any{"propertyName": "kind", "mapping": map[string]any{"cat": "Cat", "dog": "#/components/schemas/Dog"}}},
		"Cat":      map[string]any{"type": "object"},
		"Dog":      map[string]any{"type": "object"},
		"a/b":      map[string]any{"type": "string"},
		"Unused":   map[string]any{"type": "object"},
		"Animal~1": map[string]any{"$ref": "#/components/schemas/a~1b"},
	}
	for i := range 7 {
		schemas[fmt.Sprintf("Item%d", i)] = map[string]any{"type": "object", "properties": map[string]any{"owner": map[string]any{"$ref": "#/components/schemas/User"}}}
	}
	doc := map[string]any{"openapi": "3.0.3", "info": map[string]any{"title": "Shop", "version": "1"}, "servers": []any{map[string]any{"url": "https://app.test"}},
		"security": []any{map[string]any{"bearer": []any{}}}, "paths": paths,
		"components": map[string]any{"schemas": schemas, "securitySchemes": map[string]any{"bearer": map[string]any{"type": "http", "scheme": "bearer"}},
			"requestBodies": map[string]any{"Animal": map[string]any{"content": map[string]any{"application/json": map[string]any{"schema": map[string]any{"$ref": "#/components/schemas/Animal~01"}}}}}}}
	raw, _ := json.MarshalIndent(doc, "", "  ")
	if len(raw) < 4*maxInline {
		t.Fatalf("the description is too small to page: %d bytes", len(raw))
	}

	var got []string
	for i, body := range followPages(t, "openapi", raw, "paths", len(all)) {
		var pg map[string]any
		if err := json.Unmarshal([]byte(body), &pg); err != nil {
			t.Fatalf("page %d is not JSON: %v", i, err)
		}
		if len(body) > maxInline || pg["openapi"] != "3.0.3" || pg["info"] == nil || pg["servers"] == nil || pg["security"] == nil {
			t.Fatalf("page %d (%d bytes): %.200s", i, len(body), body)
		}
		comps, _ := pg["components"].(map[string]any)
		if comps["securitySchemes"] == nil {
			t.Errorf("page %d has no security schemes", i)
		}
		if schemas, _ := comps["schemas"].(map[string]any); schemas["Unused"] != nil || schemas["Cat"] == nil {
			t.Errorf("page %d carries a component none of its paths uses, or not one a discriminator names", i)
		}
		refsIn(pg, func(ref string) {
			sec, name, ok := componentRef(ref)
			if c, _ := comps[sec].(map[string]any); !ok || c[name] == nil {
				t.Errorf("page %d: %s does not resolve", i, ref)
			}
		})
		for p := range pg["paths"].(map[string]any) {
			got = append(got, p)
		}
	}
	slices.Sort(got)
	if !slices.Equal(got, all) {
		t.Errorf("the pages hold %d paths of %d, or some twice", len(got), len(all))
	}
	// The pages of the end hold /zoo: its body, through two references.
	last := followPages(t, "openapi", raw, "paths", len(all))
	if z := last[len(last)-1]; !strings.Contains(z, `"Animal~1":`) || !strings.Contains(z, `"a/b":`) || strings.Contains(last[0], `"a/b":`) {
		t.Errorf("the components of /zoo: %.300s", z[strings.Index(z, `"components"`):])
	}
}

// An introspection result is paged by definitions, each page a result of
// its own, keyed by endpoint as the export is; all of them make the
// export again.
func TestExportPagesGraphQL(t *testing.T) {
	for _, urls := range [][]string{{"https://api.test/graphql"}, {"https://api.test/graphql", "https://api.test/v2/graphql"}} {
		var raw bytes.Buffer
		if err := graphqlExport(schemaGraph(t, urls...), "graphql", "", &raw); err != nil {
			t.Fatal(err)
		}
		u, err := splitExport("graphql", raw.Bytes())
		if err != nil || u.unit != "definitions" || len(u.names) < 20 {
			t.Fatalf("%v %d", err, len(u.names))
		}
		var whole, again any
		_ = json.Unmarshal(raw.Bytes(), &whole)
		_ = json.Unmarshal(u.page(0, len(u.names)), &again)
		if !reflect.DeepEqual(whole, again) {
			t.Errorf("%d endpoints: all the definitions are not the export", len(urls))
		}
		var names []string
		for i, page := range pageAll(t, u, 4<<10) {
			results := map[string]json.RawMessage{}
			if len(urls) == 1 {
				results[urls[0]] = page
			} else if err := json.Unmarshal(page, &results); err != nil {
				t.Fatal(err)
			}
			for ep, r := range results {
				var res struct {
					Data struct {
						Schema struct {
							QueryType  struct{ Name string }
							Types      []struct{ Name string }
							Directives []struct{ Name string }
						} `json:"__schema"`
					}
				}
				if err := json.Unmarshal(r, &res); err != nil || res.Data.Schema.QueryType.Name != "Root" || !slices.Contains(urls, ep) {
					t.Fatalf("page %d, %s: %v %.200s", i, ep, err, r)
				}
				for _, d := range res.Data.Schema.Directives {
					names = append(names, "@"+d.Name)
				}
				for _, ty := range res.Data.Schema.Types {
					names = append(names, ty.Name)
				}
			}
		}
		if slices.Sort(names); !slices.Equal(names, slices.Sorted(slices.Values(u.names))) {
			t.Errorf("%d endpoints: the pages hold %d definitions of %d", len(urls), len(names), len(u.names))
		}
	}
}

// SDL is paged by definitions; each page starts with where its schema was
// read, and a blank line inside a description does not cut it.
func TestExportPagesSDL(t *testing.T) {
	var raw bytes.Buffer
	if err := graphqlExport(schemaGraph(t, "https://api.test/graphql", "https://api.test/v2/graphql"), "sdl", "", &raw); err != nil {
		t.Fatal(err)
	}
	u := sdlUnits(raw.Bytes())
	if got := string(u.page(0, len(u.names))); got != raw.String() {
		t.Fatalf("all the definitions are not the export:\n%s", got)
	}
	if !slices.Contains(u.names, "type Root") || !slices.Contains(u.names, "directive @auth") || !slices.Contains(u.names, "schema") {
		t.Errorf("names %v", u.names)
	}
	var defs []string
	for i, page := range pageAll(t, u, 300) {
		if !strings.HasPrefix(string(page), "# https://api.test/") {
			t.Errorf("page %d does not say where its schema was read: %.80s", i, page)
		}
		defs = append(defs, sdlUnits(page).names...)
	}
	if !slices.Equal(defs, u.names) {
		t.Errorf("the pages hold %v\nnot %v", defs, u.names)
	}

	sdl := "\"\"\"\nA type.\n\nWith a blank line.\n\"\"\"\ntype A {\n  \"\"\"\n  a field\n\n  more\n  \"\"\"\n  a: Int\n}\n\nscalar B\n"
	if u := sdlUnits([]byte(sdl)); !slices.Equal(u.names, []string{"type A", "scalar B"}) || string(u.page(0, 1)) != sdl[:strings.Index(sdl, "\n\nscalar")+1] {
		t.Errorf("blank lines in descriptions: %q", u.names)
	}
}

// A Burp options file is paged by scope entries, each page an options
// file of its own.
func TestExportPagesBurp(t *testing.T) {
	var inc, exc []any
	for i := range 300 {
		inc = append(inc, map[string]any{"enabled": true, "protocol": "any", "host": fmt.Sprintf(`^(.*\.)?app%03d\.example\.com$`, i)})
	}
	for i := range 20 {
		exc = append(exc, map[string]any{"enabled": true, "protocol": "any", "host": fmt.Sprintf(`^admin%d\.example\.com$`, i)})
	}
	raw, _ := json.MarshalIndent(burpScopeDoc(inc, exc), "", "  ")
	u, err := splitExport("burp", raw)
	if err != nil || len(u.names) != 320 || u.names[300] != `exclude ^admin0\.example\.com$` {
		t.Fatalf("%v %v", err, u.names)
	}
	n := 0
	for i, page := range pageAll(t, u, maxInline) {
		var doc struct {
			Target struct {
				Scope struct {
					Advanced         bool `json:"advanced_mode"`
					Include, Exclude []map[string]any
				}
			}
		}
		if err := json.Unmarshal(page, &doc); err != nil || !doc.Target.Scope.Advanced || doc.Target.Scope.Include == nil || doc.Target.Scope.Exclude == nil {
			t.Fatalf("page %d: %v %.200s", i, err, page)
		}
		n += len(doc.Target.Scope.Include) + len(doc.Target.Scope.Exclude)
	}
	if n != 320 {
		t.Errorf("the pages hold %d entries", n)
	}
}

func burpScopeDoc(inc, exc []any) map[string]any {
	return map[string]any{"target": map[string]any{"scope": map[string]any{"advanced_mode": true, "include": inc, "exclude": exc}}}
}

// The HTML report is paged by rows, each page a report of its own with the
// sections its rows are in.
func TestExportPagesHTML(t *testing.T) {
	g := &graphView{path: "x.db"}
	for i := range 400 {
		r := urlRow(fmt.Sprintf("https://app.test/page%03d", i))
		r.Role = "page"
		g.rows = append(g.rows, r)
	}
	for i := range 30 {
		g.rows = append(g.rows, urlRow(fmt.Sprintf("https://app.test/api/v%02d", i)))
	}
	var raw bytes.Buffer
	if err := htmlReport(g, &raw); err != nil {
		t.Fatal(err)
	}
	u, err := splitExport("html", raw.Bytes())
	if err != nil || u.unit != "rows" || len(u.names) < 430 {
		t.Fatalf("%v %d rows", err, len(u.names))
	}
	var rows []string
	pages := pageAll(t, u, maxInline)
	for i, page := range pages {
		doc, err := html.Parse(bytes.NewReader(page))
		if err != nil || !bytes.Contains(page, []byte("<title>Azhaq report</title>")) || !bytes.Contains(page, []byte("<h1>")) {
			t.Fatalf("page %d: %v", i, err)
		}
		for r := range htmlRows(doc) {
			rows = append(rows, htmlText(r))
		}
		// No section is left without its rows.
		var body *html.Node
		for n := range doc.Descendants() {
			if n.Data == "body" {
				body = n
			}
		}
		section, held := "", 0
		check := func() {
			if section != "" && held == 0 {
				t.Errorf("page %d: section %q without rows", i, section)
			}
		}
		for c := body.FirstChild; c != nil; c = c.NextSibling {
			if c.Data == "h2" {
				check()
				section, held = htmlText(c), 0
			}
			for range htmlRows(c) {
				held++
			}
		}
		check()
	}
	if !slices.Equal(rows, u.names) || len(pages) < 3 {
		t.Errorf("the pages hold %d rows of %d in %d pages", len(rows), len(u.names), len(pages))
	}
	// The cut rows are back: a page from the start is the same twice.
	if !bytes.Equal(u.page(0, 5), u.page(0, 5)) || !bytes.Contains(u.page(0, len(u.names)), []byte("https://app.test/page399")) {
		t.Error("paging changed the report")
	}
}

// GraphML is paged by nodes and edges, each page a well-formed document
// with the keys and the graph element.
func TestExportPagesGraphML(t *testing.T) {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>
<graphml xmlns="http://graphml.graphdrawing.org/xmlns">
  <key id="type" for="node" attr.name="type" attr.type="string"/>
  <graph id="azhaq" edgedefault="directed">
`)
	for i := range 200 {
		fmt.Fprintf(&b, "    <node id=\"n%d\"><data key=\"type\">URL</data><data key=\"label\">https://app.test/a&amp;b%d</data></node>\n", i, i)
	}
	for i := range 199 {
		fmt.Fprintf(&b, "    <edge id=\"e%d\" source=\"n%d\" target=\"n%d\"><data key=\"rel\">links</data></edge>\n", i, i, i+1)
	}
	b.WriteString("  </graph>\n</graphml>\n")
	raw := []byte(b.String())
	u, err := splitExport("graphml", raw)
	if err != nil || len(u.names) != 399 || u.names[0] != "node n0" || u.names[200] != "n0 → n1" {
		t.Fatalf("%v %d %v", err, len(u.names), u.names[:2])
	}
	if !bytes.Equal(u.page(0, len(u.names)), raw) {
		t.Fatalf("all of it is not the export:\n%s", u.page(0, len(u.names)))
	}
	n := 0
	for i, page := range pageAll(t, u, 8<<10) {
		d := xml.NewDecoder(bytes.NewReader(page))
		depth := 0
		for {
			tok, err := d.Token()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatalf("page %d: %v", i, err)
			}
			switch tok.(type) {
			case xml.StartElement:
				if depth == 2 {
					n++
				}
				depth++
			case xml.EndElement:
				depth--
			}
		}
		if !bytes.Contains(page, []byte(`<key id="type"`)) || !bytes.HasSuffix(page, []byte("</graph>\n</graphml>\n")) {
			t.Errorf("page %d: %.200s", i, page)
		}
	}
	if n != 399 {
		t.Errorf("the pages hold %d elements", n)
	}
}

// An export that fits is returned as written; one that cannot be read in
// its format is paged by lines, and the result says so.
func TestExportPartWhole(t *testing.T) {
	if got := exportPart("/x/w.json", "openapi", []byte("{\n  \"paths\": {}\n}\n"), 0); got != "wrote /x/w.json on the server's machine (18 bytes, openapi: 0 paths)\n{\n  \"paths\": {}\n}\n" {
		t.Errorf("%q", got)
	}
	big := strings.Repeat("not json\n", 3000)
	head, body, _ := strings.Cut(exportPart("/x/w.json", "openapi", []byte(big), 0), "\n")
	if !strings.Contains(head, "paged by lines") || !strings.Contains(head, "this page holds lines 0 to") || len(body) > maxInline {
		t.Errorf("%s", head)
	}
}
