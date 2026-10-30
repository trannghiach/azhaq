package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// openAPIRow validates the OpenAPI export of runs on the bench apps with
// the bench's own checker: the rules of OpenAPI 3 that azhaq's export has
// to meet (a validator such as openapi-spec-validator is what reviewers ran
// by hand; no dependency is added for it).
type openAPIRow struct {
	Specs []openAPISpec `json:"specs"`
}

type openAPISpec struct {
	App      string   `json:"app"`
	Paths    int      `json:"paths"`
	Problems []string `json:"problems,omitempty"`
}

func benchOpenAPI() *openAPIRow {
	dir, _ := filepath.Abs(filepath.Join(work, "openapi"))
	must(os.MkdirAll(dir, 0o755))
	// A page with /blog and /blog/: the duplicate operationId of MAP-02.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	must(err)
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			fmt.Fprint(w, `<html><a href="/blog">blog</a> <a href="/blog/">blog dir</a> <a href="/blog/post?postId=1">p</a> <a href="/blog/post?postId=2">p2</a><form action="/search" method="get"><input name="q"></form></html>`)
		case "/blog", "/blog/", "/blog/post", "/search":
			fmt.Fprint(w, "<html>"+r.URL.Path+"</html>")
		default:
			http.NotFound(w, r)
		}
	})}
	go srv.Serve(ln)
	defer srv.Close()
	apps := []struct {
		name, url string
		slow      bool
	}{
		{"Juice Shop", juiceURL, false}, {"VAmPI", vampiURL, false}, {"DVGA", "http://127.0.0.1:5013/", false},
		{"duplicate /blog and /blog/", "http://" + ln.Addr().String() + "/", false}, {"ginandjuice.shop", ginURL, true},
	}
	row := &openAPIRow{}
	for i, a := range apps {
		db := filepath.Join(dir, fmt.Sprintf("app%d-%s.db", i, time.Now().Format("150405")))
		args := []string{"run", "-url", a.url, "-db", db, "-quiet"}
		if a.slow { // a public site: 5 requests per second
			args = append(args, "-rate", politeHTTP)
		}
		r := azRun("openapi", 20*time.Minute, dir, args...)
		ex := azRun("openapi", 2*time.Minute, dir, "export", "-db", db, "-format", "openapi")
		spec := openAPISpec{App: a.name}
		var doc map[string]any
		if err := json.Unmarshal([]byte(ex.stdout), &doc); err != nil {
			spec.Problems = []string{"the export is not JSON: " + err.Error() + " (run exit " + fmt.Sprint(r.exit) + ")"}
		} else {
			if ps, ok := doc["paths"].(map[string]any); ok {
				spec.Paths = len(ps)
			}
			spec.Problems = validateOpenAPI(doc)
		}
		row.Specs = append(row.Specs, spec)
		addCheck("openapi: the export of "+a.name+" is a valid OpenAPI 3 document", len(spec.Problems) == 0 && spec.Paths > 0,
			"%d paths; %d problems %s", spec.Paths, len(spec.Problems), clipList(spec.Problems, 5))
	}
	return row
}

var (
	pathParam  = regexp.MustCompile(`\{([^}/]+)\}`)
	statusKey  = regexp.MustCompile(`^([1-5][0-9X]{2}|default)$`)
	httpVerbs  = map[string]bool{"get": true, "put": true, "post": true, "delete": true, "options": true, "head": true, "patch": true, "trace": true}
	paramPlace = map[string]bool{"query": true, "header": true, "path": true, "cookie": true}
	schemaType = map[string]bool{"string": true, "number": true, "integer": true, "boolean": true, "array": true, "object": true, "null": true}
)

// validateOpenAPI returns what is wrong with an OpenAPI 3 document: the
// structure the specification requires, unique operation ids, path
// parameters declared as required path parameters, resolvable references.
func validateOpenAPI(doc map[string]any) []string {
	var bad []string
	add := func(f string, a ...any) { bad = append(bad, fmt.Sprintf(f, a...)) }
	if v, _ := doc["openapi"].(string); !strings.HasPrefix(v, "3.") {
		add("openapi: %q is not a 3.x version", v)
	}
	info, _ := doc["info"].(map[string]any)
	for _, k := range []string{"title", "version"} {
		if s, _ := info[k].(string); s == "" {
			add("info.%s is missing", k)
		}
	}
	if servers, ok := doc["servers"].([]any); ok {
		for i, s := range servers {
			if u, _ := s.(map[string]any)["url"].(string); u == "" {
				add("servers[%d].url is missing", i)
			}
		}
	}
	paths, ok := doc["paths"].(map[string]any)
	if !ok {
		add("paths is missing")
		return bad
	}
	ids := map[string]string{}
	var keys []string
	for p := range paths {
		keys = append(keys, p)
	}
	sort.Strings(keys)
	for _, p := range keys {
		if !strings.HasPrefix(p, "/") {
			add("path %q does not start with /", p)
		}
		item, _ := paths[p].(map[string]any)
		shared := params(item["parameters"], doc, &bad, p)
		for k, v := range item {
			if !httpVerbs[k] && k != "parameters" && k != "summary" && k != "description" && k != "servers" && k != "$ref" && !strings.HasPrefix(k, "x-") {
				add("%s: %q is not an operation", p, k)
			}
			if !httpVerbs[k] {
				continue
			}
			op, _ := v.(map[string]any)
			where := strings.ToUpper(k) + " " + p
			if id, ok := op["operationId"].(string); ok {
				if prev, dup := ids[id]; dup {
					add("operationId %q is used by %s and %s", id, prev, where)
				}
				ids[id] = where
			}
			resp, _ := op["responses"].(map[string]any)
			if len(resp) == 0 {
				add("%s: responses is missing or empty", where)
			}
			for code, r := range resp {
				if !statusKey.MatchString(code) {
					add("%s: %q is not a response code", where, code)
				}
				if rm, _ := r.(map[string]any); rm["$ref"] == nil {
					if d, _ := rm["description"].(string); d == "" && rm["description"] == nil {
						add("%s: response %s has no description", where, code)
					}
				}
			}
			all := append(append([]paramDecl(nil), shared...), params(op["parameters"], doc, &bad, where)...)
			declared := map[string]bool{}
			seen := map[string]bool{}
			for _, d := range all {
				if seen[d.in+":"+d.name] && !contains(shared, d) {
					add("%s: parameter %s (%s) is declared twice", where, d.name, d.in)
				}
				seen[d.in+":"+d.name] = true
				if d.in == "path" {
					declared[d.name] = true
					if !d.required {
						add("%s: path parameter %s is not required: true", where, d.name)
					}
				}
			}
			for _, m := range pathParam.FindAllStringSubmatch(p, -1) {
				if !declared[m[1]] {
					add("%s: {%s} is not declared as a path parameter", where, m[1])
				}
			}
			for n := range declared {
				if !strings.Contains(p, "{"+n+"}") {
					add("%s: path parameter %s is not in the path", where, n)
				}
			}
		}
	}
	checkRefs(doc, doc, "", &bad)
	if comps, ok := doc["components"].(map[string]any); ok {
		if ss, ok := comps["schemas"].(map[string]any); ok {
			for n, s := range ss {
				checkSchema(s, "components.schemas."+n, &bad)
			}
		}
	}
	return bad
}

type paramDecl struct {
	name, in string
	required bool
}

func contains(xs []paramDecl, d paramDecl) bool {
	for _, x := range xs {
		if x == d {
			return true
		}
	}
	return false
}

func params(v any, doc map[string]any, bad *[]string, where string) []paramDecl {
	xs, _ := v.([]any)
	var out []paramDecl
	for _, x := range xs {
		m, _ := x.(map[string]any)
		if ref, ok := m["$ref"].(string); ok {
			if r, ok := resolveRef(doc, ref); ok {
				m = r
			} else {
				continue // reported by checkRefs
			}
		}
		name, _ := m["name"].(string)
		in, _ := m["in"].(string)
		if name == "" || !paramPlace[in] {
			*bad = append(*bad, fmt.Sprintf("%s: a parameter has name %q and in %q", where, name, in))
			continue
		}
		if m["schema"] == nil && m["content"] == nil {
			*bad = append(*bad, fmt.Sprintf("%s: parameter %s has neither schema nor content", where, name))
		}
		req, _ := m["required"].(bool)
		out = append(out, paramDecl{name, in, req})
	}
	return out
}

func resolveRef(doc map[string]any, ref string) (map[string]any, bool) {
	if !strings.HasPrefix(ref, "#/") {
		return nil, false
	}
	var cur any = doc
	for _, part := range strings.Split(ref[2:], "/") {
		part = strings.NewReplacer("~1", "/", "~0", "~").Replace(part)
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		if cur, ok = m[part]; !ok {
			return nil, false
		}
	}
	m, ok := cur.(map[string]any)
	return m, ok
}

func checkRefs(doc map[string]any, v any, at string, bad *[]string) {
	switch x := v.(type) {
	case map[string]any:
		if ref, ok := x["$ref"].(string); ok {
			if _, found := resolveRef(doc, ref); !found {
				*bad = append(*bad, fmt.Sprintf("%s: $ref %s does not resolve", at, ref))
			}
		}
		for k, e := range x {
			checkRefs(doc, e, at+"/"+k, bad)
		}
	case []any:
		for i, e := range x {
			checkRefs(doc, e, fmt.Sprintf("%s/%d", at, i), bad)
		}
	}
}

func checkSchema(s any, at string, bad *[]string) {
	m, ok := s.(map[string]any)
	if !ok {
		return
	}
	if t, ok := m["type"].(string); ok {
		if !schemaType[t] {
			*bad = append(*bad, fmt.Sprintf("%s: type %q", at, t))
		}
		if t == "array" && m["items"] == nil {
			*bad = append(*bad, fmt.Sprintf("%s: an array without items", at))
		}
	}
	if props, ok := m["properties"].(map[string]any); ok {
		for n, p := range props {
			checkSchema(p, at+"."+n, bad)
		}
	}
	if it, ok := m["items"]; ok {
		checkSchema(it, at+"[]", bad)
	}
}
