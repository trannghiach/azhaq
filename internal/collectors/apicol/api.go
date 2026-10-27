// Package apicol reads OpenAPI 3 and Swagger 2 documents and maps the
// operations they declare. Of those it asks only the GETs that need no
// parameter, and the run leaves out the ones whose names say they do
// something (VAmPI's GET /createdb resets its database). A Swagger UI page
// that builds its document's URL at run time is read for the names of
// the documents it may load.
package apicol

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/trannghiach/azhaq/catalog"
	"github.com/trannghiach/azhaq/internal/fetch"
	"github.com/trannghiach/azhaq/internal/neterr"
	"github.com/trannghiach/azhaq/internal/normalize"
	"github.com/trannghiach/azhaq/types"
)

const Name = "azhaq-openapi"

const maxOps = 512

var methods = []string{"get", "put", "post", "delete", "options", "head", "patch", "trace"}

type Collector struct {
	Client *http.Client
}

func New(client *http.Client) *Collector {
	return &Collector{Client: fetch.Client(client)}
}

func Register(cat *catalog.Catalog, client *http.Client) {
	cat.MustRegister(New(client))
}

func (c *Collector) Name() string { return Name }

// Info: this collector sends requests to the target.
func (c *Collector) Info() catalog.Info {
	return catalog.Info{Kind: catalog.Touch, After: "azhaq-http"}
}

func (c *Collector) Inputs() []types.SeedType { return []types.SeedType{types.TypeURL} }

func (c *Collector) Outputs() []string { return []string{"api", "url"} }

// Skip declines URLs that cannot be an API description.
func (c *Collector) Skip(seed types.Seed) bool {
	u, err := url.Parse(seed.Keys["url"])
	if err != nil {
		return true
	}
	return !specLike(u.Path)
}

func specLike(p string) bool {
	p = strings.ToLower(p)
	for _, s := range []string{".json", ".yaml", ".yml"} {
		if strings.HasSuffix(p, s) {
			return true
		}
	}
	for _, s := range []string{"openapi", "swagger", "api-docs", "apispec"} {
		if strings.Contains(p, s) {
			return true
		}
	}
	return false
}

type doc struct {
	OpenAPI  string                          `json:"openapi" yaml:"openapi"`
	Security []map[string]any                `json:"security" yaml:"security"`
	Swagger  string                          `json:"swagger" yaml:"swagger"`
	Info     struct{ Title, Version string } `json:"info" yaml:"info"`
	Servers  []struct{ URL string }          `json:"servers" yaml:"servers"`
	Host     string                          `json:"host" yaml:"host"`
	BasePath string                          `json:"basePath" yaml:"basePath"`
	Paths    map[string]map[string]any       `json:"paths" yaml:"paths"`
	Comps    struct {
		Schemas       map[string]any `json:"schemas" yaml:"schemas"`
		Parameters    map[string]any `json:"parameters" yaml:"parameters"`
		RequestBodies map[string]any `json:"requestBodies" yaml:"requestBodies"`
	} `json:"components" yaml:"components"`
	Defs   map[string]any `json:"definitions" yaml:"definitions"`
	Params map[string]any `json:"parameters" yaml:"parameters"`
}

func (c *Collector) Run(ctx context.Context, seed types.Seed, emit func(types.Observation) error) (types.RunMeta, error) {
	raw, err := normalize.URL(seed.Keys["url"])
	if err != nil {
		return types.RunMeta{Status: types.StatusError, Error: err.Error()}, err
	}
	res, _, err := fetch.Do(ctx, c.Client, raw)
	if err != nil {
		if neterr.Quiet(err) {
			return types.RunMeta{Status: types.StatusOK}, nil
		}
		return types.RunMeta{Status: types.StatusError, Error: err.Error()}, err
	}
	meta := types.RunMeta{Status: types.StatusOK}
	if res.Status != http.StatusOK {
		return meta, nil
	}
	d, ok := parse(res.Body)
	if !ok {
		return c.swaggerUI(ctx, raw, res, emit)
	}
	final := res.URL
	if final == "" {
		final = raw
	}
	base := apiBase(final, d)
	now := time.Now().UTC()

	paths := make([]string, 0, len(d.Paths))
	for p := range d.Paths {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	version := d.OpenAPI
	if version == "" {
		version = "swagger " + d.Swagger
	}
	row := map[string]any{"url": raw, "spec": version, "title": d.Info.Title, "count": len(paths), "base": base}
	if len(res.Body) <= maxDocument && !res.Truncated {
		// Kept whole, so an export can hand the original on.
		var whole any
		if json.Unmarshal(res.Body, &whole) == nil {
			row["document"] = whole
		} else if yaml.Unmarshal(res.Body, &whole) == nil {
			row["document"] = whole
		}
	}
	summary, _ := json.Marshal(row)
	if err := emit(types.Observation{
		Collector: Name, Source: raw, Kind: "api",
		Payload: summary, Confidence: 0.9, ObservedAt: now,
	}); err != nil {
		return meta, err
	}
	meta.EmitCount++

	for _, p := range paths {
		if meta.EmitCount > maxOps {
			break
		}
		item := d.Paths[p]
		var ms, params []string
		var ops []map[string]any
		shared := paramsIn(item["parameters"], d)
		for _, m := range methods {
			op, ok := item[m].(map[string]any)
			if !ok {
				continue
			}
			ms = append(ms, strings.ToUpper(m))
			in := merge(shared, paramsIn(op["parameters"], d))
			x := map[string]any{"method": strings.ToUpper(m)}
			for _, where := range []string{"query", "path", "header", "cookie"} {
				if len(in[where]) > 0 {
					x[where] = in[where]
					if where == "query" || where == "path" {
						for _, n := range in[where] {
							params = addName(params, n)
						}
					}
				}
			}
			if names, media := bodyOf(op, d); media != "" {
				x["body"], x["body_type"] = names, media
				for _, n := range names {
					params = addName(params, n)
				}
			}
			if len(in["formData"]) > 0 { // Swagger 2 forms
				x["body"], x["body_type"] = in["formData"], "application/x-www-form-urlencoded"
			}
			if secured(op, d) {
				x["auth"] = true
			}
			if s, _ := op["summary"].(string); s != "" {
				x["summary"] = s
			}
			if id, _ := op["operationId"].(string); id != "" {
				x["operation_id"] = id
			}
			ops = append(ops, x)
			if m == "get" && len(in["path"]) == 0 && len(requiredQuery(item, op, d)) == 0 {
				// A read that needs nothing: asked, to see who may read it. One
				// whose name says it does something (/createdb) is handed on too:
				// the run lists it as skipped, with the word, like a link.
				if u, err := normalize.URL(strings.TrimSuffix(base, "/") + "/" + strings.TrimPrefix(p, "/")); err == nil && !strings.Contains(u, "{") {
					meta.NextHints = append(meta.NextHints, types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": u}})
				}
			}
		}
		if len(ms) == 0 {
			continue
		}
		target, err := normalize.URL(strings.TrimSuffix(base, "/") + "/" + strings.TrimPrefix(p, "/"))
		if err != nil {
			continue
		}
		row := map[string]any{"url": target, "via": "openapi", "methods": ms, "role": "api", "ops": ops, "path": p}
		if len(params) > 0 {
			row["params"] = params
		}
		payload, _ := json.Marshal(row)
		if err := emit(types.Observation{
			Collector: Name, Source: raw, Kind: "url",
			Payload: payload, Confidence: 0.9, ObservedAt: now,
		}); err != nil {
			return meta, err
		}
		meta.EmitCount++
	}
	return meta, nil
}

func parse(body []byte) (doc, bool) {
	var d doc
	trimmed := strings.TrimSpace(string(body))
	if strings.HasPrefix(trimmed, "{") {
		if json.Unmarshal(body, &d) != nil {
			return d, false
		}
	} else if obj := embedded(trimmed); obj != "" {
		if json.Unmarshal([]byte(obj), &d) != nil {
			return d, false
		}
	} else if strings.HasPrefix(trimmed, "<") || yaml.Unmarshal(body, &d) != nil {
		return d, false
	}
	if d.OpenAPI == "" && d.Swagger == "" {
		return d, false
	}
	return d, len(d.Paths) > 0
}

// apiBase is where the operations live. A server on another host (often
// localhost in a spec copied from development) keeps only its path, on
// the origin that served the document.
func apiBase(specURL string, d doc) string {
	su, err := url.Parse(specURL)
	if err != nil {
		return specURL
	}
	origin := su.Scheme + "://" + su.Host
	prefix := ""
	switch {
	case len(d.Servers) > 0 && d.Servers[0].URL != "":
		if u, err := url.Parse(d.Servers[0].URL); err == nil {
			if u.Host != "" && strings.EqualFold(u.Host, su.Host) && (u.Scheme == "http" || u.Scheme == "https") {
				origin = u.Scheme + "://" + u.Host
			}
			prefix = u.Path
		}
	case d.BasePath != "":
		prefix = d.BasePath
	}
	if strings.Contains(prefix, "{") {
		prefix = "" // server variables: unknown at map time
	}
	return origin + "/" + strings.Trim(prefix, "/")
}

// maxDocument caps the size of a document kept whole for exports.
const maxDocument = 2 << 20

// paramsIn sorts a parameter list by where each goes: query, path,
// header, cookie, and Swagger 2's body and formData.
func paramsIn(v any, d doc) map[string][]string {
	out := map[string][]string{}
	list, _ := v.([]any)
	for _, x := range list {
		m, _ := x.(map[string]any)
		if ref, _ := m["$ref"].(string); ref != "" {
			m, _ = resolveRef(ref, d).(map[string]any)
		}
		name, _ := m["name"].(string)
		in, _ := m["in"].(string)
		if name == "" || in == "" {
			continue
		}
		if in == "body" { // Swagger 2: the body's fields are in its schema
			schema, _ := m["schema"].(map[string]any)
			out["body"] = append(out["body"], fieldNames(schema, d)...)
			continue
		}
		out[in] = addName(out[in], name)
	}
	return out
}

func merge(a, b map[string][]string) map[string][]string {
	out := map[string][]string{}
	for _, m := range []map[string][]string{a, b} {
		for k, v := range m {
			for _, n := range v {
				out[k] = addName(out[k], n)
			}
		}
	}
	return out
}

// requiredQuery lists the query parameters an operation cannot go without.
func requiredQuery(item, op map[string]any, d doc) []string {
	var out []string
	for _, v := range []any{item["parameters"], op["parameters"]} {
		list, _ := v.([]any)
		for _, x := range list {
			m, _ := x.(map[string]any)
			if ref, _ := m["$ref"].(string); ref != "" {
				m, _ = resolveRef(ref, d).(map[string]any)
			}
			// A required header (a token) is what the request is sent
			// to find out about; a required query value would be made up.
			if req, _ := m["required"].(bool); req && m["in"] == "query" {
				if name, _ := m["name"].(string); name != "" {
					out = append(out, name)
				}
			}
		}
	}
	return out
}

// bodyOf is the field names and media type of an operation's body: an
// OpenAPI 3 requestBody, or a Swagger 2 body parameter.
func bodyOf(op map[string]any, d doc) ([]string, string) {
	body, _ := op["requestBody"].(map[string]any)
	if ref, _ := body["$ref"].(string); ref != "" {
		body, _ = resolveRef(ref, d).(map[string]any)
	}
	content, _ := body["content"].(map[string]any)
	types := make([]string, 0, len(content))
	for t := range content {
		types = append(types, t)
	}
	sort.Strings(types)
	for _, t := range types { // JSON first when there is a choice
		if strings.Contains(t, "json") {
			types = append([]string{t}, types...)
			break
		}
	}
	for _, t := range types {
		m, _ := content[t].(map[string]any)
		schema, _ := m["schema"].(map[string]any)
		return fieldNames(schema, d), t
	}
	if in := paramsIn(op["parameters"], d)["body"]; len(in) > 0 {
		return in, "application/json"
	}
	return nil, ""
}

// fieldNames are the properties of a schema, through one $ref.
func fieldNames(schema map[string]any, d doc) []string {
	if ref, _ := schema["$ref"].(string); ref != "" {
		schema, _ = resolveRef(ref, d).(map[string]any)
	}
	props, _ := schema["properties"].(map[string]any)
	names := make([]string, 0, len(props))
	for name := range props {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// secured: the operation, or the document for every operation, asks for
// credentials.
func secured(op map[string]any, d doc) bool {
	if sec, ok := op["security"].([]any); ok {
		for _, s := range sec {
			if m, _ := s.(map[string]any); len(m) > 0 {
				return true
			}
		}
		return false // security: [] opts out
	}
	return len(d.Security) > 0
}

func resolveRef(ref string, d doc) any {
	switch {
	case strings.HasPrefix(ref, "#/components/schemas/"):
		return d.Comps.Schemas[strings.TrimPrefix(ref, "#/components/schemas/")]
	case strings.HasPrefix(ref, "#/components/parameters/"):
		return d.Comps.Parameters[strings.TrimPrefix(ref, "#/components/parameters/")]
	case strings.HasPrefix(ref, "#/components/requestBodies/"):
		return d.Comps.RequestBodies[strings.TrimPrefix(ref, "#/components/requestBodies/")]
	case strings.HasPrefix(ref, "#/definitions/"):
		return d.Defs[strings.TrimPrefix(ref, "#/definitions/")]
	case strings.HasPrefix(ref, "#/parameters/"):
		return d.Params[strings.TrimPrefix(ref, "#/parameters/")]
	}
	return nil
}

var (
	// specName: a document a Swagger UI page may load, as a string in it.
	specName  = regexp.MustCompile(`["'\x60]([\w./-]*\.(?:json|ya?ml))["'\x60]`)
	swaggerUI = regexp.MustCompile(`(?i)swagger-?ui|SwaggerUIBundle|redoc`)
)

// siblings are where a description usually sits next to its UI.
var siblings = []string{"swagger.json", "openapi.json", "swagger.yaml", "openapi.yaml", "v1/swagger.json", "v2/swagger.json", "api-docs"}

// swaggerUI reads a Swagger UI or ReDoc page that was not a description
// itself for the documents it may load: names in the page and its
// initializer script, and the usual names next to it.
func (c *Collector) swaggerUI(ctx context.Context, raw string, res fetch.Result, emit func(types.Observation) error) (types.RunMeta, error) {
	meta := types.RunMeta{Status: types.StatusOK}
	body := string(res.Body)
	if !swaggerUI.MatchString(body) {
		return meta, nil
	}
	base, err := url.Parse(raw)
	if err != nil {
		return meta, nil
	}
	texts := []string{body}
	for _, m := range regexp.MustCompile(`src=["']([^"']*(?:swagger-initializer|swagger-ui-init|initializer)[^"']*\.js)["']`).FindAllStringSubmatch(body, -1) {
		if u, err := base.Parse(m[1]); err == nil && u.Host == base.Host {
			if r, _, err := fetch.Do(ctx, c.Client, u.String()); err == nil && r.Status == http.StatusOK {
				texts = append(texts, string(r.Body))
			}
		}
	}
	seen := map[string]bool{}
	var found []string
	add := func(ref string) {
		u, err := base.Parse(ref)
		if err != nil || u.Host != base.Host {
			return
		}
		if n, err := normalize.URL(u.String()); err == nil && !seen[n] && n != raw {
			seen[n] = true
			found = append(found, n)
		}
	}
	for _, t := range texts {
		for _, m := range specName.FindAllStringSubmatch(t, -1) {
			if !strings.Contains(m[1], "package") {
				add(m[1])
			}
		}
	}
	for _, s := range siblings {
		add(s)
	}
	// Only what turns out to be a description is handed on: a guess that
	// answers 404 is not part of the map.
	var specs []string
	for _, u := range found {
		r, _, err := fetch.Do(ctx, c.Client, u)
		if err != nil || r.Status != http.StatusOK {
			continue
		}
		if _, ok := parse(r.Body); ok {
			specs = append(specs, u)
			meta.NextHints = append(meta.NextHints, types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": u}})
		}
	}
	payload, _ := json.Marshal(map[string]any{"url": raw, "via": "openapi", "ui": true, "tried": len(found), "documents": specs})
	if err := emit(types.Observation{Collector: Name, Source: raw, Kind: "api-ui", Payload: payload, Confidence: 0.6, ObservedAt: time.Now().UTC()}); err != nil {
		return meta, err
	}
	meta.EmitCount++
	return meta, nil
}

func addName(xs []string, n string) []string {
	for _, x := range xs {
		if x == n {
			return xs
		}
	}
	return append(xs, n)
}

// embedded finds a description written into a script, as Swagger UI's
// swagger-ui-init.js does with "swaggerDoc": {...}, or into an HTML page.
// It returns the JSON object or "".
func embedded(src string) string {
	for _, key := range []string{`"swaggerDoc"`, `swaggerDoc`, `"spec"`, `spec`} {
		for from := 0; ; {
			i := strings.Index(src[from:], key)
			if i < 0 {
				break
			}
			i += from + len(key)
			from = i
			rest := strings.TrimLeft(src[i:], " \t\r\n")
			if !strings.HasPrefix(rest, ":") {
				continue
			}
			rest = strings.TrimLeft(rest[1:], " \t\r\n")
			if obj := jsonObject(rest); obj != "" && (strings.Contains(obj, `"openapi"`) || strings.Contains(obj, `"swagger"`)) {
				return obj
			}
		}
	}
	return ""
}

// jsonObject returns the balanced {...} that s starts with, or "".
func jsonObject(s string) string {
	if !strings.HasPrefix(s, "{") {
		return ""
	}
	depth, inStr, esc := 0, false, false
	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch {
		case esc:
			esc = false
		case inStr && ch == '\\':
			esc = true
		case ch == '"':
			inStr = !inStr
		case inStr:
		case ch == '{':
			depth++
		case ch == '}':
			depth--
			if depth == 0 {
				return s[:i+1]
			}
		}
	}
	return ""
}
