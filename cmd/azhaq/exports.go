package main

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"html/template"
	"io"
	"maps"
	"net"
	"net/url"
	"os"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/trannghiach/azhaq/engine"
	"github.com/trannghiach/azhaq/internal/collectors/shotcol"
	"github.com/trannghiach/azhaq/internal/gqlschema"
	"github.com/trannghiach/azhaq/internal/normalize"
	"github.com/trannghiach/azhaq/internal/scopefile"
	"github.com/trannghiach/azhaq/internal/webextract"
	"github.com/trannghiach/azhaq/scope"
	"github.com/trannghiach/azhaq/store"
	"github.com/trannghiach/azhaq/types"
)

// graphView is a database read once for the export formats.
type graphView struct {
	path  string
	stats store.Stats
	rows  []engine.MapEntry
	obs   []types.StoredObservation
	probe []engine.ProbeRow
	live  map[string]map[string]any
	args  []string     // the options the run was started with
	rules *scope.Rules // the run's scope as resolved when it started, if it had one
}

func readGraph(path string) (*graphView, error) {
	st, err := store.OpenExisting(path)
	if err != nil {
		return nil, err
	}
	defer st.Close()
	// A workspace exports its newest run; a one-run database is the same.
	if runs, err := st.Runs(); err == nil && len(runs) > 0 {
		st.UseRun(runs[len(runs)-1].ID)
	}
	ents, err := st.Entities()
	if err != nil {
		return nil, err
	}
	obs, err := st.Observations()
	if err != nil {
		return nil, err
	}
	edges, _ := st.Edges()
	seeds, _ := st.LoadSeeds()
	leftover, _ := st.LoadLeftover()
	stats, _ := st.Stats()
	g := &graphView{path: path, stats: stats, obs: obs, live: liveNames(st), args: st.RunArgs()}
	if raw := st.GetMeta("scope:" + st.RunID()); raw != "" {
		var r scope.Rules
		if json.Unmarshal([]byte(raw), &r) == nil {
			g.rules = &r
		}
	}
	g.rows = engine.BuildMap(ents, engine.ScopeSeeds(seeds, ents, edges), obs, leftover, stats.Capped)
	g.probe = engine.ProbeRows(obs)
	return g, nil
}

func exportAs(path, format, origin string, w io.Writer) error {
	g, err := readGraph(path)
	if err != nil {
		return err
	}
	switch format {
	case "urls":
		for _, r := range g.rows {
			if r.Entity.Type == types.TypeURL {
				fmt.Fprintln(w, r.Entity.Key)
			}
		}
	case "names":
		// Every hostname in the graph, resolved or not.
		var names []string
		for _, r := range g.rows {
			if r.Entity.Type == types.TypeHostname {
				names = append(names, r.Entity.Key)
			}
		}
		sort.Strings(names)
		for _, n := range names {
			fmt.Fprintln(w, n)
		}
	case "hosts":
		names := make([]string, 0, len(g.live))
		for n := range g.live {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			fmt.Fprintln(w, n)
		}
	case "targets":
		// Web services, one front page each: what nuclei -l and httpx take.
		seen := map[string]bool{}
		for _, r := range g.probe {
			u, err := url.Parse(r.URL)
			if err != nil || (u.Path != "/" && u.Path != "") || seen[r.URL] {
				continue
			}
			seen[r.URL] = true
			fmt.Fprintln(w, r.URL)
		}
	case "openapi":
		doc, err := openAPI(g, origin)
		if err != nil {
			return err
		}
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(doc)
	case "graphql", "sdl":
		return graphqlExport(g, format, origin, w)
	case "burp":
		var rules scope.Rules
		var err error
		if g.rules != nil {
			rules = *g.rules
		} else if rules, err = runRules(g.args, loadScope); err != nil {
			fmt.Fprintf(os.Stderr, "azhaq export: the run's scope: %v; listing the hosts it mapped instead\n", err)
		}
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(burpScope(g, rules))
	case "html":
		return htmlReport(g, w)
	case "graphml":
		return graphML(path, w)
	case "secrets":
		for _, s := range secretRows(g.obs) {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", s.Severity, s.Kind, s.Value, s.Where)
		}
	default:
		return usagef("unknown -format %q (jsonl, urls, hosts, names, targets, openapi, graphql, sdl, burp, html, graphml, secrets)", format)
	}
	return nil
}

var placeholder = regexp.MustCompile(`\{[^}/]*\}`)

// openAPI describes what was mapped on one origin as OpenAPI 3, for tools
// that import a description (Burp, Postman, ZAP, nuclei's fuzzing). A
// description the target serves itself is the base, as it is; routes it
// does not list are added from what scripts call (method, query, body
// fields), from forms and from what answered. x-azhaq on each operation
// says where it came from and how the route answered a GET.
func openAPI(g *graphView, origin string) (map[string]any, error) {
	byOrigin := map[string][]engine.MapEntry{}
	queried := map[string][]engine.MapEntry{}
	for _, r := range g.rows {
		if r.Entity.Type != types.TypeURL {
			continue
		}
		u, err := url.Parse(r.Entity.Key)
		if err != nil {
			continue
		}
		o := u.Scheme + "://" + u.Host
		switch {
		case isAPI(r) || len(r.Forms) > 0:
			byOrigin[o] = append(byOrigin[o], r)
		case takesQuery(r):
			queried[o] = append(queried[o], r)
		}
	}
	if origin == "" {
		for o, rs := range byOrigin {
			if len(rs) > len(byOrigin[origin]) || (len(rs) == len(byOrigin[origin]) && o < origin) {
				origin = o
			}
		}
	}
	origin = strings.TrimSuffix(origin, "/")
	rows := slices.Concat(byOrigin[origin], queried[origin])
	if len(rows) == 0 {
		return nil, fmt.Errorf("no API routes found%s", map[bool]string{true: " on " + origin}[origin != ""])
	}
	doc := map[string]any{
		"openapi": "3.0.3",
		"info":    map[string]any{"title": "Routes mapped on " + origin, "version": version, "description": "Mapped by azhaq " + version + " from " + g.path + ": the target's own API description where it serves one, plus what its scripts call and its pages link to. Seen, not a contract."},
		"servers": []any{map[string]any{"url": origin}},
	}
	s := &spec{paths: map[string]any{}, shapes: map[string]string{}, graphql: map[string]gqlEndpoint{}}
	for _, ep := range graphqlEndpoints(g.obs) {
		s.graphql[ep.URL] = ep
	}
	doc["paths"] = s.paths
	for _, d := range served(g.obs, origin) {
		mergeDoc(doc, s.paths, d)
	}
	for _, p := range slices.Sorted(maps.Keys(s.paths)) {
		if shape := placeholder.ReplaceAllString(p, "{}"); s.shapes[shape] == "" {
			s.shapes[shape] = p
		}
	}
	for _, r := range rows {
		s.addRoute(r)
	}
	for _, r := range rows {
		for _, f := range r.Forms {
			s.addForm(origin, f)
		}
	}
	tidy(doc)
	return doc, nil
}

// spec is the paths of a description being built. OpenAPI forbids two
// templates that differ only by their parameter names (/users/{id} and
// /users/{name}), so a route goes under the first path of its shape.
type spec struct {
	paths   map[string]any
	shapes  map[string]string // the path with {} for each parameter → the path
	graphql map[string]gqlEndpoint
}

// path is the key a URL path goes under, and its parameter names.
func (s *spec) path(raw string) (string, []string) {
	p, names := openAPIPath(raw)
	shape := placeholder.ReplaceAllString(p, "{}")
	if k, ok := s.shapes[shape]; ok {
		return k, templateNames(k)
	}
	s.shapes[shape] = p
	return p, names
}

func templateNames(p string) []string {
	var out []string
	for _, ph := range placeholder.FindAllString(p, -1) {
		out = append(out, strings.Trim(ph, "{}"))
	}
	return out
}

// opMethods are the keys of a path item that are operations.
var opMethods = []string{"get", "put", "post", "delete", "options", "head", "patch", "trace"}

// servedDoc is an OpenAPI 3 document the target serves, with the path
// its operations live under.
type servedDoc struct {
	doc    map[string]any
	prefix string
}

// served lists the OpenAPI 3 documents found on origin (Swagger 2 ones
// are described operation by operation instead).
func served(obs []types.StoredObservation, origin string) []servedDoc {
	var out []servedDoc
	for _, o := range obs {
		if o.Collector != "azhaq-openapi" || o.Kind != "api" {
			continue
		}
		var p struct {
			Base     string         `json:"base"`
			Document map[string]any `json:"document"`
		}
		if json.Unmarshal(o.Payload, &p) != nil || p.Document == nil {
			continue
		}
		v, _ := p.Document["openapi"].(string)
		b, err := url.Parse(p.Base)
		if !strings.HasPrefix(v, "3.") || err != nil || b.Scheme+"://"+b.Host != origin {
			continue
		}
		out = append(out, servedDoc{doc: p.Document, prefix: strings.TrimSuffix(b.Path, "/")})
	}
	return out
}

// mergeDoc copies a served document's operations and components in.
func mergeDoc(doc, paths map[string]any, d servedDoc) {
	if v, _ := d.doc["openapi"].(string); v != "" {
		doc["openapi"] = v
	}
	if info, ok := d.doc["info"].(map[string]any); ok {
		if t, _ := info["title"].(string); t != "" {
			doc["info"].(map[string]any)["title"] = t
		}
	}
	if sec, ok := d.doc["security"]; ok {
		doc["security"] = sec
	}
	if comps, ok := d.doc["components"].(map[string]any); ok {
		mine, _ := doc["components"].(map[string]any)
		if mine == nil {
			mine = map[string]any{}
			doc["components"] = mine
		}
		for kind, v := range comps {
			src, _ := v.(map[string]any)
			dst, _ := mine[kind].(map[string]any)
			if dst == nil {
				dst = map[string]any{}
				mine[kind] = dst
			}
			for name, x := range src {
				dst[name] = x
			}
		}
	}
	ps, _ := d.doc["paths"].(map[string]any)
	for p, v := range ps {
		item, _ := v.(map[string]any)
		key := d.prefix + "/" + strings.TrimPrefix(p, "/")
		dst, _ := paths[key].(map[string]any)
		if dst == nil {
			dst = map[string]any{}
			paths[key] = dst
		}
		for m, op := range item {
			if _, ok := dst[m]; !ok {
				if opm, ok := op.(map[string]any); ok && slices.Contains(opMethods, m) {
					opm["x-azhaq"] = map[string]any{"source": "served description"}
				}
				dst[m] = op
			}
		}
	}
}

// addRoute adds a mapped route's operations that the path item lacks. A
// GraphQL endpoint's operations are one POST (see graphqlOperation).
func (s *spec) addRoute(r engine.MapEntry) {
	u, err := url.Parse(r.Entity.Key)
	if err != nil {
		return
	}
	p, pathParams := s.path(u.Path)
	item, _ := s.paths[p].(map[string]any)
	if item == nil {
		item = map[string]any{}
	}
	var ops, gql []engine.Op
	for _, o := range r.Ops {
		if o.Source == "graphql" {
			gql = append(gql, o)
		} else {
			ops = append(ops, o)
		}
	}
	if ep, ok := s.graphql[r.Entity.Key]; ok || len(gql) > 0 {
		var sc *gqlschema.Schema
		if ok {
			sc = ep.Schema
		}
		if post, ok := item["post"].(map[string]any); ok {
			post["x-azhaq-graphql"] = graphqlExtension(sc, gql)
		} else {
			item["post"] = graphqlOperation(r, p, pathParams, sc, gql)
		}
	}
	if len(ops) == 0 {
		methods := r.Methods
		if len(methods) == 0 {
			methods = []string{"GET"}
		}
		for _, m := range methods {
			op := engine.Op{Method: m}
			if strings.EqualFold(m, "GET") {
				op.Query = r.Params
			}
			ops = append(ops, op)
		}
	}
	for k := range u.Query() {
		for i := range ops {
			if strings.EqualFold(ops[i].Method, "GET") && !slices.Contains(ops[i].Query, k) {
				ops[i].Query = append(ops[i].Query, k)
			}
		}
	}
	for _, o := range ops {
		m := strings.ToLower(o.Method)
		if !slices.Contains(opMethods, m) {
			continue
		}
		if r.Coverage == "skipped" && (m == "get" || m == "head") {
			// Left alone because a GET there changes something
			// (/setup.php?action=reset): a tool importing the description
			// would send it, nor are its names the route's.
			continue
		}
		if have, ok := item[m].(map[string]any); ok {
			// Another URL of the route (/item?id=3 after /item): the
			// names it was seen with are the route's too.
			if ours(have) {
				addQuery(have, o.Query)
			}
			continue
		}
		params := pathParameters(pathParams)
		seen := map[string]bool{}
		for _, where := range []string{"query", "header", "cookie"} {
			for _, n := range map[string][]string{"query": o.Query, "header": o.Header, "cookie": o.Cookie}[where] {
				if n == "" || seen[where+" "+n] {
					continue
				}
				seen[where+" "+n] = true
				params = append(params, map[string]any{"name": n, "in": where, "schema": map[string]any{"type": "string"}})
			}
		}
		op := map[string]any{
			"operationId": operationID(o, m, p),
			"responses":   map[string]any{"default": map[string]any{"description": "not described; mapped by azhaq"}},
		}
		if o.Summary != "" {
			op["summary"] = o.Summary
		}
		if len(params) > 0 {
			op["parameters"] = params
		}
		switch {
		case len(o.Body) > 0 || o.BodyType != "":
			op["requestBody"] = requestBody(o.Body, o.BodyType)
		case m == "post" || m == "put" || m == "patch":
			op["requestBody"] = requestBody(nil, "") // sent, fields not known
		}
		x := map[string]any{"source": source(o, r)}
		if r.Coverage != "" {
			x["coverage"] = r.Coverage
		}
		if r.Status != 0 {
			x["status"] = r.Status
		}
		if o.Auth || r.Role == "auth" {
			x["needs_credentials"] = true
		}
		op["x-azhaq"] = x
		item[m] = op
	}
	if len(item) > 0 {
		s.paths[p] = item
	}
}

func pathParameters(names []string) []any {
	var out []any
	for _, n := range names {
		out = append(out, map[string]any{"name": n, "in": "path", "required": true, "schema": map[string]any{"type": "string"}})
	}
	return out
}

// addForm adds what an HTML form submits: a GET form's fields as query
// parameters, a POST form's as its request body, urlencoded or multipart
// as its enctype says, a file input as binary. An operation the export
// made for the route already (it answered a GET, scripts call it) takes
// the fields it lacks; a served description's is left as it is.
func (s *spec) addForm(origin string, f engine.MapForm) {
	u, err := url.Parse(f.Action)
	if err != nil || u.Scheme+"://"+u.Host != origin {
		return
	}
	method := strings.ToLower(f.Method)
	if method == "" {
		method = "get"
	}
	if !slices.Contains(opMethods, method) {
		return
	}
	p, pathParams := s.path(u.Path)
	item, _ := s.paths[p].(map[string]any)
	if item == nil {
		item = map[string]any{}
	}
	op, _ := item[method].(map[string]any)
	switch {
	case op == nil:
		op = map[string]any{
			"operationId": operationID(engine.Op{}, method, p),
			"responses":   map[string]any{"default": map[string]any{"description": "not described; mapped by azhaq"}},
			"x-azhaq":     map[string]any{"source": "form"},
		}
		if params := pathParameters(pathParams); len(params) > 0 {
			op["parameters"] = params
		}
		item[method] = op
		s.paths[p] = item
	case !ours(op):
		return
	}
	if method == "get" {
		// The fields replace the action's query.
		addQuery(op, f.Fields)
		return
	}
	addQuery(op, slices.Sorted(maps.Keys(u.Query())))
	addFormBody(op, f)
}

// ours: an operation the export made, not a served description's, so
// what else was seen of the route may be added to it.
func ours(op map[string]any) bool {
	x, _ := op["x-azhaq"].(map[string]any)
	return x != nil && x["source"] != "served description"
}

// addQuery adds the query parameters op does not list yet.
func addQuery(op map[string]any, names []string) {
	params, _ := op["parameters"].([]any)
	have := map[string]bool{}
	for _, x := range params {
		if m, ok := x.(map[string]any); ok && m["in"] == "query" {
			n, _ := m["name"].(string)
			have[n] = true
		}
	}
	for _, n := range names {
		if n == "" || have[n] {
			continue
		}
		have[n] = true
		params = append(params, map[string]any{"name": n, "in": "query", "schema": map[string]any{"type": "string"}})
	}
	if len(params) > 0 {
		op["parameters"] = params
	}
}

// addFormBody gives op the body a POST form sends, or adds the form's
// fields to the one op has in the same encoding. A body whose fields were
// not known (a script's POST) becomes the form's.
func addFormBody(op map[string]any, f engine.MapForm) {
	media := f.Enctype
	if media == "" {
		media = "application/x-www-form-urlencoded"
	}
	props := map[string]any{}
	for _, n := range f.Fields {
		if n == "" {
			continue
		}
		props[n] = map[string]any{"type": "string"}
		if slices.Contains(f.Files, n) {
			props[n] = map[string]any{"type": "string", "format": "binary"}
		}
	}
	body := map[string]any{"schema": map[string]any{"type": "object", "properties": props}}
	rb, _ := op["requestBody"].(map[string]any)
	content, _ := rb["content"].(map[string]any)
	if len(content) == 0 || unknownBody(content) {
		op["requestBody"] = map[string]any{"content": map[string]any{media: body}}
		return
	}
	mt, _ := content[media].(map[string]any)
	sc, _ := mt["schema"].(map[string]any)
	have, _ := sc["properties"].(map[string]any)
	if have == nil {
		content[media] = body
		return
	}
	for n, v := range props {
		if _, ok := have[n]; !ok {
			have[n] = v
		}
	}
}

// unknownBody: the body requestBody(nil, "") stands for, sent with fields
// not known.
func unknownBody(content map[string]any) bool {
	if len(content) != 1 {
		return false
	}
	mt, _ := content["application/json"].(map[string]any)
	sc, _ := mt["schema"].(map[string]any)
	props, _ := sc["properties"].(map[string]any)
	return mt != nil && len(props) == 0
}

// takesQuery: a page found or requested with a query string of its own
// (a link to /item?id=3), which is a GET that takes those names. Not a
// link the run left alone because a GET there changes something.
func takesQuery(r engine.MapEntry) bool {
	switch r.Coverage {
	case "gone", "catchall", "skipped":
		return false
	}
	if len(r.Params) == 0 {
		return false
	}
	switch r.Role {
	case "asset", "script", "sourcemap":
		return false
	}
	return true
}

// graphqlOperation is the POST a GraphQL endpoint takes: a query and its
// variables, with the schema's operations in x-azhaq-graphql.
func graphqlOperation(r engine.MapEntry, p string, pathParams []string, sc *gqlschema.Schema, ops []engine.Op) map[string]any {
	ext := graphqlExtension(sc, ops)
	count := map[string]int{}
	for _, o := range ext["operations"].([]map[string]any) {
		count[o["type"].(string)]++
	}
	var parts []string
	for _, k := range []string{"query", "mutation", "subscription"} {
		if n := count[k]; n > 0 {
			parts = append(parts, plural(n, k))
		}
	}
	summary := "GraphQL endpoint"
	if len(parts) > 0 {
		summary += ": " + strings.Join(parts, ", ")
	}
	x := map[string]any{"source": "graphql"}
	if r.Coverage != "" {
		x["coverage"] = r.Coverage
	}
	if r.Status != 0 {
		x["status"] = r.Status
	}
	op := map[string]any{
		"operationId": operationID(engine.Op{}, "post", p),
		"summary":     summary,
		"description": "A GraphQL endpoint, not REST: one POST takes every operation. x-azhaq-graphql lists them; the whole schema is in azhaq export -format graphql (introspection JSON) and -format sdl.",
		"requestBody": map[string]any{"required": true, "content": map[string]any{"application/json": map[string]any{"schema": map[string]any{
			"type": "object", "required": []any{"query"},
			"properties": map[string]any{"query": map[string]any{"type": "string"}, "operationName": map[string]any{"type": "string"}, "variables": map[string]any{"type": "object"}},
		}}}},
		"responses":       map[string]any{"default": map[string]any{"description": "not described; mapped by azhaq"}},
		"x-azhaq":         x,
		"x-azhaq-graphql": ext,
	}
	if params := pathParameters(pathParams); len(params) > 0 {
		op["parameters"] = params
	}
	return op
}

func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	if word == "query" {
		return fmt.Sprintf("%d queries", n)
	}
	return fmt.Sprintf("%d %ss", n, word)
}

// graphqlExtension lists a GraphQL endpoint's operations: their type
// (query, mutation, subscription), name, arguments with their types and
// what they return; by name only when the schema was not kept whole.
func graphqlExtension(sc *gqlschema.Schema, ops []engine.Op) map[string]any {
	list := []map[string]any{}
	if sc != nil {
		for _, o := range sc.Operations() {
			e := map[string]any{"type": o.Kind, "name": o.Name, "returns": o.Type.String()}
			args := []map[string]any{}
			for _, a := range o.Args {
				arg := map[string]any{"name": a.Name, "type": a.Type.String()}
				if a.DefaultValue != nil {
					arg["default"] = *a.DefaultValue
				}
				args = append(args, arg)
			}
			e["arguments"] = args
			if o.Deprecated {
				e["deprecated"] = true
			}
			list = append(list, e)
		}
		return map[string]any{"operations": list}
	}
	for _, o := range ops {
		kind, _, _ := strings.Cut(o.Summary, " ")
		list = append(list, map[string]any{"type": kind, "name": o.OperationID})
	}
	return map[string]any{"operations": list}
}

// openAPIPath turns a mapped path into an OpenAPI one: every placeholder
// has a name, and a name used twice gets a number.
func openAPIPath(p string) (string, []string) {
	if p == "" {
		p = "/"
	}
	var names []string
	seen := map[string]int{}
	p = placeholder.ReplaceAllStringFunc(p, func(ph string) string {
		n := strings.Trim(ph, "{}")
		switch n {
		case "", "n", "v", "hex", "uuid":
			n = "id"
		}
		seen[n]++
		if seen[n] > 1 {
			n = fmt.Sprintf("%s%d", n, seen[n])
		}
		names = append(names, n)
		return "{" + n + "}"
	})
	return p, names
}

func requestBody(fields []string, media string) map[string]any {
	if media == "" {
		media = "application/json"
	}
	props := map[string]any{}
	for _, f := range fields {
		props[f] = map[string]any{"type": "string"}
	}
	return map[string]any{"content": map[string]any{media: map[string]any{"schema": map[string]any{"type": "object", "properties": props}}}}
}

func operationID(o engine.Op, method, p string) string {
	if o.OperationID != "" {
		return o.OperationID
	}
	var b strings.Builder
	b.WriteString(method)
	for _, part := range strings.FieldsFunc(p, func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) }) {
		b.WriteString("_" + part)
	}
	return b.String()
}

func source(o engine.Op, r engine.MapEntry) string {
	switch {
	case o.Source != "":
		return o.Source
	case r.Coverage == "visited":
		return "answered a GET"
	default:
		return "found"
	}
}

// tidy makes the description valid whatever went into it: every {name} in
// a path is a path parameter of each of its operations, a parameter is
// listed once, operationIds are unique, and component names are ones
// OpenAPI allows.
func tidy(doc map[string]any) {
	paths, _ := doc["paths"].(map[string]any)
	keys := slices.Sorted(maps.Keys(paths))
	var ops []map[string]any
	for _, p := range keys {
		item, _ := paths[p].(map[string]any)
		shared := paramKeys(doc, item["parameters"])
		for _, m := range opMethods {
			op, ok := item[m].(map[string]any)
			if !ok {
				continue
			}
			ops = append(ops, op)
			params, _ := op["parameters"].([]any)
			var kept []any
			have := map[string]bool{}
			for _, x := range params {
				k := paramKey(doc, x)
				if k != "" && have[k] {
					continue
				}
				have[k] = true
				kept = append(kept, x)
			}
			for _, n := range templateNames(p) {
				if !have["path "+n] && !shared["path "+n] {
					have["path "+n] = true
					kept = append(kept, pathParameters([]string{n})...)
				}
			}
			if len(kept) > 0 {
				op["parameters"] = kept
			}
		}
	}
	uniqueOperationIDs(ops)
	tidyComponents(doc)
}

// paramKey is "in name" of a parameter, through its $ref.
func paramKey(doc map[string]any, x any) string {
	p, _ := x.(map[string]any)
	if ref, ok := p["$ref"].(string); ok {
		name, found := strings.CutPrefix(ref, "#/components/parameters/")
		comps, _ := doc["components"].(map[string]any)
		params, _ := comps["parameters"].(map[string]any)
		if p, _ = params[name].(map[string]any); !found || p == nil {
			return ""
		}
	}
	in, _ := p["in"].(string)
	name, _ := p["name"].(string)
	if in == "" {
		return ""
	}
	return in + " " + name
}

func paramKeys(doc map[string]any, list any) map[string]bool {
	out := map[string]bool{}
	xs, _ := list.([]any)
	for _, x := range xs {
		if k := paramKey(doc, x); k != "" {
			out[k] = true
		}
	}
	return out
}

// uniqueOperationIDs renames repeated operationIds (/blog and /blog/ are
// both get_blog): a served description's operations keep theirs, then the
// first in path order does, and the others get _2, _3….
func uniqueOperationIDs(ops []map[string]any) {
	servedFirst := func(op map[string]any) bool {
		x, _ := op["x-azhaq"].(map[string]any)
		return x["source"] == "served description"
	}
	sort.SliceStable(ops, func(i, j int) bool { return servedFirst(ops[i]) && !servedFirst(ops[j]) })
	taken := map[string]bool{}
	for _, op := range ops {
		if id, _ := op["operationId"].(string); id != "" {
			taken[id] = true
		}
	}
	kept := map[string]bool{}
	for _, op := range ops {
		id, _ := op["operationId"].(string)
		if id == "" {
			continue
		}
		if !kept[id] {
			kept[id] = true
			continue
		}
		for n := 2; ; n++ {
			if c := fmt.Sprintf("%s_%d", id, n); !taken[c] {
				taken[c], kept[c] = true, true
				op["operationId"] = c
				break
			}
		}
	}
}

var componentName = regexp.MustCompile(`^[a-zA-Z0-9.\-_]+$`)

// tidyComponents renames components whose names OpenAPI does not allow
// (letters, digits, '.', '-' and '_'), and the references to them.
func tidyComponents(doc map[string]any) {
	comps, _ := doc["components"].(map[string]any)
	renamed := map[string]string{}
	for _, kind := range slices.Sorted(maps.Keys(comps)) {
		set, _ := comps[kind].(map[string]any)
		for _, name := range slices.Sorted(maps.Keys(set)) {
			if componentName.MatchString(name) {
				continue
			}
			fixed := strings.Map(func(r rune) rune {
				if r < 128 && componentName.MatchString(string(r)) {
					return r
				}
				return '_'
			}, name)
			for set[fixed] != nil {
				fixed += "_"
			}
			set[fixed] = set[name]
			delete(set, name)
			renamed["#/components/"+kind+"/"+name] = "#/components/" + kind + "/" + fixed
			// A reference may escape the name as a JSON pointer does.
			renamed["#/components/"+kind+"/"+strings.ReplaceAll(strings.ReplaceAll(name, "~", "~0"), "/", "~1")] = "#/components/" + kind + "/" + fixed
		}
	}
	if len(renamed) > 0 {
		renameRefs(doc, renamed)
	}
}

func renameRefs(v any, renamed map[string]string) {
	switch x := v.(type) {
	case map[string]any:
		for k, y := range x {
			if s, ok := y.(string); ok && k == "$ref" {
				if to, ok := renamed[s]; ok {
					x[k] = to
				}
				continue
			}
			renameRefs(y, renamed)
		}
	case []any:
		for _, y := range x {
			renameRefs(y, renamed)
		}
	}
}

// burpScope is a Burp Suite project options file whose target scope is
// the run's: the rules of its -scope and -allow included, its deny rules
// excluded, each for any protocol, port and path. A run without allow
// rules includes every host with a web service in the graph.
func burpScope(g *graphView, rules scope.Rules) map[string]any {
	include := burpEntries(rules.Allow)
	if len(rules.Allow) == 0 {
		include = observedHosts(g)
	}
	return map[string]any{"target": map[string]any{"scope": map[string]any{
		"advanced_mode": true, "include": include, "exclude": burpEntries(rules.Deny),
	}}}
}

// burpEntries turns scope rules into Burp's advanced scope entries: a
// domain matches itself and its subdomains, =host that host, an address
// itself; a range is given as Burp takes one (10.0.0.0/24).
func burpEntries(rules []string) []map[string]any {
	out := []map[string]any{}
	seen := map[string]bool{}
	for _, r := range rules {
		r = strings.TrimSpace(r)
		var host string
		switch {
		case strings.Contains(r, "/"):
			_, n, err := net.ParseCIDR(r)
			if err != nil {
				continue
			}
			if ones, bits := n.Mask.Size(); ones == bits {
				host = "^" + regexp.QuoteMeta(n.IP.String()) + "$"
			} else {
				host = n.String()
			}
		case strings.HasPrefix(r, "="):
			host = "^" + regexp.QuoteMeta(normalize.Hostname(r[1:])) + "$"
		default:
			h := normalize.Hostname(strings.TrimPrefix(r, "*."))
			if net.ParseIP(h) != nil {
				host = "^" + regexp.QuoteMeta(h) + "$"
			} else {
				host = `^(.*\.)?` + regexp.QuoteMeta(h) + "$"
			}
		}
		if host == "" || host == "^$" || host == `^(.*\.)?$` || seen[host] {
			continue
		}
		seen[host] = true
		out = append(out, map[string]any{"enabled": true, "protocol": "any", "host": host})
	}
	return out
}

// observedHosts are Burp scope entries for every web service in the graph.
func observedHosts(g *graphView) []map[string]any {
	type key struct{ proto, host, port string }
	seen := map[key]bool{}
	include := []map[string]any{}
	for _, r := range g.probe {
		u, err := url.Parse(r.URL)
		if err != nil {
			continue
		}
		port := u.Port()
		if port == "" {
			port = map[string]string{"http": "80", "https": "443"}[u.Scheme]
		}
		k := key{u.Scheme, u.Hostname(), port}
		if seen[k] {
			continue
		}
		seen[k] = true
		include = append(include, map[string]any{
			"enabled": true, "protocol": u.Scheme, "host": "^" + regexp.QuoteMeta(u.Hostname()) + "$", "port": "^" + port + "$", "file": "^/.*",
		})
	}
	return include
}

// runRules are the scope rules a run was started with, read back from its
// stored options: its -allow and -deny, and the rules of its -scope, which
// load reads (the file again, or the program's current scope from its
// platform).
func runRules(args []string, load func(spec, program string) (scopefile.Scope, error)) (scope.Rules, error) {
	var r scope.Rules
	spec, program := "", ""
	for i := 0; i < len(args); i++ {
		if !strings.HasPrefix(args[i], "-") {
			continue
		}
		name, val, inline := strings.Cut(strings.TrimLeft(args[i], "-"), "=")
		switch name {
		case "allow", "deny", "scope", "program":
		default:
			continue
		}
		if !inline {
			if i+1 >= len(args) {
				break
			}
			i++
			val = args[i]
		}
		switch name {
		case "allow":
			r.Allow = append(r.Allow, val)
		case "deny":
			r.Deny = append(r.Deny, val)
		case "scope":
			spec = val
		case "program":
			program = val
		}
	}
	if spec == "" {
		return r, nil
	}
	sc, err := load(spec, program)
	if err != nil {
		return scope.Rules{}, fmt.Errorf("-scope %s: %w", spec, err)
	}
	r.Allow = append(r.Allow, sc.Allow...)
	r.Deny = append(r.Deny, sc.Deny...)
	return r, nil
}

var reportTmpl = template.Must(template.New("report").Funcs(template.FuncMap{
	"join": func(xs []string) string { return strings.Join(xs, ", ") },
}).Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Azhaq report</title>
<style>
:root{--bg:#fff;--fg:#1a1a1a;--muted:#666;--line:#e3e3e3;--accent:#0a58ca}
@media (prefers-color-scheme: dark){:root{--bg:#141414;--fg:#e8e8e8;--muted:#999;--line:#2c2c2c;--accent:#6ea8fe}}
body{background:var(--bg);color:var(--fg);font:14px/1.45 system-ui,sans-serif;margin:0 auto;max-width:1200px;padding:24px 16px}
h1{font-size:22px;margin:0 0 4px}h2{font-size:17px;margin:32px 0 8px}.muted{color:var(--muted)}
table{border-collapse:collapse;width:100%;display:block;overflow-x:auto}th,td{border-bottom:1px solid var(--line);padding:5px 8px;text-align:left;vertical-align:top;white-space:nowrap}
td.wrap{white-space:normal;word-break:break-all}a{color:var(--accent)}code{font-size:13px}
.group{display:flex;flex-wrap:wrap;gap:12px;padding:12px 0;border-bottom:1px solid var(--line)}figure{margin:0;width:280px}
figure img{width:100%;border:1px solid var(--line)}figcaption{font-size:12px;color:var(--muted);word-break:break-all}
</style></head><body>
<h1>Azhaq report</h1>
<p class="muted">{{.Generated}} · {{.Path}} · {{.Stats.Entities}} entities, {{.Stats.Observations}} observations{{if .Stats.Capped}} · capped{{end}}</p>
{{if .Probe}}<h2>Web services ({{len .Probe}})</h2>
<table><tr><th>URL</th><th>Status</th><th>Title</th><th>Technologies</th><th>CDN</th><th>Address</th></tr>
{{range .Probe}}<tr><td class="wrap"><a href="{{.URL}}">{{.URL}}</a></td><td>{{.Status}}{{if .FinalStatus}} → {{.FinalStatus}}{{end}}</td><td class="wrap">{{.Title}}</td><td class="wrap">{{join .Tech}}</td><td>{{.CDN}}</td><td>{{.IP}}</td></tr>
{{end}}</table>{{end}}
{{if .Hosts}}<h2>Hostnames that resolve ({{len .Hosts}})</h2>
<table><tr><th>Name</th><th>Addresses</th><th>CDN</th></tr>
{{range .Hosts}}<tr><td>{{.Name}}</td><td class="wrap">{{join .IPs}}</td><td>{{.CDN}}</td></tr>
{{end}}</table>{{end}}
{{if .Shots}}<h2>Screenshots ({{len .Shots}} groups)</h2>
{{range .Shots}}<div class="group">{{range .}}<figure><a href="{{.File}}"><img src="{{.File}}" alt="{{.URL}}" loading="lazy"></a><figcaption>{{.URL}}{{if .Title}} · {{.Title}}{{end}}</figcaption></figure>{{end}}</div>
{{end}}{{end}}
{{if .Secrets}}<h2>Secrets in scripts ({{len .Secrets}})</h2>
<table><tr><th>Severity</th><th>Kind</th><th>Value</th><th>Where</th></tr>
{{range .Secrets}}<tr><td>{{.Severity}}</td><td>{{.Kind}}</td><td><code>{{.Redacted}}</code></td><td class="wrap">{{.Where}}</td></tr>
{{end}}</table><p class="muted">Values are shortened here; azhaq export -format secrets prints them whole.</p>{{end}}
{{if .API}}<h2>API routes ({{len .API}})</h2>
<table><tr><th>Route</th><th>Methods</th><th>Parameters</th><th>Seen</th></tr>
{{range .API}}<tr><td class="wrap"><code>{{.Entity.Key}}</code></td><td>{{join .Methods}}</td><td class="wrap">{{join .Params}}</td><td>{{.Coverage}}</td></tr>
{{end}}</table>{{end}}
<h2>Map ({{len .Map}} rows)</h2>
<table><tr><th>Entity</th><th>Scope</th><th>Seen</th><th>Role</th><th>Facts</th></tr>
{{range .Map}}<tr><td class="wrap">{{.Entity.Type}} <code>{{.Entity.Key}}</code>{{if .Count}} ({{.Count}}){{end}}</td><td>{{.Scope}}</td><td>{{.Coverage}}</td><td>{{.Role}}</td><td class="wrap">{{.Proof}}</td></tr>
{{end}}</table>
</body></html>
`))

type reportHost struct {
	Name string
	IPs  []string
	CDN  string
}

func htmlReport(g *graphView, w io.Writer) error {
	var hosts []reportHost
	for name, p := range g.live {
		h := reportHost{Name: name}
		for _, ip := range p["ips"].([]any) {
			h.IPs = append(h.IPs, fmt.Sprint(ip))
		}
		h.CDN, _ = p["cdn"].(string)
		hosts = append(hosts, h)
	}
	sort.Slice(hosts, func(i, j int) bool { return hosts[i].Name < hosts[j].Name })
	var api []engine.MapEntry
	for _, r := range g.rows {
		if r.Entity.Type == types.TypeURL && isAPI(r) {
			api = append(api, r)
		}
	}
	// A web service is a front page; the other pages are in the map.
	var services []engine.ProbeRow
	for _, p := range g.probe {
		if isFront(p.URL) {
			services = append(services, p)
		}
	}
	return reportTmpl.Execute(w, map[string]any{
		"Generated": time.Now().UTC().Format("2006-01-02 15:04 UTC"),
		"Path":      g.path, "Stats": g.stats, "Probe": services, "Hosts": hosts, "API": api, "Shots": shotGroups(g.obs), "Secrets": secretRows(g.obs),
		"Map": engine.GroupTemplates(g.rows),
	})
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// graphML writes the graph for Gephi, yEd or Cytoscape: entities are
// nodes with their type and first sighting, relations are edges.
func graphML(path string, w io.Writer) error {
	st, err := store.OpenExisting(path)
	if err != nil {
		return err
	}
	defer st.Close()
	if runs, err := st.Runs(); err == nil && len(runs) > 0 {
		st.UseRun(runs[len(runs)-1].ID)
	}
	ents, err := st.Entities()
	if err != nil {
		return err
	}
	edges, err := st.Edges()
	if err != nil {
		return err
	}
	esc := func(s string) string {
		var b strings.Builder
		_ = xml.EscapeText(&b, []byte(s))
		return b.String()
	}
	fmt.Fprint(w, `<?xml version="1.0" encoding="UTF-8"?>
<graphml xmlns="http://graphml.graphdrawing.org/xmlns">
  <key id="type" for="node" attr.name="type" attr.type="string"/>
  <key id="label" for="node" attr.name="label" attr.type="string"/>
  <key id="first_seen" for="node" attr.name="first_seen" attr.type="string"/>
  <key id="rel" for="edge" attr.name="type" attr.type="string"/>
  <graph id="azhaq" edgedefault="directed">
`)
	known := map[string]bool{}
	for _, e := range ents {
		known[e.ID] = true
		fmt.Fprintf(w, "    <node id=\"%s\"><data key=\"type\">%s</data><data key=\"label\">%s</data><data key=\"first_seen\">%s</data></node>\n",
			esc(e.ID), esc(string(e.Type)), esc(e.Key), e.FirstSeen.UTC().Format(time.RFC3339))
	}
	for i, e := range edges {
		if !known[e.From] || !known[e.To] {
			continue
		}
		fmt.Fprintf(w, "    <edge id=\"e%d\" source=\"%s\" target=\"%s\"><data key=\"rel\">%s</data></edge>\n", i, esc(e.From), esc(e.To), esc(e.Type))
	}
	_, err = fmt.Fprint(w, "  </graph>\n</graphml>\n")
	return err
}

// isAPI: a route the map calls an API, one with methods from a
// description, or one whose path says so even when it answered 401 or 403
// (the map shows those as auth or forbidden).
func isAPI(r engine.MapEntry) bool {
	return r.Role == "api" || len(r.Methods) > 0 || webextract.ClassifyURL(r.Entity.Key) == "api"
}

type reportShot struct{ URL, File, Title, Hash string }

// shotGroups puts screenshots that look alike (perceptual hashes at most 8
// bits apart) together, largest group first: a login portal deployed on
// thirty hosts is one row.
func shotGroups(obs []types.StoredObservation) [][]reportShot {
	var shots []reportShot
	for _, o := range obs {
		if o.Collector != "azhaq-shots" || o.Kind != "screenshot" {
			continue
		}
		var p struct{ URL, File, Title, Phash string }
		if json.Unmarshal(o.Payload, &p) == nil && p.File != "" {
			shots = append(shots, reportShot{p.URL, p.File, p.Title, p.Phash})
		}
	}
	var groups [][]reportShot
	for _, s := range shots {
		placed := false
		for i, g := range groups {
			if s.Hash != "" && shotcol.Distance(s.Hash, g[0].Hash) <= 8 {
				groups[i] = append(groups[i], s)
				placed = true
				break
			}
		}
		if !placed {
			groups = append(groups, []reportShot{s})
		}
	}
	sort.SliceStable(groups, func(i, j int) bool { return len(groups[i]) > len(groups[j]) })
	return groups
}

type secretRow struct{ Severity, Kind, Value, Redacted, Where string }

// secretRows lists the credentials the scripts carried, worst first, each
// value once.
func secretRows(obs []types.StoredObservation) []secretRow {
	var out []secretRow
	seen := map[string]bool{}
	for _, o := range obs {
		if o.Kind != "secrets" {
			continue
		}
		var p struct {
			Secrets []struct{ Kind, Severity, Value, Script string }
		}
		if json.Unmarshal(o.Payload, &p) != nil {
			continue
		}
		for _, s := range p.Secrets {
			if !seen[s.Value] {
				seen[s.Value] = true
				out = append(out, secretRow{s.Severity, s.Kind, s.Value, webextract.Redact(s.Value), s.Script})
			}
		}
	}
	order := map[string]int{"high": 0, "medium": 1, "info": 2}
	sort.SliceStable(out, func(i, j int) bool { return order[out[i].Severity] < order[out[j].Severity] })
	return out
}
