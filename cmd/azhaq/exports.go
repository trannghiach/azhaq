package main

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"html/template"
	"io"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/trannghiach/azhaq/engine"
	"github.com/trannghiach/azhaq/internal/collectors/shotcol"
	"github.com/trannghiach/azhaq/internal/webextract"
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
	g := &graphView{path: path, stats: stats, obs: obs, live: liveNames(st)}
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
	case "burp":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(burpScope(g))
	case "html":
		return htmlReport(g, w)
	case "graphml":
		return graphML(path, w)
	case "secrets":
		for _, s := range secretRows(g.obs) {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", s.Severity, s.Kind, s.Value, s.Where)
		}
	default:
		return usagef("unknown -format %q (jsonl, urls, hosts, names, targets, openapi, burp, html, graphml, secrets)", format)
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
	for _, r := range g.rows {
		if r.Entity.Type != types.TypeURL || !(isAPI(r) || len(r.Forms) > 0) {
			continue
		}
		u, err := url.Parse(r.Entity.Key)
		if err != nil {
			continue
		}
		o := u.Scheme + "://" + u.Host
		byOrigin[o] = append(byOrigin[o], r)
	}
	if origin == "" {
		for o, rs := range byOrigin {
			if len(rs) > len(byOrigin[origin]) || (len(rs) == len(byOrigin[origin]) && o < origin) {
				origin = o
			}
		}
	}
	origin = strings.TrimSuffix(origin, "/")
	rows := byOrigin[origin]
	if len(rows) == 0 {
		return nil, fmt.Errorf("no API routes found%s", map[bool]string{true: " on " + origin}[origin != ""])
	}
	doc := map[string]any{
		"openapi": "3.0.3",
		"info":    map[string]any{"title": "Routes mapped on " + origin, "version": version, "description": "Mapped by azhaq " + version + " from " + g.path + ": the target's own API description where it serves one, plus what its scripts call and its pages link to. Seen, not a contract."},
		"servers": []any{map[string]any{"url": origin}},
	}
	paths := map[string]any{}
	doc["paths"] = paths
	for _, d := range served(g.obs, origin) {
		mergeDoc(doc, paths, d)
	}
	for _, r := range rows {
		addRoute(paths, r)
	}
	for _, r := range rows {
		for _, f := range r.Forms {
			addForm(paths, origin, f)
		}
	}
	return doc, nil
}

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
				if opm, ok := op.(map[string]any); ok {
					opm["x-azhaq"] = map[string]any{"source": "served description"}
				}
				dst[m] = op
			}
		}
	}
}

// addRoute adds a mapped route's operations that the path item lacks.
func addRoute(paths map[string]any, r engine.MapEntry) {
	u, err := url.Parse(r.Entity.Key)
	if err != nil {
		return
	}
	p, pathParams := openAPIPath(u.Path)
	item, _ := paths[p].(map[string]any)
	if item == nil {
		item = map[string]any{}
	}
	ops := r.Ops
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
		if _, ok := item[m]; ok || m == "" {
			continue
		}
		var params []any
		for _, n := range pathParams {
			params = append(params, map[string]any{"name": n, "in": "path", "required": true, "schema": map[string]any{"type": "string"}})
		}
		for where, names := range map[string][]string{"query": o.Query, "header": o.Header, "cookie": o.Cookie} {
			for _, n := range names {
				params = append(params, map[string]any{"name": n, "in": where, "schema": map[string]any{"type": "string"}})
			}
		}
		sort.SliceStable(params, func(i, j int) bool {
			a, b := params[i].(map[string]any), params[j].(map[string]any)
			return a["in"].(string) > b["in"].(string) // path, query, header, cookie
		})
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
		paths[p] = item
	}
}

// addForm adds the operation an HTML form submits.
func addForm(paths map[string]any, origin string, f engine.MapForm) {
	u, err := url.Parse(f.Action)
	if err != nil || u.Scheme+"://"+u.Host != origin {
		return
	}
	method := strings.ToLower(f.Method)
	if method == "" {
		method = "get"
	}
	p, _ := openAPIPath(u.Path)
	item, _ := paths[p].(map[string]any)
	if item == nil {
		item = map[string]any{}
	}
	if _, ok := item[method]; ok {
		return
	}
	op := map[string]any{
		"operationId": operationID(engine.Op{}, method, p),
		"responses":   map[string]any{"default": map[string]any{"description": "not described; mapped by azhaq"}},
		"x-azhaq":     map[string]any{"source": "form"},
	}
	if method == "get" {
		var params []any
		for _, n := range f.Fields {
			params = append(params, map[string]any{"name": n, "in": "query", "schema": map[string]any{"type": "string"}})
		}
		if len(params) > 0 {
			op["parameters"] = params
		}
	} else {
		op["requestBody"] = requestBody(f.Fields, "application/x-www-form-urlencoded")
	}
	item[method] = op
	paths[p] = item
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

// burpScope is a Burp Suite project options file whose target scope
// includes every host with a web service in the graph.
func burpScope(g *graphView) map[string]any {
	type key struct{ proto, host, port string }
	seen := map[key]bool{}
	var include []map[string]any
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
	return map[string]any{"target": map[string]any{"scope": map[string]any{
		"advanced_mode": true, "include": include, "exclude": []any{},
	}}}
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
	return reportTmpl.Execute(w, map[string]any{
		"Generated": time.Now().UTC().Format("2006-01-02 15:04 UTC"),
		"Path":      g.path, "Stats": g.stats, "Probe": g.probe, "Hosts": hosts, "API": api, "Shots": shotGroups(g.obs), "Secrets": secretRows(g.obs),
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
