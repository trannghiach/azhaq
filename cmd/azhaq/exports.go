package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/trannghiach/azhaq/engine"
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
	default:
		return fmt.Errorf("unknown -format %q (jsonl, urls, hosts, targets, openapi, burp, html)", format)
	}
	return nil
}

var placeholder = regexp.MustCompile(`\{[^}/]*\}`)

// openAPI describes the API routes found on one origin as OpenAPI 3.0, for
// tools that import a description (Burp's API scan, Postman, ZAP). What
// was seen, not a contract: operations without a known method are GET.
func openAPI(g *graphView, origin string) (map[string]any, error) {
	byOrigin := map[string][]engine.MapEntry{}
	for _, r := range g.rows {
		if r.Entity.Type != types.TypeURL || (r.Role != "api" && len(r.Methods) == 0) {
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
	rows := byOrigin[strings.TrimSuffix(origin, "/")]
	if len(rows) == 0 {
		return nil, fmt.Errorf("no API routes found%s", map[bool]string{true: " on " + origin}[origin != ""])
	}
	paths := map[string]map[string]any{}
	for _, r := range rows {
		u, _ := url.Parse(r.Entity.Key)
		p := u.Path
		if p == "" {
			p = "/"
		}
		// Path placeholders become parameters with names OpenAPI accepts.
		var params []map[string]any
		n := 0
		p = placeholder.ReplaceAllStringFunc(p, func(string) string {
			n++
			name := fmt.Sprintf("p%d", n)
			params = append(params, map[string]any{"name": name, "in": "path", "required": true, "schema": map[string]string{"type": "string"}})
			return "{" + name + "}"
		})
		query := map[string]bool{}
		for k := range u.Query() {
			query[k] = true
		}
		for _, k := range r.Params {
			query[k] = true
		}
		for _, k := range sortedKeys(query) {
			params = append(params, map[string]any{"name": k, "in": "query", "schema": map[string]string{"type": "string"}})
		}
		methods := r.Methods
		if len(methods) == 0 {
			methods = []string{"GET"}
		}
		item := paths[p]
		if item == nil {
			item = map[string]any{}
			paths[p] = item
		}
		for _, m := range methods {
			op := map[string]any{"responses": map[string]any{"default": map[string]string{"description": "not described; mapped by azhaq"}}}
			if len(params) > 0 {
				op["parameters"] = params
			}
			item[strings.ToLower(m)] = op
		}
	}
	return map[string]any{
		"openapi": "3.0.3",
		"info":    map[string]string{"title": "Routes mapped on " + origin, "version": version, "description": "Mapped by azhaq " + version + " from " + g.path + ". Seen, not a contract."},
		"servers": []map[string]string{{"url": origin}},
		"paths":   paths,
	}, nil
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
		if r.Entity.Type == types.TypeURL && (r.Role == "api" || len(r.Methods) > 0) {
			api = append(api, r)
		}
	}
	return reportTmpl.Execute(w, map[string]any{
		"Generated": time.Now().UTC().Format("2006-01-02 15:04 UTC"),
		"Path":      g.path, "Stats": g.stats, "Probe": g.probe, "Hosts": hosts, "API": api,
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
