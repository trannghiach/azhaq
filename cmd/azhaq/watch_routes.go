package main

import (
	"net/url"
	"path"
	"slices"
	"sort"
	"strings"

	"github.com/trannghiach/azhaq/engine"
	"github.com/trannghiach/azhaq/internal/webextract"
	"github.com/trannghiach/azhaq/store"
	"github.com/trannghiach/azhaq/types"
)

// routeChange is one change in an app's API surface between two runs, tied
// to the script that calls the route.
type routeChange struct {
	Kind           string   `json:"kind"` // new, methods, fields, gone
	Host           string   `json:"host,omitempty"`
	Route          string   `json:"route"`            // the path template: /api/orders/{id}
	Method         string   `json:"method,omitempty"` // fields: the method whose names changed
	MethodsAdded   []string `json:"methods_added,omitempty"`
	MethodsRemoved []string `json:"methods_removed,omitempty"`
	FieldsAdded    []string `json:"fields_added,omitempty"` // query and body names
	FieldsRemoved  []string `json:"fields_removed,omitempty"`
	Script         string   `json:"script,omitempty"` // the first script that names the route
	key            string   // host and folded path, to match URLs
}

// routeInfo is what one run knows of one route, by lower-cased method.
type routeInfo struct {
	host, route string
	methods     map[string]bool
	fields      map[string]map[string]string // method → lower-cased name → name, from operations
	script      string
	held        bool // a script or an API description names it
}

// routeTable reads the routes of the store's selected run, the way the
// exports read a map.
func routeTable(st *store.Store) (map[string]*routeInfo, map[string]bool, error) {
	ents, err := st.Entities()
	if err != nil {
		return nil, nil, err
	}
	obs, err := st.Observations()
	if err != nil {
		return nil, nil, err
	}
	edges, _ := st.Edges()
	seeds, _ := st.LoadSeeds()
	leftover, _ := st.LoadLeftover()
	stats, _ := st.Stats()
	rows := engine.BuildMap(ents, engine.ScopeSeeds(seeds, ents, edges), obs, leftover, stats.Capped)
	routes, all := routesOf(engine.GroupTemplates(rows))
	return routes, all, nil
}

// routesOf keys the API and route rows by host and path template. The
// second result holds every URL row's key, whatever the row is.
func routesOf(rows []engine.MapEntry) (map[string]*routeInfo, map[string]bool) {
	routes := map[string]*routeInfo{}
	all := map[string]bool{}
	for _, r := range rows {
		if r.Entity.Type != types.TypeURL {
			continue
		}
		key, host, route, ok := routeKey(r)
		if !ok {
			continue
		}
		all[key] = true
		scripted := false
		for _, o := range r.Ops {
			scripted = scripted || o.Source == "js-call" || o.Source == "openapi"
		}
		if r.Role != "api" && len(r.Methods) == 0 && !scripted {
			continue
		}
		ri := routes[key]
		if ri == nil {
			ri = &routeInfo{host: host, route: route, methods: map[string]bool{}, fields: map[string]map[string]string{}}
			routes[key] = ri
		}
		for _, m := range r.Methods {
			ri.methods[strings.ToUpper(m)] = true
		}
		for _, o := range r.Ops {
			if o.Source != "js-call" && o.Source != "openapi" {
				continue
			}
			m := strings.ToUpper(o.Method)
			ri.methods[m] = true
			if ri.fields[m] == nil {
				ri.fields[m] = map[string]string{}
			}
			for _, n := range append(slices.Clone(o.Query), o.Body...) {
				ri.fields[m][strings.ToLower(n)] = n
			}
		}
		if len(ri.methods) == 0 {
			ri.methods["GET"] = true // a route only fetched: a GET
		}
		if scripted || len(r.Found) > 0 {
			ri.held = true
		}
		if ri.script == "" && len(r.Found) > 0 {
			ri.script = r.Found[0].Script
		}
	}
	return routes, all
}

// routeKey is a row's identity, host and path template with placeholder
// names, the query and case folded away, and the path to show.
func routeKey(r engine.MapEntry) (key, host, route string, ok bool) {
	raw := r.Template
	if raw == "" {
		raw = r.Entity.Key
	}
	return routeKeyOf(raw)
}

func routeKeyOf(raw string) (key, host, route string, ok bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "", "", "", false
	}
	route = strings.TrimRight(u.Path, "/")
	if route == "" {
		route = "/"
	}
	segs := strings.Split(route, "/")
	for i, s := range segs {
		if strings.HasPrefix(s, "{") && strings.HasSuffix(s, "}") {
			segs[i] = "{}"
		}
	}
	host = strings.ToLower(u.Host)
	return host + strings.ToLower(strings.Join(segs, "/")), host, route, true
}

// diffRoutes compares the API surface of two runs. A route is gone only
// when a script or description held it before and no row of the newest
// run names it any more.
func diffRoutes(old, neu *store.Store) ([]routeChange, error) {
	oldR, _, err := routeTable(old)
	if err != nil {
		return nil, err
	}
	newR, newAll, err := routeTable(neu)
	if err != nil {
		return nil, err
	}
	return compareRoutes(oldR, newR, newAll), nil
}

func compareRoutes(oldR, newR map[string]*routeInfo, newAll map[string]bool) []routeChange {
	var out []routeChange
	for key, n := range newR {
		if !n.held {
			continue // found by guessing or a crawl: no deploy to tie it to, and it varies run to run
		}
		o, seen := oldR[key]
		if !seen {
			c := routeChange{key: key, Kind: "new", Host: n.host, Route: n.route, MethodsAdded: setNames(n.methods), Script: n.script}
			c.FieldsAdded = union(n, setNames(n.methods))
			out = append(out, c)
			continue
		}
		added, removed := setDiff(n.methods, o.methods), setDiff(o.methods, n.methods)
		if len(added)+len(removed) > 0 {
			c := routeChange{key: key, Kind: "methods", Host: n.host, Route: n.route, MethodsAdded: added, MethodsRemoved: removed, Script: n.script}
			c.FieldsAdded = union(n, added)
			out = append(out, c)
		}
		for m, nf := range n.fields {
			of, ok := o.fields[m]
			if !ok {
				continue // no operation to compare in the older run
			}
			add, rem := fieldDiff(nf, of), fieldDiff(of, nf)
			if len(add)+len(rem) > 0 {
				out = append(out, routeChange{key: key, Kind: "fields", Host: n.host, Route: n.route, Method: m, FieldsAdded: add, FieldsRemoved: rem, Script: n.script})
			}
		}
	}
	for key, o := range oldR {
		if _, ok := newR[key]; !ok && o.held && !newAll[key] {
			out = append(out, routeChange{key: key, Kind: "gone", Host: o.host, Route: o.route, MethodsRemoved: setNames(o.methods), Script: o.script})
		}
	}
	order := map[string]int{"new": 0, "methods": 1, "fields": 2, "gone": 3}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if order[a.Kind] != order[b.Kind] {
			return order[a.Kind] < order[b.Kind]
		}
		if a.Host != b.Host {
			return a.Host < b.Host
		}
		if a.Route != b.Route {
			return a.Route < b.Route
		}
		return a.Method < b.Method
	})
	return out
}

// union is the names the given methods send.
func union(ri *routeInfo, methods []string) []string {
	seen := map[string]string{}
	for _, m := range methods {
		for k, n := range ri.fields[m] {
			seen[k] = n
		}
	}
	var out []string
	for _, n := range seen {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

func setNames(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func setDiff(a, b map[string]bool) []string {
	var out []string
	for k := range a {
		if !b[k] {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

func fieldDiff(a, b map[string]string) []string {
	var out []string
	for k, n := range a {
		if _, ok := b[k]; !ok {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

// text is the change as one line of a notification.
func (c routeChange) text(withHost bool) string {
	route := c.Route
	if withHost {
		route = c.Host + route
	}
	fields := func(xs []string) string { return " {" + strings.Join(xs, ", ") + "}" }
	var b strings.Builder
	switch c.Kind {
	case "new":
		b.WriteString("+ " + strings.Join(c.MethodsAdded, ",") + " " + route)
		if len(c.FieldsAdded) > 0 {
			b.WriteString(fields(c.FieldsAdded))
		}
	case "methods":
		b.WriteString("~ " + route + ":")
		var parts []string
		for _, m := range c.MethodsAdded {
			parts = append(parts, "+"+m)
		}
		for _, m := range c.MethodsRemoved {
			parts = append(parts, "-"+m)
		}
		b.WriteString(" " + strings.Join(parts, " "))
		if len(c.FieldsAdded) > 0 {
			b.WriteString(fields(c.FieldsAdded))
		}
	case "fields":
		b.WriteString("~ " + c.Method + " " + route + ":")
		for _, n := range c.FieldsAdded {
			b.WriteString(" +" + n)
		}
		for _, n := range c.FieldsRemoved {
			b.WriteString(" -" + n)
		}
	case "gone":
		b.WriteString("- " + route)
	}
	if c.Script != "" {
		if u, err := url.Parse(c.Script); err == nil && path.Base(u.Path) != "." && path.Base(u.Path) != "/" {
			b.WriteString("  (" + path.Base(u.Path) + ")")
		} else {
			b.WriteString("  (" + c.Script + ")")
		}
	}
	return b.String()
}

// routeLines renders the changes, naming the host only when several
// hosts have changes.
func routeLines(rs []routeChange) []string {
	hosts := map[string]bool{}
	for _, r := range rs {
		hosts[r.Host] = true
	}
	lines := make([]string, 0, len(rs))
	for _, r := range rs {
		lines = append(lines, r.text(len(hosts) > 1))
	}
	return lines
}

// withoutRoutes drops the URLs a route change already reports.
func withoutRoutes(urls []string, rs []routeChange, kinds ...string) []string {
	if len(rs) == 0 {
		return urls
	}
	named := map[string]bool{}
	for _, r := range rs {
		if slices.Contains(kinds, r.Kind) {
			named[r.key] = true
		}
	}
	var out []string
	for _, raw := range urls {
		if key, _, _, ok := routeKeyOf(webextract.Template(raw)); ok && named[key] {
			continue
		}
		out = append(out, raw)
	}
	return out
}
