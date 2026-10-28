package webextract

import (
	"regexp"
	"sort"
	"strings"
)

// ClientRoute is a view a single-page app's router draws: a URL the
// browser shows, not a request the server answers. Routers keep them in
// tables that bundles carry as written:
//
//	{path:`administration`,component:Su,canActivate:[cs]}           (Angular)
//	{path:"/admin",element:(0,r.jsx)(RequireAuth,{children:…})}      (React Router)
//	{path:"/admin",component:Admin,meta:{requiresAuth:!0}}           (Vue Router)
//	<Route path="admin" element={<RequireAuth><Admin/></RequireAuth>}/>
type ClientRoute struct {
	Path       string // from the app's root, parameters as {name}: /order-completion/{id}
	Guard      string // what must let the browser in: canActivate, meta.requiresAuth, RequireAuth; "" for none
	Start, End int    // where the route's path is written
}

const (
	// maxClientRoutes caps the routes read from one script.
	maxClientRoutes = 500
	// maxRouteObjects caps the path: values whose object is read for one
	// script; maxOpenObjects the ones that never close, each a 64 KiB
	// scan: a one-line bundle of them is no route table.
	maxRouteObjects = 5000
	maxOpenObjects  = 64
)

var (
	// routePath is a path key with a literal value, as route objects have.
	routePath = regexp.MustCompile(`(?:^|[{,\s])["']?path["']?\s*:\s*["'\x60]`)
	// jsxRoute is a <Route> element or a wrapper named for one
	// (<PrivateRoute>), opening or closing.
	jsxRoute = regexp.MustCompile(`<(/?)([A-Z][\w.]*)?Route\b`)
	jsxPath  = regexp.MustCompile(`\bpath\s*=\s*(?:"([^"]*)"|'([^']*)'|\{\s*["'\x60]([^"'\x60$]*)["'\x60]\s*\})`)
	jsxElem  = regexp.MustCompile(`\belement\s*=\s*\{\s*<([A-Z][\w.]*)`)
	// firstComponent is what an element renders first: jsx(RequireAuth,…),
	// createElement(PrivateRoute,…) or <RequireAuth>.
	firstComponent = regexp.MustCompile(`^(?:\(\s*0\s*,\s*)?[\w$.]*(?:jsxs?|jsxDEV|createElement)\)?\s*\(\s*([A-Za-z_$][\w$.]*)|^<([A-Z][\w.]*)`)
	wrapperBefore  = regexp.MustCompile(`([A-Za-z_$][\w$]*)\s*,\s*$`)
	// guardComponent names a component that stands before a view:
	// RequireAuth, PrivateRoute, ProtectedRoute, AuthGuard, WithAuth.
	guardComponent = regexp.MustCompile(`(?i)^(?:require|private|protected|auth|guard|secure)|(?:auth|guard|private|protected|secured?)(?:route|wrapper|layout)?$`)
	// guardMeta names a route meta key that asks for a session or a role.
	guardMeta = regexp.MustCompile(`(?i)auth|login|admin|role|permission|guard|private|protect|secure|access`)
	// guardName is a guard worth naming: not a minified identifier.
	guardName = regexp.MustCompile(`\b([A-Z][\w$]{3,}|[a-z][\w$]*Guard)\b`)
	routeSeg  = regexp.MustCompile(`^[\w.~@$%+-]+$`)
	// hashRouting: the app keeps its routes after # (/#/administration).
	// React Router's own HashRouter calls createHashHistory, so that name
	// says nothing of the app.
	hashRouting = regexp.MustCompile(`useHash\s*:\s*(?:!0|true)\b|<HashRouter\b|[.(]\s*HashRouter\s*,\s*\{|\bmode\s*:\s*["'\x60]hash["'\x60]|\b(?:withHashLocation|createWebHashHistory|createHashRouter)\s*\(`)
)

// viewKeys make an object with a path a route: it draws something, holds
// routes, or loads them. A cookie's or a socket's options have a path too.
var viewKeys = []string{"component", "components", "loadComponent", "loadChildren", "children", "element", "Component", "lazy", "render"}

// drawsView says whether a route-like object draws something: a view key
// whose value is code or routes, not a string or a number.
func drawsView(props []prop) bool {
	for _, p := range props {
		for _, k := range viewKeys {
			if p.key != k {
				continue
			}
			v := strings.TrimSpace(p.val)
			if v != "" && !strings.ContainsRune("\"'`0123456789", rune(v[0])) {
				return true
			}
		}
	}
	return false
}

// guardKeys are Angular's guards, in the order they are named.
var guardKeys = []string{"canActivate", "canMatch", "canLoad", "canActivateChild"}

type routeObj struct {
	start, end  int // the object
	at, atEnd   int // its path value
	path, guard string
}

// ClientRoutes reads the route tables of Angular, React Router and Vue
// Router in a script: nested routes joined to their parents', a parent's
// guard applying to its children. Catch-alls (**, *) and the root are
// left out.
func ClientRoutes(script string) []ClientRoute {
	var objs []routeObj
	seen := map[int]bool{}
	read, unclosed := 0, 0
	for _, m := range routePath.FindAllStringIndex(script, -1) {
		if len(objs) >= maxClientRoutes || read >= maxRouteObjects || unclosed >= maxOpenObjects {
			break
		}
		q := m[1] - 1
		val, vend, ok := literalAt(script, q)
		if !ok || !routeLike(val) {
			continue
		}
		k := m[0] + strings.Index(script[m[0]:m[1]], "path")
		if k > 0 && (script[k-1] == '"' || script[k-1] == '\'') {
			k--
		}
		open := openBrace(script, k)
		if open < 0 || seen[open] {
			continue
		}
		read++
		obj := balanced(script[open:])
		if obj == "" {
			unclosed++
			continue
		}
		props := objectProps(obj)
		if !drawsView(props) {
			continue
		}
		seen[open] = true
		o := routeObj{start: open, end: open + len(obj), at: q, atEnd: vend, path: val}
		o.guard = routeGuard(props)
		if o.guard == "" {
			if w := wrapperBefore.FindStringSubmatch(script[max(0, open-80):open]); w != nil && w[1] != "Route" && strings.HasSuffix(w[1], "Route") && guardComponent.MatchString(w[1]) {
				o.guard = w[1] // jsx(PrivateRoute,{path:…})
			}
		}
		objs = append(objs, o)
	}
	sort.Slice(objs, func(i, j int) bool { return objs[i].start < objs[j].start })
	var out []ClientRoute
	index := map[string]int{}
	add := func(p, guard string, at, end int) {
		if p == "/" || len(out) >= maxClientRoutes {
			return
		}
		if i, ok := index[p]; ok {
			if out[i].Guard == "" {
				out[i].Guard = guard
			}
			return
		}
		index[p] = len(out)
		out = append(out, ClientRoute{Path: p, Guard: guard, Start: at, End: end})
	}
	var stack []int // the routes around the one at hand, innermost last
	for i := range objs {
		o := &objs[i]
		for len(stack) > 0 && objs[stack[len(stack)-1]].end <= o.start {
			stack = stack[:len(stack)-1]
		}
		parent := "/"
		if len(stack) > 0 {
			p := objs[stack[len(stack)-1]]
			parent = p.path
			if o.guard == "" {
				o.guard = p.guard
			}
		}
		full, catchAll, ok := joinRoute(parent, o.path)
		o.path = full
		if !ok {
			o.path = parent // its children are still under the parent
		}
		stack = append(stack, i)
		if ok && (!catchAll || full != parent) {
			add(full, o.guard, o.at, o.atEnd) // admin/* is admin and what lies under it
		}
	}
	for _, r := range jsxRoutes(script) {
		add(r.Path, r.Guard, r.Start, r.End)
	}
	return out
}

// jsxRoutes reads <Route path=…> elements, nested ones joined.
func jsxRoutes(script string) []ClientRoute {
	if !strings.Contains(script, "Route") {
		return nil
	}
	type open struct{ path, guard string }
	var stack []open
	var out []ClientRoute
	for _, m := range jsxRoute.FindAllStringSubmatchIndex(script, -1) {
		if len(out) >= maxClientRoutes {
			break
		}
		if m[3] > m[2] { // </Route>
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
			continue
		}
		end := tagEnd(script, m[1])
		if end < 0 {
			continue
		}
		tag := script[m[0] : end+1]
		parent, guard := "/", ""
		if len(stack) > 0 {
			parent, guard = stack[len(stack)-1].path, stack[len(stack)-1].guard
		}
		if m[4] >= 0 && guardComponent.MatchString(script[m[4]:m[5]]+"Route") {
			guard = script[m[4]:m[5]] + "Route"
		}
		if e := jsxElem.FindStringSubmatch(tag); e != nil && guardComponent.MatchString(e[1]) {
			guard = e[1]
		}
		full := parent
		if pm := jsxPath.FindStringSubmatchIndex(tag); pm != nil {
			for g := 1; g <= 3; g++ {
				if pm[2*g] >= 0 {
					p := tag[pm[2*g]:pm[2*g+1]]
					if f, catchAll, ok := joinRoute(parent, p); ok && routeLike(p) {
						full = f
						if !catchAll || f != parent {
							out = append(out, ClientRoute{Path: f, Guard: guard, Start: m[0] + pm[0], End: m[0] + pm[1]})
						}
					}
				}
			}
		}
		if script[end-1] != '/' {
			stack = append(stack, open{full, guard})
		}
	}
	return out
}

// HashRouting says the app keeps its routes after # (/#/administration):
// Angular's useHash or withHashLocation, Vue's hash mode or
// createWebHashHistory, React Router's HashRouter (as written, or as a
// development build compiles it) or createHashRouter. A library's own
// definition of those functions does not count.
func HashRouting(script string) bool {
	for _, m := range hashRouting.FindAllStringIndex(script, 64) {
		if strings.HasSuffix(strings.TrimRight(script[max(0, m[0]-12):m[0]], " \t"), "function") {
			continue
		}
		return true
	}
	return false
}

// routeLike is a router's path: no spaces, no scheme, no SVG drawing.
func routeLike(p string) bool {
	if len(p) > 200 || strings.ContainsAny(p, " \t\n\"'<>`") || strings.Contains(p, "://") {
		return false
	}
	for _, c := range p {
		if !(c == '/' || c == ':' || c == '*' || c == '?' || c == '(' || c == ')' || c == '\\' || c == '[' || c == ']' || c == '{' || c == '}' ||
			c == '.' || c == '-' || c == '_' || c == '~' || c == '@' || c == '+' || c == '$' || c == '%' || c == '|' ||
			c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') {
			return false
		}
	}
	return true
}

// joinRoute is p under parent, as the map writes routes: :id, :id(\d+)
// and [id] as {id}. A catch-all (**, *, :pathMatch(.*)*) ends it; ok is
// false for a path that is not one.
func joinRoute(parent, p string) (full string, catchAll, ok bool) {
	var segs []string
	if !strings.HasPrefix(p, "/") && parent != "/" && parent != "" {
		segs = strings.Split(strings.Trim(parent, "/"), "/")
	}
	for _, seg := range strings.Split(strings.Trim(p, "/"), "/") {
		switch {
		case seg == "":
			continue
		case seg == "*" || seg == "**" || strings.Contains(seg, ".*") || strings.HasPrefix(seg, "*"):
			catchAll = true
		case strings.HasPrefix(seg, ":"):
			name := seg[1:]
			if i := strings.IndexAny(name, "(?*+"); i >= 0 {
				name = name[:i]
			}
			if name == "" || !routeSeg.MatchString(name) {
				return "", false, false
			}
			seg = "{" + name + "}"
		case strings.HasPrefix(seg, "["):
			name := dynamicSegment(seg)
			if name == "" {
				return "", false, false
			}
			seg = name
		case strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "}"):
		case !routeSeg.MatchString(seg):
			return "", false, false
		}
		if catchAll {
			break
		}
		segs = append(segs, seg)
	}
	return "/" + strings.Join(segs, "/"), catchAll, true
}

var dynSeg = regexp.MustCompile(`^\[\[?(?:\.\.\.)?([A-Za-z_$][\w$]*)\]\]?$`)

// dynamicSegment is a file-system router's parameter as {name}: [id],
// [...slug], [[...slug]]; "" for anything else in brackets.
func dynamicSegment(seg string) string {
	m := dynSeg.FindStringSubmatch(seg)
	if m == nil {
		return ""
	}
	return "{" + m[1] + "}"
}

// routeGuard is what a route object says must let the browser in.
func routeGuard(props []prop) string {
	for _, k := range guardKeys {
		v := strings.TrimSpace(propOf(props, k))
		if v == "" || v == "[]" {
			continue
		}
		if m := guardName.FindStringSubmatch(v); m != nil {
			return k + " " + m[1]
		}
		return k
	}
	if meta := strings.TrimSpace(propOf(props, "meta")); strings.HasPrefix(meta, "{") {
		for _, p := range objectProps(meta) {
			v := strings.TrimSpace(p.val)
			if guardMeta.MatchString(p.key) && v != "false" && v != "!1" && v != "0" && v != "null" && v != "[]" {
				return "meta." + p.key
			}
		}
	}
	if propOf(props, "beforeEnter") != "" {
		return "beforeEnter"
	}
	if m := firstComponent.FindStringSubmatch(strings.TrimSpace(propOf(props, "element"))); m != nil {
		name := m[1] + m[2]
		if i := strings.LastIndexByte(name, '.'); i >= 0 {
			name = name[i+1:]
		}
		if guardComponent.MatchString(name) {
			return name
		}
	}
	return ""
}

type prop struct{ key, val string }

// objectProps lists the top-level properties of an object literal, a
// shorthand one ({path, component}) as its own value.
func objectProps(obj string) []prop {
	obj = strings.TrimSpace(obj)
	if !strings.HasPrefix(obj, "{") || !strings.HasSuffix(obj, "}") {
		return nil
	}
	var out []prop
	for _, part := range splitTop(obj[1:len(obj)-1], ",") {
		part = strings.TrimSpace(part)
		m := keyRE.FindStringSubmatch(part)
		if m == nil {
			continue
		}
		v := part
		if _, after, ok := strings.Cut(part, ":"); ok {
			v = after
		}
		out = append(out, prop{m[1], v})
	}
	return out
}

func propOf(props []prop, key string) string {
	for _, p := range props {
		if p.key == key {
			return p.val
		}
	}
	return ""
}

func hasAny(props []prop, keys []string) bool {
	for _, k := range keys {
		for _, p := range props {
			if p.key == k {
				return true
			}
		}
	}
	return false
}

// literalAt reads the string literal whose quote is at i ('…', "…", or a
// template with no ${…}), and where it ends.
func literalAt(s string, i int) (string, int, bool) {
	if i < 0 || i >= len(s) {
		return "", 0, false
	}
	q := s[i]
	for j := i + 1; j < len(s) && j <= i+256; j++ {
		switch s[j] {
		case q:
			return s[i+1 : j], j + 1, true
		case '\\', '\n':
			return "", 0, false
		case '$':
			if q == '`' && j+1 < len(s) && s[j+1] == '{' {
				return "", 0, false
			}
		}
	}
	return "", 0, false
}

// openBrace finds the { that opens the object around i, looking back at
// most 2 KB.
func openBrace(s string, i int) int {
	depth := 0
	for j := i - 1; j >= 0 && j >= i-2048; j-- {
		switch c := s[j]; c {
		case '"', '\'', '`':
			k := strings.LastIndexByte(s[:j], c)
			if k < 0 {
				return -1
			}
			j = k
		case ')', ']', '}':
			depth++
		case '(', '[', '{':
			if depth > 0 {
				depth--
				continue
			}
			if c == '{' {
				return j
			}
			return -1
		}
	}
	return -1
}

// tagEnd finds the > that ends the JSX tag whose name ends at i, past
// attribute strings and {…} expressions, within 4 KB.
func tagEnd(s string, i int) int {
	depth := 0
	var quote byte
	for j := i; j < len(s) && j < i+4096; j++ {
		c := s[j]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case depth == 0 && (c == '"' || c == '\''):
			quote = c
		case c == '{':
			depth++
		case c == '}':
			depth--
		case c == '>' && depth == 0:
			return j
		case c == '<' && depth == 0:
			return -1
		}
	}
	return -1
}
