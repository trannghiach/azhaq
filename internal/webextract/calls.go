package webextract

import (
	"regexp"
	"sort"
	"strings"
)

// Call is a request a script makes: the method of the client call, the
// path it builds, and the names of what it sends.
//
//	this.http.post(this.hostServer+`/rest/2fa/verify`,{tmpToken:t,totpToken:e})
//	→ POST /rest/2fa/verify, body tmpToken totpToken
//
// Paths keep the parts known only at run time as {name} placeholders:
// `${this.host}/${e.id}` in a service whose host is …+`/api/Cards` is
// /api/Cards/{id}.
type Call struct {
	Method string
	Path   string   // starts with / (the app's origin), or an absolute URL
	Query  []string // query parameter names
	Body   []string // field names of an object literal body
}

var (
	// clientCall: .get( .post( … on any object (an HTTP client, axios, $).
	clientCall = regexp.MustCompile(`\.(get|post|put|patch|delete|head)\s*\(`)
	fetchCall  = regexp.MustCompile(`(?:^|[^\w$.])fetch\s*\(`)
	xhrOpen    = regexp.MustCompile(`\.open\s*\(\s*["'\x60](GET|POST|PUT|PATCH|DELETE|HEAD)["'\x60]\s*,`)
	methodOpt  = regexp.MustCompile(`(?i)\bmethod\s*:\s*["'\x60](get|post|put|patch|delete|head)["'\x60]`)
	identChain = regexp.MustCompile(`^[A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*$`)
	// originName: a variable that holds a scheme and host, not a path.
	originName = regexp.MustCompile(`(?i)(host|server|base|origin|domain|backend|endpoint|apiurl|api_url|baseurl|root|url)`)
	pathChars  = regexp.MustCompile(`^(?:https?://[\w.:-]+)?/[\w.~%{}@!$&'*+,;=:/?-]*$`)
	keyRE      = regexp.MustCompile(`^\s*(?:["'\x60]?)([A-Za-z_$][\w$-]*)(?:["'\x60]?)\s*(?::|$)`)
)

// maxCalls caps the calls read from one script.
const maxCalls = 4000

// Calls returns the requests script makes through an HTTP client, fetch
// or XMLHttpRequest whose URL it can work out.
func Calls(script string) []Call { return calls(script, false) }

// PageCalls is Calls for a script inline in a page: a path without a
// leading slash given to fetch or XMLHttpRequest (xhr.open("GET",
// "util/status.jsp?host=" + h)) is relative to the page, and is kept as
// written for the caller to resolve.
func PageCalls(script string) []Call { return calls(script, true) }

// relPath: a page-relative path that names a resource (a directory or a
// file with an extension), not a bare word.
var relPath = regexp.MustCompile(`^[\w~-][\w.~%{}@!$&'*+,;=:-]*(?:/[\w.~%{}@!$&'*+,;=:-]*)+$|^[\w~-][\w~-]*\.(?:jsp|jspx|php|asp|aspx|ashx|do|action|cgi|pl|json|xml|html?)$`)

func calls(script string, relative bool) []Call {
	var out []Call
	add := func(c Call, ok bool) {
		if ok && len(out) < maxCalls {
			out = append(out, c)
		}
	}
	for _, m := range clientCall.FindAllStringSubmatchIndex(script, -1) {
		method := strings.ToUpper(script[m[2]:m[3]])
		args := callArgs(script, m[1]-1)
		if len(args) == 0 {
			continue
		}
		// An HTTP client may have a base URL of its own: only fetch and
		// XMLHttpRequest resolve a relative path against the page.
		c, ok := callOf(script, m[0], method, args[0], false)
		if ok && len(args) > 1 {
			opts := strings.TrimSpace(args[1])
			switch method {
			case "POST", "PUT", "PATCH":
				c.Body = objectKeys(opts)
				if c.Body == nil && identChain.MatchString(opts) && len(opts) <= 2 {
					// post(r,n) with n declared just before as an object.
					ev := evaluator{src: script}
					if rhs, _, ok := ev.declared(opts, m[0]); ok {
						c.Body = objectKeys(rhs)
					}
				}
				if strings.HasPrefix(opts, "{") && len(args) > 2 {
					c.Query = append(c.Query, paramsOption(args[2])...)
				}
			default:
				c.Query = append(c.Query, paramsOption(opts)...)
			}
		}
		add(c, ok)
	}
	for _, m := range fetchCall.FindAllStringIndex(script, -1) {
		args := callArgs(script, m[1]-1)
		if len(args) == 0 {
			continue
		}
		method := "GET"
		var body []string
		if len(args) > 1 {
			if mm := methodOpt.FindStringSubmatch(args[1]); mm != nil {
				method = strings.ToUpper(mm[1])
			}
			body = bodyOption(args[1])
		}
		c, ok := callOf(script, m[0], method, args[0], relative)
		c.Body = body
		add(c, ok)
	}
	for _, m := range xhrOpen.FindAllStringSubmatchIndex(script, -1) {
		rest := topExpr(script[m[1]:])
		c, ok := callOf(script, m[0], script[m[2]:m[3]], rest, relative)
		add(c, ok)
	}
	return out
}

// callOf evaluates the URL argument of a call at pos; relative allows a
// page-relative path.
func callOf(script string, pos int, method, arg string, relative bool) (Call, bool) {
	ev := evaluator{src: script}
	path, ok := ev.eval(arg, pos, 0)
	if !ok {
		return Call{}, false
	}
	path, query := splitQuery(path)
	if relative && relPath.MatchString(path) && !strings.HasPrefix(path, "{") {
		return Call{Method: method, Path: path, Query: query}, true
	}
	if !pathChars.MatchString(path) || path == "/" && len(query) == 0 || strings.Contains(path, "//{") {
		return Call{}, false
	}
	return Call{Method: method, Path: path, Query: query}, true
}

// splitQuery separates a built path from its query and keeps the names.
func splitQuery(p string) (string, []string) {
	path, q, ok := strings.Cut(p, "?")
	if !ok {
		return p, nil
	}
	var names []string
	for _, kv := range strings.Split(q, "&") {
		k, _, _ := strings.Cut(kv, "=")
		if k = strings.TrimSpace(k); k != "" && !strings.ContainsAny(k, "{}") {
			names = append(names, k)
		}
	}
	return path, names
}

// evaluator works out the string an expression builds, from the literals
// in it and the variables the script assigns once.
type evaluator struct {
	src string
}

const maxDepth = 4

func (ev evaluator) eval(expr string, pos, depth int) (string, bool) {
	expr = strings.TrimSpace(expr)
	if expr == "" || depth > maxDepth {
		return "", false
	}
	var b strings.Builder
	for _, term := range splitTop(expr, "+") {
		term = strings.TrimSpace(term)
		if term == "" {
			return "", false
		}
		v, known, name := ev.term(term, pos, depth)
		switch {
		case known:
			b.WriteString(v)
		case b.Len() == 0:
			// What a URL starts with but the script does not spell out
			// is its scheme and host: hostServer, baseUrl, environment.api.
			if name == "" || !originName.MatchString(name) && !strings.HasPrefix(name, "this.") {
				return "", false
			}
		case endsPart(b.String()):
			b.WriteString(placeholderFor(name))
		default:
			// "/whoami"+t: what follows is not a segment of its own (a
			// query string, a suffix); the path is what is known.
			return b.String(), true
		}
	}
	return b.String(), b.Len() > 0
}

// endsPart: the next part of a path or query starts here.
func endsPart(s string) bool {
	return strings.HasSuffix(s, "/") || strings.HasSuffix(s, "=")
}

// term is the value of one operand of a concatenation: known, or unknown
// with the name of the variable that holds it.
func (ev evaluator) term(t string, pos, depth int) (string, bool, string) {
	switch t[0] {
	case '"', '\'':
		if s, ok := unquote(t); ok {
			return s, true, ""
		}
		return "", false, ""
	case '`':
		return ev.template(t, pos, depth)
	case '(':
		if strings.HasSuffix(t, ")") {
			v, ok := ev.eval(t[1:len(t)-1], pos, depth+1)
			return v, ok, ""
		}
	}
	if !identChain.MatchString(t) {
		return "", false, lastName(t)
	}
	name := strings.Join(strings.Fields(t), "")
	if v, ok := ev.binding(name, pos, depth); ok {
		return v, true, name
	}
	return "", false, name
}

// template evaluates a template literal; each ${…} is evaluated or kept
// as a placeholder.
func (ev evaluator) template(t string, pos, depth int) (string, bool, string) {
	if len(t) < 2 || t[len(t)-1] != '`' {
		return "", false, ""
	}
	body := t[1 : len(t)-1]
	var b strings.Builder
	for len(body) > 0 {
		i := strings.Index(body, "${")
		if i < 0 {
			b.WriteString(body)
			break
		}
		b.WriteString(body[:i])
		end := closeBrace(body, i+2)
		if end < 0 {
			return "", false, ""
		}
		inner := body[i+2 : end]
		v, ok := ev.eval(inner, pos, depth+1)
		switch {
		case ok:
			b.WriteString(v)
		case b.Len() == 0 && (originName.MatchString(inner) || strings.HasPrefix(strings.TrimSpace(inner), "this.")):
			// ${this.hostServer}/rest/…: the origin.
		case b.Len() == 0:
			return "", false, ""
		case endsPart(b.String()):
			b.WriteString(placeholderFor(lastName(inner)))
		default:
			return b.String(), true, ""
		}
		body = body[end+1:]
	}
	return b.String(), true, ""
}

// binding finds the last assignment to name before pos and evaluates it:
// this.host=…, a class field host=…, a variable r=….
func (ev evaluator) binding(name string, pos, depth int) (string, bool) {
	field := strings.TrimPrefix(name, "this.")
	if strings.Contains(field, ".") {
		return "", false // a property of another object: environment.apiUrl
	}
	if field == name && len(field) <= 2 {
		// A minified local: its name is reused everywhere, so only a
		// declaration just before, in the same function, is trusted:
		// let r=this.host+`/submitKey`,n={…};return this.http.post(r,n)
		rhs, at, ok := ev.declared(field, pos)
		if !ok {
			return "", false
		}
		return ev.eval(rhs, at, depth+1)
	}
	window := 3000
	if field != name || len(field) > 2 {
		window = 30000 // a field or a real name, not a minified local
	}
	start := max(0, pos-window)
	re, err := regexp.Compile(`(?:^|[^\w$.]|this\.)` + regexp.QuoteMeta(field) + `\s*=([^=>])`)
	if err != nil {
		return "", false
	}
	locs := re.FindAllStringSubmatchIndex(ev.src[start:pos], -1)
	if len(locs) == 0 {
		return "", false
	}
	at := start + locs[len(locs)-1][2]
	rhs := topExpr(ev.src[at:])
	if rhs == "" {
		return "", false
	}
	return ev.eval(rhs, at, depth+1)
}

// declared finds `let NAME=…`, `const NAME=…` or `, NAME=…` of a
// declaration list in the 300 bytes before pos, and returns what it is
// set to and where.
func (ev evaluator) declared(name string, pos int) (string, int, bool) {
	start := max(0, pos-300)
	re := regexp.MustCompile(`(?:\b(?:let|const|var)\s+|,\s*)` + regexp.QuoteMeta(name) + `\s*=([^=>])`)
	locs := re.FindAllStringSubmatchIndex(ev.src[start:pos], -1)
	if len(locs) == 0 {
		return "", 0, false
	}
	at := start + locs[len(locs)-1][2]
	rhs := topExpr(ev.src[at:])
	return rhs, at, rhs != ""
}

// placeholderFor names a run-time part of a path after the variable that
// holds it when the name says something (e.username → {username}).
func placeholderFor(name string) string {
	n := lastName(name)
	if len(n) < 3 || strings.ContainsAny(n, "$") {
		return "{id}"
	}
	return "{" + n + "}"
}

func lastName(expr string) string {
	expr = strings.TrimSpace(expr)
	if i := strings.LastIndexAny(expr, ".("); i >= 0 && i+1 < len(expr) && identChain.MatchString(expr[i+1:]) {
		return expr[i+1:]
	}
	if identChain.MatchString(expr) {
		return expr
	}
	return ""
}

// callArgs splits the arguments of the call whose "(" is at open.
func callArgs(s string, open int) []string {
	end := closeParen(s, open)
	if end < 0 {
		return nil
	}
	return splitTop(s[open+1:end], ",")
}

// closeParen finds the ")" that closes the "(" at open, within 4 KB.
func closeParen(s string, open int) int {
	depth := 0
	var quote byte
	limit := min(len(s), open+4096)
	for i := open; i < limit; i++ {
		c := s[i]
		switch {
		case quote != 0:
			if c == '\\' {
				i++
			} else if c == quote {
				quote = 0
			}
		case c == '"' || c == '\'' || c == '`':
			quote = c
		case c == '(' || c == '{' || c == '[':
			depth++
		case c == ')' || c == '}' || c == ']':
			depth--
			if depth == 0 {
				if c != ')' {
					return -1
				}
				return i
			}
		}
	}
	return -1
}

// closeBrace finds the "}" that ends a ${…} opened before i.
func closeBrace(s string, i int) int {
	depth := 0
	var quote byte
	for ; i < len(s); i++ {
		c := s[i]
		switch {
		case quote != 0:
			if c == '\\' {
				i++
			} else if c == quote {
				quote = 0
			}
		case c == '"' || c == '\'':
			quote = c
		case c == '{':
			depth++
		case c == '}':
			if depth == 0 {
				return i
			}
			depth--
		}
	}
	return -1
}

func unquote(t string) (string, bool) {
	if len(t) < 2 || t[len(t)-1] != t[0] {
		return "", false
	}
	inner := t[1 : len(t)-1]
	if strings.ContainsRune(inner, rune(t[0])) && !strings.Contains(inner, `\`) {
		return "", false // two strings, not one
	}
	return strings.ReplaceAll(inner, `\/`, `/`), true
}

// objectKeys lists the top-level keys of an object literal.
func objectKeys(obj string) []string {
	obj = strings.TrimSpace(obj)
	if !strings.HasPrefix(obj, "{") || !strings.HasSuffix(obj, "}") {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	for _, part := range splitTop(obj[1:len(obj)-1], ",") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "...") || part == "" {
			continue
		}
		m := keyRE.FindStringSubmatch(part)
		if m == nil || seen[m[1]] {
			continue
		}
		seen[m[1]] = true
		out = append(out, m[1])
	}
	return out
}

// paramsOption reads {params:{a:…,b:…}} from a client call's options.
func paramsOption(opts string) []string {
	return optionKeys(opts, "params")
}

// bodyOption reads body:JSON.stringify({…}) or body:{…} from fetch options.
func bodyOption(opts string) []string {
	for _, part := range splitTop(strings.Trim(strings.TrimSpace(opts), "{}"), ",") {
		k, v, ok := strings.Cut(part, ":")
		if !ok || strings.TrimSpace(k) != "body" {
			continue
		}
		v = strings.TrimSpace(v)
		v = strings.TrimSuffix(strings.TrimPrefix(v, "JSON.stringify("), ")")
		return objectKeys(v)
	}
	return nil
}

func optionKeys(opts, key string) []string {
	opts = strings.TrimSpace(opts)
	if !strings.HasPrefix(opts, "{") {
		return nil
	}
	for _, part := range splitTop(opts[1:len(opts)-1], ",") {
		k, v, ok := strings.Cut(part, ":")
		if ok && strings.Trim(strings.TrimSpace(k), `"'`) == key {
			return objectKeys(v)
		}
	}
	return nil
}

// MergeCalls folds calls to the same method and path together, names
// sorted, in a stable order.
func MergeCalls(calls []Call) []Call {
	idx := map[string]int{}
	var out []Call
	for _, c := range calls {
		k := c.Method + " " + c.Path
		i, ok := idx[k]
		if !ok {
			idx[k] = len(out)
			out = append(out, Call{Method: c.Method, Path: c.Path})
			i = len(out) - 1
		}
		out[i].Query = union(out[i].Query, c.Query)
		out[i].Body = union(out[i].Body, c.Body)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Path != out[j].Path {
			return out[i].Path < out[j].Path
		}
		return out[i].Method < out[j].Method
	})
	return out
}

func union(a, b []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range append(append([]string(nil), a...), b...) {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	sort.Strings(out)
	return out
}
