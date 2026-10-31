package webextract

import (
	"strings"
)

// Pages wrap their requests in helpers that take the URL as a parameter:
//
//	async function logQuery(url,params){await fetch(url,{method:"post",body:JSON.stringify(params)})}
//	… logQuery('/logger',config.params)
//
// The path is only named where the helper is called, and the method only
// inside it. A wrapper joins the two, one level deep: a helper that hands
// its URL on to another helper is not followed.

// shape is what a request says about itself besides its URL.
type shape struct {
	method    string   // a literal method; "" when methodEx or opts decide it
	methodEx  string   // the expression that gives the method
	opts      string   // options or settings that are not an object literal
	bodyKey   string   // where the options hold the body: body (fetch), data
	bodyEx    string   // the expression sent as the body
	body      []string // the keys of an object literal body
	query     []string // the keys of an object literal of query parameters
	dataQuery bool     // jQuery: a GET's data is its query string
	pageRel   bool     // a path without a leading slash is the page's (fetch, XHR, $.ajax)
}

// wrapper is a function that makes a request with one of its parameters
// as the URL.
type wrapper struct {
	name      string
	dotted    bool     // a method or a property: called as x.name(…)
	urlArg    int      // the parameter that is the URL
	prefix    string   // what the function puts before it: fetch("/api"+path)
	method    string   // the method, when the function fixes it
	verbArg   int      // else the parameter that holds the method, or -1
	optsArg   int      // else the parameter that holds the request's options, or -1
	bodyArg   int      // the parameter sent as the body, or -1
	defaults  []string // each parameter's default, as written, or ""
	bodyKey   string
	body      []string
	query     []string
	dataQuery bool
	pageRel   bool
}

// same: two requests in one function that a call of it makes alike.
func (w wrapper) same(x wrapper) bool {
	return w.name == x.name && w.dotted == x.dotted && w.urlArg == x.urlArg && w.prefix == x.prefix &&
		w.method == x.method && w.verbArg == x.verbArg && w.optsArg == x.optsArg && w.bodyArg == x.bodyArg &&
		w.bodyKey == x.bodyKey && w.dataQuery == x.dataQuery && w.pageRel == x.pageRel &&
		strings.Join(w.body, ",") == strings.Join(x.body, ",") && strings.Join(w.query, ",") == strings.Join(x.query, ",")
}

// maxWrappers caps the wrappers followed in one script, and
// maxWrapperTries the requests looked at for one.
const (
	maxWrappers     = 64
	maxWrapperTries = 512
	// wrapperReach is how far before a request its function may start.
	wrapperReach = 4096
)

var (
	httpMethods = map[string]bool{"GET": true, "POST": true, "PUT": true, "PATCH": true, "DELETE": true, "HEAD": true, "OPTIONS": true}
	plainIdent  = lazyRE(`^[A-Za-z_$][\w$]*$`)
	// notWrappers are names whose calls are read as requests already, and
	// words that open a block like a function does.
	notWrappers = map[string]bool{
		"fetch": true, "open": true, "get": true, "post": true, "put": true, "patch": true, "delete": true, "head": true,
		"ajax": true, "then": true, "call": true, "apply": true, "bind": true, "constructor": true,
		"if": true, "for": true, "while": true, "switch": true, "catch": true, "with": true, "function": true,
		"return": true, "typeof": true, "new": true, "async": true, "await": true, "else": true, "do": true,
	}
)

// settingsShape reads fetch options, $.ajax settings or an axios config:
// the method (method, or jQuery's type), the body under bodyKey, params.
func settingsShape(settings, bodyKey string) shape {
	settings = strings.TrimSpace(settings)
	if !strings.HasPrefix(settings, "{") || !strings.HasSuffix(settings, "}") {
		return shape{opts: settings, bodyKey: bodyKey}
	}
	sh := shape{method: "GET", bodyKey: bodyKey}
	ex := optionExpr(settings, "method")
	if ex == "" {
		ex = optionExpr(settings, "type")
	}
	if ex != "" {
		if lit, ok := literal(ex); ok && httpMethods[strings.ToUpper(lit)] {
			sh.method = strings.ToUpper(lit)
		} else {
			sh.method, sh.methodEx = "", ex
		}
	}
	if b := stripStringify(optionExpr(settings, bodyKey)); b != "" {
		if keys := objectKeys(b); keys != nil {
			sh.body = keys
		} else {
			sh.bodyEx = b
		}
	}
	sh.query = objectKeys(optionExpr(settings, "params"))
	return sh
}

// optionExpr is the expression a top-level key of an object literal is
// set to; {url, method} is {url:url, method:method}.
func optionExpr(obj, key string) string {
	obj = strings.TrimSpace(obj)
	if !strings.HasPrefix(obj, "{") || !strings.HasSuffix(obj, "}") {
		return ""
	}
	for _, part := range splitTop(obj[1:len(obj)-1], ",") {
		k, v, ok := strings.Cut(part, ":")
		k = strings.Trim(strings.TrimSpace(k), `"'`)
		if k != key {
			continue
		}
		if !ok {
			return key
		}
		return strings.TrimSpace(v)
	}
	return ""
}

// literal is the value of a string literal without substitutions.
func literal(ex string) (string, bool) {
	ex = strings.TrimSpace(ex)
	if strings.HasPrefix(ex, "`") && strings.Contains(ex, "${") {
		return "", false
	}
	if len(ex) >= 2 && strings.ContainsRune(`"'`+"`", rune(ex[0])) {
		return unquote(ex)
	}
	return "", false
}

func stripStringify(ex string) string {
	ex = strings.TrimSpace(ex)
	if strings.HasPrefix(ex, "JSON.stringify(") && strings.HasSuffix(ex, ")") {
		if args := callArgs(ex, len("JSON.stringify")); len(args) > 0 {
			return strings.TrimSpace(args[0]) // JSON.stringify({…}, null, 2)
		}
		ex = strings.TrimSpace(ex[len("JSON.stringify(") : len(ex)-1])
	}
	return ex
}

// urlParam splits a URL expression into what comes before and the name
// it ends with: path, "/api"+path, base+path, `/api${path}`.
func urlParam(ex string) (name, prefix string, ok bool) {
	ex = strings.TrimSpace(ex)
	terms := splitTop(ex, "+")
	last := strings.TrimSpace(terms[len(terms)-1])
	if len(terms) == 1 && strings.HasPrefix(last, "`") && strings.HasSuffix(last, "}`") {
		i := strings.LastIndex(last, "${")
		if i < 0 {
			return "", "", false
		}
		name = strings.TrimSpace(last[i+2 : len(last)-2])
		if prefix = last[:i] + "`"; prefix == "``" {
			prefix = ""
		}
		return name, prefix, plainIdent.MatchString(name)
	}
	if !plainIdent.MatchString(last) {
		return "", "", false
	}
	return last, strings.Join(terms[:len(terms)-1], "+"), true
}

// originOnly: every part of ex names a scheme and host, not a path
// (base, this.hostServer, `${environment.apiUrl}`).
func originOnly(ex string) bool {
	for _, t := range splitTop(ex, "+") {
		t = strings.TrimSpace(t)
		if len(t) >= 2 && strings.HasPrefix(t, "`") && strings.HasSuffix(t, "`") {
			inner := t[1 : len(t)-1]
			for inner != "" {
				if !strings.HasPrefix(inner, "${") {
					return false
				}
				end := closeBrace(inner, 2)
				if end < 0 || !originOnly(inner[2:end]) {
					return false
				}
				inner = inner[end+1:]
			}
			continue
		}
		if !identChain.MatchString(t) || !originName.MatchString(t) && !strings.HasPrefix(t, "this.") {
			return false
		}
	}
	return true
}

// wrapperOf is the function around the request at pos when the request's
// URL ends with one of the function's parameters. names caches which
// names are worth following.
func wrapperOf(script string, pos int, urlEx string, sh shape, names map[string]bool) (wrapper, bool) {
	param, prefixEx, ok := urlParam(urlEx)
	if !ok {
		return wrapper{}, false
	}
	fn, ok := enclosingFunc(script, pos, param)
	if !ok {
		return wrapper{}, false
	}
	trusted, seen := names[fn.name]
	if !seen {
		trusted = declaredOnce(script, fn.name)
		names[fn.name] = trusted
	}
	if !trusted {
		return wrapper{}, false
	}
	// url = API_ROOT + url before the request: the callers' paths go
	// under that prefix too.
	inner, at, ok := reassigned(script, fn.body, pos, param)
	if !ok {
		return wrapper{}, false
	}
	outer, ok1 := prefixValue(script, prefixEx, pos)
	under, ok2 := prefixValue(script, inner, at)
	if !ok1 || !ok2 {
		return wrapper{}, false
	}
	w := wrapper{name: fn.name, dotted: fn.dotted, urlArg: indexOf(fn.params, param), verbArg: -1, optsArg: -1, bodyArg: -1,
		prefix: joinPath(outer, under), defaults: fn.defaults, method: sh.method, bodyKey: sh.bodyKey,
		body: sh.body, query: sh.query, dataQuery: sh.dataQuery, pageRel: sh.pageRel}
	if w.bodyKey == "" {
		w.bodyKey = "body"
	}
	switch {
	case sh.methodEx != "":
		w.verbArg = indexOf(fn.params, strings.TrimSpace(sh.methodEx))
	case sh.opts != "":
		w.optsArg = indexOf(fn.params, strings.TrimSpace(sh.opts))
	}
	if sh.bodyEx != "" {
		w.bodyArg = indexOf(fn.params, stripStringify(sh.bodyEx))
	}
	return w, true
}

// prefixValue is what a prefix expression at pos comes to: "" for none,
// or for a scheme and host the script does not spell out.
func prefixValue(script, ex string, pos int) (string, bool) {
	if strings.TrimSpace(ex) == "" {
		return "", true
	}
	ev := evaluator{src: script}
	if v, ok := ev.eval(ex, pos, 0); ok {
		return v, true
	}
	return "", originOnly(ex)
}

// compoundSet is an assignment that changes a value in place: url+=…
var compoundSet = lazyRE(`^(?:[-+*/%&|^]|\*\*|<<|>>>?|&&|\|\||\?\?)=`)

// reassigned reads what a function does to its URL parameter between its
// body's start and the request at pos: nothing, or one
// param = PREFIX + param, whose prefix it returns with where it is. Any
// other assignment makes the parameter something the callers did not pass.
func reassigned(script string, body, pos int, param string) (string, int, bool) {
	prefix, at, n := "", pos, 0
	for from := body; from < pos; {
		i := strings.Index(script[from:pos], param)
		if i < 0 {
			break
		}
		i += from
		from = i + len(param)
		if i > 0 && (isIdentByte(script[i-1]) || script[i-1] == '.') || from < len(script) && isIdentByte(script[from]) {
			continue
		}
		j := skipSpace(script, from)
		switch {
		case j >= len(script):
		case compoundSet.MatchString(script[j:min(len(script), j+4)]):
			return "", 0, false
		case script[j] == '=' && (j+1 >= len(script) || script[j+1] != '=' && script[j+1] != '>'):
			name, pre, ok := urlParam(topExpr(script[j+1:]))
			if n++; !ok || name != param || n > 1 {
				return "", 0, false
			}
			prefix, at = pre, j+1
		}
	}
	return prefix, at, true
}

func indexOf(xs []string, x string) int {
	for i, v := range xs {
		if v == x {
			return i
		}
	}
	return -1
}

// wrapperName: a name worth looking for calls of.
func wrapperName(name string) bool {
	return len(name) >= 3 && !notWrappers[name]
}

// declaredOnce: a function is followed only when its name is declared
// once in the script. Two functions of one name (usersApi.request and
// ordersApi.request, or a minifier's short name given anew in every
// module) cannot be told apart where they are called.
func declaredOnce(script, name string) bool {
	n := 0
	for from := 0; ; {
		i := strings.Index(script[from:], name)
		if i < 0 {
			break
		}
		i += from
		from = i + len(name)
		if i > 0 && isIdentByte(script[i-1]) || from < len(script) && isIdentByte(script[from]) {
			continue
		}
		decl := false
		if w, _ := wordBefore(script, i); w == "function" {
			decl = true
		} else if j := skipSpace(script, from); j < len(script) {
			switch script[j] {
			case '=':
				decl = j+1 < len(script) && script[j+1] != '=' && script[j+1] != '>'
			case ':':
				decl = true
			case '(':
				if e := closeParen(script, j); e > 0 {
					k := skipSpace(script, e+1)
					decl = k < len(script) && script[k] == '{'
				}
			}
		}
		if decl {
			if n++; n > 1 {
				return false
			}
		}
	}
	return n == 1
}

// fn is a named function a request sits in.
type fn struct {
	name     string
	params   []string
	defaults []string // each parameter's default, or ""
	dotted   bool     // called as x.name(…)
	body     int      // where its body starts
}

// header is a function's head, read back from where its body starts.
type header struct {
	name, list string
	start      int  // where the name starts
	sep        byte // '=' or ':' when the function is assigned, else 0
	method     bool // name(a){ in a class or an object
}

// enclosingFunc is the innermost named function that contains pos and
// takes param. Bodies start at a "{" after a parameter list or after
// "=>": walking back from pos, the first that still contains it is the
// innermost.
func enclosingFunc(script string, pos int, param string) (fn, bool) {
	lo := max(0, pos-wrapperReach)
	for i := pos - 1; i >= lo; i-- {
		var h header
		var ok bool
		body := i
		switch {
		case script[i] == '{':
			h, ok = blockHeader(script, i)
		case script[i] == '>' && i > 0 && script[i-1] == '=':
			h, ok = arrowHeader(script, i-1)
			body = skipSpace(script, i+1)
		}
		if !ok || !wrapperName(h.name) {
			continue
		}
		params := paramNames(h.list)
		if indexOf(params, param) < 0 {
			continue
		}
		end := -1
		switch {
		case body < len(script) && script[body] == '{':
			end = closeBlock(script, body)
		case body > i:
			end = body + len(topExpr(script[body:]))
		}
		if end <= pos {
			continue
		}
		f := fn{name: h.name, params: params, defaults: paramDefaults(h.list), body: body}
		switch h.sep {
		case ':':
			f.dotted = true // a property of an object
		case '=':
			f.dotted = h.start > 0 && script[h.start-1] == '.' // this.name=…
		default:
			f.dotted = h.method
		}
		return f, true
	}
	return fn{}, false
}

// blockHeader reads the head of the function whose body opens at open:
// name(a){, function name(a){, name=function(a){, name:async function x(a){.
func blockHeader(s string, open int) (header, bool) {
	rp := skipSpaceBack(s, open)
	if rp < 0 || s[rp] != ')' {
		return header{}, false
	}
	lp, list, ok := paramList(s, rp)
	if !ok {
		return header{}, false
	}
	name, start := wordBefore(s, lp)
	if name == "" {
		return header{}, false
	}
	if name == "function" {
		// name=function(a){: called by the name it is assigned to.
		return assignedTo(s, start, list)
	}
	if w, wstart := wordBefore(s, skipStarBack(s, start)); w == "function" {
		if h, ok := assignedTo(s, wstart, list); ok {
			return h, true // name=function inner(a){
		}
		return header{name: name, list: list, start: start}, true
	}
	return header{name: name, list: list, start: start, method: true}, true
}

// arrowHeader reads the head of the arrow function whose "=>" is at
// arrow: name=(a,b)=>, name:async a=>.
func arrowHeader(s string, arrow int) (header, bool) {
	b := skipSpaceBack(s, arrow)
	if b < 0 {
		return header{}, false
	}
	if s[b] == ')' {
		lp, list, ok := paramList(s, b)
		if !ok {
			return header{}, false
		}
		return assignedTo(s, lp, list)
	}
	p, start := wordBefore(s, b+1)
	if p == "" {
		return header{}, false
	}
	return assignedTo(s, start, p)
}

// assignedTo reads "name=" or "name:" (and an optional async) before i.
func assignedTo(s string, i int, list string) (header, bool) {
	if w, start := wordBefore(s, i); w == "async" {
		i = start
	}
	b := skipSpaceBack(s, i)
	if b < 1 || s[b] != '=' && s[b] != ':' || s[b] == '=' && strings.IndexByte("=!<>+-*/%&|^", s[b-1]) >= 0 {
		return header{}, false
	}
	name, start := wordBefore(s, b)
	if name == "" {
		return header{}, false
	}
	return header{name: name, list: list, start: start, sep: s[b]}, true
}

// paramList finds the "(" of the parameter list that ends at rp; a list
// with parentheses inside (defaults that call) is not read.
func paramList(s string, rp int) (int, string, bool) {
	from := max(0, rp-256)
	lp := strings.LastIndexByte(s[from:rp], '(')
	if lp < 0 {
		return 0, "", false
	}
	lp += from
	list := s[lp+1 : rp]
	return lp, list, !strings.ContainsAny(list, ")")
}

// wordBefore is the identifier that ends just before i (spaces allowed),
// and where it starts.
func wordBefore(s string, i int) (string, int) {
	j := skipSpaceBack(s, i) + 1
	k := j
	for k > 0 && isIdentByte(s[k-1]) {
		k--
	}
	if k == j || s[k] >= '0' && s[k] <= '9' {
		return "", i
	}
	return s[k:j], k
}

// skipSpaceBack is the index of the last byte before i that is not white
// space, or -1.
func skipSpaceBack(s string, i int) int {
	i--
	for i >= 0 && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r') {
		i--
	}
	return i
}

// skipStarBack steps back over the * of function*.
func skipStarBack(s string, i int) int {
	if b := skipSpaceBack(s, i); b >= 0 && s[b] == '*' {
		return b
	}
	return i
}

// paramNames are the names in a parameter list; a destructured one keeps
// its place and matches nothing.
func paramNames(list string) []string {
	var out []string
	for _, p := range splitTop(list, ",") {
		p = strings.TrimPrefix(strings.TrimSpace(p), "...")
		if i := strings.IndexByte(p, '='); i >= 0 {
			p = strings.TrimSpace(p[:i])
		}
		out = append(out, p)
	}
	return out
}

// paramDefaults are what each parameter defaults to, as written, or "":
// (path, method = "POST", opts = {}) is "", "POST" quoted, {}.
func paramDefaults(list string) []string {
	var out []string
	for _, p := range splitTop(list, ",") {
		d := ""
		if _, v, ok := strings.Cut(p, "="); ok {
			d = strings.TrimSpace(v)
		}
		out = append(out, d)
	}
	return out
}

// closeBlock finds the "}" that closes the "{" at open, within 16 KB,
// skipping strings and comments.
func closeBlock(s string, open int) int {
	depth := 0
	var quote byte
	limit := min(len(s), open+16<<10)
	for i := open; i < limit; i++ {
		c := s[i]
		switch {
		case quote != 0:
			if c == '\\' {
				i++
			} else if c == quote {
				quote = 0
			}
		case c == '/' && i+1 < limit && s[i+1] == '/':
			if j := strings.IndexByte(s[i:limit], '\n'); j >= 0 {
				i += j
			} else {
				return -1
			}
		case c == '/' && i+1 < limit && s[i+1] == '*':
			if j := strings.Index(s[i+2:limit], "*/"); j >= 0 {
				i += j + 3
			} else {
				return -1
			}
		case c == '"' || c == '\'' || c == '`':
			quote = c
		case c == '(' || c == '{' || c == '[':
			depth++
		case c == ')' || c == '}' || c == ']':
			depth--
			if depth == 0 {
				if c != '}' {
					return -1
				}
				return i
			}
		}
	}
	return -1
}

// receiverStart walks back from i over the object a method is called on:
// this.http.post( starts at this.
func receiverStart(s string, i int) int {
	for i > 0 && (isIdentByte(s[i-1]) || s[i-1] == '.') {
		i--
	}
	return i
}

// calls are the requests the script makes through w: one per call of it
// whose URL argument holds a string the evaluator works out.
func (w wrapper) calls(script string, relative bool) []Call {
	ev := evaluator{src: script}
	var out []Call
	for from := 0; ; {
		i := strings.Index(script[from:], w.name)
		if i < 0 {
			break
		}
		i += from
		from = i + len(w.name)
		if i > 0 && isIdentByte(script[i-1]) || from < len(script) && isIdentByte(script[from]) {
			continue
		}
		open := skipSpace(script, from)
		if open >= len(script) || script[open] != '(' {
			continue
		}
		b := skipSpaceBack(script, i)
		if dot := b >= 0 && script[b] == '.'; dot != w.dotted {
			continue
		}
		at := i
		if w.dotted {
			at = receiverStart(script, b)
		} else if word, _ := wordBefore(script, i); word == "function" {
			continue // function name(…){: the wrapper itself
		}
		end := closeParen(script, open)
		if end < 0 {
			continue
		}
		if j := skipSpace(script, end+1); j < len(script) && script[j] == '{' {
			continue // name(…){: a method's definition
		}
		args := callArgs(script, open)
		if len(args) <= w.urlArg || !strings.ContainsAny(args[w.urlArg], "\"'`") {
			continue
		}
		path, ok := ev.eval(args[w.urlArg], i, 0)
		if !ok {
			continue
		}
		// As for the request itself: only fetch, XHR and $.ajax take a
		// path relative to the page; an HTTP client has a base of its own.
		c, ok := callFrom(joinPath(w.prefix, path), w.methodAt(args), relative && w.pageRel)
		if !ok {
			continue
		}
		c.Body = w.bodyAt(args)
		c.Query = append(c.Query, w.query...)
		if w.dataQuery && (c.Method == "GET" || c.Method == "HEAD") {
			c.Query, c.Body = append(c.Query, c.Body...), nil
		}
		c.At, c.End = at, end+1
		out = append(out, c)
		if len(out) >= maxCalls {
			break
		}
	}
	return out
}

func joinPath(prefix, path string) string {
	switch {
	case prefix == "" || strings.Contains(path, "://"):
		return path
	case strings.HasSuffix(prefix, "/") && strings.HasPrefix(path, "/"):
		return prefix + path[1:]
	}
	return prefix + path
}

// arg is what parameter i holds in a call with args: the argument, else
// the parameter's default (an argument of undefined takes it too); false
// when neither.
func (w wrapper) arg(args []string, i int) (string, bool) {
	given := i >= 0 && i < len(args)
	if given {
		switch strings.TrimSpace(args[i]) {
		case "undefined", "void 0":
			given = false
		}
	}
	switch {
	case i < 0:
		return "", false
	case given:
		return args[i], true
	case i < len(w.defaults) && w.defaults[i] != "":
		return w.defaults[i], true
	}
	return "", false
}

// methodAt is the method of a call to w with args; "" when a value known
// only at run time decides it.
func (w wrapper) methodAt(args []string) string {
	switch {
	case w.method != "":
		return w.method
	case w.verbArg >= 0:
		ex, ok := w.arg(args, w.verbArg)
		if !ok {
			return "GET" // undefined: the request's default
		}
		if lit, ok := literal(ex); ok && httpMethods[strings.ToUpper(lit)] {
			return strings.ToUpper(lit)
		}
	case w.optsArg >= 0:
		ex, ok := w.arg(args, w.optsArg)
		if !ok {
			return "GET"
		}
		return settingsShape(ex, w.bodyKey).method
	}
	return ""
}

func (w wrapper) bodyAt(args []string) []string {
	if w.body != nil {
		return w.body
	}
	if ex, ok := w.arg(args, w.bodyArg); ok {
		return objectKeys(stripStringify(ex))
	}
	if ex, ok := w.arg(args, w.optsArg); ok {
		return settingsShape(ex, w.bodyKey).body
	}
	return nil
}
