package hunt

import (
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/trannghiach/azhaq/engine"
	"github.com/trannghiach/azhaq/internal/webextract"
)

var braces = strings.NewReplacer("%7B", "{", "%7D", "}", "%7b", "{", "%7d", "}")

// GroupKey is the route template of a URL: numbers, UUIDs and hashes in
// the path and every query value fold to a placeholder, so /basket/6 and
// /basket/7 are one route and ?page=a and ?page=b are one. A client-side
// route keeps its fragment.
func GroupKey(raw string, clientRoute bool) string {
	if clientRoute {
		return raw
	}
	t := braces.Replace(webextract.Template(raw))
	u, err := url.Parse(t)
	if err != nil {
		return t
	}
	if u.RawQuery == "" {
		if u.Path != "/" && strings.HasSuffix(t, "/") && u.Fragment == "" {
			t = strings.TrimSuffix(t, "/")
		}
		return t
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return t
	}
	names := make([]string, 0, len(q))
	for k := range q {
		names = append(names, k)
	}
	sort.Strings(names)
	for i, k := range names {
		names[i] = k + "={v}"
	}
	return strings.TrimSuffix(t, "?"+u.RawQuery) + "?" + strings.Join(names, "&")
}

var wordSplit = regexp.MustCompile(`[^a-z0-9]+`)

// wordsOf are the lower-case words of a path or a host, with the
// hyphenated ones ("api-docs") kept whole too.
func wordsOf(s string) []string {
	s = strings.ToLower(s)
	out := wordSplit.Split(s, -1)
	if strings.Contains(strings.ReplaceAll(s, "_", "-"), "api-docs") {
		out = append(out, "api-docs")
	}
	for i := 0; i+1 < len(out); i++ {
		// sign-in, log_in, sign/up: one word written as two.
		switch w := out[i] + out[i+1]; w {
		case "signin", "signup", "signon", "login", "logon":
			out = append(out, w)
		}
	}
	return out
}

// singular folds a plural to its word (users, addresses).
func singular(w string) string {
	if _, ok := pathWords[w]; ok {
		return w
	}
	for _, suf := range []string{"es", "s"} {
		if t := strings.TrimSuffix(w, suf); t != w {
			if _, ok := pathWords[t]; ok {
				return t
			}
		}
	}
	return w
}

func staticURL(r engine.MapEntry) bool {
	switch r.Role {
	case "asset", "script":
		return true
	}
	c := webextract.ClassifyURL(r.Entity.Key)
	return (c == "asset" || c == "script") && r.Role != "sourcemap"
}

// url reads the signals of one map row into its route's candidate.
func (h *hunter) url(r engine.MapEntry) {
	if r.Coverage == "catchall" || r.Coverage == "gone" || staticURL(r) {
		return
	}
	raw := r.Entity.Key
	u, err := url.Parse(raw)
	if err != nil {
		return
	}
	key := GroupKey(raw, r.Role == "client-route")
	c := h.get("URL", key, r.Scope)
	c.instances = append(c.instances, raw)
	c.origin = u.Scheme + "://" + u.Host
	if r.Entity.FirstSeen.After(h.cut) {
		c.fresh = true
	}
	st := r.Status
	fetched := r.Coverage == "visited"
	ok := fetched && st >= 200 && st < 300
	unfetched := r.Coverage == "hint" || r.Coverage == "skipped" || r.Coverage == "capped" || st == 0
	known := unfetched && len(r.Methods) > 0 // not asked, but a script or a description says it takes requests
	path := u.Path

	if r.Role == "sourcemap" {
		c.add("sourcemap", "source map served: "+path)
		return
	}
	// Path words, one signal per class.
	words := map[string]pathWord{} // class → the word that weighs most
	wordOf := map[string]string{}
	for _, w := range wordsOf(path) {
		pw, isWord := pathWords[singular(w)]
		if !isWord {
			continue
		}
		switch {
		case ok, st >= 500, known:
		case st == 401 || st == 403:
			if !guardedWords[pw.signal] {
				continue
			}
			if pw.signal != "path-data" {
				pw.w = pw.w * 3 / 4 // data behind a login is the target; a guarded admin page less so
			}
		case unfetched || (st >= 300 && st < 400):
			pw.w /= 2
		default:
			continue
		}
		if pw.w > words[pw.signal].w {
			words[pw.signal], wordOf[pw.signal] = pw, w
		}
	}
	for sig, pw := range words {
		how := "answers " + fmt.Sprint(st)
		switch {
		case st == 401 || st == 403:
			how += ": guarded, but there"
		case st == 0:
			how = "named, not requested"
		}
		c.addW(sig, pw.w, fmt.Sprintf("%q in %s, %s", wordOf[sig], path, how))
	}
	switch {
	case st == 401 || st == 403:
		c.add("gated", fmt.Sprintf("answers %d: a session is needed", st))
	case st >= 500:
		h.serverError(c, r, raw)
	}
	// Backup and secret-bearing files.
	if w, what := exposedFile(path); w > 0 {
		switch {
		case ok:
			c.addW("exposed-file", w, what+" served")
		case st == 401 || st == 403 || unfetched:
			c.addW("exposed-file", w*fileUnseen/100, what+" named, "+map[bool]string{true: "answers " + fmt.Sprint(st), false: "not requested"}[st != 0])
		}
	}
	if ok && isListing(r.Title) {
		c.add("listing", "directory listing: "+clip(r.Title, 60))
	}
	if ok && (h.apiDoc[r.Entity.ID] || apiDocPath(path)) {
		c.add("api-description", "API description served at "+path)
	}
	h.graphql(c, r, path)
	h.objects(c, r, path)
	h.params(c, r, raw, u)
	h.writes(c, r, ok, st)
	h.bodies(c, r)
	for _, f := range r.Forms {
		if strings.EqualFold(f.Method, "GET") && passwordField(f.Fields) != "" {
			c.add("password-in-url", "a GET form sends "+passwordField(f.Fields)+" in the URL")
		}
		if len(f.Files) > 0 {
			c.add("upload", fmt.Sprintf("file field %s in a %s form to %s", strings.Join(f.Files, ", "), f.Method, f.Action))
		}
	}
	if r.Coverage == "skipped" && strings.Contains(r.Proof, "skipped=looks like a GET would change something") {
		w := proofWord(r.Proof)
		if !logoutWord[w] {
			c.add("state-change", "GET that looks state-changing, left alone ("+w+")")
		}
	}
	if names := inputNames(r); len(names) > 0 {
		w := weights["input"]
		if writesBody(r) {
			w = writeInputWeight // a body sent with a write is input that matters more than a query name
		}
		c.addW("input", w, "takes "+join(names, 5))
	}
}

// writeInputWeight is the input signal of a route a script or a description
// writes to with named fields.
const writeInputWeight = 12

// writesBody says whether a write operation of the route sends named fields.
func writesBody(r engine.MapEntry) bool {
	for _, o := range r.Ops {
		if writeMethods[strings.ToUpper(o.Method)] && len(o.Body) > 0 {
			return true
		}
	}
	return false
}

// bodies reads the content types the operations take: XML, files.
func (h *hunter) bodies(c *cand, r engine.MapEntry) {
	for _, o := range r.Ops {
		t := strings.ToLower(o.BodyType)
		switch {
		case strings.Contains(t, "xml"):
			c.add("xml", fmt.Sprintf("%s takes %s", o.Method, o.BodyType))
		case strings.Contains(t, "multipart") || strings.Contains(t, "octet-stream"):
			c.add("upload", fmt.Sprintf("%s takes a file upload (%s)", o.Method, o.BodyType))
		}
	}
}

// serverError weighs a 5xx by what the row shows besides the status: the
// body's error text, a parameter that came back in the answer; alone it is
// a lead, and the weaker when the plain request lacked the input the route
// takes.
func (h *hunter) serverError(c *cand, r engine.MapEntry, raw string) {
	st := r.Status
	e := h.errs[r.Entity.ID]
	without := r.Answer != ""
	switch {
	case e.kind == webextract.ErrSQL:
		c.addW("server-error", serverErrorSQL, fmt.Sprintf("answers %d and the body has SQL error text: %q", st, e.sample))
	case e.kind == webextract.ErrDebug:
		c.addW("server-error", serverErrorDebug, fmt.Sprintf("answers %d with a framework's debug page: %q", st, e.sample))
	case h.reflected[webextract.RouteKey(raw)]:
		c.addW("server-error", serverErrorReflected, fmt.Sprintf("answers %d, and a parameter's value comes back in the answer", st))
	case e.kind == webextract.ErrStack && without:
		c.addW("server-error", serverErrorStackBare, fmt.Sprintf("answers %d to a request without its input, with a stack trace: %q", st, e.sample))
	case e.kind == webextract.ErrStack:
		c.addW("server-error", serverErrorStack, fmt.Sprintf("answers %d with a stack trace: %q", st, e.sample))
	case without:
		c.addW("server-error", serverErrorBare, fmt.Sprintf("answers %d to a request without the input it takes (%s): a lead, nothing in the answer points further", st, join(inputNames(r), 3)))
	default:
		c.add("server-error", fmt.Sprintf("answers %d: %s", st, clip(r.Title, 60)))
	}
}

var passField = regexp.MustCompile(`(?i)pass(word|wd)?(_|$)`)

func passwordField(fields []string) string {
	for _, n := range fields {
		if passField.MatchString(n) {
			return n
		}
	}
	return ""
}

var logoutWord = map[string]bool{"logout": true, "signout": true, "logoff": true, "sign-out": true}

func proofWord(proof string) string {
	i := strings.Index(proof, "word=")
	if i < 0 {
		return "?"
	}
	w := proof[i+5:]
	if j := strings.IndexByte(w, ' '); j >= 0 {
		w = w[:j]
	}
	return w
}

func exposedFile(path string) (int, string) {
	p := strings.ToLower(path)
	if strings.Contains(p, "/.git/") || strings.HasSuffix(p, "/.git") {
		return gitWeight, "git repository"
	}
	for _, e := range fileExt {
		if strings.HasSuffix(p, e.ext) {
			return e.w, e.ext + " file"
		}
	}
	return 0, ""
}

func isListing(title string) bool {
	t := strings.ToLower(strings.TrimSpace(title))
	return strings.HasPrefix(t, "index of") || strings.Contains(t, "listing directory") || strings.HasPrefix(t, "directory listing for")
}

func apiDocPath(path string) bool {
	p := strings.ToLower(strings.TrimSuffix(path, "/"))
	for _, s := range []string{"/openapi.json", "/openapi.yaml", "/swagger.json", "/swagger.yaml", "/api-docs", "/swagger-ui", "/swagger-ui.html", "/swagger/index.html", "/v2/api-docs", "/v3/api-docs"} {
		if strings.HasSuffix(p, s) {
			return true
		}
	}
	return false
}

func (h *hunter) graphql(c *cand, r engine.MapEntry, path string) {
	schema := false
	for _, op := range r.Ops {
		if op.Source == "graphql" {
			schema = true
		}
	}
	switch p := strings.ToLower(path); {
	case schema:
		c.addW("graphql", graphqlStrong, "GraphQL endpoint, schema read by introspection")
	case strings.Contains(r.Proof, "role=graphql") && strings.Contains(p, "graphiql"), strings.Contains(strings.ToLower(r.Title), "graphiql"):
		c.addW("graphql", graphqlStrong, "GraphQL IDE answers at "+path)
	case strings.Contains(r.Proof, "role=graphql"):
		c.add("graphql", "answers like GraphQL at "+path)
	}
}

// objects finds an object identifier in the path or in a parameter's name.
func (h *hunter) objects(c *cand, r engine.MapEntry, path string) {
	w := weights["object-id"]
	if len(r.Methods) > 0 && !slices.Contains(r.Methods, "GET") {
		w = objectWriteOnly // nothing reads it that we know of
	}
	for _, seg := range strings.Split(path, "/") {
		if strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "}") {
			c.addW("object-id", w, seg+" in the path")
			return
		}
	}
	for _, p := range engine.Watch(r) {
		if strings.HasSuffix(p, "(id)") {
			c.addW("object-id", w, "identifier parameter "+strings.TrimSuffix(p, " (id)"))
			return
		}
	}
}

// extraKinds are names the engine's kinds leave out: what a form passes
// to a shell, and what a search feeds a query.
var extraKinds = []struct {
	kind string
	re   *regexp.Regexp
}{
	{"command", regexp.MustCompile(`(?i)^(ip|ip_?address|address|addr|hostname|eqn|expr|expression)$`)},
	{"query", regexp.MustCompile(`(?i)^(q|query|search|keyword|term|filter|sort|order|order_?by|s)$`)},
}

// fileish are selectors that name a file only when their value looks like
// one (?page=file1.php); a page number is not.
var fileish = regexp.MustCompile(`(?i)^(page|view|module|doc)$`)

func (h *hunter) params(c *cand, r engine.MapEntry, raw string, u *url.URL) {
	seen := map[string]bool{}
	note := func(kind, name string) {
		if kind == "id" || seen[kind+name] {
			return // identifiers are the object-id signal
		}
		seen[kind+name] = true
		c.add("param-"+kind, name)
	}
	for _, w := range engine.Watch(r) {
		if i := strings.LastIndex(w, " ("); i > 0 {
			note(strings.TrimSuffix(w[i+2:], ")"), w[:i])
		}
	}
	for _, name := range allNames(r, u) {
		for _, k := range extraKinds {
			if k.re.MatchString(name) {
				note(k.kind, name)
			}
		}
		if fileish.MatchString(name) {
			if v := u.Query().Get(name); strings.ContainsAny(v, "./") {
				note("file", name+"="+clip(v, 30))
			}
		}
	}
}

func allNames(r engine.MapEntry, u *url.URL) []string {
	var out []string
	out = append(out, r.Params...)
	out = append(out, r.Body...)
	for _, o := range r.Ops {
		out = append(out, o.Query...)
		out = append(out, o.Body...)
	}
	for _, f := range r.Forms {
		out = append(out, f.Fields...)
	}
	for k := range u.Query() {
		out = append(out, k)
	}
	return out
}

func inputNames(r engine.MapEntry) []string {
	seen := map[string]bool{}
	var out []string
	add := func(n string) {
		if n == "" || seen[n] || strings.EqualFold(n, "submit") {
			return
		}
		seen[n] = true
		out = append(out, n)
	}
	for _, n := range r.Params {
		add(n)
	}
	for _, n := range r.Body {
		add(n)
	}
	for _, f := range r.Forms {
		for _, n := range f.Fields {
			add(n)
		}
	}
	return out
}

var writeMethods = map[string]bool{"POST": true, "PUT": true, "PATCH": true, "DELETE": true}

// writes: a write method no description asks credentials for, on a route
// that did not turn the plain request away.
func (h *hunter) writes(c *cand, r engine.MapEntry, ok bool, st int) {
	if st == 401 || st == 403 || strings.Contains(r.Proof, "auth=") {
		return // the run held a session, or the route wants one
	}
	guarded := map[string]bool{}
	for _, o := range r.Ops {
		if o.Auth {
			guarded[strings.ToUpper(o.Method)] = true
		}
	}
	var ms []string
	for _, m := range r.Methods {
		if m = strings.ToUpper(m); writeMethods[m] && !guarded[m] {
			ms = append(ms, m)
		}
	}
	if len(ms) == 0 {
		return
	}
	if ok {
		c.add("unauth-write", strings.Join(ms, ", ")+": nothing that names it asks for credentials, and a GET of it answers without a session (the write was not tried)")
	} else {
		c.addW("unauth-write", unauthWriteDry, strings.Join(ms, ", ")+": nothing that names it asks for credentials (not tried)")
	}
}

// host reads the signals of a hostname: a word that names a staging or
// internal machine.
func (h *hunter) host(r engine.MapEntry) {
	if r.Role != "live" && r.Role != "sibling" {
		return
	}
	var c *cand
	labels := strings.Split(r.Entity.Key, ".")
	if len(labels) < 3 {
		return // the registered domain's own label is not a hint
	}
	for _, w := range wordsOf(strings.Join(labels[:len(labels)-2], ".")) {
		pw, ok := pathWords[w]
		if !ok || pw.signal == "path-function" || pw.signal == "path-data" || pw.signal == "path-auth" || pw.signal == "path-search" {
			continue // for routes, not for names
		}
		if c == nil {
			c = h.get("Hostname", r.Entity.Key, r.Scope)
			if r.Entity.FirstSeen.After(h.cut) {
				c.fresh = true
			}
		}
		c.addW(pw.signal, pw.w, fmt.Sprintf("%q in the host name, which resolves", w))
	}
}

func (h *hunter) secrets() {
	for _, s := range h.in.Secrets {
		w := secretWeight[s.Severity]
		if w == 0 {
			w = secretWeight["info"]
		}
		c := h.get("URL", s.Where, "target")
		c.instances = append(c.instances, s.Where)
		c.addW("secret", w, fmt.Sprintf("%s (%s) in %s", s.Kind, s.Severity, s.Where))
	}
}

func (h *hunter) takeovers() {
	for _, t := range h.in.Takeovers {
		c := h.get("Hostname", t.Host, "target")
		w := weights["takeover"]
		if t.Strong {
			w = takeoverStrong
		}
		c.addW("takeover", w, t.Detail)
	}
}
