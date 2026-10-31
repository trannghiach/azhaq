package engine

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"slices"
	"sort"
	"strings"

	"github.com/trannghiach/azhaq/internal/normalize"
	"github.com/trannghiach/azhaq/internal/webextract"
	"github.com/trannghiach/azhaq/types"
)

// MapEntry is one line of the ranked recon map (confirmed vs hint).
type MapEntry struct {
	Entity    types.Entity
	Scope     string // target, fanout
	Coverage  string // visited, catchall, error, hint, capped (URLs)
	Role      string // live, app, auth, forbidden, api, page, script, sibling, …
	Proof     string
	Status    int      // the URL's own answer (first hop), 0 if not fetched
	Title     string   // the page title, if any
	Template  string   // URL template; set on every templated URL row
	Count     int      // URLs folded into this row by GroupTemplates
	NotAsked  int      // of Count, the URLs found and not requested (-per-template, a budget)
	Folded    int      // hostnames folded into a summary row (dead, wildcard)
	Methods   []string // from API descriptions and the calls scripts make
	Params    []string // query, form and API parameter names
	Body      []string // names scripts send in request bodies
	Ops       []Op     // per method: what is sent, from API descriptions and scripts
	Forms     []MapForm
	Found     []webextract.Site // where scripts name the route, calls first
	Guard     string            // client-route: what the app's router checks before it draws the view
	Protocol  string            // websocket: socket.io, or "" for a plain WebSocket
	Namespace string            // websocket: socket.io's namespace, when known
	// How the URL is known (answered, browser, described, called, linked,
	// archived, guessed, given) and the collectors behind it, sorted.
	Evidence     string   `json:"evidence,omitempty"`
	EvidenceFrom []string `json:"evidence_from,omitempty"`
	// What a 5xx the run got says less of than it looks: "500 without
	// input" when the route takes names and the request carried none.
	Answer string `json:"answer,omitempty"`
}

// maxFound caps the places a row lists for where scripts name it.
const maxFound = 3

// Op is one operation on a route: a method and the names it sends.
type Op struct {
	Method      string   `json:"method"`
	Query       []string `json:"query,omitempty"`
	Path        []string `json:"path,omitempty"`
	Header      []string `json:"header,omitempty"`
	Cookie      []string `json:"cookie,omitempty"`
	Body        []string `json:"body,omitempty"`
	BodyType    string   `json:"body_type,omitempty"`
	Auth        bool     `json:"auth,omitempty"` // the description asks for credentials
	Summary     string   `json:"summary,omitempty"`
	OperationID string   `json:"operation_id,omitempty"`
	Source      string   `json:"source,omitempty"`  // js-call, openapi
	Partial     bool     `json:"partial,omitempty"` // graphql: recovered from errors, not introspected
}

// MapForm is a form on a page: where it submits and the fields it sends,
// and for a POST how it encodes them and which fields are files.
type MapForm struct {
	Method  string   `json:"method"`
	Action  string   `json:"action"`
	Enctype string   `json:"enctype,omitempty"`
	Fields  []string `json:"fields,omitempty"`
	Files   []string `json:"files,omitempty"`
}

// BuildMap ranks seed host, live apps, auth-gated, APIs, then fan-out.
// Hints and leftover/capped URLs sort after visited nodes.
// runCapped is the run summary: leftover URLs are hints unless the run
// actually hit the item/depth cap.
func BuildMap(ents []types.Entity, seeds []types.Seed, obs []types.StoredObservation, leftover []types.Seed, runCapped bool) []MapEntry {
	hosts, domains, ips := seedScope(seeds)
	byEnt := map[string][]types.StoredObservation{}
	for _, o := range obs {
		byEnt[o.EntityID] = append(byEnt[o.EntityID], o)
	}
	left := map[string]bool{}
	for _, s := range leftover {
		s = normalize.Seed(s)
		if s.Type == types.TypeURL && s.Key() != "" {
			left[s.Key()] = true
		}
	}
	apiOps := apiOperations(obs)
	probes := pathProbes(obs)
	finds := findings(obs)
	evidence := evidenceIndex(obs)
	givenURLs := map[string]bool{}
	for _, s := range seeds {
		if s = normalize.Seed(s); s.Type == types.TypeURL {
			givenURLs[s.Key()] = true
		}
	}
	decl := declaredRoles(obs)
	secured := securedHosts(obs)
	out := make([]MapEntry, 0, len(ents))
	for _, e := range ents {
		rows := ownObs(e, byEnt[e.ID])
		if e.Type == types.TypeURL {
			rows = append(rows, probes[e.Key]...)
		}
		m := MapEntry{
			Entity:   e,
			Scope:    scopeLabel(e, hosts, domains, ips),
			Coverage: coverageOf(e, rows, left, runCapped),
			Role:     roleOf(e, rows, hosts, domains),
			Proof:    proofOf(e, rows),
		}
		if e.Type == types.TypeURL {
			if foldedHTTP(e.Key, m.Coverage, secured) {
				continue // its https URL is the row
			}
			m.Status, m.Title = answerOf(rows)
			if d, ok := decl[e.Key]; ok {
				// What a GET does not tell: a view the app's router draws
				// (the server answers it with the app's shell), a
				// WebSocket endpoint, a source map, a build manifest. A
				// view in the path the server answered itself (a sign-in,
				// a page it renders) keeps the server's role, with what
				// the router checks noted beside it.
				if m.Coverage != "visited" && m.Role != "auth" && m.Role != "forbidden" {
					m.Role = d.role
				}
				m.Guard, m.Protocol, m.Namespace = d.guard, d.protocol, d.namespace
				switch p := d.proof(); {
				case m.Proof == "":
					m.Proof = p
				case p != "" && !strings.Contains(m.Proof, p):
					m.Proof += " " + p
				}
			}
			if webextract.Templated(e.Key) {
				m.Template = webextract.Template(e.Key)
			}
			f := finds[e.Key]
			if webextract.VersionPrefix(e.Key) && f.stringsOnly() && (m.Coverage == "catchall" || m.Coverage == "gone") {
				continue // /v3 in a script: a prefix routes are built on, and nothing answers at it
			}
			if f.scriptsOnly() && (m.Role == "page" || m.Role == "api") && m.Coverage == "gone" && len(apiOps[e.Key].methods) == 0 {
				// Named in a script with no method to go by: a GET that
				// answers 404 says nothing of a route scripts may POST to.
				m.Coverage = "hint"
				m.Proof = fmt.Sprintf("GET answers %d; found only in scripts, method unknown", m.Status)
			}
			m.Found = f.sites
			if op, ok := apiOps[e.Key]; ok {
				m.Methods = op.methods
				m.Params = op.params
				m.Body = op.body
				m.Ops = op.ops
				if m.Coverage == "catchall" && !hasGET(op.methods) {
					// Called with POST or PUT: a GET answered like an
					// unknown path, which says nothing about the route.
					m.Coverage, m.Status, m.Title = "hint", 0, ""
					m.Proof = "GET answers like an unknown path"
				}
				if m.Coverage == "gone" && len(op.methods) > 0 && !hasGET(op.methods) {
					// A route only written to: no GET handler is not "not
					// there".
					m.Coverage = "hint"
					m.Proof = fmt.Sprintf("GET answers %d; called with %s", m.Status, strings.Join(op.methods, ", "))
				}
				if m.Role == "page" && len(op.methods) > 0 {
					m.Role = "api"
				}
			}
			if gql := graphqlOps(byEnt[e.ID]); len(gql) > 0 {
				m.Ops = append(m.Ops, gql...)
				m.Methods = addName(m.Methods, "POST")
			}
			// Body is every operation's body fields, whatever described
			// them: a description lists them on its operations only.
			for _, o := range m.Ops {
				for _, n := range o.Body {
					m.Body = addName(m.Body, n)
				}
			}
			m.Forms = pageForms(byEnt[e.ID])
			m.Answer = answerNote(m, e.Key)
			m.setEvidence(evidence[e.Key], rows, givenURLs[e.Key])
			// The URL's own query names; those in the links on a page
			// are the links' rows'.
			if u, err := url.Parse(e.Key); err == nil {
				for _, k := range queryNames(u.RawQuery) {
					m.Params = addName(m.Params, k)
				}
			}
		}
		out = append(out, m)
	}
	sort.SliceStable(out, func(i, j int) bool {
		ri, rj := mapRank(out[i], hosts, domains, ips), mapRank(out[j], hosts, domains, ips)
		if ri != rj {
			return ri < rj
		}
		if vi, vj := drawn(out[i]), drawn(out[j]); vi != vj {
			return vj // the server's routes before the app's views and sockets
		}
		if out[i].Entity.Type != out[j].Entity.Type {
			return out[i].Entity.Type < out[j].Entity.Type
		}
		return out[i].Entity.Key < out[j].Entity.Key
	})
	return out
}

// answerOf is the status and title a URL answered with: a real page
// first, else the catch-all answer.
func answerOf(obs []types.StoredObservation) (int, string) {
	status, title := 0, ""
	for _, o := range obs {
		if o.Kind == "error" || (o.Collector != "azhaq-http" && o.Collector != "azhaq-paths" && o.Kind != "application") {
			continue
		}
		st := statusOf(o.Payload)
		if st == 0 {
			continue
		}
		var p struct {
			Title string `json:"title"`
		}
		_ = json.Unmarshal(o.Payload, &p)
		if !isCatchAll(o) {
			return st, p.Title
		}
		if status == 0 {
			status, title = st, p.Title
		}
	}
	return status, title
}

func scopeLabel(e types.Entity, hosts, domains, ips map[string]bool) string {
	if entityRank(e, hosts, domains, ips) <= 1 {
		return "target"
	}
	return "fanout"
}

func coverageOf(e types.Entity, obs []types.StoredObservation, leftover map[string]bool, runCapped bool) string {
	if e.Type != types.TypeURL {
		return ""
	}
	if fetched(obs) {
		if st := gone(obs); st {
			return "gone" // found somewhere, and the server says it is not there
		}
		return "visited"
	}
	for _, o := range obs {
		if isCatchAll(o) {
			return "catchall"
		}
	}
	for _, o := range obs {
		if o.Kind == "error" && (o.Collector == "azhaq-http" || o.Collector == "httpx") {
			return "error" // requested, no answer (httpx -probe's failed lines, taken in)
		}
		if o.Kind == "skipped" {
			return "skipped" // found, deliberately not requested
		}
	}
	if leftover[e.Key] && runCapped {
		return "capped"
	}
	return "hint"
}

// ownObs drops child crawl/JS facts and payloads that describe another URL
// so / does not inherit /api/* role or /admin 403.
func ownObs(e types.Entity, obs []types.StoredObservation) []types.StoredObservation {
	if e.Type != types.TypeURL {
		return obs
	}
	var out []types.StoredObservation
	for _, o := range obs {
		if o.Collector == "azhaq-js" || o.Collector == "azhaq-crawl" || o.Collector == "azhaq-render" {
			continue
		}
		if o.Collector == "azhaq-shots" && o.Kind == "url" {
			continue // a write the page sent, to itself too: its route's
		}
		if u := payloadURL(o); u != "" && !sameRoute(u, e.Key) {
			continue
		}
		out = append(out, o)
	}
	return out
}

func payloadURL(o types.StoredObservation) string {
	var p struct {
		URL string `json:"url"`
	}
	_ = json.Unmarshal(o.Payload, &p)
	return p.URL
}

func sameRoute(a, b string) bool {
	return webextract.RouteKey(a) == webextract.RouteKey(b)
}

// dnsResult is "dead" for a name with no address and "wildcard" for one
// answered only by a wildcard record, from azhaq-dns.
func dnsResult(obs []types.StoredObservation) string {
	for _, o := range obs {
		if o.Collector != "azhaq-dns" && o.Kind != "dns" {
			continue
		}
		var p struct {
			Result   string `json:"result"`
			Error    string `json:"error"`
			Wildcard bool   `json:"wildcard"`
		}
		_ = json.Unmarshal(o.Payload, &p)
		switch {
		case p.Wildcard:
			return "wildcard"
		case p.Result == "nxdomain" || p.Result == "nodata" || p.Result == "cname" || p.Result == "servfail" || p.Error == "nxdomain":
			return "dead"
		}
	}
	return ""
}

// resolved: azhaq-dns looked the name up in this run.
func resolved(obs []types.StoredObservation) bool {
	for _, o := range obs {
		if o.Collector == "azhaq-dns" || o.Kind == "dns" {
			return true
		}
	}
	return false
}

// isCatchAll is a fetch that returned the origin's answer for any path.
func isCatchAll(o types.StoredObservation) bool {
	var p struct {
		CatchAll bool `json:"catchall"`
	}
	_ = json.Unmarshal(o.Payload, &p)
	return p.CatchAll
}

// gone: the URL's own answer is 404 or 410.
func gone(obs []types.StoredObservation) bool {
	for _, o := range obs {
		if o.Kind == "error" || isCatchAll(o) || o.Collector != "azhaq-http" && o.Kind != "application" {
			continue
		}
		switch statusOf(o.Payload) {
		case 404, 410:
			return true
		case 0:
		default:
			return false
		}
	}
	return false
}

func fetched(obs []types.StoredObservation) bool {
	for _, o := range obs {
		if isCatchAll(o) || o.Kind == "error" {
			continue
		}
		if (o.Collector == "azhaq-http" || o.Kind == "application") && statusOf(o.Payload) > 0 {
			return true
		}
		if o.Collector == "azhaq-paths" && o.Kind == "url" && statusOf(o.Payload) > 0 {
			return true
		}
	}
	return false
}

func roleOf(e types.Entity, obs []types.StoredObservation, hosts, domains map[string]bool) string {
	switch e.Type {
	case types.TypeHostname:
		if r := dnsResult(obs); r != "" {
			return r
		}
		if !resolved(obs) {
			return "unresolved" // a name from a source or a list, not looked up
		}
		if hosts[e.Key] || under(e.Key, domains) {
			return "live" // one of your targets: a host you gave, or a name of a domain you gave
		}
		return "sibling"
	case types.TypeDomain:
		return "domain"
	case types.TypeIPAddress:
		return "addr"
	case types.TypeOrganization:
		return "org"
	case types.TypeURL:
		switch gate(obs) {
		case 401:
			return "auth"
		case 403:
			return "forbidden"
		}
		switch c := webextract.ClassifyURL(e.Key); c {
		case "api", "asset", "script":
			return c
		}
		if fetched(obs) && appRoot(e.Key) {
			return "app"
		}
		return webextract.ClassifyURL(e.Key)
	default:
		return ""
	}
}

func appRoot(raw string) bool {
	u, err := url.Parse(webextract.RouteKey(raw))
	if err != nil {
		return false
	}
	return u.Path == "/" || u.Path == ""
}

// gate is 401 (credentials required) or 403 (refused) from a real fetch
// of the URL itself, else 0. A 403 is not an auth wall: WAFs, directory
// listings and IP rules send it too.
func gate(obs []types.StoredObservation) int {
	for _, o := range obs {
		switch o.Collector {
		case "azhaq-http", "azhaq-paths":
		default:
			if o.Kind != "application" {
				continue
			}
		}
		if isCatchAll(o) {
			continue
		}
		if st := statusOf(o.Payload); st == 401 || st == 403 {
			return st
		}
	}
	return 0
}

// proofOf summarizes a row's facts: the first value of each key, so a page
// fetched by two collectors shows status=403 once; the open ports are the
// newest scan's, as a scan a limit stopped is followed by the one that
// finishes it.
func proofOf(e types.Entity, obs []types.StoredObservation) string {
	keys := []string{"status", "title", "role", "ips", "cname", "open", "count", "error", "skipped", "word", "warning", "note", "auth", "via"}
	vals := map[string]string{}
	for _, o := range obs {
		var m map[string]any
		if json.Unmarshal(o.Payload, &m) != nil {
			continue
		}
		if v, ok := m["open"]; ok && v != nil && o.Kind == "ports" && m["range"] != true {
			vals["open"] = fmt.Sprint(v)
		}
		for _, k := range keys {
			if _, done := vals[k]; done {
				continue
			}
			if v, ok := m[k]; ok && v != nil && fmt.Sprint(v) != "" {
				vals[k] = fmt.Sprint(v)
				if k == "error" {
					vals[k] = ShortError(vals[k])
				}
			}
		}
	}
	var parts []string
	for _, k := range keys {
		if v, ok := vals[k]; ok {
			parts = append(parts, k+"="+v)
		}
	}
	return strings.Join(parts, " ")
}

func statusOf(raw json.RawMessage) int {
	var p struct {
		Status int `json:"status"`
	}
	_ = json.Unmarshal(raw, &p)
	if p.Status != 0 {
		return p.Status
	}
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return 0
	}
	switch n := m["status"].(type) {
	case float64:
		return int(n)
	default:
		var i int
		fmt.Sscanf(fmt.Sprint(n), "%d", &i)
		return i
	}
}

// under says whether host is one of domains or a name below one.
func under(host string, domains map[string]bool) bool {
	for h := host; h != ""; {
		if domains[h] {
			return true
		}
		_, rest, ok := strings.Cut(h, ".")
		if !ok {
			return false
		}
		h = rest
	}
	return false
}

func mapRank(m MapEntry, hosts, domains, ips map[string]bool) int {
	e := m.Entity
	switch e.Type {
	case types.TypeHostname:
		if m.Role == "dead" || m.Role == "wildcard" || m.Role == "unresolved" {
			return 9
		}
		if hosts[e.Key] {
			return 0
		}
		if d := normalize.RegistrableDomain(e.Key); domains[d] {
			return 7
		}
		return 8
	case types.TypeIPAddress:
		return 8 // addresses follow the names that resolve to them
	case types.TypeDomain:
		if domains[e.Key] {
			return 1
		}
		return 8
	case types.TypeURL:
		h := normalize.HostFromURL(e.Key)
		onSeed := hosts[h]
		if ip := net.ParseIP(h); ip != nil && ips[ip.String()] {
			onSeed = true
		}
		if !onSeed {
			if d := normalize.RegistrableDomain(h); domains[d] {
				return 7
			}
			return 9
		}
		switch {
		case m.Coverage == "gone":
			return 8
		case m.Coverage == "visited" && m.Role == "app":
			return 2
		case m.Role == "auth":
			return 3
		case m.Role == "api" && m.Coverage == "visited":
			return 4
		case m.Coverage == "visited":
			return 5
		case m.Role == "api":
			return 6
		default:
			return 6
		}
	default:
		return 10
	}
}

// drawn: a view the app's router draws, or a socket; no page of the
// server's.
func drawn(m MapEntry) bool { return m.Role == "client-route" || m.Role == "websocket" }

func (m MapEntry) Line() string {
	var b strings.Builder
	b.WriteString(string(m.Entity.Type))
	b.WriteByte(' ')
	if m.Folded > 0 {
		switch m.Role {
		case "wildcard":
			fmt.Fprintf(&b, "(%d names answered only by a wildcard record)", m.Folded)
		case "unresolved":
			fmt.Fprintf(&b, "(%d names from sources, not resolved in this run)", m.Folded)
		default:
			fmt.Fprintf(&b, "(%d names with no address)", m.Folded)
		}
		return b.String()
	}
	if m.Count > 1 {
		b.WriteString(m.Template)
	} else {
		b.WriteString(m.Entity.Key)
	}
	for _, p := range []string{m.Scope, m.Coverage, m.Role, strings.Join(m.Methods, ","), m.Proof, m.Answer, m.EvidenceTag()} {
		if p == "" {
			continue
		}
		b.WriteString("  ")
		b.WriteString(p)
	}
	if m.Count > 1 {
		if m.NotAsked > 0 {
			fmt.Fprintf(&b, "  (%d urls, %d not asked)", m.Count, m.NotAsked)
		} else {
			fmt.Fprintf(&b, "  (%d urls)", m.Count)
		}
	}
	return b.String()
}

// Details are the indented lines under a row: forms, operations (a
// GraphQL endpoint's as their signatures) and parameter names.
func (m MapEntry) Details() []string {
	var out []string
	origin := ""
	if u, err := url.Parse(m.Entity.Key); err == nil {
		origin = u.Scheme + "://" + u.Host
	}
	for _, f := range m.Forms {
		action := strings.TrimPrefix(f.Action, origin)
		if action == "" {
			action = "/"
		}
		line := "form " + f.Method + " " + action
		if f.Enctype == "multipart/form-data" {
			line += " multipart"
		}
		if len(f.Fields) > 0 {
			line += "  " + strings.Join(f.Fields, " ")
		}
		out = append(out, line)
	}
	seen := map[string]bool{}
	gql := 0
	for _, op := range m.Ops {
		if op.Source == "graphql" {
			if gql == 0 && op.Partial {
				out = append(out, "GraphQL: introspection disabled, schema recovered (partial, may lack types and fields)")
			}
			if gql++; gql <= maxGraphQLLines {
				out = append(out, op.Summary)
			}
			continue
		}
		line := op.Method
		if len(op.Query) > 0 {
			line += "  ?" + strings.Join(op.Query, " ")
		}
		if len(op.Body) > 0 {
			line += "  body " + strings.Join(op.Body, " ")
		}
		if seen[line] {
			continue
		}
		seen[line] = true
		out = append(out, line)
	}
	if gql > maxGraphQLLines {
		out = append(out, fmt.Sprintf("… %d more GraphQL operations (azhaq export -format sdl)", gql-maxGraphQLLines))
	}
	if len(m.Params) > 0 && len(m.Ops) == 0 {
		out = append(out, "params "+strings.Join(m.Params, " "))
	}
	return out
}

// GroupTemplates folds URL rows that share a template (/product?id={n})
// into the best-ranked one, and lists each form once, under the first row
// that has it: a newsletter form in the footer is not news on every page.
// Rows must already be sorted by BuildMap.
func GroupTemplates(rows []MapEntry) []MapEntry {
	return dedupeForms(groupTemplates(rows, true))
}

// GroupURLTemplates folds URL templates only: every name is its own row,
// for query, where each one can be asked about.
func GroupURLTemplates(rows []MapEntry) []MapEntry {
	return dedupeForms(groupTemplates(rows, false))
}

func dedupeForms(out []MapEntry) []MapEntry {
	seen := map[string]bool{}
	for i := range out {
		var keep []MapForm
		for _, f := range out[i].Forms {
			k := f.Method + " " + f.Action + " " + strings.Join(f.Fields, " ")
			if seen[k] {
				continue
			}
			seen[k] = true
			keep = append(keep, f)
		}
		out[i].Forms = keep
	}
	return out
}

func groupTemplates(rows []MapEntry, foldNames bool) []MapEntry {
	idx := map[string]int{}
	out := make([]MapEntry, 0, len(rows))
	folded := map[string]int{}
	for _, r := range rows {
		if foldNames && r.Entity.Type == types.TypeHostname && (r.Role == "dead" || r.Role == "wildcard" || r.Role == "unresolved") {
			if i, ok := folded[r.Role]; ok {
				out[i].Folded++
				continue
			}
			r.Folded = 1
			folded[r.Role] = len(out)
			out = append(out, r)
			continue
		}
		if r.Template == "" {
			out = append(out, r)
			continue
		}
		key := r.Scope + "\x00" + r.Template
		i, ok := idx[key]
		if !ok {
			r.Count = 1
			r.NotAsked = notAsked(r)
			idx[key] = len(out)
			out = append(out, r)
			continue
		}
		g := &out[i]
		g.Count++
		g.NotAsked += notAsked(r)
		g.mergeEvidence(r)
		for _, f := range r.Forms {
			g.Forms = addForm(g.Forms, f)
		}
		for _, p := range r.Params {
			g.Params = addName(g.Params, p)
		}
	}
	for i := range out {
		if out[i].Count == 1 {
			out[i].Count, out[i].NotAsked = 0, 0
		}
	}
	return out
}

// notAsked is 1 for a URL found and never requested.
func notAsked(r MapEntry) int {
	if r.Coverage == "hint" || r.Coverage == "capped" {
		return 1
	}
	return 0
}

type apiOp struct {
	methods []string
	params  []string
	body    []string
	ops     []Op
}

// FoundKey is the map's key for a URL a collector found: a view of a
// single-page app keeps its hash route (/#/administration), the only part
// that tells it from the app's front page.
func FoundKey(raw, role string) (string, error) {
	if role == "client-route" {
		return normalize.ClientURL(raw)
	}
	return normalize.URL(raw)
}

// declared is what a script says a URL is, where a GET would not tell.
type declared struct {
	role, guard, protocol, namespace string
}

func (d declared) proof() string {
	var parts []string
	for _, kv := range [][2]string{{"guard", d.guard}, {"protocol", d.protocol}, {"namespace", d.namespace}} {
		if kv[1] != "" {
			parts = append(parts, kv[0]+"="+kv[1])
		}
	}
	return strings.Join(parts, " ")
}

// declaredRoles indexes the URLs azhaq-js read as views of the app's
// router, WebSocket endpoints, source maps and build manifests.
func declaredRoles(obs []types.StoredObservation) map[string]declared {
	out := map[string]declared{}
	for _, o := range obs {
		if o.Collector != "azhaq-js" || o.Kind != "url" {
			continue
		}
		var p struct {
			URL       string `json:"url"`
			Role      string `json:"role"`
			Guard     string `json:"guard"`
			Protocol  string `json:"protocol"`
			Namespace string `json:"namespace"`
		}
		if json.Unmarshal(o.Payload, &p) != nil || p.URL == "" {
			continue
		}
		switch p.Role {
		case "client-route", "websocket", "sourcemap", "manifest":
		default:
			continue
		}
		u, err := FoundKey(p.URL, p.Role)
		if err != nil {
			continue
		}
		d, ok := out[u]
		if !ok {
			d.role = p.Role
		}
		if d.guard == "" {
			d.guard = p.Guard
		}
		if d.protocol == "" {
			d.protocol = p.Protocol
		}
		if d.namespace == "" {
			d.namespace = p.Namespace
		}
		out[u] = d
	}
	return out
}

// finding is how a URL was found: named in a script's strings or in a
// JSON document, called by a script, or anything else (a link, a form,
// an archive, an API description, a wordlist, the browser); and where
// scripts name it.
type finding struct {
	strs, calls, other bool
	sites              []webextract.Site
}

// scriptsOnly: only scripts name or call it.
func (f finding) scriptsOnly() bool { return (f.strs || f.calls) && !f.other }

// stringsOnly: only strings name it, nothing calls it.
func (f finding) stringsOnly() bool { return f.strs && !f.calls && !f.other }

// findings indexes how each URL was found, with up to maxFound places
// scripts name it, calls first.
func findings(obs []types.StoredObservation) map[string]finding {
	out := map[string]finding{}
	strSites := map[string][]webextract.Site{}
	for _, o := range obs {
		if o.Kind != "url" {
			continue
		}
		var p struct {
			URL     string            `json:"url"`
			Via     string            `json:"via"`
			Role    string            `json:"role"`
			FoundIn []webextract.Site `json:"found_in"`
		}
		if json.Unmarshal(o.Payload, &p) != nil || p.URL == "" {
			continue
		}
		u, err := FoundKey(p.URL, p.Role)
		if err != nil {
			continue
		}
		f := out[u]
		switch {
		case o.Collector == "azhaq-js" && p.Via == "js-call":
			f.calls = true
			f.sites = addSites(f.sites, p.FoundIn)
		case o.Collector == "azhaq-js" && p.Via == "js", o.Collector == "azhaq-crawl" && p.Via == "json":
			f.strs = true
			strSites[u] = addSites(strSites[u], p.FoundIn)
		default:
			f.other = true
		}
		out[u] = f
	}
	for u, sites := range strSites {
		f := out[u]
		f.sites = addSites(f.sites, sites)
		out[u] = f
	}
	return out
}

func addSites(xs, ys []webextract.Site) []webextract.Site {
	for _, y := range ys {
		dup := false
		for _, x := range xs {
			if x.Script == y.Script && x.Source == y.Source && x.Line == y.Line && x.Col == y.Col {
				dup = true
				break
			}
		}
		if !dup && len(xs) < maxFound {
			xs = append(xs, y)
		}
	}
	return xs
}

// pathProbes indexes wordlist hits by the URL they probed. They are stored
// on the page that was swept, and files such as robots.txt are not fetched
// again, so without this they would read as hints.
func pathProbes(obs []types.StoredObservation) map[string][]types.StoredObservation {
	out := map[string][]types.StoredObservation{}
	for _, o := range obs {
		if o.Collector != "azhaq-paths" || o.Kind != "url" {
			continue
		}
		if u, err := normalize.URL(payloadURL(o)); err == nil {
			out[u] = append(out[u], o)
		}
	}
	return out
}

// apiOperations indexes the methods and parameter names collectors report
// for a URL: API descriptions, and query names next to routes in scripts.
func apiOperations(obs []types.StoredObservation) map[string]apiOp {
	out := map[string]apiOp{}
	for _, o := range obs {
		if o.Kind != "url" {
			continue
		}
		var p struct {
			URL     string   `json:"url"`
			Via     string   `json:"via"`
			Methods []string `json:"methods"`
			Params  []string `json:"params"`
			Body    []string `json:"body"`
			Ops     []Op     `json:"ops"`
		}
		if json.Unmarshal(o.Payload, &p) != nil || len(p.Methods)+len(p.Params) == 0 {
			continue
		}
		u, err := normalize.URL(p.URL)
		if err != nil {
			continue
		}
		op := out[u]
		for _, m := range p.Methods {
			op.methods = addName(op.methods, m)
		}
		for _, n := range p.Params {
			op.params = addName(op.params, n)
		}
		for _, n := range p.Body {
			op.body = addName(op.body, n)
		}
		for _, x := range p.Ops {
			if x.Source == "" {
				x.Source = p.Via
			}
			// Every page Chrome renders sends the app's same write, and
			// two scripts may make the same call: the operation once.
			if !slices.ContainsFunc(op.ops, func(y Op) bool { return sameOp(x, y) }) {
				op.ops = append(op.ops, x)
			}
		}
		out[u] = op
	}
	return out
}

func sameOp(a, b Op) bool {
	return a.Method == b.Method && a.Source == b.Source && a.BodyType == b.BodyType && a.Auth == b.Auth &&
		a.Summary == b.Summary && a.OperationID == b.OperationID && slices.Equal(a.Query, b.Query) &&
		slices.Equal(a.Path, b.Path) && slices.Equal(a.Header, b.Header) && slices.Equal(a.Cookie, b.Cookie) && slices.Equal(a.Body, b.Body)
}

// pageForms collects the forms found on a page (crawled, rendered, or
// taken in from katana).
func pageForms(obs []types.StoredObservation) []MapForm {
	var forms []MapForm
	for _, o := range obs {
		if o.Kind != "form" {
			continue
		}
		var f MapForm
		if json.Unmarshal(o.Payload, &f) != nil {
			continue
		}
		forms = addForm(forms, f)
	}
	return forms
}

// queryNames are the names in a raw query, in their order, once each.
func queryNames(raw string) []string {
	var out []string
	for _, part := range strings.Split(raw, "&") {
		k, _, _ := strings.Cut(part, "=")
		if n, err := url.QueryUnescape(k); err == nil && n != "" {
			out = addName(out, n)
		}
	}
	return out
}

func hasGET(methods []string) bool {
	for _, m := range methods {
		if strings.EqualFold(m, "GET") {
			return true
		}
	}
	return false
}

func addForm(xs []MapForm, f MapForm) []MapForm {
	for _, x := range xs {
		if x.Method == f.Method && x.Action == f.Action && strings.Join(x.Fields, " ") == strings.Join(f.Fields, " ") {
			return xs
		}
	}
	return append(xs, f)
}

func addName(xs []string, n string) []string {
	for _, x := range xs {
		if x == n {
			return xs
		}
	}
	return append(xs, n)
}
