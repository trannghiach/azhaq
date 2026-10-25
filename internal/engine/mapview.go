package engine

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"

	"github.com/trannghiach/azhaq/internal/normalize"
	"github.com/trannghiach/azhaq/internal/types"
	"github.com/trannghiach/azhaq/internal/webextract"
)

// MapEntry is one line of the ranked recon map (confirmed vs hint).
type MapEntry struct {
	Entity   types.Entity
	Scope    string // target, fanout
	Coverage string // visited, catchall, hint, capped (URLs)
	Role     string // live, app, auth, forbidden, api, page, script, sibling, …
	Proof    string
	Template string   // URL template; set on every templated URL row
	Count    int      // URLs folded into this row by GroupTemplates
	Folded   int      // hostnames folded into a summary row (dead, wildcard)
	Methods  []string // from API descriptions
	Params   []string // query, form and API parameter names
	Forms    []MapForm
}

// MapForm is a form on a page: where it submits and the fields it sends.
type MapForm struct {
	Method string   `json:"method"`
	Action string   `json:"action"`
	Fields []string `json:"fields,omitempty"`
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
			Role:     roleOf(e, rows, hosts),
			Proof:    proofOf(e, rows),
		}
		if e.Type == types.TypeURL {
			if webextract.Templated(e.Key) {
				m.Template = webextract.Template(e.Key)
			}
			if op, ok := apiOps[e.Key]; ok {
				m.Methods = op.methods
				m.Params = op.params
				if m.Role == "page" && len(op.methods) > 0 {
					m.Role = "api"
				}
			}
			m.Forms, m.Params = pageForms(byEnt[e.ID], m.Params)
		}
		out = append(out, m)
	}
	sort.SliceStable(out, func(i, j int) bool {
		ri, rj := mapRank(out[i], hosts, domains, ips), mapRank(out[j], hosts, domains, ips)
		if ri != rj {
			return ri < rj
		}
		if out[i].Entity.Type != out[j].Entity.Type {
			return out[i].Entity.Type < out[j].Entity.Type
		}
		return out[i].Entity.Key < out[j].Entity.Key
	})
	return out
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
		return "visited"
	}
	for _, o := range obs {
		if isCatchAll(o) {
			return "catchall"
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
		if o.Collector == "azhaq-js" || o.Collector == "azhaq-crawl" {
			continue
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
		if o.Collector != "azhaq-dns" {
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
		case p.Result == "nxdomain" || p.Result == "nodata" || p.Result == "cname" || p.Error == "nxdomain":
			return "dead"
		}
	}
	return ""
}

// isCatchAll is a fetch that returned the origin's answer for any path.
func isCatchAll(o types.StoredObservation) bool {
	var p struct {
		CatchAll bool `json:"catchall"`
	}
	_ = json.Unmarshal(o.Payload, &p)
	return p.CatchAll
}

func fetched(obs []types.StoredObservation) bool {
	for _, o := range obs {
		if isCatchAll(o) {
			continue
		}
		if o.Collector == "azhaq-http" || o.Kind == "application" {
			return true
		}
		if o.Collector == "azhaq-paths" && o.Kind == "url" && statusOf(o.Payload) > 0 {
			return true
		}
	}
	return false
}

func roleOf(e types.Entity, obs []types.StoredObservation, hosts map[string]bool) string {
	switch e.Type {
	case types.TypeHostname:
		if r := dnsResult(obs); r != "" {
			return r
		}
		if hosts[e.Key] {
			return "live"
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
// fetched by two collectors shows status=403 once.
func proofOf(e types.Entity, obs []types.StoredObservation) string {
	keys := []string{"status", "title", "role", "ips", "cname", "count", "error", "warning", "note", "auth", "via"}
	vals := map[string]string{}
	for _, o := range obs {
		var m map[string]any
		if json.Unmarshal(o.Payload, &m) != nil {
			continue
		}
		for _, k := range keys {
			if _, done := vals[k]; done {
				continue
			}
			if v, ok := m[k]; ok && v != nil && fmt.Sprint(v) != "" {
				vals[k] = fmt.Sprint(v)
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

func mapRank(m MapEntry, hosts, domains, ips map[string]bool) int {
	e := m.Entity
	switch e.Type {
	case types.TypeHostname:
		if m.Role == "dead" || m.Role == "wildcard" {
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

func (m MapEntry) Line() string {
	var b strings.Builder
	b.WriteString(string(m.Entity.Type))
	b.WriteByte(' ')
	if m.Folded > 0 {
		switch m.Role {
		case "wildcard":
			fmt.Fprintf(&b, "(%d names answered only by a wildcard record)", m.Folded)
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
	for _, p := range []string{m.Scope, m.Coverage, m.Role, strings.Join(m.Methods, ","), m.Proof} {
		if p == "" {
			continue
		}
		b.WriteString("  ")
		b.WriteString(p)
	}
	if m.Count > 1 {
		fmt.Fprintf(&b, "  (%d urls)", m.Count)
	}
	return b.String()
}

// Details are the indented lines under a row: forms and parameter names.
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
		if len(f.Fields) > 0 {
			line += "  " + strings.Join(f.Fields, " ")
		}
		out = append(out, line)
	}
	if len(m.Params) > 0 {
		out = append(out, "params "+strings.Join(m.Params, " "))
	}
	return out
}

// GroupTemplates folds URL rows that share a template (/product?id={n})
// into the best-ranked one, and lists each form once, under the first row
// that has it: a newsletter form in the footer is not news on every page.
// Rows must already be sorted by BuildMap.
func GroupTemplates(rows []MapEntry) []MapEntry {
	out := groupTemplates(rows)
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

func groupTemplates(rows []MapEntry) []MapEntry {
	idx := map[string]int{}
	out := make([]MapEntry, 0, len(rows))
	folded := map[string]int{}
	for _, r := range rows {
		if r.Entity.Type == types.TypeHostname && (r.Role == "dead" || r.Role == "wildcard") {
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
			idx[key] = len(out)
			out = append(out, r)
			continue
		}
		g := &out[i]
		g.Count++
		for _, f := range r.Forms {
			g.Forms = addForm(g.Forms, f)
		}
		for _, p := range r.Params {
			g.Params = addName(g.Params, p)
		}
	}
	for i := range out {
		if out[i].Count == 1 {
			out[i].Count = 0
		}
	}
	return out
}

type apiOp struct {
	methods []string
	params  []string
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
			Methods []string `json:"methods"`
			Params  []string `json:"params"`
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
		out[u] = op
	}
	return out
}

// pageForms collects the forms crawled on a page and adds the page's other
// parameter names (query strings in its links) to params.
func pageForms(obs []types.StoredObservation, params []string) ([]MapForm, []string) {
	var forms []MapForm
	inForm := map[string]bool{}
	for _, o := range obs {
		if o.Collector != "azhaq-crawl" || o.Kind != "form" {
			continue
		}
		var f MapForm
		if json.Unmarshal(o.Payload, &f) != nil {
			continue
		}
		forms = addForm(forms, f)
		for _, n := range f.Fields {
			inForm[n] = true
		}
	}
	for _, o := range obs {
		if o.Collector != "azhaq-crawl" || o.Kind != "param" {
			continue
		}
		var p struct {
			Params []string `json:"params"`
		}
		if json.Unmarshal(o.Payload, &p) != nil {
			continue
		}
		for _, n := range p.Params {
			if !inForm[n] {
				params = addName(params, n)
			}
		}
	}
	return forms, params
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
