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
	Coverage string // visited, hint, capped (URLs)
	Role     string // live, app, auth, api, page, sibling, …
	Proof    string
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
	out := make([]MapEntry, 0, len(ents))
	for _, e := range ents {
		rows := ownObs(e, byEnt[e.ID])
		m := MapEntry{
			Entity:   e,
			Scope:    scopeLabel(e, hosts, domains, ips),
			Coverage: coverageOf(e, rows, left, runCapped),
			Role:     roleOf(e, rows, hosts),
			Proof:    proofOf(e, rows),
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

func fetched(obs []types.StoredObservation) bool {
	for _, o := range obs {
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
		if authGated(obs) {
			return "auth"
		}
		switch webextract.ClassifyURL(e.Key) {
		case "api":
			return "api"
		case "asset":
			return "asset"
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

func authGated(obs []types.StoredObservation) bool {
	for _, o := range obs {
		switch o.Collector {
		case "azhaq-http", "azhaq-paths":
		default:
			if o.Kind != "application" {
				continue
			}
		}
		st := statusOf(o.Payload)
		if st == 401 || st == 403 {
			return true
		}
		var p map[string]any
		if json.Unmarshal(o.Payload, &p) != nil {
			continue
		}
		if fmt.Sprint(p["auth"]) == "cookie" && (st == 200 || st == 0) {
			// cookie was sent; not necessarily gated
			continue
		}
	}
	return false
}

func proofOf(e types.Entity, obs []types.StoredObservation) string {
	var parts []string
	seen := map[string]bool{}
	for _, o := range obs {
		line := compactProof(o.Payload)
		if line == "" || seen[line] {
			continue
		}
		seen[line] = true
		parts = append(parts, line)
		if len(parts) == 2 {
			break
		}
	}
	return strings.Join(parts, " ")
}

func compactProof(raw json.RawMessage) string {
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return ""
	}
	var parts []string
	for _, k := range []string{"status", "title", "role", "ips", "count", "error", "warning", "note", "auth", "via"} {
		if v, ok := m[k]; ok && v != nil && fmt.Sprint(v) != "" {
			parts = append(parts, fmt.Sprintf("%s=%v", k, v))
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
		if hosts[e.Key] {
			return 0
		}
		if d := normalize.RegistrableDomain(e.Key); domains[d] {
			return 7
		}
		return 8
	case types.TypeIPAddress:
		if ips[e.Key] {
			return 1
		}
		return 8
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
	b.WriteString(m.Entity.Key)
	for _, p := range []string{m.Scope, m.Coverage, m.Role, m.Proof} {
		if p == "" {
			continue
		}
		b.WriteString("  ")
		b.WriteString(p)
	}
	return b.String()
}
