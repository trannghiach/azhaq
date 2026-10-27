package engine

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/trannghiach/azhaq/internal/normalize"
	"github.com/trannghiach/azhaq/types"
)

// Failure is work that did not get its answer, grouped: a source that
// failed for a domain, requests to a target that got no response, a
// resolver that gave up, a target that answered 429.
type Failure struct {
	Collector string   `json:"collector"`
	Source    string   `json:"source,omitempty"` // a third-party source (crtsh, wayback)
	Error     string   `json:"error"`
	Retryable bool     `json:"retryable"`
	Count     int      `json:"count"`
	Targets   []string `json:"targets"` // the first 100; azhaq query -failed lists all
	// Fanout: none of the targets is what the user asked about (the
	// domain of a URL, a name found on the way).
	Fanout bool `json:"fanout,omitempty"`
	// Partial: a third-party source failed, and for each of its targets
	// other sources answered. The results stand on those; the failure is
	// listed, and does not make the exit code 3 (-fail-on-errors does).
	Partial bool `json:"partial,omitempty"`
}

// Skip is a request or a target Azhaq chose not to touch, and why.
type Skip struct {
	Target string `json:"target"`
	Reason string `json:"reason"`
}

// maxFailureTargets caps the targets a summary names per kind of
// failure; azhaq query -failed lists every one.
const maxFailureTargets = 100

// Failures lists what failed in obs, grouped by collector, source and
// kind of error, most frequent first. ents names the entities the
// observations sit on.
func Failures(ents []types.Entity, obs []types.StoredObservation) []Failure {
	idx := map[string]int{}
	var out []Failure
	eachFailure(ents, obs, func(collector, source, raw, target string) {
		msg := ShortError(raw)
		k := collector + "\x00" + source + "\x00" + msg
		i, ok := idx[k]
		if !ok {
			i = len(out)
			idx[k] = i
			out = append(out, Failure{Collector: collector, Source: source, Error: msg, Retryable: Retryable(raw)})
		}
		f := &out[i]
		f.Count++
		if target != "" && len(f.Targets) < maxFailureTargets && !contains(f.Targets, target) {
			f.Targets = append(f.Targets, target)
		}
	})
	sort.SliceStable(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	return out
}

// FailedTarget is one target whose work did not get its answer.
type FailedTarget struct {
	Target    string `json:"target"`
	Collector string `json:"collector"`
	Source    string `json:"source,omitempty"`
	Error     string `json:"error"`
	Retryable bool   `json:"retryable"`
}

// FailedTargets lists every failed target in obs, once per collector,
// source and error: the list to retry.
func FailedTargets(ents []types.Entity, obs []types.StoredObservation) []FailedTarget {
	seen := map[string]bool{}
	var out []FailedTarget
	eachFailure(ents, obs, func(collector, source, raw, target string) {
		msg := ShortError(raw)
		k := target + "\x00" + collector + "\x00" + source + "\x00" + msg
		if target == "" || seen[k] {
			return
		}
		seen[k] = true
		out = append(out, FailedTarget{Target: target, Collector: collector, Source: source, Error: msg, Retryable: Retryable(raw)})
	})
	sort.SliceStable(out, func(i, j int) bool { return out[i].Target < out[j].Target })
	return out
}

// eachFailure calls add for every failure in obs: a collector's error on
// a target, a third-party source's error, a 429 from the target.
func eachFailure(ents []types.Entity, obs []types.StoredObservation, add func(collector, source, raw, target string)) {
	keys := map[string]string{}
	for _, e := range ents {
		keys[e.ID] = e.Key
	}
	for _, o := range obs {
		var p map[string]any
		_ = json.Unmarshal(o.Payload, &p)
		target := keys[o.EntityID]
		if o.Kind == "error" {
			msg, _ := p["error"].(string)
			if msg == "" || strings.HasPrefix(msg, "not requested:") {
				continue // a choice, listed by Skips
			}
			add(o.Collector, "", msg, target)
			continue
		}
		if p == nil {
			continue
		}
		for _, field := range []string{"sources", "engines"} {
			srcs, _ := p[field].(map[string]any)
			for name, v := range srcs {
				row, _ := v.(map[string]any)
				if msg, _ := row["error"].(string); msg != "" {
					add(o.Collector, name, msg, sourceTarget(p, target))
				}
			}
		}
		if _, ok := p["sources"]; ok {
			continue
		}
		if _, ok := p["engines"]; ok {
			continue
		}
		if msg, _ := p["error"].(string); msg != "" && p["degraded"] == true {
			add(o.Collector, "", msg, sourceTarget(p, target))
			continue
		}
		if o.Collector == "azhaq-http" || o.Collector == "azhaq-paths" {
			// 429 is the target slowing the run down; a 503 is an answer
			// (a service that is down, an edge with no origin).
			switch st := statusOf(o.Payload); st {
			case 429:
				u, _ := p["url"].(string)
				if u == "" {
					u = target
				}
				add(o.Collector, "", fmt.Sprintf("HTTP %d from the target", st), u)
			}
		}
	}
}

// Skips lists the requests Azhaq refused to send in obs (outside the
// scope, would end the session), one row per target and reason.
func Skips(ents []types.Entity, obs []types.StoredObservation) []Skip {
	keys := map[string]string{}
	for _, e := range ents {
		keys[e.ID] = e.Key
	}
	// A URL a path or parameter guess asked for was requested, whatever
	// the crawler then chose: it is not listed as left alone.
	asked := map[string]bool{}
	for _, o := range obs {
		if (o.Kind == "url" || o.Kind == "application") && o.Collector != "azhaq-js" && o.Collector != "azhaq-crawl" && statusOf(o.Payload) > 0 {
			asked[keys[o.EntityID]] = true
			if u := payloadURL(o); u != "" {
				if n, err := normalize.URL(u); err == nil {
					u = n
				}
				asked[u] = true
			}
		}
	}
	seen := map[string]bool{}
	var out []Skip
	for _, o := range obs {
		var p struct {
			Error   string   `json:"error"`
			Skipped string   `json:"skipped"`
			Word    string   `json:"word"`
			URLs    []string `json:"urls"` // guesses a collector did not send
		}
		var reason string
		switch o.Kind {
		case "error":
			_ = json.Unmarshal(o.Payload, &p)
			var ok bool
			if reason, ok = strings.CutPrefix(p.Error, "not requested: "); !ok {
				continue
			}
		case "skipped":
			_ = json.Unmarshal(o.Payload, &p)
			reason = p.Skipped
		default:
			continue
		}
		targets := []string{keys[o.EntityID]}
		if len(p.URLs) > 0 {
			targets = p.URLs
		}
		for _, t := range targets {
			if asked[t] {
				continue
			}
			s := Skip{Target: t, Reason: reason}
			if k := s.Target + "\x00" + s.Reason; !seen[k] {
				seen[k] = true
				out = append(out, s)
			}
		}
	}
	return out
}

func sourceTarget(p map[string]any, fallback string) string {
	for _, k := range []string{"domain", "fqdn", "asn", "url"} {
		if v, _ := p[k].(string); v != "" {
			return v
		}
	}
	return fallback
}

var (
	statusRE = regexp.MustCompile(`(?i)(?:status(?: code)?|http)[ :=]*([45]\d\d)\b`)
	quotedRE = regexp.MustCompile(`"[^"]*"`)
)

// ShortError reduces an error to what went wrong, without the URL and the
// layers of wrapping: "timeout", "connection refused", "HTTP 400".
func ShortError(s string) string {
	l := strings.ToLower(s)
	switch {
	case strings.Contains(l, "timeout") || strings.Contains(l, "deadline exceeded") || strings.Contains(l, "timed out"):
		return "timeout"
	case strings.Contains(l, "connection refused"):
		return "connection refused"
	case strings.Contains(l, "connection reset"):
		return "connection reset"
	case strings.Contains(l, "no such host"):
		return "no such host"
	case strings.Contains(l, "rate limit") || strings.Contains(l, "429"):
		return "HTTP 429 (rate limited)"
	}
	if m := statusRE.FindStringSubmatch(s); m != nil {
		return "HTTP " + m[1]
	}
	switch {
	case strings.Contains(l, "x509") || strings.Contains(l, "tls:"):
		return "TLS error"
	case strings.HasSuffix(l, "eof"):
		return "connection closed (EOF)"
	}
	s = quotedRE.ReplaceAllString(s, "…")
	if i := strings.LastIndex(s, ": "); i >= 0 && len(s)-i > 12 {
		s = s[i+2:]
	}
	if len(s) > 120 {
		s = s[:120] + "…"
	}
	return strings.TrimSpace(s)
}

// Retryable: a later attempt may well succeed (timeouts, dropped
// connections, rate limits, server errors).
func Retryable(s string) bool {
	switch e := ShortError(s); {
	case e == "timeout", e == "connection reset", e == "connection closed (EOF)", strings.HasPrefix(e, "HTTP 429"):
		return true
	case strings.HasPrefix(e, "HTTP 5"):
		return true
	}
	return false
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

// Own reports whether target (a URL, host, address or domain) is one of
// the seeds or under them: what the user asked about, as opposed to
// fan-out the run found on its way (the domain of a URL, a CNAME target).
func Own(target string, seeds []types.Seed) bool {
	hosts, _, ips := seedScope(seeds)
	explicit := map[string]bool{}
	for _, s := range seeds {
		if s = normalize.Seed(s); s.Type == types.TypeDomain && !s.Derived() {
			explicit[s.Key()] = true
		}
	}
	h := target
	if strings.Contains(target, "://") {
		h = normalize.HostFromURL(target)
	}
	h = normalize.Hostname(h)
	if h == "" {
		return false
	}
	if ips[h] || hosts[h] || explicit[h] {
		return true
	}
	for d := range explicit {
		if strings.HasSuffix(h, "."+d) {
			return true
		}
	}
	return false
}

// MarkFanout sets Fanout on the failures none of whose targets the user
// asked about: a subdomain source that failed for the domain of a URL
// does not make a map of that URL incomplete.
func MarkFanout(fs []Failure, seeds []types.Seed) []Failure {
	for i := range fs {
		own := false
		for _, t := range fs[i].Targets {
			if thirdParty[fs[i].Collector] && ownDomain(t, seeds) || !thirdParty[fs[i].Collector] && Own(t, seeds) {
				own = true
				break
			}
		}
		fs[i].Fanout = !own
	}
	return fs
}

// MarkPartial sets Partial on the source failures of a collector whose
// other sources answered, with names, for every target of the failure.
func MarkPartial(fs []Failure, ents []types.Entity, obs []types.StoredObservation) []Failure {
	keys := map[string]string{}
	for _, e := range ents {
		keys[e.ID] = e.Key
	}
	answered := map[string]int{} // collector + target → sources that answered
	for _, o := range obs {
		var p map[string]any
		if json.Unmarshal(o.Payload, &p) != nil {
			continue
		}
		srcs, _ := p["sources"].(map[string]any)
		if len(srcs) == 0 || p["degraded"] == true {
			continue // nothing found and something broke: not an honest zero
		}
		target := sourceTarget(p, keys[o.EntityID])
		for _, v := range srcs {
			row, _ := v.(map[string]any)
			if row["error"] != nil || row["skipped"] != nil {
				continue
			}
			// A source answered when it gave something: a padding source
			// counts by the names it kept, not the ones it made up.
			n, _ := row["count"].(float64)
			if kept, ok := row["kept"].(float64); ok {
				n = kept
			}
			if n > 0 {
				answered[o.Collector+"\x00"+target]++
			}
		}
	}
	for i := range fs {
		if fs[i].Source == "" || len(fs[i].Targets) == 0 {
			continue
		}
		all := true
		for _, t := range fs[i].Targets {
			if answered[fs[i].Collector+"\x00"+t] == 0 {
				all = false
				break
			}
		}
		fs[i].Partial = all
	}
	return fs
}

// thirdParty collectors ask others about a domain (archives, CT, RDAP):
// what they fail to say is part of a map only when the domain itself was
// asked about, not when it is the domain of a URL being mapped.
var thirdParty = map[string]bool{"azhaq-subdomains": true, "azhaq-urls": true, "azhaq-rdap": true, "azhaq-search": true, "azhaq-asn": true}

// ownDomain: target is a domain the user named (-domain, subs -d), or
// under one.
func ownDomain(target string, seeds []types.Seed) bool {
	h := normalize.Hostname(target)
	for _, s := range seeds {
		if s = normalize.Seed(s); s.Type == types.TypeDomain && !s.Derived() && (h == s.Key() || strings.HasSuffix(h, "."+s.Key())) {
			return true
		}
	}
	return false
}

// Unreachable lists the URL seeds that never answered: every request to
// them failed. A map of a target that did not answer is not a map.
func Unreachable(seeds []types.Seed, ents []types.Entity, obs []types.StoredObservation) []string {
	answered := map[string]bool{}
	failed := map[string]bool{}
	keys := map[string]string{}
	for _, e := range ents {
		keys[e.ID] = e.Key
	}
	for _, o := range obs {
		if o.Collector != "azhaq-http" {
			continue
		}
		k := keys[o.EntityID]
		if o.Kind == "error" {
			failed[k] = true
		} else if statusOf(o.Payload) > 0 {
			answered[k] = true
			if u := payloadURL(o); u != "" {
				answered[u] = true
			}
		}
	}
	var out []string
	for _, s := range seeds {
		s = normalize.Seed(s)
		if s.Type != types.TypeURL {
			continue
		}
		if k := s.Key(); failed[k] && !answered[k] {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// Notes are the warnings collectors left in their reports that are not
// failures: a cap that was hit, an inventory that held nothing.
func Notes(obs []types.StoredObservation) []string {
	seen := map[string]bool{}
	var out []string
	for _, o := range obs {
		var p struct {
			Warning string `json:"warning"`
			Note    string `json:"note"`
		}
		if json.Unmarshal(o.Payload, &p) != nil {
			continue
		}
		for _, w := range []string{p.Warning, p.Note} {
			if w == "" || strings.HasPrefix(w, "failed: ") || seen[w] {
				continue
			}
			seen[w] = true
			out = append(out, w)
		}
	}
	return out
}
