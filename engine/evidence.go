package engine

import (
	"encoding/json"
	"fmt"
	"net/url"
	"slices"
	"sort"

	"github.com/trannghiach/azhaq/types"
)

// How a route is known, strongest first. A row carries the strongest
// level any of its sources reaches.
const (
	EvAnswered  = "answered"  // the run fetched it and the server answered
	EvBrowser   = "browser"   // Chrome, loading the page, sent the request (or a write)
	EvDescribed = "described" // an API description the run read lists it
	EvCalled    = "called"    // a script calls it
	EvLinked    = "linked"    // a page, a script string or a form names it
	EvArchived  = "archived"  // only archives hold it
	EvGuessed   = "guessed"   // a wordlist guess that did not answer
	EvGiven     = "given"     // the user named it, and nothing else holds it
)

// EvidenceLevels lists the levels, strongest first.
var EvidenceLevels = []string{EvAnswered, EvBrowser, EvDescribed, EvCalled, EvLinked, EvArchived, EvGuessed, EvGiven}

// EvidenceRank orders a level: 0 is the strongest, an unknown or empty
// level is last.
func EvidenceRank(level string) int {
	if i := slices.Index(EvidenceLevels, level); i >= 0 {
		return i
	}
	return len(EvidenceLevels)
}

// evidenceSource is what the observations of one URL add up to.
type evidenceSource struct {
	level      string
	collectors map[string]bool
}

// evidenceLevel is the level one observation gives the URL it names.
func evidenceLevel(collector, kind, via, seen string, p evidenceFields) string {
	if st := p.Status; st > 0 && st != 404 && st != 410 && !p.CatchAll && kind != "error" {
		switch collector {
		case "azhaq-paths", "azhaq-dirs", "ffuf", "katana", "httpx":
			return EvAnswered // a request of this run, and it answered
		}
	}
	switch collector {
	case "azhaq-openapi", "azhaq-cloud": // azhaq-cloud: stores of earlier versions
		return EvDescribed
	case "azhaq-js":
		if via == "js-call" {
			return EvCalled
		}
		return EvLinked
	case "azhaq-render":
		if seen == "request" || seen == "write" {
			return EvBrowser
		}
		return EvLinked
	case "azhaq-shots":
		return EvBrowser
	case "azhaq-crawl", "katana":
		return EvLinked
	case "azhaq-urls":
		return EvArchived
	case "azhaq-paths", "azhaq-dirs", "ffuf":
		return EvGuessed
	}
	return ""
}

type evidenceFields struct {
	Status   int
	CatchAll bool
}

// evidenceIndex gathers, per URL, the collectors that name it and the
// strongest level they reach, from every observation that carries the
// URL (the page that holds a link stores it, the route is the payload's)
// and from the form actions pages hold.
func evidenceIndex(obs []types.StoredObservation) map[string]*evidenceSource {
	out := map[string]*evidenceSource{}
	add := func(raw, role, collector, level string) {
		if level == "" {
			return
		}
		u, err := FoundKey(raw, role)
		if err != nil {
			return
		}
		s := out[u]
		if s == nil {
			s = &evidenceSource{level: level, collectors: map[string]bool{}}
			out[u] = s
		}
		s.collectors[collector] = true
		if EvidenceRank(level) < EvidenceRank(s.level) {
			s.level = level
		}
	}
	for _, o := range obs {
		switch o.Kind {
		case "url":
			var p struct {
				URL      string `json:"url"`
				Via      string `json:"via"`
				Seen     string `json:"seen"`
				Role     string `json:"role"`
				Status   int    `json:"status"`
				CatchAll bool   `json:"catchall"`
			}
			if json.Unmarshal(o.Payload, &p) != nil || p.URL == "" {
				continue
			}
			f := evidenceFields{Status: p.Status, CatchAll: p.CatchAll}
			add(p.URL, p.Role, o.Collector, evidenceLevel(o.Collector, o.Kind, p.Via, p.Seen, f))
		case "form":
			var p struct {
				Action string `json:"action"`
			}
			if json.Unmarshal(o.Payload, &p) != nil || p.Action == "" {
				continue
			}
			add(p.Action, "", o.Collector, EvLinked)
		}
	}
	return out
}

// setEvidence fills a URL row's evidence from the index and, for a row
// the run fetched, the collectors that fetched it.
func (m *MapEntry) setEvidence(src *evidenceSource, own []types.StoredObservation, given bool) {
	m.Evidence, m.EvidenceFrom = "", nil
	if src != nil {
		m.Evidence = src.level
		for c := range src.collectors {
			m.EvidenceFrom = append(m.EvidenceFrom, c)
		}
	}
	if m.Coverage == "visited" {
		m.Evidence = EvAnswered // fetched, not a 404, not the origin's any-path answer
		for _, o := range own {
			if fetched([]types.StoredObservation{o}) && !slices.Contains(m.EvidenceFrom, o.Collector) {
				m.EvidenceFrom = append(m.EvidenceFrom, o.Collector)
			}
		}
	}
	if m.Evidence == "" && given {
		m.Evidence = EvGiven // a URL asked for that gave no answer: only the user's word
	}
	sort.Strings(m.EvidenceFrom)
}

// mergeEvidence folds another row of the same template in: the strongest
// level, and every collector behind either.
func (m *MapEntry) mergeEvidence(o MapEntry) {
	if EvidenceRank(o.Evidence) < EvidenceRank(m.Evidence) {
		m.Evidence = o.Evidence
	}
	for _, c := range o.EvidenceFrom {
		if !slices.Contains(m.EvidenceFrom, c) {
			m.EvidenceFrom = append(m.EvidenceFrom, c)
		}
	}
	sort.Strings(m.EvidenceFrom)
}

// EvidenceTag is the short mark a text row carries when its level is not
// answered, or "".
func (m MapEntry) EvidenceTag() string {
	if m.Evidence == "" || m.Evidence == EvAnswered {
		return ""
	}
	return "[" + m.Evidence + "]"
}

// answerNote qualifies a 5xx the run got from a plain request: when the
// route takes names (query, body) and the request carried none, the
// failure says little of the route, and the row says so ("500 without
// input"). Only a row the run fetched has one.
func answerNote(m MapEntry, key string) string {
	if m.Coverage != "visited" || m.Status < 500 {
		return ""
	}
	taken := map[string]bool{}
	for _, n := range m.Params {
		taken[n] = true
	}
	for _, n := range m.Body {
		taken[n] = true
	}
	for _, o := range m.Ops {
		for _, n := range append(slices.Clone(o.Query), o.Body...) {
			taken[n] = true
		}
	}
	if u, err := url.Parse(key); err == nil {
		for n := range u.Query() {
			delete(taken, n)
		}
	}
	if len(taken) == 0 {
		return ""
	}
	return fmt.Sprintf("%d without input", m.Status)
}
