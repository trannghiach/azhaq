package engine

import (
	"encoding/json"
	"fmt"
	"net/url"
	"sort"

	"github.com/trannghiach/azhaq/internal/webextract"
	"github.com/trannghiach/azhaq/types"
)

// thinMap is how few routes an origin's map has for an empty shell of a
// front page to mean its scripts hold the rest.
const thinMap = 10

// BrowserHint is the command to map again with Chrome, and why, or "":
// a run without -browser whose target pages leave their links to their
// scripts, as Markdown or {{templates}} in their text, or whose front
// page is an empty shell with few routes found behind it. A server-built
// site, or an app whose scripts gave up their routes, gets no hint.
func BrowserHint(rows []MapEntry, obs []types.StoredObservation) string {
	routes := map[string]int{} // origin → page and API rows
	target := map[string]bool{}
	for _, r := range rows {
		if r.Entity.Type != types.TypeURL || r.Scope != "target" {
			continue
		}
		target[r.Entity.Key] = true
		switch r.Role {
		case "asset", "script", "sourcemap":
		default:
			routes[originOf(r.Entity.Key)]++
		}
	}
	type page struct {
		url string
		n   int // what it leaves unrendered: the page with most is named
	}
	var md, tmpl, shells []page
	for _, o := range obs {
		if o.Collector == "azhaq-render" {
			return "" // the run had Chrome
		}
		if o.Collector != "azhaq-crawl" || o.Kind != "meta" {
			continue
		}
		var p struct {
			URL        string                 `json:"url"`
			Unrendered *webextract.Unrendered `json:"unrendered"`
		}
		if json.Unmarshal(o.Payload, &p) != nil || p.Unrendered == nil || !target[p.URL] {
			continue
		}
		u := p.Unrendered
		if u.Markdown > 0 {
			md = append(md, page{p.URL, u.Markdown})
		}
		if u.Templates >= 3 { // one or two may be a page about templates
			tmpl = append(tmpl, page{p.URL, u.Templates})
		}
		if u.Shell && routes[originOf(p.URL)] < thinMap {
			shells = append(shells, page{p.URL, 1})
		}
	}
	pages := func(ps []page) (string, string) {
		sort.Slice(ps, func(i, j int) bool {
			if ps[i].n != ps[j].n {
				return ps[i].n > ps[j].n
			}
			return ps[i].url < ps[j].url
		})
		first := ps[0].url
		if u, err := url.Parse(first); err == nil {
			first = u.Path
		}
		if len(ps) == 1 {
			return originOf(ps[0].url), first
		}
		return originOf(ps[0].url), fmt.Sprintf("%s and %d more pages", first, len(ps)-1)
	}
	switch {
	case len(md) > 0:
		o, which := pages(md)
		return fmt.Sprintf("azhaq run -url %s/ -browser …   (%s: Markdown its scripts turn into links; read as text here, Chrome sees the page as rendered)", o, which)
	case len(tmpl) > 0:
		o, which := pages(tmpl)
		return fmt.Sprintf("azhaq run -url %s/ -browser …   (%s: {{templates}} its scripts fill; Chrome sees the page as rendered)", o, which)
	case len(shells) > 0:
		o, which := pages(shells)
		return fmt.Sprintf("azhaq run -url %s/ -browser …   (%s: an empty page its scripts draw, and %d routes found on %s)", o, which, routes[o], o)
	}
	return ""
}

func originOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	return u.Scheme + "://" + u.Host
}
