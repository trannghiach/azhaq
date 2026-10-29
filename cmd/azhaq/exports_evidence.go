package main

import (
	"net/url"

	"github.com/trannghiach/azhaq/engine"
	"github.com/trannghiach/azhaq/types"
)

// flagEvidence gives the operations a served description lists the level
// of the route's own row: the description names every route, and the run
// may have fetched it too.
func (s *spec) flagEvidence(g *graphView, origin string) {
	best := map[string]string{} // path key → strongest level of its rows
	for _, r := range g.rows {
		if r.Entity.Type != types.TypeURL || r.Evidence == "" {
			continue
		}
		u, err := url.Parse(r.Entity.Key)
		if err != nil || u.Scheme+"://"+u.Host != origin || u.RawQuery != "" {
			continue
		}
		p := s.key(u.Path)
		if engine.EvidenceRank(r.Evidence) < engine.EvidenceRank(best[p]) {
			best[p] = r.Evidence
		}
	}
	for p, level := range best {
		item, _ := s.paths[p].(map[string]any)
		for _, m := range opMethods {
			op, ok := item[m].(map[string]any)
			if !ok {
				continue
			}
			if x, _ := op["x-azhaq"].(map[string]any); x != nil && x["source"] == "served description" {
				op["x-azhaq-evidence"] = level
			}
		}
	}
}
