package main

import (
	"fmt"

	"github.com/trannghiach/azhaq/internal/collectors/subcol"
)

// subsNotes are the notes subs adds from the sources' payloads: how complete
// the result is, and a name history that could not be written. keep, if
// set, limits the coverage to the names printed (-live).
func subsNotes(ps []map[string]any, keep map[string]bool) []string {
	dep := subcol.Dependent()
	var notes []string
	var observed int
	var estimated float64
	for _, p := range ps {
		foundBy := map[string][]string{}
		raw, _ := p["found_by"].(map[string]any)
		for name, by := range raw {
			foundBy[name] = strs(by)
		}
		var filter func(string) bool
		if keep != nil {
			filter = func(n string) bool { return keep[n] }
		}
		if s, est, ok := subcol.Chao1(foundBy, dep, filter); ok {
			observed += s
			estimated += est
		}
		if msg, _ := p["history_error"].(string); msg != "" {
			notes = append(notes, "name history not saved: "+msg)
		}
	}
	if observed > 0 {
		notes = append(notes, fmt.Sprintf("coverage: the independent sources hold about %d names; this run has %d of them (%d%%) — an estimate of what the sources know, not of every name that exists",
			int(estimated+0.5), observed, int(100*float64(observed)/estimated+0.5)))
	}
	return notes
}
