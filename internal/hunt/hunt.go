// Package hunt ranks a mapped surface: which routes, hosts and files a
// tester should open first, and why. One row per route template; every
// row names the evidence behind its score and the command to run next.
package hunt

import (
	"sort"
	"strings"
	"time"

	"github.com/trannghiach/azhaq/engine"
	"github.com/trannghiach/azhaq/types"
)

// Input is what a ranking reads, all from the workspace and the roles
// output; the command fills it.
type Input struct {
	DB        string // the workspace path, for the commands in Next
	Rows      []engine.MapEntry
	Obs       []types.StoredObservation
	Secrets   []Secret
	Takeovers []Takeover
	Roles     []RoleRow
	Now       time.Time
	Since     time.Duration // "new" means first seen within this long
}

// Secret is a credential a script carried; Where is the file.
type Secret struct{ Kind, Severity, Where string }

// Takeover is a name another party may claim.
type Takeover struct {
	Host   string
	Strong bool
	Detail string
}

// Reason is one piece of evidence for a row's rank.
type Reason struct {
	Signal string `json:"signal"`
	Detail string `json:"detail"`
}

// Row is one line of the hunt list.
type Row struct {
	Rank    int      `json:"rank"`
	Score   int      `json:"score"`
	Key     string   `json:"key"`
	Type    string   `json:"type"`
	Reasons []Reason `json:"reasons"`
	Next    string   `json:"next"`

	scope   string
	signals int // distinct signals, "new" not counted
}

// cand is a route template while its signals are collected.
type cand struct {
	key, typ, scope string
	instances       []string // the keys of the map rows folded into it
	weights         map[string]int
	reasons         []Reason
	roleURL, roleM  string // the roles row behind a cross-role reason
	origin          string
	fresh           bool
}

type hunter struct {
	in     Input
	cands  map[string]*cand
	apiDoc map[string]bool // entity IDs of API descriptions the run parsed
	cut    time.Time
	old    bool // some URL is older than the window: "new" tells rows apart
}

// Build ranks the surface: best first, rows with no signal of their own
// left out.
func Build(in Input) []Row {
	if in.Now.IsZero() {
		in.Now = time.Now()
	}
	h := &hunter{in: in, cands: map[string]*cand{}, apiDoc: apiDescriptions(in.Obs), cut: in.Now.Add(-in.Since)}
	for _, r := range in.Rows {
		if r.Entity.Type == types.TypeURL && r.Entity.FirstSeen.Before(h.cut) {
			h.old = true
		}
	}
	for _, r := range in.Rows {
		switch r.Entity.Type {
		case types.TypeURL:
			h.url(r)
		case types.TypeHostname:
			h.host(r)
		}
	}
	h.secrets()
	h.takeovers()
	h.roles()
	var out []Row
	for _, c := range h.cands {
		if c.fresh && h.old {
			c.add("new", "first seen within "+in.Since.String())
		}
		if len(c.weights) == 0 || (len(c.weights) == 1 && c.weights["new"] > 0) {
			continue // a row whose only signal is "new" never ranks
		}
		out = append(out, c.row(in.DB))
	}
	sortRows(out)
	for i := range out {
		out[i].Rank = i + 1
	}
	return out
}

// sortRows orders best first: by score, then target scope before fan-out,
// then more distinct signals, then key.
func sortRows(out []Row) {
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		switch {
		case a.Score != b.Score:
			return a.Score > b.Score
		case (a.scope == "target") != (b.scope == "target"):
			return a.scope == "target"
		case a.signals != b.signals:
			return a.signals > b.signals
		}
		return a.Key < b.Key
	})
}

// add records one reason; a signal counts once toward the score, at the
// highest weight any of its reasons had.
func (c *cand) addW(signal string, w int, detail string) {
	if w <= 0 {
		return
	}
	// One reason per signal, the strongest; the roles verdicts keep all.
	for i, r := range c.reasons {
		if r.Signal != signal || signal == "cross-role" {
			if r.Signal == signal && r.Detail == detail {
				return
			}
			continue
		}
		if w > c.weights[signal] {
			c.reasons[i].Detail, c.weights[signal] = detail, w
		}
		return
	}
	c.reasons = append(c.reasons, Reason{signal, detail})
	if w > c.weights[signal] {
		c.weights[signal] = w
	}
}

func (c *cand) add(signal, detail string) { c.addW(signal, weights[signal], detail) }

func (c *cand) row(db string) Row {
	rs := append([]Reason(nil), c.reasons...)
	sort.SliceStable(rs, func(i, j int) bool { return c.weights[rs[i].Signal] > c.weights[rs[j].Signal] })
	score, n := 0, 0
	for s, w := range c.weights {
		score += w
		if s != "new" {
			n++
		}
	}
	best := ""
	if len(rs) > 0 {
		best = rs[0].Signal
	}
	return Row{Score: score, Key: c.display(), Type: c.typ, Reasons: rs, Next: c.next(db, best), scope: c.scope, signals: n}
}

// display is the key a row shows: the URL itself when only one was seen,
// else the template that folds them.
func (c *cand) display() string {
	if len(c.instances) == 1 {
		return c.instances[0]
	}
	return c.key
}

// get finds or makes the candidate of a type and key.
func (h *hunter) get(typ, key, scope string) *cand {
	id := typ + "\x00" + key
	c := h.cands[id]
	if c == nil {
		c = &cand{key: key, typ: typ, scope: scope, weights: map[string]int{}}
		h.cands[id] = c
	}
	if scope == "target" {
		c.scope = scope
	}
	return c
}

func apiDescriptions(obs []types.StoredObservation) map[string]bool {
	out := map[string]bool{}
	for _, o := range obs {
		if o.Collector == "azhaq-openapi" && o.Kind == "api" {
			out[o.EntityID] = true
		}
	}
	return out
}

func clip(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n]) + "…"
	}
	return s
}

func join(xs []string, n int) string {
	if len(xs) > n {
		return strings.Join(xs[:n], ", ") + ", …"
	}
	return strings.Join(xs, ", ")
}
