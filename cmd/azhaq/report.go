package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/trannghiach/azhaq/engine"
	"github.com/trannghiach/azhaq/internal/collectors/portcol"
	"github.com/trannghiach/azhaq/internal/fetch"
	"github.com/trannghiach/azhaq/store"
	"github.com/trannghiach/azhaq/types"
)

// report is what every command prints last, on stderr: what came out,
// what failed, what was left alone and why, and whether the work is
// complete. With -json it is one JSON object with "type":"summary".
type report struct {
	Type        string           `json:"type"`
	Command     string           `json:"command"`
	Version     string           `json:"version"`
	Complete    bool             `json:"complete"`
	Exit        int              `json:"exit"`
	Results     int              `json:"results"`
	Counts      map[string]int   `json:"counts,omitempty"`
	Seconds     float64          `json:"seconds"`
	Requests    int64            `json:"requests"` // sent to targets
	DB          string           `json:"db,omitempty"`
	RunID       string           `json:"run_id,omitempty"`
	Unreachable []string         `json:"unreachable,omitempty"`
	Failed      []engine.Failure `json:"failed,omitempty"`
	Skipped     []engine.Skip    `json:"skipped,omitempty"`
	Stopped     string           `json:"stopped,omitempty"` // the limit that stopped the work
	Resume      string           `json:"resume,omitempty"`
	Notes       []string         `json:"notes,omitempty"`
	Next        []string         `json:"next,omitempty"`

	what   string // the unit of Results: "names", "web services"
	warned bool   // a note says the results mislead (a role's dead session): exit 3
	start  time.Time
}

func newReport(command string) *report {
	return &report{Type: "summary", Command: command, Version: version, start: time.Now()}
}

// settle fills the exit code and seconds.
func (r *report) settle() {
	if r.start.IsZero() {
		r.start = time.Now()
	}
	r.Seconds = float64(time.Since(r.start).Milliseconds()) / 1000
	switch {
	case r.Stopped != "":
		r.Exit = exitLimit
	case len(r.Unreachable) > 0 || r.ownFailures() > 0 || r.warned:
		r.Exit = exitPartial
	default:
		r.Exit = exitOK
	}
	r.Complete = r.Exit == exitOK
}

func (r *report) ownFailures() int {
	n := 0
	for _, f := range r.Failed {
		if !f.Fanout && !f.Partial {
			n++
		}
	}
	return n
}

// err is the command's result for main: nil, or the exit code the
// summary explained.
func (r *report) err() error {
	if r.Exit == exitOK {
		return nil
	}
	return exitErr{code: r.Exit}
}

// finish prints the summary: always with asJSON, otherwise unless silent
// and complete. It returns the command's error.
func (r *report) finish(asJSON, silent bool) error {
	r.settle()
	switch {
	case asJSON:
		raw, _ := json.Marshal(r)
		fmt.Fprintf(os.Stderr, "%s\n", raw)
	case silent && r.Exit == exitOK:
	default:
		r.print(os.Stderr)
	}
	return r.err()
}

func (r *report) print(w io.Writer) {
	var head []string
	what := r.what
	if what == "" {
		what = "results"
	}
	head = append(head, fmt.Sprintf("%d %s", r.Results, what))
	if len(r.Counts) > 0 {
		var parts []string
		for _, k := range sortedCountKeys(r.Counts) {
			parts = append(parts, fmt.Sprintf("%d %s", r.Counts[k], k))
		}
		head[0] += " (" + strings.Join(parts, ", ") + ")"
	}
	if r.Requests > 0 {
		head = append(head, fmt.Sprintf("%d requests", r.Requests))
	}
	head = append(head, fmt.Sprintf("%.1f s", r.Seconds))
	if r.DB != "" {
		head = append(head, "db "+r.DB)
	}
	fmt.Fprintf(w, "azhaq %s: %s\n", r.Command, strings.Join(head, " · "))
	for _, u := range r.Unreachable {
		fmt.Fprintf(w, "  ! did not answer: %s\n", u)
	}
	for i, f := range r.Failed {
		if i == 8 {
			fmt.Fprintf(w, "  ! … %d more kinds of failure (-json lists them)\n", len(r.Failed)-8)
			break
		}
		who := f.Collector
		if f.Source != "" {
			who += " source " + f.Source
		}
		line := fmt.Sprintf("  ! %s failed: %s", who, f.Error)
		if f.Count > 1 {
			line += fmt.Sprintf(" ×%d", f.Count)
		}
		if len(f.Targets) > 0 {
			line += " (" + strings.Join(f.Targets[:min(len(f.Targets), 2)], ", ")
			if f.Count > 2 {
				line += ", …"
			}
			line += ")"
		}
		var tags []string
		if f.Retryable {
			tags = append(tags, "retryable")
		}
		if f.Fanout {
			tags = append(tags, "fan-out, not your target")
		}
		if f.Partial && !f.Fanout {
			tags = append(tags, "other sources answered")
		}
		if len(tags) > 0 {
			line += " [" + strings.Join(tags, "; ") + "]"
		}
		fmt.Fprintln(w, line)
	}
	if len(r.Skipped) > 0 {
		byReason := map[string][]string{}
		var reasons []string
		for _, s := range r.Skipped {
			if _, ok := byReason[s.Reason]; !ok {
				reasons = append(reasons, s.Reason)
			}
			byReason[s.Reason] = append(byReason[s.Reason], s.Target)
		}
		for _, why := range reasons {
			ts := byReason[why]
			line := fmt.Sprintf("  - left alone, %s: %s", why, strings.Join(ts[:min(len(ts), 3)], ", "))
			if len(ts) > 3 {
				line += fmt.Sprintf(" and %d more", len(ts)-3)
			}
			fmt.Fprintln(w, line)
		}
	}
	for _, n := range r.Notes {
		fmt.Fprintf(w, "  note: %s\n", n)
	}
	if r.Stopped != "" {
		line := "  stopped: " + r.Stopped
		if r.Resume != "" {
			line += "; " + r.Resume + " continues"
		}
		fmt.Fprintln(w, line)
	}
	for _, n := range r.Next {
		fmt.Fprintf(w, "  next: %s\n", n)
	}
	switch r.Exit {
	case exitPartial:
		if len(r.Unreachable) == 0 && r.ownFailures() == 0 {
			fmt.Fprintf(w, "  exit 3: finished, but a note above says what to check first\n")
			break
		}
		fmt.Fprintf(w, "  exit 3: finished, but what is marked ! failed; the results are usable\n")
	case exitLimit:
		fmt.Fprintf(w, "  exit 4: stopped by a limit with work left\n")
	}
}

func sortedCountKeys(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool {
		if m[out[i]] != m[out[j]] {
			return m[out[i]] > m[out[j]]
		}
		return out[i] < out[j]
	})
	return out
}

// runEmbedded maps with args for a command built on run (watch, roles):
// no map on stdout, the run's summary on stderr. Failures and limits are
// in the summary it returns, not errors.
func runEmbedded(args []string) (*report, error) {
	return runEmbeddedAs(args, false)
}

// runEmbeddedAs is runEmbedded with the summary as one JSON line when
// asJSON is set.
func runEmbeddedAs(args []string, asJSON bool) (*report, error) {
	rep := newReport("run")
	out := runOut{embedded: true}
	if err := mapTarget(args, rep, &out); err != nil {
		return nil, err
	}
	rep.settle()
	if asJSON {
		raw, _ := json.Marshal(rep)
		fmt.Fprintf(os.Stderr, "%s\n", raw)
	} else {
		rep.print(os.Stderr)
	}
	return rep, nil
}

// fillReport adds what a run's database says to rep: failures, skips,
// targets that did not answer, notes and counts.
func fillReport(rep *report, path string, seeds []types.Seed, ents []types.Entity, obs []types.StoredObservation, rows []engine.MapEntry) {
	rep.DB = path
	rep.Failed = engine.MarkPartial(engine.MarkFanout(engine.Failures(ents, obs), seeds), ents, obs)
	rep.Skipped = append(rep.Skipped, engine.Skips(ents, obs)...)
	rep.Unreachable = engine.Unreachable(seeds, ents, obs)
	rep.Notes = append(rep.Notes, engine.Notes(obs)...)
	rep.Notes = append(rep.Notes, portcol.Notes(obs)...)
	if path != "" && !strings.HasPrefix(path, os.TempDir()) && rep.ownFailures() > 0 {
		rep.Next = append(rep.Next, "azhaq query -db "+path+" -failed   (every failed target, the list to retry)")
	}
	if rep.Command != "run" {
		return // the command counts its own results
	}
	counts := map[string]int{}
	for _, r := range rows {
		switch r.Entity.Type {
		case types.TypeURL:
			switch r.Role {
			case "asset", "script", "sourcemap":
				continue
			case "api", "auth", "forbidden":
				counts[r.Role]++
			}
			counts["URLs"]++
		case types.TypeHostname:
			if r.Role != "dead" && r.Role != "wildcard" {
				counts["hostnames"]++
			}
		}
	}
	for k, v := range counts {
		if v == 0 {
			delete(counts, k)
		}
	}
	rep.Results = len(engine.GroupTemplates(rows))
	rep.what = "map rows"
	rep.Counts = counts
	if path == "" {
		return
	}
	if counts["auth"]+counts["forbidden"] > 0 {
		rep.Next = append(rep.Next, "azhaq query -db "+path+" -role auth,forbidden   (what needs a session)")
	}
	if counts["api"] > 0 {
		rep.Next = append(rep.Next, "azhaq query -db "+path+" -role api -fields key,methods,params,body",
			"azhaq export -db "+path+" -format openapi > api.json   (for Burp, Postman, ZAP)")
	}
	if counts["auth"] > 0 {
		rep.Next = append(rep.Next, "azhaq roles -role anon -role 'user=Authorization: Bearer …' -- RUN FLAGS   (who may read what)")
	}
}

// mapRowJSON is one row of the map for -json output and azhaq query.
func mapRowJSON(r engine.MapEntry) map[string]any {
	key := r.Entity.Key
	if r.Count > 1 {
		key = r.Template
	}
	row := map[string]any{"type": r.Entity.Type, "key": key, "scope": r.Scope}
	set := func(k string, v any, ok bool) {
		if ok {
			row[k] = v
		}
	}
	set("coverage", r.Coverage, r.Coverage != "")
	set("role", r.Role, r.Role != "")
	set("status", r.Status, r.Status != 0)
	set("title", r.Title, r.Title != "")
	set("methods", r.Methods, len(r.Methods) > 0)
	set("params", r.Params, len(r.Params) > 0)
	set("body", r.Body, len(r.Body) > 0)
	set("ops", r.Ops, len(r.Ops) > 0)
	set("forms", r.Forms, len(r.Forms) > 0)
	set("template", r.Template, r.Template != "")
	set("count", r.Count, r.Count > 1)
	set("folded", r.Folded, r.Folded > 0)
	set("proof", r.Proof, r.Proof != "")
	set("first_seen", r.Entity.FirstSeen.UTC().Format(time.RFC3339), !r.Entity.FirstSeen.IsZero())
	return row
}

// progressTicker prints a line on stderr every half minute while a run
// works, so a long run is not mistaken for a hung one.
func progressTicker(ctx context.Context, st *store.Store, silent bool) func() {
	if silent {
		return func() {}
	}
	done := make(chan struct{})
	var once sync.Once
	t0 := time.Now()
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				return
			case <-t.C:
				fmt.Fprintf(os.Stderr, "azhaq: working, %s: %d tasks done, %d requests sent\n",
					time.Since(t0).Round(time.Second), st.TasksDone(), fetch.Sent())
			}
		}
	}()
	return func() { once.Do(func() { close(done) }) }
}
