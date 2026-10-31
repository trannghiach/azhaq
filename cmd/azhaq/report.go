package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/trannghiach/azhaq/engine"
	"github.com/trannghiach/azhaq/internal/collectors/pathscol"
	"github.com/trannghiach/azhaq/internal/collectors/portcol"
	"github.com/trannghiach/azhaq/internal/collectors/subcol"
	"github.com/trannghiach/azhaq/internal/fetch"
	"github.com/trannghiach/azhaq/internal/normalize"
	"github.com/trannghiach/azhaq/internal/takeover"
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
	Takeover    []takeoverRow    `json:"takeover,omitempty"` // names another party may take over
	Degraded    bool             `json:"degraded,omitempty"` // a source the run depends on failed (subs); the exit code is not changed
	Junk        map[string]int   `json:"junk,omitempty"`     // urls: URLs left out as junk, by reason (-raw keeps them)
	Sources     *sourceHealth    `json:"sources,omitempty"`  // subs and urls: how many sources answered, which failed and why, what each gave
	Stopped     string           `json:"stopped,omitempty"`  // the limit that stopped the work
	Resume      string           `json:"resume,omitempty"`
	Notes       []string         `json:"notes,omitempty"`
	Next        []string         `json:"next,omitempty"`

	what   string // the unit of Results: "names", "web services"
	warned bool   // a note says the results mislead (a role's dead session): exit 3
	// failOnErrors: -fail-on-errors was given, so no failure is made up for.
	failOnErrors bool
	start        time.Time

	// hints are measured suggestions, printed as "next:" lines for a person
	// (see hints.go); they are never in the JSON summary.
	hints              []string
	late               []func() string
	hintsOff, hintsVrb bool
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
	r.hintsOff = r.hintsOff || asJSON || silent
	switch {
	case asJSON:
		raw, _ := json.Marshal(r)
		fmt.Fprintf(os.Stderr, "%s\n", raw)
	case silent && r.Exit == exitOK && (r.Sources == nil || r.Sources.failures() == 0):
		// A source that failed is something that failed: it is said under -silent too.
		// So is a takeover candidate: a finding, not a note.
		for _, t := range r.Takeover {
			fmt.Fprintln(os.Stderr, takeoverLine(t))
		}
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
			name := k
			if k == "URLs" && r.what == "map rows" && r.Counts[k] > r.Results {
				// A templated row holds many URLs: say so, or the numbers
				// read as not adding up (44 map rows, 65 URLs).
				name = "URLs, folded into templated rows"
			}
			if r.Counts[k] == 1 && (k == "websockets" || k == "client routes") {
				name = strings.TrimSuffix(k, "s")
			}
			parts = append(parts, fmt.Sprintf("%d %s", r.Counts[k], name))
		}
		head[0] += " (" + strings.Join(parts, ", ") + ")"
	}
	if r.Degraded {
		// Exit 0 and "complete" say the run finished, not that every source
		// answered: the first line of the summary says it too.
		head = append(head, fmt.Sprintf("DEGRADED: %d of %d sources failed, the names may be incomplete", r.Counts["sources failed"], r.Counts["sources asked"]))
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
			line := fmt.Sprintf("  - not requested, %s: %s", why, strings.Join(ts[:min(len(ts), 3)], ", "))
			if len(ts) > 3 {
				line += fmt.Sprintf(" and %d more", len(ts)-3)
			}
			fmt.Fprintln(w, line)
		}
	}
	for _, t := range r.Takeover {
		fmt.Fprintf(w, "  ! takeover candidate (%s): %s · %s\n", t.Strength, t.Host, t.Evidence)
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
	for _, h := range r.shownHints() {
		fmt.Fprintf(w, "  next: %s\n", h)
	}
	if r.Sources != nil && r.Sources.failures() > 0 {
		fmt.Fprintf(w, "  %s\n", r.Sources.line(r.Exit, r.ownFailures(), r.failOnErrors, r.Command == "urls"))
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
	rep.Notes = append(rep.Notes, portcol.StoppedNotes()...)
	rep.Notes = append(rep.Notes, engine.GraphQLNotes(obs)...)
	rep.Notes = append(rep.Notes, pathscol.Notes(obs)...)
	rep.Notes = append(rep.Notes, fetch.Notes()...)
	if partialShots(obs) {
		rep.warned = true // a picture short of its page is not a result to take as whole
	}
	rep.Notes = append(rep.Notes, interactNotes(obs)...)
	rep.Takeover = takeovers(ents, obs)
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
			case "asset", "script", "sourcemap", "manifest":
				continue
			case "client-route":
				counts["client routes"]++
				continue
			case "websocket":
				counts["websockets"]++
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
	if hint := engine.BrowserHint(rows, obs); hint != "" {
		rep.Next = append(rep.Next, hint)
	}
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
	set("answer", r.Answer, r.Answer != "")
	set("evidence", r.Evidence, r.Evidence != "")
	set("evidence_from", r.EvidenceFrom, len(r.EvidenceFrom) > 0)
	set("title", r.Title, r.Title != "")
	set("methods", r.Methods, len(r.Methods) > 0)
	set("params", r.Params, len(r.Params) > 0)
	set("body", r.Body, len(r.Body) > 0)
	set("ops", r.Ops, len(r.Ops) > 0)
	set("forms", r.Forms, len(r.Forms) > 0)
	set("found_in", r.Found, len(r.Found) > 0)
	w := engine.Watch(r)
	set("watch", w, len(w) > 0)
	set("guard", r.Guard, r.Guard != "")
	set("protocol", r.Protocol, r.Protocol != "")
	set("namespace", r.Namespace, r.Namespace != "")
	set("template", r.Template, r.Template != "")
	set("count", r.Count, r.Count > 1)
	set("not_asked", r.NotAsked, r.NotAsked > 0)
	set("folded", r.Folded, r.Folded > 0)
	set("proof", r.Proof, r.Proof != "")
	set("first_seen", r.Entity.FirstSeen.UTC().Format(time.RFC3339), !r.Entity.FirstSeen.IsZero())
	return row
}

// progressMode says how a command that works for long reports it on stderr:
// "" for none (-quiet, unless -v), "json" with -json, else "text". forced is
// what a drop-in decided for itself ("json" for its -json).
func progressMode(quiet, verbose, asJSON bool, forced string) string {
	switch {
	case forced != "":
		return forced
	case quiet && !verbose:
		return ""
	case asJSON:
		return "json"
	}
	return "text"
}

// stillWaiting names the subdomain sources that have not answered, for the
// progress line: a run held by one (crt.sh on a large domain) says so.
func stillWaiting() string {
	ws := subcol.Waiting()
	if len(ws) == 0 {
		return ""
	}
	var parts []string
	for i, w := range ws {
		if i == 3 {
			parts = append(parts, fmt.Sprintf("%d more", len(ws)-3))
			break
		}
		p := fmt.Sprintf("%s (%s", w.Source, w.Longest.Round(time.Second))
		if w.Domains > 1 {
			p += fmt.Sprintf(", %d domains", w.Domains)
		}
		parts = append(parts, p+")")
	}
	return "; still waiting for " + strings.Join(parts, ", ") + " (-source-timeout bounds each source)"
}

// takeoverLine is a candidate as -silent prints it on stderr, one per line:
// [takeover] name -> cname (service, strength).
func takeoverLine(t takeoverRow) string {
	line := "[takeover] " + t.Host
	if t.Target != "" {
		line += " -> " + t.Target
	}
	return line + " (" + t.Service + ", " + t.Strength + ")"
}

// takeoverRow is a name another party may take over, and why.
type takeoverRow struct {
	Host string `json:"host"`
	takeover.Finding
}

// takeovers are the names whose DNS answer (a CNAME to something gone) or
// front page (a service's page for a name nobody claimed) says another
// party may take them, one each, the strongest finding kept.
func takeovers(ents []types.Entity, obs []types.StoredObservation) []takeoverRow {
	keys := map[string]string{}
	for _, e := range ents {
		keys[e.ID] = e.Key
	}
	type finding struct {
		FQDN     string            `json:"fqdn"`
		URL      string            `json:"url"`
		CNAMEs   []string          `json:"cnames"`
		Takeover *takeover.Finding `json:"takeover"`
	}
	var found []finding
	chains := map[string][]string{} // host → its CNAME chain, from DNS
	for _, o := range obs {
		if o.Collector != "azhaq-dns" && o.Collector != "azhaq-http" {
			continue
		}
		var p finding
		if json.Unmarshal(o.Payload, &p) != nil {
			continue
		}
		if p.FQDN == "" && p.URL == "" {
			p.FQDN = normalize.Hostname(keys[o.EntityID])
		}
		if len(p.CNAMEs) > 0 {
			chains[normalize.Hostname(p.FQDN)] = p.CNAMEs
		}
		if p.Takeover != nil {
			found = append(found, p)
		}
	}
	byHost := map[string]takeoverRow{}
	for _, p := range found {
		host := normalize.Hostname(p.FQDN)
		if host == "" {
			host = normalize.HostFromURL(p.URL)
		}
		f := *p.Takeover
		if f.Strength == "page" {
			// A service's page, judged again by where DNS says the name
			// points: to that service, strong; elsewhere, nothing.
			if chain := chains[host]; len(chain) > 0 {
				var ok bool
				if f, ok = takeover.ByPage(chain, []byte(pageWords(f))); !ok {
					continue
				}
			}
		}
		if old, ok := byHost[host]; ok && old.Strength == "strong" {
			continue
		}
		byHost[host] = takeoverRow{Host: host, Finding: f}
	}
	out := make([]takeoverRow, 0, len(byHost))
	for _, t := range byHost {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Host < out[j].Host })
	return out
}

// pageWords is the quoted page text a page finding rests on, to judge
// again beside a CNAME chain.
func pageWords(f takeover.Finding) string {
	if i := strings.Index(f.Evidence, `"`); i >= 0 {
		if j := strings.Index(f.Evidence[i+1:], `"`); j >= 0 {
			return f.Evidence[i+1 : i+1+j]
		}
	}
	return ""
}

// partialShots says a screenshot was taken before its page was loaded. A
// picture that is partial only because the scope blocked assets of other
// hosts is not one: the scope is the user's, and the row and a note say so.
func partialShots(obs []types.StoredObservation) bool {
	for _, o := range obs {
		if o.Collector != "azhaq-shots" || o.Kind != "screenshot" {
			continue
		}
		var p struct {
			Partial  bool
			Unloaded int
			Blocked  int
		}
		if json.Unmarshal(o.Payload, &p) == nil && (p.Unloaded > 0 || p.Partial && p.Blocked == 0) {
			return true
		}
	}
	return false
}

// interactNotes say what -interact did: the clicks made, the candidates
// not clicked (downloads, mail and phone links), the routes found and the
// writes the clicks would have sent.
func interactNotes(obs []types.StoredObservation) []string {
	var pages, clicks, skipped, routes, writes int
	for _, o := range obs {
		if o.Kind != "interact" {
			continue
		}
		var p struct {
			Clicks, Skipped, Routes int
			Writes                  int `json:"writes_mapped"`
		}
		if json.Unmarshal(o.Payload, &p) != nil {
			continue
		}
		pages++
		clicks += p.Clicks
		skipped += p.Skipped
		routes += p.Routes
		writes += p.Writes
	}
	if pages == 0 {
		return nil
	}
	note := fmt.Sprintf("-interact: %d clicks on %d pages found %d routes; %d downloads and mail or phone links not clicked; the %d writes the clicks tried were mapped, not sent", clicks, pages, routes, skipped, writes)
	if clicks == 0 {
		note += "; no button, link or menu showed on a page that had settled: it may draw them only after a slower answer than the page waits for, or need a sign-in (-login)"
	}
	return []string{note}
}
