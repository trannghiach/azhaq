package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/trannghiach/azhaq/engine"
	"github.com/trannghiach/azhaq/internal/normalize"
	"github.com/trannghiach/azhaq/store"
	"github.com/trannghiach/azhaq/types"
)

// cmdQuery answers one question about a database: the map rows that
// match, best first, with the fields asked for.
func cmdQuery(args []string) error {
	fs := newFlags("query")
	db := fs.String("db", "", "the database (default: the last run's)")
	typ := fs.String("type", "", "entity types, comma-separated: URL, Hostname, Domain, IPAddress, …")
	roleF := fs.String("role", "", "roles, comma-separated: app, auth, forbidden, api, page, client-route, websocket, live, sibling, unresolved, dead, …")
	cov := fs.String("coverage", "", "coverage, comma-separated: visited, catchall, error, gone, hint, skipped, capped")
	status := fs.String("status", "", "statuses, comma-separated: 200, 401, 4xx, 5xx")
	method := fs.String("method", "", "routes with this method: GET, POST, …")
	host := fs.String("host", "", "entities on this host or under this domain")
	match := fs.String("match", "", "keys that contain this text (case-insensitive), or match it as a regular expression with -re")
	re := fs.Bool("re", false, "-match is a regular expression")
	scopeF := fs.String("scope", "", "target (what was asked about) or fanout (found on the way)")
	isNew := fs.Bool("new", false, "only what the last run saw that the run before it did not (a workspace)")
	since := fs.Duration("since", 0, "only what was first seen within this long")
	fields := fs.String("fields", "", "print only these fields, comma-separated: key, type, role, coverage, status, title, methods, params, body, scope, first_seen, found_in, watch, guard, protocol, namespace")
	limit := fs.Int("limit", 0, "rows at most, best first (default 0: all)")
	asJSON := fs.Bool("json", false, "one JSON object per row, and the summary as JSON on stderr")
	failed := fs.Bool("failed", false, "list every target whose work failed (timeouts, refusals, a source's errors): the list to retry")
	if err := parse(fs, args); err != nil {
		return err
	}
	path := *db
	if path == "" {
		if path = readLastDB(); path == "" {
			return usagef("give -db FILE")
		}
	}
	rep := newReport("query")
	rep.what = "rows"
	if *failed {
		return queryFailed(path, *asJSON, rep)
	}
	rows, err := mapRows(path)
	if err != nil {
		return err
	}
	var matchRE *regexp.Regexp
	if *re && *match != "" {
		if matchRE, err = regexp.Compile("(?i)" + *match); err != nil {
			return usagef("-match: %v", err)
		}
	}
	var fresh map[string]bool
	if *isNew {
		if fresh, err = newKeys(path); err != nil {
			return err
		}
	}
	keep := func(r engine.MapEntry) bool {
		e := r.Entity
		switch {
		case !inList(*typ, string(e.Type)), !inList(*roleF, r.Role), !inList(*cov, r.Coverage), !inList(*scopeF, r.Scope):
			return false
		case *status != "" && !statusIn(*status, r.Status):
			return false
		case *method != "" && !hasMethod(r, *method):
			return false
		case *host != "" && !onHost(e, *host):
			return false
		case matchRE != nil && !matchRE.MatchString(e.Key):
			return false
		case matchRE == nil && *match != "" && !strings.Contains(strings.ToLower(e.Key), strings.ToLower(*match)):
			return false
		case fresh != nil && !fresh[string(e.Type)+"\x00"+e.Key]:
			return false
		case *since > 0 && e.FirstSeen.Before(time.Now().Add(-*since)):
			return false
		}
		return true
	}
	var out []engine.MapEntry
	matched := 0
	for _, r := range engine.GroupURLTemplates(rows) {
		if !keep(r) {
			continue
		}
		matched++
		if *limit == 0 || len(out) < *limit {
			out = append(out, r)
		}
	}
	cols := splitList(*fields)
	for _, r := range out {
		row := mapRowJSON(r)
		switch {
		case *asJSON && len(cols) > 0:
			sub := map[string]any{}
			for _, c := range cols {
				if v, ok := row[c]; ok {
					sub[c] = v
				}
			}
			raw, _ := json.Marshal(sub)
			fmt.Println(string(raw))
		case *asJSON:
			raw, _ := json.Marshal(row)
			fmt.Println(string(raw))
		case len(cols) > 0:
			vals := make([]string, len(cols))
			for i, c := range cols {
				vals[i] = cell(row[c])
			}
			fmt.Println(strings.Join(vals, "\t"))
		default:
			fmt.Println(r.Line())
			for _, d := range r.Details() {
				fmt.Printf("    %s\n", d)
			}
		}
	}
	rep.Results = len(out)
	rep.DB = path
	if matched > len(out) {
		rep.Notes = append(rep.Notes, fmt.Sprintf("%d rows matched; -limit %d printed the first %d (best first)", matched, *limit, len(out)))
	}
	return rep.finish(*asJSON, false)
}

// queryFailed prints every failed target of the newest run, one per
// line: target, who failed, the error, and whether retrying may help.
func queryFailed(path string, asJSON bool, rep *report) error {
	g, err := readGraph(path)
	if err != nil {
		return err
	}
	ents := make([]types.Entity, 0, len(g.rows))
	for _, r := range g.rows {
		ents = append(ents, r.Entity)
	}
	list := engine.FailedTargets(ents, g.obs)
	for _, f := range list {
		if asJSON {
			raw, _ := json.Marshal(f)
			fmt.Println(string(raw))
			continue
		}
		who := f.Collector
		if f.Source != "" {
			who += " source " + f.Source
		}
		line := f.Target + "\t" + who + "\t" + f.Error
		if f.Retryable {
			line += "\tretryable"
		}
		fmt.Println(line)
	}
	rep.what = "failed targets"
	rep.Results = len(list)
	rep.DB = path
	return rep.finish(asJSON, false)
}

// mapRows is the map of a database's newest run.
func mapRows(path string) ([]engine.MapEntry, error) {
	g, err := readGraph(path)
	if err != nil {
		return nil, err
	}
	return g.rows, nil
}

// newKeys are the entities the last run of a workspace saw and the run
// before it did not.
func newKeys(path string) (map[string]bool, error) {
	old, err := store.OpenExisting(path)
	if err != nil {
		return nil, err
	}
	defer old.Close()
	neu, err := store.OpenExisting(path)
	if err != nil {
		return nil, err
	}
	defer neu.Close()
	runs, err := old.Runs()
	if err != nil || len(runs) == 0 {
		return nil, err
	}
	neu.UseRun(runs[len(runs)-1].ID)
	if len(runs) == 1 {
		old.UseRun("\x00none")
	} else {
		old.UseRun(runs[len(runs)-2].ID)
	}
	d, err := store.Compare(old, neu)
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, e := range d.Added {
		out[string(e.Type)+"\x00"+e.Key] = true
	}
	return out, nil
}

func inList(list, v string) bool {
	if list == "" {
		return true
	}
	for _, x := range splitList(list) {
		if strings.EqualFold(x, v) {
			return true
		}
	}
	return false
}

func statusIn(list string, st int) bool {
	for _, x := range splitList(list) {
		x = strings.ToLower(x)
		if strings.HasSuffix(x, "xx") && len(x) == 3 && st/100 == int(x[0]-'0') {
			return true
		}
		if n, err := strconv.Atoi(x); err == nil && n == st {
			return true
		}
	}
	return false
}

func hasMethod(r engine.MapEntry, m string) bool {
	for _, x := range r.Methods {
		if strings.EqualFold(x, m) {
			return true
		}
	}
	return strings.EqualFold(m, "GET") && len(r.Methods) == 0 && r.Entity.Type == types.TypeURL && r.Coverage == "visited"
}

func onHost(e types.Entity, h string) bool {
	h = normalize.Hostname(h)
	k := e.Key
	if e.Type == types.TypeURL {
		k = normalize.HostFromURL(k)
	}
	return k == h || strings.HasSuffix(k, "."+h)
}

func cell(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case []string:
		return strings.Join(t, ",")
	default:
		raw, _ := json.Marshal(t)
		return string(raw)
	}
}

// cmdShow prints everything a database knows about one entity: its row
// in the map, what found it, what it leads to, and every observation.
func cmdShow(args []string) error {
	fs := newFlags("show")
	db := fs.String("db", "", "the database (default: the last run's)")
	asJSON := fs.Bool("json", false, "one JSON object")
	if err := parse(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return usagef("give one URL, hostname, address or domain after the flags")
	}
	path := *db
	if path == "" {
		if path = readLastDB(); path == "" {
			return usagef("give -db FILE")
		}
	}
	g, err := readGraph(path)
	if err != nil {
		return err
	}
	want := fs.Arg(0)
	var keys []string
	if strings.Contains(want, "://") {
		// A view of the app's router is its hash route's row first.
		if n, err := normalize.ClientURL(want); err == nil {
			keys = append(keys, n)
		}
		if n, err := normalize.URL(want); err == nil {
			keys = append(keys, n)
		}
	}
	keys = append(keys, normalize.Hostname(want), want)
	var row *engine.MapEntry
	for _, k := range keys {
		for i := range g.rows {
			if g.rows[i].Entity.Key == k {
				row = &g.rows[i]
				break
			}
		}
		if row != nil {
			break
		}
	}
	if row == nil {
		var near []string
		for _, r := range g.rows {
			if strings.Contains(strings.ToLower(r.Entity.Key), strings.ToLower(want)) {
				near = append(near, r.Entity.Key)
			}
		}
		sort.Strings(near)
		if len(near) > 10 {
			near = append(near[:10], fmt.Sprintf("… %d more", len(near)-10))
		}
		if len(near) == 0 {
			return fmt.Errorf("%s is not in %s", want, path)
		}
		return usagef("%s is not in %s; did you mean one of:\n  %s", want, path, strings.Join(near, "\n  "))
	}
	st, err := store.OpenExisting(path)
	if err != nil {
		return err
	}
	defer st.Close()
	if runs, err := st.Runs(); err == nil && len(runs) > 0 {
		st.UseRun(runs[len(runs)-1].ID)
	}
	ents, _ := st.Entities()
	edges, _ := st.Edges()
	byID := map[string]types.Entity{}
	for _, e := range ents {
		byID[e.ID] = e
	}
	type link struct {
		Rel  string `json:"rel"`
		Dir  string `json:"dir"` // in: the other entity points here
		Type string `json:"type"`
		Key  string `json:"key"`
	}
	var links []link
	for _, e := range edges {
		switch row.Entity.ID {
		case e.From:
			if o, ok := byID[e.To]; ok {
				links = append(links, link{e.Type, "out", string(o.Type), o.Key})
			}
		case e.To:
			if o, ok := byID[e.From]; ok {
				links = append(links, link{e.Type, "in", string(o.Type), o.Key})
			}
		}
	}
	sort.Slice(links, func(i, j int) bool {
		if links[i].Dir != links[j].Dir {
			return links[i].Dir < links[j].Dir
		}
		if links[i].Rel != links[j].Rel {
			return links[i].Rel < links[j].Rel
		}
		return links[i].Key < links[j].Key
	})
	var mine []types.StoredObservation
	for _, o := range g.obs {
		if o.EntityID == row.Entity.ID || o.Kind == "url" && payloadURLIs(o.Payload, row.Entity.Key) {
			mine = append(mine, o)
		}
	}
	// A name's web services: what was asked on it, and how it answered
	// or failed.
	type service struct {
		URL      string `json:"url"`
		Coverage string `json:"coverage"`
		Status   int    `json:"status,omitempty"`
		Title    string `json:"title,omitempty"`
		Error    string `json:"error,omitempty"`
	}
	var services []service
	if row.Entity.Type == types.TypeHostname {
		errs := map[string]string{}
		for _, f := range engine.FailedTargets(ents, g.obs) {
			if errs[f.Target] == "" {
				errs[f.Target] = f.Error
			}
		}
		for _, r := range g.rows {
			if r.Entity.Type != types.TypeURL || normalize.HostFromURL(r.Entity.Key) != row.Entity.Key {
				continue
			}
			if u, err := url.Parse(r.Entity.Key); err != nil || u.Path != "" && u.Path != "/" {
				continue
			}
			services = append(services, service{URL: r.Entity.Key, Coverage: r.Coverage, Status: r.Status, Title: r.Title, Error: errs[r.Entity.Key]})
		}
	}
	if *asJSON {
		obs := make([]map[string]any, 0, len(mine))
		for _, o := range mine {
			obs = append(obs, map[string]any{"collector": o.Collector, "kind": o.Kind, "source": o.Source, "observed_at": o.ObservedAt, "payload": o.Payload})
		}
		out := map[string]any{"row": mapRowJSON(*row), "links": links, "observations": obs}
		if len(services) > 0 {
			out["services"] = services
		}
		return json.NewEncoder(os.Stdout).Encode(out)
	}
	fmt.Println(row.Line())
	for _, d := range row.Details() {
		fmt.Printf("    %s\n", d)
	}
	fmt.Printf("first seen %s, last seen %s\n", row.Entity.FirstSeen.Local().Format(time.DateTime), row.Entity.LastSeen.Local().Format(time.DateTime))
	if len(row.Found) > 0 {
		fmt.Println("found in")
		for _, s := range row.Found {
			fmt.Printf("  %s\n", s)
		}
	}
	if len(links) > 0 {
		fmt.Println("links")
		for i, l := range links {
			if i == 40 {
				fmt.Printf("  … %d more (-json lists all)\n", len(links)-40)
				break
			}
			arrow := "→"
			if l.Dir == "in" {
				arrow = "←"
			}
			fmt.Printf("  %s %s %s %s\n", arrow, l.Rel, l.Type, l.Key)
		}
	}
	if len(services) > 0 {
		fmt.Println("web services")
		for _, sv := range services {
			line := fmt.Sprintf("  %s  %s", sv.URL, sv.Coverage)
			if sv.Status != 0 {
				line += fmt.Sprintf("  status=%d", sv.Status)
			}
			if sv.Title != "" {
				line += "  " + sv.Title
			}
			if sv.Error != "" {
				line += "  ! " + sv.Error
			}
			fmt.Println(line)
		}
	}
	fmt.Println("observations")
	for _, o := range mine {
		fmt.Printf("  %s %s %s\n", o.Collector, o.Kind, compact(o.Payload))
	}
	return nil
}

func payloadURLIs(raw json.RawMessage, key string) bool {
	var p struct {
		URL string `json:"url"`
	}
	if json.Unmarshal(raw, &p) != nil || p.URL == "" {
		return false
	}
	n, err := normalize.URL(p.URL)
	return err == nil && n == key
}
