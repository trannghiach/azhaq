package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/trannghiach/azhaq/internal/collectors/httpcol"
	"github.com/trannghiach/azhaq/internal/fetch"
	"github.com/trannghiach/azhaq/internal/normalize"
	"github.com/trannghiach/azhaq/internal/webextract"
	"github.com/trannghiach/azhaq/store"
	"github.com/trannghiach/azhaq/types"
)

// role is one session: a name and the headers its requests carry, or the
// account it signs in with. A role with neither is anonymous.
type role struct {
	name       string
	headers    []string
	user, pass string
	session    http.Header // what its requests carried, once its run signed in
}

func (r role) anonymous() bool { return len(r.headers) == 0 && r.user == "" }

// answer is how an endpoint answered one session.
type answer struct {
	Status int      `json:"status"`
	Length int      `json:"length"`
	Hash   string   `json:"hash,omitempty"`
	Keys   []string `json:"keys,omitempty"` // a JSON answer's top-level fields
	Title  string   `json:"title,omitempty"`
}

// roleRow is one endpoint across the sessions.
type roleRow struct {
	URL     string            `json:"url"`
	Status  map[string]int    `json:"status"` // 0: not asked in that role
	Answers map[string]answer `json:"answers"`
	FoundBy []string          `json:"found_by"`           // the roles whose own runs reached it
	From    string            `json:"template,omitempty"` // the route it fills in, for an object URL made from a role's answers
	Verdict string            `json:"verdict"`
}

// Verdicts, in the order rows are listed.
const (
	verdictObject     = "every signed-in role reads the same object"
	verdictPublicObj  = "anyone reads the same object, signed in or not"
	verdictShared     = "same answer for a session that did not find it"
	verdictSignedIn   = "signed-in only"
	verdictRoleGated  = "some roles refused"
	verdictFields     = "different fields per role"
	verdictStatus     = "status differs"
	verdictData       = "different data per role"
	verdictSame       = "same for every role"
	verdictNone       = "no role reads it"
	verdictUnanswered = "not answered"
)

var verdictOrder = map[string]int{verdictObject: 0, verdictShared: 1, verdictSignedIn: 2, verdictRoleGated: 3, verdictFields: 4,
	verdictPublicObj: 5, verdictStatus: 6, verdictData: 7, verdictSame: 8, verdictNone: 9, verdictUnanswered: 10}

// cmdRoles maps the same target once per session, then asks every
// endpoint any session reached with every other session, and lists the
// endpoints whose answer depends on who asks:
//
//	azhaq roles -role anon -role 'user=Authorization: Bearer …' -- -url https://app/
//	azhaq roles -login https://app/login -role anon -role-login 'alice=a@x.test:pw' -role-login 'bob=b@x.test:pw' -- -url https://app/
func cmdRoles(args []string) error {
	fs := newFlags("roles")
	var specs, logins stringsFlag
	fs.Var(&specs, "role", "NAME, or NAME=Header: value (repeat a name to add headers; a role with none is anonymous)")
	fs.Var(&logins, "role-login", "NAME=USER:PASSWORD: a role that signs in on the -login page with Chrome")
	loginURL := fs.String("login", "", "the login page for -role-login")
	dir := fs.String("dir", "", "directory for one database per role (default: azhaq-roles-<time>)")
	jsonl := fs.Bool("jsonl", false, "one JSON object per endpoint (same as -json)")
	asJSON := fs.Bool("json", false, "one JSON object per endpoint, and the summary as JSON on stderr")
	replay := fs.Bool("replay", true, "ask every endpoint one session reached with every other session (GETs that change nothing only)")
	replayMax := fs.Int("replay-max", 2000, "requests the replay may send, over all roles")
	all := fs.Bool("all", false, "also list endpoints that answer every role the same, or with each role's own data")
	if err := parse(fs, args); err != nil {
		return err
	}
	*asJSON = *asJSON || *jsonl
	runArgs := fs.Args()
	if len(runArgs) > 0 && runArgs[0] == "--" {
		runArgs = runArgs[1:]
	}
	roles, err := parseRoles(specs)
	if err != nil {
		return err
	}
	if roles, err = addLogins(roles, logins); err != nil {
		return err
	}
	if len(logins) > 0 && *loginURL == "" {
		return usagef("-role-login needs -login, the page to sign in on")
	}
	if len(roles) < 2 {
		return usagef("need at least two -role, for example -role anon -role 'user=Cookie: session=…'")
	}
	if len(runArgs) == 0 {
		return usagef("give the run options after --, for example -- -url https://app.example.com/")
	}
	for _, a := range runArgs {
		switch strings.TrimLeft(strings.SplitN(a, "=", 2)[0], "-") {
		case "db", "cookie", "header", "login", "login-user", "login-pass":
			return usagef("roles sets -%s itself; leave it out of the run options", strings.TrimLeft(strings.SplitN(a, "=", 2)[0], "-"))
		}
	}
	if *dir == "" {
		*dir = "azhaq-roles-" + time.Now().Format("20060102-150405")
	}
	if err := os.MkdirAll(*dir, 0o755); err != nil {
		return err
	}
	rep := newReport("roles")
	rep.what = "endpoints listed"
	rep.DB = *dir

	answers := map[string]map[string]answer{} // role → URL → answer
	found := map[string][]string{}            // URL → roles whose run reached it
	ids := map[string]map[string][]string{}   // role → field → values its answers held
	templates := map[string]bool{}            // GET routes with path parameters
	made := map[string]string{}               // object URL → the template it fills
	var scopeHosts []string
	for i, r := range roles {
		db := filepath.Join(*dir, r.name+".db")
		args := append([]string{"-db", db, "-quiet"}, runArgs...)
		for _, h := range r.headers {
			args = append(args, "-header", h)
		}
		if r.user != "" {
			args = append(args, "-login", *loginURL, "-login-user", r.user, "-login-pass", r.pass)
		}
		fmt.Fprintf(os.Stderr, "azhaq roles: %s\n", r.name)
		sub, err := runEmbedded(args)
		if err != nil {
			return fmt.Errorf("role %s: %w", r.name, err)
		}
		roles[i].session = fetch.Extra.Clone()
		rep.Requests += sub.Requests
		rep.Failed = append(rep.Failed, sub.Failed...)
		got, hosts, seen, err := endpointAnswers(db)
		if err != nil {
			return err
		}
		answers[r.name], ids[r.name] = got, seen.ids
		for t := range seen.templates {
			templates[t] = true
		}
		for u := range got {
			found[u] = append(found[u], r.name)
		}
		scopeHosts = append(scopeHosts, hosts...)
	}
	if *replay {
		// /books/v1/{book_title} with the titles each role's answers held:
		// whose objects can the others read?
		for u, inst := range instances(templates, ids) {
			if _, ok := found[u]; !ok {
				found[u] = inst.owners
				made[u] = inst.template
			}
		}
		n, err := replayAll(roles, answers, found, scopeHosts, runArgs, *replayMax)
		rep.Requests += int64(n)
		if err != nil {
			rep.Notes = append(rep.Notes, "replay: "+err.Error())
		}
	}

	rows := roleRows(roles, answers, found, made)
	counts := map[string]int{}
	var shown []roleRow
	for _, row := range rows {
		counts[row.Verdict]++
		if *all || listed(row.Verdict) {
			shown = append(shown, row)
		}
	}
	rep.Results, rep.Counts = len(shown), counts
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		for _, row := range shown {
			if err := enc.Encode(row); err != nil {
				return err
			}
		}
		return rep.finish(true, false)
	}
	printRoles(roles, shown, len(rows), *dir)
	return rep.finish(false, false)
}

// listed: the verdicts worth a reader's time by default.
func listed(v string) bool {
	switch v {
	case verdictObject, verdictPublicObj, verdictShared, verdictSignedIn, verdictRoleGated, verdictFields, verdictStatus:
		return true
	}
	return false
}

func printRoles(roles []role, rows []roleRow, compared int, dir string) {
	names := make([]string, len(roles))
	for i, r := range roles {
		names[i] = r.name
	}
	fmt.Printf("roles  %s  (%d endpoints compared, %d listed; databases in %s)\n", strings.Join(names, " · "), compared, len(rows), dir)
	for _, row := range rows {
		cells := make([]string, len(roles))
		for i, r := range roles {
			a, ok := row.Answers[r.name]
			switch {
			case !ok || a.Status == 0:
				cells[i] = "-"
			case a.Status >= 200 && a.Status < 300:
				cells[i] = fmt.Sprintf("%d:%s", a.Status, size(a.Length))
			default:
				cells[i] = strconv.Itoa(a.Status)
			}
		}
		line := fmt.Sprintf("  %s  %s  [%s]", strings.Join(cells, " → "), row.URL, row.Verdict)
		switch row.Verdict {
		case verdictShared:
			line += " found by " + strings.Join(row.FoundBy, ", ")
		case verdictObject, verdictPublicObj:
			line += " from " + row.From
		}
		fmt.Println(line)
	}
}

func size(n int) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1fM", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1fk", float64(n)/(1<<10))
	default:
		return strconv.Itoa(n)
	}
}

// replayAll asks each URL some role reached with every role that did not
// reach it, through that role's session. Only GETs that change nothing,
// on the run's own hosts, are sent.
func replayAll(roles []role, answers map[string]map[string]answer, found map[string][]string, hosts, runArgs []string, budget int) (int, error) {
	own := map[string]bool{}
	for _, h := range hosts {
		own[h] = true
	}
	var urls []string
	for u := range found {
		if replayable(u, own) {
			urls = append(urls, u)
		}
	}
	sort.Strings(urls)
	rate := 0.0
	if fs := flagsOf("run"); fs != nil && fs.Parse(runArgs) == nil {
		rate, _ = strconv.ParseFloat(fs.Lookup("rate").Value.String(), 64)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	client := fetch.Client(nil)
	sent := 0
	for _, r := range roles {
		fetch.Reset()
		fetch.SetRate(rate)
		fetch.Allow = func(h string) bool { return own[normalize.Hostname(h)] }
		fetch.Extra = r.session.Clone()
		for _, u := range urls {
			if _, ok := answers[r.name][u]; ok {
				continue
			}
			if sent >= budget {
				return sent, fmt.Errorf("stopped after -replay-max %d requests", budget)
			}
			if ctx.Err() != nil {
				return sent, ctx.Err()
			}
			res, _, err := fetch.Do(ctx, client, u)
			sent++
			if err != nil {
				continue
			}
			answers[r.name][u] = answerOf(res.Status, res.Body, res.Header.Get("Content-Type"))
		}
	}
	fetch.Reset()
	return sent, nil
}

// replayable: a page or API route on the run's hosts, asked with GET and
// a name that does not say it does something.
func replayable(u string, own map[string]bool) bool {
	if strings.Contains(u, "{") || !own[normalize.HostFromURL(u)] || webextract.StateChanging(u) != "" {
		return false
	}
	switch webextract.ClassifyURL(u) {
	case "asset", "script":
		return false
	}
	return true
}

// roleRows puts each endpoint's answers side by side and says what the
// difference means.
func roleRows(roles []role, answers map[string]map[string]answer, found map[string][]string, made map[string]string) []roleRow {
	var rows []roleRow
	for u, by := range found {
		if c := webextract.ClassifyURL(u); c == "asset" || c == "script" {
			continue // the same file for everyone, by design
		}
		row := roleRow{URL: u, Status: map[string]int{}, Answers: map[string]answer{}, FoundBy: by, From: made[u]}
		for _, r := range roles {
			a := answers[r.name][u]
			row.Status[r.name] = a.Status
			if a.Status != 0 {
				row.Answers[r.name] = a
			}
		}
		row.Verdict = verdict(roles, row)
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool {
		if a, b := verdictOrder[rows[i].Verdict], verdictOrder[rows[j].Verdict]; a != b {
			return a < b
		}
		return rows[i].URL < rows[j].URL
	})
	return rows
}

func ok2xx(s int) bool { return s >= 200 && s < 300 }

func verdict(roles []role, row roleRow) string {
	if len(row.Answers) < 2 {
		return verdictUnanswered
	}
	found := map[string]bool{}
	for _, n := range row.FoundBy {
		found[n] = true
	}
	var anonOK, anonNo, stranger bool
	signedOK, signedNo := 0, 0
	statuses := map[int]bool{}
	hashes := map[string]bool{}
	shapes := map[string]bool{}
	for _, r := range roles {
		a, ok := row.Answers[r.name]
		if !ok {
			continue
		}
		statuses[a.Status] = true
		if ok2xx(a.Status) {
			hashes[a.Hash] = true
			shapes[strings.Join(a.Keys, ",")] = true
			if !found[r.name] {
				stranger = true // it reads what it never reached itself
			}
		}
		denied := a.Status == 401 || a.Status == 403
		switch {
		case r.anonymous() && ok2xx(a.Status):
			anonOK = true
		case r.anonymous() && denied:
			anonNo = true
		case ok2xx(a.Status):
			signedOK++
		case denied || a.Status == 404:
			signedNo++
		}
	}
	same := len(hashes) == 1
	switch {
	case signedOK == 0 && !anonOK:
		return verdictNone
	case row.From != "" && same && anonOK && signedNo == 0:
		return verdictPublicObj
	case row.From != "" && same && signedOK > 1 && signedNo == 0:
		// An object named in one answer (a book, a basket, a user) that
		// every signed-in role reads alike: worth a look for whose it is.
		return verdictObject
	case same && stranger && !public(row.URL):
		// A role that never reached the URL gets the answer the role
		// that found it got: another user's basket, an order.
		return verdictShared
	case len(statuses) == 1 && same:
		return verdictSame
	case len(statuses) == 1:
		if len(shapes) > 1 {
			return verdictFields
		}
		return verdictData
	case anonNo && signedOK > 0 && signedNo == 0:
		return verdictSignedIn
	case signedOK > 0 && signedNo > 0:
		return verdictRoleGated
	}
	return verdictStatus
}

// public: a front page or a static document every visitor gets.
func public(u string) bool {
	p, err := url.Parse(u)
	return err == nil && (p.Path == "" || p.Path == "/")
}

func firstKey(m map[int]bool) int {
	for k := range m {
		return k
	}
	return 0
}

// answerOf summarizes a response the way roles compares them.
func answerOf(status int, body []byte, contentType string) answer {
	sum := sha256.Sum256(body)
	a := answer{Status: status, Length: len(body), Hash: hex.EncodeToString(sum[:8])}
	a.Keys = httpcol.JSONKeys(body, contentType)
	return a
}

func parseRoles(specs []string) ([]role, error) {
	var out []role
	idx := map[string]int{}
	for _, s := range specs {
		name, header, hasHeader := strings.Cut(s, "=")
		name = strings.TrimSpace(name)
		if name == "" || strings.ContainsAny(name, `/\ `) {
			return nil, usagef("-role %q: want NAME or NAME=Header: value", s)
		}
		i, ok := idx[name]
		if !ok {
			i = len(out)
			idx[name] = i
			out = append(out, role{name: name})
		}
		if hasHeader {
			if k, _, ok := strings.Cut(header, ":"); !ok || strings.TrimSpace(k) == "" {
				return nil, usagef("-role %q: the header must be K: V", s)
			}
			out[i].headers = append(out[i].headers, strings.TrimSpace(header))
		}
	}
	return out, nil
}

// addLogins adds the roles that sign in: NAME=USER:PASSWORD.
func addLogins(roles []role, specs []string) ([]role, error) {
	for _, s := range specs {
		name, cred, _ := strings.Cut(s, "=")
		user, pass, ok := strings.Cut(cred, ":")
		name = strings.TrimSpace(name)
		if !ok || name == "" || user == "" || pass == "" || strings.ContainsAny(name, `/\ `) {
			return nil, usagef("-role-login %q: want NAME=USER:PASSWORD", strings.SplitN(s, ":", 2)[0]+":…")
		}
		for _, r := range roles {
			if r.name == name {
				return nil, usagef("-role-login %s: a role of that name is already given", name)
			}
		}
		roles = append(roles, role{name: name, user: user, pass: pass})
	}
	return roles, nil
}

// instances fills each template's path parameters with values the roles'
// answers held for a field of that name (a few per role): the URL of an
// object and the role it belongs to.
type instance struct {
	template string
	owners   []string
}

func instances(templates map[string]bool, ids map[string]map[string][]string) map[string]instance {
	out := map[string]instance{}
	for t := range templates {
		names := placeholder.FindAllString(t, -1)
		for owner, pool := range ids {
			n := 0
			for _, v := range valuesFor(strings.Trim(names[0], "{}"), pool) {
				if n == 3 {
					break
				}
				u := strings.Replace(t, names[0], url.PathEscape(v), 1)
				filled := true
				for _, ph := range names[1:] {
					vs := valuesFor(strings.Trim(ph, "{}"), pool)
					if len(vs) == 0 {
						filled = false
						break
					}
					u = strings.Replace(u, ph, url.PathEscape(vs[0]), 1)
				}
				if filled {
					in := out[u]
					in.template, in.owners = t, append(in.owners, owner)
					out[u] = in
					n++
				}
			}
		}
	}
	return out
}

// valuesFor finds values for a path parameter: a field of the same name,
// else for an id-like name, the id fields.
func valuesFor(name string, pool map[string][]string) []string {
	if vs := pool[name]; len(vs) > 0 {
		return vs
	}
	for k, vs := range pool {
		if strings.EqualFold(k, name) {
			return vs
		}
	}
	if l := strings.ToLower(name); l == "id" || strings.HasSuffix(l, "id") || strings.HasSuffix(l, "_id") {
		return pool["id"]
	}
	return nil
}

// runSeen is what one role's run saw besides answers: identifier values
// in JSON answers and GET routes with path parameters.
type runSeen struct {
	ids       map[string][]string
	templates map[string]bool
}

// endpointAnswers is how each URL answered in one role's run (the first
// real answer, catch-all answers left out), the hosts the run was pointed
// at, and what it saw that the replay can fill templates with.
func endpointAnswers(db string) (map[string]answer, []string, runSeen, error) {
	seen := runSeen{ids: map[string][]string{}, templates: map[string]bool{}}
	st, err := store.Open(db)
	if err != nil {
		return nil, nil, seen, err
	}
	defer st.Close()
	obs, err := st.Observations()
	if err != nil {
		return nil, nil, seen, err
	}
	out := map[string]answer{}
	for _, o := range obs {
		var q struct {
			URL     string              `json:"url"`
			Methods []string            `json:"methods"`
			IDs     map[string][]string `json:"json_ids"`
		}
		if json.Unmarshal(o.Payload, &q) == nil {
			for k, vs := range q.IDs {
				for _, v := range vs {
					if len(seen.ids[k]) < 10 && !slices.Contains(seen.ids[k], v) {
						seen.ids[k] = append(seen.ids[k], v)
					}
				}
			}
			if o.Kind == "url" && strings.Contains(q.URL, "{") && slices.ContainsFunc(q.Methods, func(m string) bool { return strings.EqualFold(m, "GET") }) {
				if u, err := normalize.URL(q.URL); err == nil {
					seen.templates[webextract.RouteKey(u)] = true
				}
			}
		}
		if o.Kind == "error" || o.Kind == "skipped" {
			continue
		}
		var p struct {
			URL      string   `json:"url"`
			Status   int      `json:"status"`
			CatchAll bool     `json:"catchall"`
			Length   int      `json:"length"`
			Hash     string   `json:"body_hash"`
			Keys     []string `json:"json_keys"`
			Title    string   `json:"title"`
		}
		if json.Unmarshal(o.Payload, &p) != nil || p.URL == "" || p.Status == 0 || p.CatchAll {
			continue
		}
		if o.Collector != "azhaq-http" && o.Collector != "azhaq-paths" && o.Kind != "application" {
			continue
		}
		u, err := normalize.URL(p.URL)
		if err != nil {
			continue
		}
		if _, ok := out[u]; !ok {
			out[u] = answer{Status: p.Status, Length: p.Length, Hash: p.Hash, Keys: p.Keys, Title: p.Title}
		}
	}
	seeds, _ := st.LoadSeeds()
	var hosts []string
	for _, s := range seeds {
		s = normalize.Seed(s)
		switch s.Type {
		case types.TypeURL:
			hosts = append(hosts, normalize.HostFromURL(s.Key()))
		case types.TypeHostname, types.TypeIPAddress:
			hosts = append(hosts, s.Key())
		}
	}
	return out, hosts, seen, nil
}
