package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/trannghiach/azhaq/internal/browser"
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
	cmd        string      // prints its headers: run before its run and again before the replay
	session    http.Header // what its requests carried, once its run signed in
}

func (r role) anonymous() bool { return len(r.headers) == 0 && r.user == "" && r.cmd == "" }

// roleRow is one endpoint across the sessions.
type roleRow struct {
	URL       string            `json:"url"`
	Method    string            `json:"method,omitempty"` // a write's: POST, PUT, PATCH, DELETE; reads have none
	Status    map[string]int    `json:"status"`           // 0: not asked in that role
	Answers   map[string]answer `json:"answers"`
	FoundBy   []string          `json:"found_by"`            // the roles whose own runs reached it, or whose answers held its identifier
	From      string            `json:"template,omitempty"`  // the route it fills in, for an object URL
	Owner     string            `json:"owner,omitempty"`     // the role whose own object it is: given with -id, or held by that role's answers alone
	OwnerBy   string            `json:"owner_by,omitempty"`  // what says it is the owner's: bid claim of alice's token → /rest/basket/{id}
	Readers   []string          `json:"readers,omitempty"`   // the roles the verdict says read it
	Sensitive []string          `json:"sensitive,omitempty"` // the sensitive fields the verdict is about
	Verdict   string            `json:"verdict"`

	given bool   // Owner was given with -id
	value string // the identifier filled into the route
}

// Verdicts, in the order rows are listed.
const (
	verdictAnyoneSecrets = "anyone reads sensitive fields"
	verdictCross         = "reads another role's object"
	verdictObject        = "every signed-in role reads the same object"
	verdictSecrets       = "roles read the same sensitive fields"
	verdictShared        = "same answer for a session that did not find it"
	verdictSignedIn      = "signed-in only"
	verdictOnly          = "only one role reads it"
	verdictRoleGated     = "some roles refused"
	verdictFields        = "different fields per role"
	verdictPublicObj     = "anyone reads the same object, signed in or not"
	verdictStatus        = "status differs"
	verdictData          = "different data per role"
	verdictSame          = "same for every role"
	verdictNone          = "no role reads it"
	verdictUnanswered    = "not answered"
)

var verdictOrder = map[string]int{verdictAnyoneSecrets: 0, verdictCross: 1, verdictObject: 2, verdictSecrets: 3, verdictShared: 4,
	verdictSignedIn: 5, verdictOnly: 6, verdictRoleGated: 7, verdictFields: 8, verdictPublicObj: 9, verdictStatus: 10,
	verdictData: 11, verdictSame: 12, verdictNone: 13, verdictUnanswered: 14}

// cmdRoles maps the same target once per session, then asks every
// endpoint any session reached with every other session, and lists the
// endpoints whose answer depends on who asks:
//
//	azhaq roles -role anon -role 'user=Authorization: Bearer …' -- -url https://app/
//	azhaq roles -login https://app/login -role anon -role-login 'alice=a@x.test:pw' -role-login 'bob=b@x.test:pw' -- -url https://app/
func cmdRoles(args []string) error {
	fs := newFlags("roles")
	var specs, logins, cmds, idSpecs, hars stringsFlag
	fs.Var(&specs, "role", "NAME, or NAME=Header: value (repeat a name to add headers; a role with none is anonymous). Only these headers are sent: a session the app reads from a cookie needs NAME=Cookie: …")
	fs.Var(&cmds, "role-cmd", "NAME=COMMAND: a role whose headers a shell command prints, one Header: value per line (a bare token is sent as Authorization: Bearer); run before the role's run and again before the replay, for tokens that live minutes")
	fs.Var(&logins, "role-login", "NAME=USER:PASSWORD: a role that signs in on the -login page with Chrome, and sends the cookies and the token the login left")
	fs.Var(&idSpecs, "id", "[ROLE:]NAME=VALUE: also fill routes with this identifier. NAME is a path parameter (book_title), a JSON field holding such values (basket_id) or a route (/rest/basket/{id}); with ROLE, VALUE names ROLE's own object, and another role that reads it is listed")
	loginURL := fs.String("login", "", "the login page for -role-login")
	dir := fs.String("dir", "", "directory for one database per role (default: azhaq-roles-<time>)")
	jsonl := fs.Bool("jsonl", false, "one JSON object per endpoint (same as -json)")
	asJSON := fs.Bool("json", false, "one JSON object per endpoint, and only the summary, as JSON, on stderr")
	replay := fs.Bool("replay", true, "ask every endpoint one session reached with every other session, and each role's objects with the others (GETs that change nothing only)")
	replayMax := fs.Int("replay-max", 2000, "requests the replay may send, over all roles")
	all := fs.Bool("all", false, "also list endpoints that answer every role the same, or with each role's own data")
	writesSpec := fs.String("replay-writes", "", "also replay writes with every other role's session: post,put,patch (add delete to delete objects). They change data on the target; needs -allow or -scope in the run options. The writes are each role's own from -har, and the PUT, PATCH (an empty object, which changes nothing) and DELETE the runs' routes take, on each role's objects")
	dryWrites := fs.Bool("dry-writes", false, "with -replay-writes: list the writes it would send, with whose and why, and send none")
	fs.Var(&hars, "har", "NAME=FILE: the requests role NAME sent, as a browser or Burp saved them (HAR): its writes are replayed with -replay-writes")
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
	if roles, err = addCmds(roles, cmds); err != nil {
		return err
	}
	if len(logins) > 0 && *loginURL == "" {
		return usagef("-role-login needs -login, the page to sign in on")
	}
	if len(roles) < 2 {
		return usagef("need at least two -role, for example -role anon -role 'user=Cookie: session=…'")
	}
	given, err := parseIDs(idSpecs, roles)
	if err != nil {
		return err
	}
	if len(runArgs) == 0 {
		return usagef("give the run options after --, for example -- -url https://app.example.com/")
	}
	var methods map[string]bool
	harOf := map[string]string{}
	if *writesSpec != "" {
		if methods, err = writeMethods(*writesSpec); err != nil {
			return err
		}
		if !hasFlag(runArgs, "allow", "scope") {
			return usagef("-replay-writes changes data on the target: name the scope with -allow or -scope in the run options")
		}
	}
	for _, h := range hars {
		name, file, ok := strings.Cut(h, "=")
		if !ok || !slices.ContainsFunc(roles, func(r role) bool { return r.name == name && !r.anonymous() }) {
			return usagef("-har %q: want NAME=FILE for a signed-in role", h)
		}
		if *writesSpec == "" {
			return usagef("-har gives writes to replay: add -replay-writes post,put,patch")
		}
		harOf[name] = file
	}
	for _, a := range runArgs {
		switch strings.TrimLeft(strings.SplitN(a, "=", 2)[0], "-") {
		case "db":
			return usagef("roles sets -db itself, one database per role in -dir; leave it out of the run options, and give -dir DIR before -- to choose where they go")
		case "cookie", "header", "login", "login-user", "login-pass":
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

	stale, soon, expired := expiryNotes(roles, time.Now())
	if !*asJSON {
		for _, n := range append(stale, soon...) {
			fmt.Fprintln(os.Stderr, "note: "+n)
		}
	}
	rep.Notes = append(rep.Notes, soon...)

	answers := map[string]map[string]answer{} // role → URL → answer
	found := map[string][]string{}            // URL → roles whose run reached it
	seen := map[string]runSeen{}              // role → the values its answers held
	templates := map[string]bool{}            // GET routes with path parameters
	made := map[string]instance{}             // object URL → the route it fills and whose object it is
	signedIn := map[string]browser.Session{}  // role → what its Chrome login left
	var scopeHosts []string
	for i, r := range roles {
		if r.cmd != "" {
			if roles[i].headers, err = cmdHeaders(r); err != nil {
				return rolesFailed(rep, *asJSON, err)
			}
			r = roles[i]
		}
		db := filepath.Join(*dir, r.name+".db")
		args := append([]string{"-db", db, "-quiet"}, runArgs...)
		for _, h := range r.headers {
			args = append(args, "-header", h)
		}
		if r.user != "" {
			args = append(args, "-login", *loginURL, "-login-user", r.user, "-login-pass", r.pass)
		}
		if !*asJSON {
			fmt.Fprintf(os.Stderr, "azhaq roles: %s\n", r.name)
		}
		browser.OnLogin = func(s browser.Session) { signedIn[r.name] = s }
		sub, err := quietly(*asJSON, func() (*report, error) { return runEmbedded(args) })
		browser.OnLogin = nil
		if err != nil {
			return rolesFailed(rep, *asJSON, fmt.Errorf("role %s: %w", r.name, err))
		}
		roles[i].session = fetch.Extra.Clone()
		got, raw, hosts, s, err := endpointAnswers(db)
		if err != nil {
			return err
		}
		readBodies(got, raw, s, hostSet(hosts))
		rep.Requests += fetch.Sent() // the run's requests, and any the cache could not answer
		absorb(rep, r.name, sub)
		answers[r.name], seen[r.name] = got, s
		for t := range s.templates {
			templates[t] = true
		}
		for u := range got {
			found[u] = append(found[u], r.name)
		}
		scopeHosts = append(scopeHosts, hosts...)
	}
	replayed := 0 // requests the read replay sent, of -replay-max
	if *replay {
		// /books/v1/{book_title} with the titles each role's answers held
		// and those given with -id: whose objects can the others read?
		rank := map[string]int{}
		who := identities(roles, answers, seen, signedIn)
		for u, in := range instances(roles, templates, seen, answers, given, who) {
			if _, ok := found[u]; ok {
				rank[u] = min(in.rank, 2)
			} else {
				found[u], rank[u] = in.holders, in.rank
			}
			made[u] = in
		}
		for _, g := range given {
			if !g.used {
				rep.Notes = append(rep.Notes, fmt.Sprintf("-id %s=%s: no GET route with path parameters the runs found takes it", g.name, g.value))
			}
		}
		for i, r := range roles {
			// A fresh token for the replay: the runs before it may have
			// outlived the one each run started with.
			if r.cmd == "" {
				continue
			}
			lines, err := cmdHeaders(r)
			if err != nil {
				rep.Notes = append(rep.Notes, "replay: "+err.Error()+"; it sends the token the role's run started with")
				continue
			}
			if roles[i].session == nil {
				roles[i].session = http.Header{}
			}
			for k, v := range headerOf(lines) {
				roles[i].session[k] = v
			}
		}
		n, err := replayAll(roles, answers, found, rank, scopeHosts, runArgs, *replayMax)
		rep.Requests += int64(n)
		replayed = n
		if err != nil {
			rep.Notes = append(rep.Notes, "replay: "+err.Error())
		}
		// Whose each object is, as its own answer says (UserId, owner,
		// BasketId), over what the identifier that filled its route said.
		settleOwners(roles, made, answers, who)
	}

	markRedirects(answers, *loginURL)
	rows := roleRows(roles, answers, found, made)
	notes, warn, asked := sessionNotes(roles, rows, expired, hostSet(scopeHosts))
	rep.Notes = append(rep.Notes, notes...)
	rep.warned = rep.warned || warn
	rep.Requests += int64(asked)
	if methods != nil {
		var reqs []writeReq
		for _, r := range roles {
			if file := harOf[r.name]; file != "" {
				ws, err := harWrites(r.name, file, methods, hostSet(scopeHosts))
				if err != nil {
					return rolesFailed(rep, *asJSON, err)
				}
				reqs = append(reqs, ws...)
			}
		}
		writes := map[string][]writeOp{}
		for _, s := range seen {
			for k, ops := range s.writes {
				for _, op := range ops {
					if !slices.ContainsFunc(writes[k], func(o writeOp) bool { return o.method == op.method }) {
						writes[k] = append(writes[k], op)
					}
				}
			}
		}
		reqs = append(reqs, mapWrites(made, writes, methods)...)
		rate := 0.0
		if fs := flagsOf("run"); fs != nil && fs.Parse(runArgs) == nil {
			rate, _ = strconv.ParseFloat(fs.Lookup("rate").Value.String(), 64)
		}
		var wrows []roleRow
		if *dryWrites {
			for _, w := range reqs {
				wrows = append(wrows, roleRow{URL: w.url, Method: w.method, Status: map[string]int{}, Answers: map[string]answer{},
					FoundBy: []string{w.owner}, Owner: w.owner, OwnerBy: w.from, Verdict: verdictWriteDry})
			}
		} else {
			var n int
			wrows, n, err = replayWrites(roles, reqs, answers, hostSet(scopeHosts), rate, max(0, *replayMax-replayed))
			rep.Requests += int64(n)
			if err != nil {
				rep.Notes = append(rep.Notes, "write replay: "+err.Error())
			}
		}
		if len(reqs) == 0 {
			rep.Notes = append(rep.Notes, "-replay-writes: no write to replay (no -har, and no PUT, PATCH or DELETE on a route with a role's own object)")
		}
		rows = append(wrows, rows...)
		sort.SliceStable(rows, func(i, j int) bool { return verdictOrder[rows[i].Verdict] < verdictOrder[rows[j].Verdict] })
	}
	counts, hidden := map[string]int{}, map[string]int{}
	public := map[string]bool{} // routes with an object anyone reads listed already: one says it
	var shown []roleRow
	for _, row := range rows {
		show := *all || listed(row.Verdict)
		if show && !*all && row.Verdict == verdictPublicObj {
			show = !public[row.From]
			public[row.From] = true
		}
		if show {
			counts[row.Verdict]++
			shown = append(shown, row)
		} else {
			hidden[row.Verdict]++
		}
	}
	if n := len(rows) - len(shown); n > 0 {
		var parts []string
		for _, v := range sortedCountKeys(hidden) {
			parts = append(parts, fmt.Sprintf("%d %s", hidden[v], v))
		}
		rep.Notes = append(rep.Notes, fmt.Sprintf("%d more endpoints compared and not listed (%s); -all lists them", n, strings.Join(parts, ", ")))
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

// quietly runs f with stderr going nowhere when on: under -json, stderr
// carries the summary of roles and nothing else.
func quietly(on bool, f func() (*report, error)) (*report, error) {
	if !on {
		return f()
	}
	null, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		return f()
	}
	saved := os.Stderr
	os.Stderr = null
	defer func() { os.Stderr = saved; null.Close() }()
	return f()
}

// absorb adds to the summary of roles what a role's run did not finish:
// its failures, targets that did not answer, what it left alone, its
// notes, and the limit that stopped it.
func absorb(rep *report, name string, sub *report) {
	rep.Failed = append(rep.Failed, sub.Failed...)
	for _, u := range sub.Unreachable {
		if !slices.Contains(rep.Unreachable, u) {
			rep.Unreachable = append(rep.Unreachable, u)
		}
	}
	for _, s := range sub.Skipped {
		if !slices.Contains(rep.Skipped, s) {
			rep.Skipped = append(rep.Skipped, s)
		}
	}
	for _, n := range sub.Notes {
		if !slices.Contains(rep.Notes, n) {
			rep.Notes = append(rep.Notes, n)
		}
	}
	if sub.Stopped != "" {
		// Its map is incomplete, and so is the comparison.
		stop := fmt.Sprintf("role %s: %s", name, sub.Stopped)
		if rep.Stopped == "" {
			rep.Stopped = stop
		} else {
			rep.Notes = append(rep.Notes, stop)
		}
	}
}

// rolesFailed ends roles when a role's run could not be done (a sign-in
// that failed): under -json, as a summary that says so.
func rolesFailed(rep *report, asJSON bool, err error) error {
	if !asJSON {
		return err
	}
	rep.settle()
	rep.Exit, rep.Complete = exitCode(err), false
	rep.Notes = append(rep.Notes, err.Error())
	raw, _ := json.Marshal(rep)
	fmt.Fprintf(os.Stderr, "%s\n", raw)
	return exitErr{code: rep.Exit}
}

// listed: the verdicts worth a reader's time by default.
func listed(v string) bool {
	switch v {
	case verdictWriteAnyone, verdictWriteCross, verdictWriteDry, verdictAnyoneSecrets, verdictCross, verdictObject, verdictSecrets, verdictShared, verdictSignedIn, verdictOnly,
		verdictRoleGated, verdictFields, verdictPublicObj, verdictStatus:
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
			case a.Error && ok2xx(a.Status):
				cells[i] = fmt.Sprintf("%d:err", a.Status) // a refusal answered as success
			case a.Status >= 200 && a.Status < 300:
				cells[i] = fmt.Sprintf("%d:%s", a.Status, size(a.Length))
			default:
				cells[i] = strconv.Itoa(a.Status)
			}
		}
		target := row.URL
		if row.Method != "" {
			target = row.Method + " " + row.URL
		}
		line := fmt.Sprintf("  %s  %s  [%s]", strings.Join(cells, " → "), target, row.label())
		switch row.Verdict {
		case verdictShared:
			line += " found by " + strings.Join(row.FoundBy, ", ")
		case verdictWriteAnyone, verdictWriteCross, verdictWriteDry:
			line += " · " + row.Owner + "'s, by " + row.OwnerBy
		case verdictCross, verdictObject, verdictPublicObj, verdictOnly:
			if row.From != "" {
				line += " from " + row.From
			}
			if row.Verdict == verdictCross && row.OwnerBy != "" {
				line += " · " + row.Owner + "'s by " + shortBy(row.OwnerBy)
			}
		}
		if len(row.Sensitive) > 0 && row.Verdict != verdictAnyoneSecrets && row.Verdict != verdictSecrets {
			line += " · sensitive: " + strings.Join(row.Sensitive, ", ")
		}
		fmt.Println(line)
	}
}

// shortBy is owner_by as the text table prints it: without the route,
// printed already, nor where each value was read ("bid claim of alice's
// token; the answer's UserId 27 names alice").
func shortBy(by string) string {
	parts := strings.Split(by, "; ")
	for i, p := range parts {
		p, _, _ = strings.Cut(p, " → ")
		if j := strings.LastIndex(p, " ("); j > 0 && strings.HasSuffix(p, ")") {
			p = p[:j]
		}
		parts[i] = p
	}
	return strings.Join(parts, "; ")
}

// label is the verdict as the text table says it, with who and what.
func (row roleRow) label() string {
	who := strings.Join(row.Readers, ", ")
	switch {
	case row.Verdict == verdictAnyoneSecrets:
		return row.Verdict + ": " + strings.Join(row.Sensitive, ", ")
	case row.Verdict == verdictSecrets && len(row.Readers) > 0:
		return who + " read the same sensitive fields: " + strings.Join(row.Sensitive, ", ")
	case row.Verdict == verdictWriteAnyone:
		return "anyone writes " + row.Owner + "'s object (" + who + ")"
	case row.Verdict == verdictWriteCross && len(row.Readers) == 1:
		return who + " writes " + row.Owner + "'s object"
	case row.Verdict == verdictWriteCross:
		return who + " write " + row.Owner + "'s object"
	case row.Verdict == verdictCross && len(row.Readers) == 1:
		return who + " reads " + row.Owner + "'s object"
	case row.Verdict == verdictCross && len(row.Readers) > 1:
		return who + " read " + row.Owner + "'s object"
	case row.Verdict == verdictOnly && len(row.Readers) == 1:
		return "only " + who + " reads it"
	}
	return row.Verdict
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

// replayAll asks each URL some role reached, and each object URL made
// from the roles' answers, with every role that has no answer for it,
// through that role's session. Only GETs that change nothing, on the
// run's own hosts, are sent. URLs go by rank (objects given with -id,
// the roles' own objects, what the runs reached, other objects), then
// name, and one is taken only while the budget holds every role's
// request for it.
func replayAll(roles []role, answers map[string]map[string]answer, found map[string][]string, rank map[string]int, hosts, runArgs []string, budget int) (int, error) {
	own := hostSet(hosts)
	rankOf := func(u string) int {
		if r, ok := rank[u]; ok {
			return r
		}
		return 2
	}
	need := func(u string) int {
		n := 0
		for _, r := range roles {
			if _, ok := answers[r.name][u]; !ok {
				n++
			}
		}
		return n
	}
	var urls []string
	for u := range found {
		if replayable(u, own) && need(u) > 0 {
			urls = append(urls, u)
		}
	}
	sort.Slice(urls, func(i, j int) bool {
		if a, b := rankOf(urls[i]), rankOf(urls[j]); a != b {
			return a < b
		}
		return urls[i] < urls[j]
	})
	var stopped error
	total := 0
	for i, u := range urls {
		if total+need(u) > budget {
			stopped = fmt.Errorf("stopped after -replay-max %d requests; %d URLs were not asked of every role", budget, len(urls)-i)
			urls = urls[:i]
			break
		}
		total += need(u)
	}
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
			if ctx.Err() != nil {
				fetch.Reset()
				return sent, ctx.Err()
			}
			res, _, err := fetch.Do(ctx, client, u)
			sent++
			if err != nil {
				continue
			}
			answers[r.name][u], _ = resultAnswer(res)
		}
	}
	fetch.Reset()
	return sent, stopped
}

// contentType is the type of the body a fetch kept: the last hop's.
func contentType(res fetch.Result) string {
	if res.FinalHeader != nil {
		return res.FinalHeader.Get("Content-Type")
	}
	return res.Header.Get("Content-Type")
}

// resultAnswer is readAnswer for a fetch, with where a redirect sends
// the role.
func resultAnswer(res fetch.Result) (answer, *jsonFacts) {
	a, f := readAnswer(res.Status, res.Body, contentType(res))
	if res.Status >= 300 && res.Status < 400 {
		a.Location = bareLocation(res.Header.Get("Location"))
	}
	return a, f
}

// signInPath: a path that asks the visitor to sign in, or says it may not.
var signInPath = regexp.MustCompile(`(?i)(^|[/._-])(login|log-in|log_in|logon|signin|sign-in|sign_in|auth|authenticate|authorize|oauth2?|sso|saml|cas|openid|sessions?/new|unauthori[sz]ed|access-?denied|forbidden)($|[/._-])`)

// signInHost: another site's sign-in service (login.example.com, sso.…).
var signInHost = regexp.MustCompile(`(?i)(^|[.-])(login|auth|sso|signin|accounts|idp)([.-]|$)`)

// markRedirects marks the redirects that refuse: to a sign-in page (a
// path that says login, sign-in, auth…, another site's sign-in service,
// or the -login page), and to the front page of the same site, which
// refuses when another role reads the endpoint.
func markRedirects(answers map[string]map[string]answer, loginURL string) {
	for _, as := range answers {
		for u, a := range as {
			if a.Status >= 300 && a.Status < 400 && a.Location != "" {
				a.toLogin, a.toRoot = redirectKind(u, a.Location, loginURL)
				as[u] = a
			}
		}
	}
}

// redirectKind says where a redirect from from to location goes: a
// sign-in page, or the site's front page.
func redirectKind(from, location, loginURL string) (toLogin, toRoot bool) {
	base, err := url.Parse(from)
	if err != nil {
		return false, false
	}
	to, err := base.Parse(location)
	if err != nil {
		return false, false
	}
	sameHost := strings.EqualFold(to.Host, base.Host)
	if l, err := url.Parse(loginURL); err == nil && loginURL != "" && strings.Trim(l.Path, "/") != "" &&
		strings.EqualFold(l.Host, to.Host) && strings.TrimRight(l.Path, "/") == strings.TrimRight(to.Path, "/") {
		return true, false
	}
	if signInPath.MatchString(to.Path) || !sameHost && signInHost.MatchString(to.Hostname()) {
		return true, false
	}
	return false, sameHost && strings.Trim(to.Path, "/") == "" && strings.Trim(base.Path, "/") != ""
}

func hostSet(hosts []string) map[string]bool {
	own := map[string]bool{}
	for _, h := range hosts {
		own[h] = true
	}
	return own
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
func roleRows(roles []role, answers map[string]map[string]answer, found map[string][]string, made map[string]instance) []roleRow {
	var rows []roleRow
	for u, by := range found {
		if c := webextract.ClassifyURL(u); c == "asset" || c == "script" {
			continue // the same file for everyone, by design
		}
		in := made[u]
		if by == nil {
			by = []string{}
		}
		row := roleRow{URL: u, Status: map[string]int{}, Answers: map[string]answer{}, FoundBy: by,
			From: in.template, Owner: in.owner, given: in.given, value: in.value}
		if in.owner != "" {
			row.OwnerBy = in.by
		}
		for _, r := range roles {
			a := answers[r.name][u]
			row.Status[r.name] = a.Status
			if a.Status != 0 {
				row.Answers[r.name] = a
			}
		}
		row.Verdict = verdict(roles, &row)
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

// refusing are the roles a row's answers refuse: refused, or sent back to
// the front page while another role reads the endpoint.
func refusing(row roleRow) map[string]bool {
	anyReads := false
	for _, a := range row.Answers {
		anyReads = anyReads || reads(a)
	}
	out := map[string]bool{}
	for n, a := range row.Answers {
		if refused(a) || a.toRoot && anyReads {
			out[n] = true
		}
	}
	return out
}

// verdict says what the difference between the answers means, and fills
// the row's readers and sensitive fields when the verdict names them. A
// role reads an endpoint when it gets a 2xx answer that is not an error;
// any 4xx, an error answered as 2xx, and a redirect to a sign-in page (or
// to the front page, while another role reads it) is a refusal.
func verdict(roles []role, row *roleRow) string {
	if len(row.Answers) < 2 {
		return verdictUnanswered
	}
	found := map[string]bool{}
	for _, n := range row.FoundBy {
		found[n] = true
	}
	no := refusing(*row)
	var readers, refusers []string
	var anonReads, anonRefused, stranger bool
	signedReads, signedRefused := 0, 0
	statuses := map[int]bool{}
	hashes := map[string]bool{}
	for _, r := range roles {
		a, ok := row.Answers[r.name]
		if !ok {
			continue
		}
		statuses[a.Status] = true
		switch {
		case reads(a):
			readers = append(readers, r.name)
			hashes[a.Hash] = true
			if !found[r.name] {
				stranger = true // it reads what it never reached itself
			}
			if r.anonymous() {
				anonReads = true
			} else {
				signedReads++
			}
		case no[r.name]:
			refusers = append(refusers, r.name)
			if r.anonymous() {
				anonRefused = true
			} else {
				signedRefused++
			}
		}
	}
	if len(readers) == 0 {
		return verdictNone
	}
	for _, r := range roles {
		if r.anonymous() && found[r.name] {
			stranger = false // the anonymous visitor reached it: no one's private data
		}
	}
	if len(row.FoundBy) == 0 {
		stranger = false // an identifier given with -id: nobody found it
	}
	same := len(hashes) == 1
	anyone, shared, holders := exposed(roles, *row, readers)
	if len(anyone) > 0 {
		// Passwords, keys and other people's tokens, to a visitor who
		// never signed in, even when everyone gets the same answer.
		row.Sensitive = anyone
		return verdictAnyoneSecrets
	}
	if row.Owner != "" {
		if rs := othersRead(roles, *row); len(rs) > 0 {
			row.Readers, row.Sensitive = rs, shared
			return verdictCross
		}
	}
	switch {
	case row.From != "" && same && anonReads && signedRefused == 0:
		return verdictPublicObj
	case row.From != "" && same && signedReads > 1 && signedRefused == 0:
		// An object named in one answer (a book, a basket, a user) that
		// every signed-in role reads alike: worth a look for whose it is.
		row.Sensitive = shared
		return verdictObject
	case len(shared) > 0:
		// The same secret values for several sessions: not their own.
		row.Sensitive, row.Readers = shared, holders
		return verdictSecrets
	case same && stranger && !public(row.URL):
		// A role that never reached the URL gets the answer the role
		// that found it got: another user's basket, an order.
		return verdictShared
	}
	allRead := len(readers) == len(row.Answers)
	switch {
	case allRead && same:
		return verdictSame
	case allRead && len(statuses) == 1:
		for _, n := range readers[1:] {
			if fieldsDiffer(row.Answers[readers[0]], row.Answers[n]) {
				return verdictFields
			}
		}
		return verdictData
	case anonRefused && signedReads > 0 && signedRefused == 0:
		return verdictSignedIn
	case len(readers) == 1 && len(refusers) == len(row.Answers)-1:
		row.Readers = readers
		return verdictOnly
	case signedReads > 0 && signedRefused > 0:
		return verdictRoleGated
	}
	return verdictStatus
}

// exposed sorts the sensitive values the readers got: the fields the
// anonymous visitor reads (a token only when another session reads the
// same value, else it is the visitor's own), and the fields more than
// one session reads with the same value (no session's own), with the
// roles that read them.
func exposed(roles []role, row roleRow, readers []string) (anyone, shared, holders []string) {
	count := map[string]int{}
	for _, n := range readers {
		sums := map[string]bool{}
		for _, s := range row.Answers[n].secrets {
			sums[s.sum] = true
		}
		for s := range sums {
			count[s]++
		}
	}
	for _, r := range roles {
		if !slices.Contains(readers, r.name) {
			continue
		}
		for _, s := range row.Answers[r.name].secrets {
			if r.anonymous() && (!s.token || count[s.sum] > 1) && !slices.Contains(anyone, s.field) {
				anyone = append(anyone, s.field)
			}
			if count[s.sum] > 1 {
				if !slices.Contains(shared, s.field) {
					shared = append(shared, s.field)
				}
				if !slices.Contains(holders, r.name) {
					holders = append(holders, r.name)
				}
			}
		}
	}
	sort.Strings(anyone)
	sort.Strings(shared)
	return anyone, shared, holders
}

// othersRead are the roles besides the owner that read the owner's
// object as the owner does. An object the owner was not given for, which
// the anonymous visitor reads alike, is public rather than the owner's.
func othersRead(roles []role, row roleRow) []string {
	oa, ok := row.Answers[row.Owner]
	if !ok || !reads(oa) {
		return nil
	}
	var out []string
	for _, r := range roles {
		a, ok := row.Answers[r.name]
		if r.name == row.Owner || !ok || !reads(a) || !alike(a, oa, row.value) {
			continue
		}
		if r.anonymous() && !row.given {
			return nil
		}
		out = append(out, r.name)
	}
	return out
}

// alike: the same object: the same body, or the same fields around the
// same identifier.
func alike(a, b answer, id string) bool {
	if a.Hash == b.Hash {
		return true
	}
	return id != "" && len(a.Keys) > 0 && !fieldsDiffer(a, b) && a.held[id] && b.held[id]
}

// public: a front page or a static document every visitor gets.
func public(u string) bool {
	p, err := url.Parse(u)
	return err == nil && (p.Path == "" || p.Path == "/")
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

// addCmds adds the roles whose headers a command prints: NAME=COMMAND.
func addCmds(roles []role, specs []string) ([]role, error) {
	for _, s := range specs {
		name, cmd, _ := strings.Cut(s, "=")
		name = strings.TrimSpace(name)
		if name == "" || strings.TrimSpace(cmd) == "" || strings.ContainsAny(name, `/\ `) {
			return nil, usagef("-role-cmd %q: want NAME=COMMAND", s)
		}
		for _, r := range roles {
			if r.name == name {
				return nil, usagef("-role-cmd %s: a role of that name is already given", name)
			}
		}
		roles = append(roles, role{name: name, cmd: cmd})
	}
	return roles, nil
}

// cmdHeaders runs a -role-cmd role's command and reads the headers it
// prints: Header: value lines, or one bare token, sent as a bearer
// token.
func cmdHeaders(r role) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	c := exec.CommandContext(ctx, "sh", "-c", r.cmd)
	c.Stderr = os.Stderr
	out, err := c.Output()
	if err != nil {
		return nil, fmt.Errorf("role %s: its -role-cmd failed: %w", r.name, err)
	}
	var lines []string
	for _, l := range strings.Split(string(out), "\n") {
		l = strings.TrimSpace(l)
		switch {
		case l == "":
		case strings.Contains(l, ": "):
			lines = append(lines, l)
		case !strings.ContainsAny(l, " :") && len(lines) == 0:
			lines = append(lines, "Authorization: Bearer "+l)
		default:
			return nil, fmt.Errorf("role %s: its -role-cmd printed a line that is neither Header: value nor a token", r.name)
		}
	}
	if len(lines) == 0 {
		return nil, fmt.Errorf("role %s: its -role-cmd printed no header", r.name)
	}
	return lines, nil
}

// readBodies reads the answers of a role's run again, through the
// process cache the run just filled with the role's session, so nothing
// is sent unless the cache lost one: the JSON answers for their nested
// fields, error shape, sensitive fields, the identifiers they hold and
// the list items that name their owner, and every answer the run kept
// without its body (a URL the paths collector found keeps its status
// only), so that no answer is compared by its status alone. A JSON answer
// that is not the one the run stored is left as stored. Only GETs that
// change nothing, on the run's own hosts, are asked.
func readBodies(got map[string]answer, raw map[string]string, seen runSeen, own map[string]bool) {
	ctx := context.Background()
	client := fetch.Client(nil)
	urls := make([]string, 0, len(got))
	for u := range got {
		urls = append(urls, u)
	}
	sort.Strings(urls)
	for _, u := range urls {
		a := got[u]
		blind := a.Hash == "" // the run kept no body
		if !replayable(u, own) || !blind && (!ok2xx(a.Status) || len(a.Keys) == 0) {
			continue
		}
		res, _, err := fetch.Do(ctx, client, raw[u])
		if err != nil || !blind && res.Status != a.Status {
			continue
		}
		b, f := resultAnswer(res)
		if !blind {
			if f == nil || b.Hash != a.Hash {
				continue
			}
			b.Length, b.Title = a.Length, a.Title
		}
		got[u] = b
		if f != nil {
			seen.add(u, f.ids)
			if len(f.objects) > 0 {
				seen.objects[u] = f.objects
			}
		}
	}
}

// endpointAnswers is how each URL answered in one role's run (the first
// real answer, catch-all answers left out) with the URL as the run asked
// for it, the hosts the run was pointed at, and what it saw that the
// replay can fill templates with.
func endpointAnswers(db string) (map[string]answer, map[string]string, []string, runSeen, error) {
	seen := newRunSeen()
	st, err := store.Open(db)
	if err != nil {
		return nil, nil, nil, seen, err
	}
	defer st.Close()
	obs, err := st.Observations()
	if err != nil {
		return nil, nil, nil, seen, err
	}
	out := map[string]answer{}
	raw := map[string]string{}
	for _, o := range obs {
		var q struct {
			URL     string              `json:"url"`
			Methods []string            `json:"methods"`
			IDs     map[string][]string `json:"json_ids"`
			Ops     []struct {
				Method   string `json:"method"`
				BodyType string `json:"body_type"`
			} `json:"ops"`
		}
		if json.Unmarshal(o.Payload, &q) == nil {
			if o.Kind == "url" {
				seen.addWrites(q.URL, q.Methods, q.Ops)
			}
			if u, err := normalize.URL(q.URL); err == nil {
				seen.add(u, q.IDs)
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
			URL      string      `json:"url"`
			Status   int         `json:"status"`
			CatchAll bool        `json:"catchall"`
			Length   int         `json:"length"`
			Hash     string      `json:"body_hash"`
			Keys     []string    `json:"json_keys"`
			Title    string      `json:"title"`
			Location string      `json:"location"`
			Hops     []fetch.Hop `json:"hops"`
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
		// The first answer with its body's hash: the paths collector keeps
		// a status only, and the probe of the same URL comes later.
		if old, ok := out[u]; !ok || old.Hash == "" && p.Hash != "" {
			a := storedAnswer(p.Status, p.Length, p.Hash, p.Keys, p.Title)
			if a.Status >= 300 && a.Status < 400 {
				a.Location = bareLocation(p.Location)
				if a.Location == "" && len(p.Hops) > 0 {
					a.Location = bareLocation(p.Hops[0].Location)
				}
			}
			out[u] = a
			raw[u] = p.URL
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
	return out, raw, hosts, seen, nil
}
