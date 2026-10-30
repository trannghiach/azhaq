package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/trannghiach/azhaq/internal/ledger"
)

// claimsRow is every safety claim azhaq makes about what it sent, checked
// on every path a request takes against a count made outside azhaq: a
// reverse proxy in front of the app that logs each request as its headers
// arrive, and listeners that count connections and datagrams. For each run
// the summary's requests, the ledger's lines and that count must agree.
type claimsRow struct {
	Rows    []claimRow `json:"rows"`
	Seconds float64    `json:"seconds"`
}

type claimRow struct {
	Case    string `json:"case"`
	Pace    string `json:"pace"`
	Summary int    `json:"summary"`
	Ledger  int    `json:"ledger"`
	Counter int    `json:"counter"`
	Pass    bool   `json:"pass"`
	Detail  string `json:"detail,omitempty"`
}

// The local apps the claims may touch (the bench's own azq-* containers).
const (
	claimJuice = "http://127.0.0.1:3001"
	claimVampi = "http://127.0.0.1:5002"
	claimDVWA  = "http://127.0.0.1:5030"
)

// A pace: the flags every paced run gets. A run stopped by the cap exits 4.
type claimPace struct {
	name  string
	flags []string
	cap   int
}

var (
	paceFree = claimPace{name: "unpaced"}
	pace10   = claimPace{"rate 10", []string{"-rate", "10", "-max-requests", "200"}, 200}
	pace2    = claimPace{"rate 2", []string{"-rate", "2", "-max-requests", "60"}, 60}
	paces3   = []claimPace{paceFree, pace10, pace2}
)

// ---- the independent counter ----

// seenReq is one request at the proxy, logged when its headers arrived.
type seenReq struct {
	Method  string
	Target  string // path with query
	At      time.Time
	Upgrade bool // a WebSocket upgrade
}

func (s seenReq) key() string { return s.Method + " " + s.Target }

// countProxy is a reverse proxy on 127.0.0.1 that logs every request before
// forwarding it. It forwards WebSocket upgrades (httputil.ReverseProxy does).
type countProxy struct {
	origin string // http://127.0.0.1:PORT, no slash
	srv    *http.Server
	mu     sync.Mutex
	log    []seenReq
}

func newCountProxy(upstream string) (*countProxy, error) {
	up, err := url.Parse(upstream)
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	p := &countProxy{origin: "http://" + ln.Addr().String()}
	rp := httputil.NewSingleHostReverseProxy(up)
	rp.FlushInterval = -1
	rp.ErrorLog = log.New(io.Discard, "", 0)
	// A redirect to the app's own address would lead clients around the proxy.
	rp.ModifyResponse = func(resp *http.Response) error {
		if loc := resp.Header.Get("Location"); strings.HasPrefix(loc, up.Scheme+"://"+up.Host) {
			resp.Header.Set("Location", p.origin+strings.TrimPrefix(loc, up.Scheme+"://"+up.Host))
		}
		return nil
	}
	p.srv = &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.record(r)
		rp.ServeHTTP(w, r)
	})}
	go p.srv.Serve(ln)
	return p, nil
}

func (p *countProxy) record(r *http.Request) {
	up := strings.EqualFold(r.Header.Get("Upgrade"), "websocket")
	p.mu.Lock()
	p.log = append(p.log, seenReq{r.Method, r.URL.RequestURI(), time.Now(), up})
	p.mu.Unlock()
}

func (p *countProxy) n() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.log)
}

// since is what arrived after the first n requests.
func (p *countProxy) since(n int) []seenReq {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]seenReq(nil), p.log[min(n, len(p.log)):]...)
}

func (p *countProxy) close() { _ = p.srv.Close() }

// ---- comparing ----

// multiset diff: what a holds more of than b, and the reverse, as "key xN".
func diffMultiset(a, b []string) (onlyA, onlyB []string) {
	count := map[string]int{}
	for _, k := range a {
		count[k]++
	}
	for _, k := range b {
		count[k]--
	}
	for k, n := range count {
		switch {
		case n > 0:
			onlyA = append(onlyA, fmt.Sprintf("%s x%d", k, n))
		case n < 0:
			onlyB = append(onlyB, fmt.Sprintf("%s x%d", k, -n))
		}
	}
	sort.Strings(onlyA)
	sort.Strings(onlyB)
	return
}

// ledgerKey is the entry as the proxy logs it: method and path with query
// for a request to origin; anything else keeps its whole target, so a line
// of another host or kind shows in the diff.
func ledgerKey(e ledger.Entry, origin string) string {
	if e.Kind != "http" && e.Kind != "chrome" {
		return e.Kind + " " + e.Target
	}
	u, err := url.Parse(e.Target)
	if err != nil || (u.Host != strings.TrimPrefix(origin, "http://")) {
		return strings.ToUpper(e.Method) + " " + e.Target
	}
	return strings.ToUpper(e.Method) + " " + u.RequestURI()
}

func ledgerKeys(es []ledger.Entry, origin string) []string {
	var out []string
	for _, e := range es {
		out = append(out, ledgerKey(e, origin))
	}
	return out
}

func kindCounts(es []ledger.Entry) string {
	n := map[string]int{}
	for _, e := range es {
		n[e.Kind]++
	}
	var parts []string
	for _, k := range sortedKeysInt(n) {
		parts = append(parts, fmt.Sprintf("%s %d", k, n[k]))
	}
	return strings.Join(parts, ", ")
}

func sortedKeysInt(m map[string]int) []string {
	var ks []string
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

// readLedger is the requests and connections of a ledger file, seals left out.
func readLedger(path string) []ledger.Entry {
	var out []ledger.Entry
	if err := ledger.Read(path, func(e ledger.Entry) error { out = append(out, e); return nil }); err != nil {
		logf("claims: ledger %s: %v", path, err)
	}
	return out
}

func listDiff(label string, items []string) string {
	if len(items) == 0 {
		return ""
	}
	shown := items
	if len(shown) > 12 {
		shown = shown[:12]
	}
	s := fmt.Sprintf("only %s (%d): %s", label, len(items), strings.Join(shown, "; "))
	if len(items) > len(shown) {
		s += fmt.Sprintf("; … %d more", len(items)-len(shown))
	}
	return s
}

// tally is one process's three counts and what stood in the way.
type tally struct {
	label            string
	exit             int
	summary          int // -1: the process printed none
	ledger, counter  []string
	ledgerOf         []ledger.Entry
	extra            []string // other things that must hold, when they do not
	note             string   // detail that is not a failure
	skipCounterEqual bool     // the counter holds only what can be counted (closed ports)
}

func (t tally) problems() []string {
	var out []string
	if t.exit != 0 && t.exit != 3 && t.exit != 4 {
		out = append(out, fmt.Sprintf("exit %d", t.exit))
	}
	if t.summary < 0 {
		out = append(out, "no summary with requests")
	} else if t.summary != len(t.ledger) {
		out = append(out, fmt.Sprintf("summary %d != ledger %d", t.summary, len(t.ledger)))
	}
	if !t.skipCounterEqual {
		oa, ob := diffMultiset(t.ledger, t.counter)
		if len(oa)+len(ob) > 0 {
			out = append(out, fmt.Sprintf("ledger %d != counter %d", len(t.ledger), len(t.counter)))
			out = append(out, listDiff("in the ledger", oa), listDiff("at the counter", ob))
		}
	}
	return append(out, t.extra...)
}

// claims collects the section's rows and checks.
type claims struct {
	dir    string
	row    *claimsRow
	chrome bool
	only   map[string]bool
}

func (c *claims) want(name string) bool { return len(c.only) == 0 || c.only[name] }

// finish records one check for a case at a pace, from one or more processes
// (a run and its resume): each must agree, and their counts add up.
func (c *claims) finish(name, pace string, parts ...tally) {
	var probs, details []string
	var sumS, sumL, sumC int
	first := len(c.row.Rows)
	for _, t := range parts {
		p := filterEmpty(t.problems())
		sumS, sumL, sumC = sumS+max(t.summary, 0), sumL+len(t.ledger), sumC+len(t.counter)
		label := t.label
		if label != "" {
			label += ": "
		}
		details = append(details, fmt.Sprintf("%ssummary %d, ledger %d (%s), counter %d", label, t.summary, len(t.ledger), kindCounts(t.ledgerOf), len(t.counter)))
		if t.note != "" {
			details = append(details, t.note)
		}
		probs = append(probs, p...)
		c.row.Rows = append(c.row.Rows, claimRow{Case: name + labelSuffix(t.label), Pace: pace, Summary: t.summary, Ledger: len(t.ledger), Counter: len(t.counter), Pass: len(p) == 0})
	}
	if len(parts) > 1 {
		details = append(details, fmt.Sprintf("together: summary %d, ledger %d, counter %d", sumS, sumL, sumC))
	}
	detail := strings.Join(details, "; ")
	if len(probs) > 0 {
		detail += " | " + strings.Join(probs, " | ")
	}
	c.row.Rows[first].Detail = detail
	addCheck(fmt.Sprintf("claims: %s %s: summary = ledger = what arrived", name, pace), len(probs) == 0, "%s", detail)
	logf("claims: %s %s: %v", name, pace, len(probs) == 0)
}

func labelSuffix(l string) string {
	if l == "" {
		return ""
	}
	return " (" + l + ")"
}

func filterEmpty(in []string) []string {
	var out []string
	for _, s := range in {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// ---- running azhaq ----

type azResult struct {
	stdout, stderr string
	exit           int
	seconds        float64
}

// summaryRequests is "requests" of the last JSON object on stderr that has
// one, or -1.
func summaryRequests(stderr string) int {
	ls := strings.Split(stderr, "\n")
	for i := len(ls) - 1; i >= 0; i-- {
		l := strings.TrimSpace(ls[i])
		if !strings.HasPrefix(l, "{") {
			continue
		}
		var o map[string]any
		if json.Unmarshal([]byte(l), &o) != nil {
			continue
		}
		if n, ok := o["requests"].(float64); ok {
			return int(n)
		}
	}
	return -1
}

type azProc struct {
	cmd      *exec.Cmd
	out, err bytes.Buffer
	t0       time.Time
	done     chan struct{}
}

func azStart(dir string, args ...string) *azProc {
	p := &azProc{t0: time.Now(), done: make(chan struct{})}
	p.cmd = exec.Command(azhaq, args...)
	p.cmd.Dir = dir
	p.cmd.Stdout, p.cmd.Stderr = &p.out, &p.err
	if verbose {
		logf("$ azhaq %s", strings.Join(args, " "))
	}
	if err := p.cmd.Start(); err != nil {
		p.err.WriteString(err.Error())
		close(p.done)
		return p
	}
	go func() { _ = p.cmd.Wait(); close(p.done) }()
	return p
}

func (p *azProc) wait(timeout time.Duration) azResult {
	select {
	case <-p.done:
	case <-time.After(timeout):
		_ = p.cmd.Process.Signal(syscall.SIGKILL)
		<-p.done
		p.err.WriteString("\nbench: timed out after " + timeout.String())
	}
	exit := -1
	if p.cmd.ProcessState != nil {
		exit = p.cmd.ProcessState.ExitCode()
	}
	return azResult{p.out.String(), p.err.String(), exit, time.Since(p.t0).Seconds()}
}

func azExec(dir string, timeout time.Duration, args ...string) azResult {
	r := azStart(dir, args...).wait(timeout)
	rec.Runs = append(rec.Runs, runMeasure{Tool: "azhaq", Target: "claims", Seconds: r.seconds})
	if r.exit != 0 && r.exit != 3 && r.exit != 4 {
		logf("claims: azhaq %s: exit %d: %s", firstWord(args), r.exit, lastLine(r.stderr))
	}
	return r
}

func firstWord(a []string) string {
	if len(a) == 0 {
		return ""
	}
	return a[0]
}

// settle waits out what a killed or finished process (Chrome) may still send.
func settle() { time.Sleep(700 * time.Millisecond) }

// httpTally reads the three counts of one process that sent to p: the
// ledger lines after the first ledgerFrom, the proxy's log after seenFrom.
func httpTally(label string, r azResult, ledgerPath string, ledgerFrom int, p *countProxy, seenFrom int) tally {
	es := readLedger(ledgerPath)
	es = es[min(ledgerFrom, len(es)):]
	var seen []string
	for _, s := range p.since(seenFrom) {
		seen = append(seen, s.key())
	}
	t := tally{label: label, exit: r.exit, summary: summaryRequests(r.stderr), ledger: ledgerKeys(es, p.origin), counter: seen, ledgerOf: es}
	if t.summary < 0 {
		t.note = "stderr ends: " + clip(lastLine(r.stderr), 160)
	}
	return t
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

func ledgerCount(path string) int { return len(readLedger(path)) }

// ---- the section ----

func benchClaims() *claimsRow {
	row := &claimsRow{}
	c := &claims{row: row, only: map[string]bool{}}
	for _, s := range strings.Split(os.Getenv("CLAIMS_ONLY"), ",") { // while developing: CLAIMS_ONLY=3,4
		if s = strings.TrimSpace(s); s != "" {
			c.only[s] = true
		}
	}
	c.dir, _ = filepath.Abs(filepath.Join(work, "claims-"+time.Now().Format("150405")))
	must(os.MkdirAll(c.dir, 0o755))
	if _, err := exec.LookPath("google-chrome"); err == nil {
		c.chrome = true
	} else if _, err := exec.LookPath("chromium"); err == nil {
		c.chrome = true
	}
	for _, u := range []string{claimJuice, claimVampi, claimDVWA} {
		if err := waitUp(u+"/", 20*time.Second); err != nil && !strings.Contains(u, "5030") {
			addCheck("claims: the local apps are up", false, "%v", err)
			return row
		}
	}
	t0 := time.Now()
	c.selfCheck()
	steps := []struct {
		id string
		fn func()
	}{
		{"1", c.caseRun}, {"2", c.caseBrowser}, {"3", c.caseShots}, {"4", c.caseDVWA}, {"5", c.caseRoles},
		{"6", c.caseSweeps}, {"7", c.casePorts}, {"8", c.caseMCP}, {"9", c.caseBudget}, {"10", c.caseKill}, {"11", c.caseKillShots},
	}
	for _, s := range steps {
		if c.want(s.id) {
			s0 := time.Now()
			s.fn()
			logf("claims: case %s took %.0fs", s.id, time.Since(s0).Seconds())
		}
	}
	row.Seconds = time.Since(t0).Seconds()
	return row
}

// selfCheck: the counter forwards a WebSocket upgrade (Juice Shop's
// socket.io) and logs it as one, before anything is measured with it.
func (c *claims) selfCheck() {
	px, err := newCountProxy(claimJuice)
	must(err)
	defer px.close()
	status, detail := "", ""
	conn, err := net.DialTimeout("tcp", strings.TrimPrefix(px.origin, "http://"), 5*time.Second)
	if err == nil {
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		fmt.Fprintf(conn, "GET /socket.io/?EIO=4&transport=websocket HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n", strings.TrimPrefix(px.origin, "http://"))
		status, _ = bufio.NewReader(conn).ReadString('\n')
	} else {
		detail = err.Error()
	}
	seen := px.since(0)
	ok := strings.Contains(status, " 101 ") && len(seen) == 1 && seen[0].Upgrade
	addCheck("claims: the counter forwards and logs a WebSocket upgrade (Juice Shop socket.io)", ok, "answer %q, logged %d requests, upgrade flag %v %s", strings.TrimSpace(status), len(seen), len(seen) == 1 && seen[0].Upgrade, detail)
}

// caseFile is a fresh path in the claims directory.
func (c *claims) caseFile(name string) string {
	return filepath.Join(c.dir, strings.NewReplacer(" ", "-", "/", "_").Replace(name))
}

// httpCase runs one command at every pace against up through a fresh
// counter; args builds its arguments from the proxy's origin and the db.
func (c *claims) httpCase(name string, up string, ps []claimPace, args func(origin, db string, p claimPace) []string, extra func(t *tally, p *countProxy)) {
	for _, p := range ps {
		px, err := newCountProxy(up)
		must(err)
		db := c.caseFile(name + "-" + p.name + ".db")
		r := azExec(c.dir, 15*time.Minute, args(px.origin, db, p)...)
		settle()
		t := httpTally("", r, db+".ledger.jsonl", 0, px, 0)
		if extra != nil {
			extra(&t, px)
		}
		px.close()
		c.finish(name, p.name, t)
	}
}

// 1. The plain HTTP map.
func (c *claims) caseRun() {
	c.httpCase("run", claimJuice, paces3, func(o, db string, p claimPace) []string {
		return append([]string{"run", "-url", o, "-db", db, "-json"}, p.flags...)
	}, nil)
}

// 2. Chrome renders pages: socket.io polling and WebSocket too.
func (c *claims) caseBrowser() {
	if !c.chrome {
		logf("claims: no Chrome, browser cases skipped")
		return
	}
	c.httpCase("run -browser", claimJuice, paces3, func(o, db string, p claimPace) []string {
		return append([]string{"run", "-url", o, "-db", db, "-json", "-browser"}, p.flags...)
	}, func(t *tally, px *countProxy) {
		ws, poll := 0, 0
		for _, s := range px.since(0) {
			if s.Upgrade {
				ws++
			}
			if strings.HasPrefix(s.Target, "/socket.io/") {
				poll++
			}
		}
		t.note = fmt.Sprintf("socket.io requests at the counter %d, WebSocket upgrades %d", poll, ws)
	})
}

// 3. Screenshots: the case that failed in the trial.
func (c *claims) caseShots() {
	if !c.chrome {
		return
	}
	c.httpCase("shots", claimJuice, []claimPace{paceFree, pace2}, func(o, db string, p claimPace) []string {
		return append([]string{"shots", "-u", o, "-db", db, "-json", "-dir", c.caseFile("shots-" + p.name)}, p.flags...)
	}, nil)
}

// 4. DVWA, signed in; with and without Chrome. No logout, and no request
// Chrome answered from its cache.
func (c *claims) caseDVWA() {
	for _, browser := range []bool{false, true} {
		name := "run -login"
		if browser {
			if !c.chrome {
				continue
			}
			name = "run -login -browser"
		}
		c.httpCase(name, claimDVWA, paces3, func(o, db string, p claimPace) []string {
			a := []string{"run", "-url", o + "/", "-db", db, "-json", "-login", o + "/login.php", "-login-user", "admin", "-login-pass", "password"}
			if browser {
				a = append(a, "-browser")
			}
			return append(a, p.flags...)
		}, func(t *tally, px *countProxy) {
			for _, s := range px.since(0) {
				if strings.Contains(s.Target, "logout.php") {
					t.extra = append(t.extra, "a request to logout.php reached the app: "+s.key())
					break
				}
			}
		})
	}
}

// ---- roles ----

// vampiUsers resets VAmPI and registers two users, returning their tokens.
func vampiUsers() (t1, t2 string, err error) {
	cli := &http.Client{Timeout: 20 * time.Second}
	if resp, err := cli.Get(claimVampi + "/createdb"); err != nil {
		return "", "", err
	} else {
		resp.Body.Close()
	}
	post := func(path string, body map[string]string, out any) error {
		raw, _ := json.Marshal(body)
		resp, err := cli.Post(claimVampi+path, "application/json", bytes.NewReader(raw))
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 300 {
			return &httpError{path, resp.Status}
		}
		if out != nil {
			return json.NewDecoder(resp.Body).Decode(out)
		}
		return nil
	}
	tok := func(name string) (string, error) {
		pw := "Claims-Passw0rd!"
		if err := post("/users/v1/register", map[string]string{"username": name, "password": pw, "email": name + "@azhaq.test"}, nil); err != nil {
			return "", err
		}
		var l struct {
			Token string `json:"auth_token"`
		}
		err := post("/users/v1/login", map[string]string{"username": name, "password": pw}, &l)
		return l.Token, err
	}
	if t1, err = tok("claimsone"); err != nil {
		return
	}
	t2, err = tok("claimstwo")
	return
}

// 5. roles on VAmPI with two header roles, plain and with -replay-writes put.
func (c *claims) caseRoles() {
	for _, writes := range []bool{false, true} {
		name := "roles"
		if writes {
			name = "roles -replay-writes put"
		}
		for _, p := range paces3 {
			t1, t2, err := vampiUsers()
			if err != nil {
				addCheck(fmt.Sprintf("claims: %s %s: summary = ledger = what arrived", name, p.name), false, "could not register users on VAmPI: %v", err)
				continue
			}
			px, err := newCountProxy(claimVampi)
			must(err)
			dir := c.caseFile(name + "-" + p.name + ".d")
			args := []string{"roles", "-dir", dir, "-jsonl", "-role", "anon", "-role", "u1=Authorization: Bearer " + t1, "-role", "u2=Authorization: Bearer " + t2}
			if writes {
				args = append(args, "-replay-writes", "put")
			}
			if p.cap > 0 {
				args = append(args, "-replay-max", strconv.Itoa(p.cap))
			}
			args = append(args, "--", "-url", px.origin+"/")
			args = append(args, p.flags...)
			r := azExec(c.dir, 15*time.Minute, args...)
			settle()
			t := httpTally("", r, filepath.Join(dir, "roles.ledger.jsonl"), 0, px, 0)
			px.close()
			c.finish(name, p.name, t)
		}
	}
}

// ---- sweeps ----

// firstLines writes the first n lines of a wordlist for the sweeps.
func (c *claims) firstLines(src wordlist, n int, name string) string {
	path, err := fetchWordlist(src)
	must(err)
	raw, err := os.ReadFile(path)
	must(err)
	var keep []string
	for _, l := range strings.Split(string(raw), "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
			keep = append(keep, l)
		}
		if len(keep) == n {
			break
		}
	}
	out := filepath.Join(c.dir, name)
	must(os.WriteFile(out, []byte(strings.Join(keep, "\n")+"\n"), 0o644))
	return out
}

// 6. dirs, fuzz and params.
func (c *claims) caseSweeps() {
	words := c.firstLines(webWords, 500, "words.txt")
	params := c.firstLines(paramWords, 200, "params.txt")
	c.httpCase("dirs", claimJuice, paces3, func(o, db string, p claimPace) []string {
		return append([]string{"dirs", "-u", o + "/", "-w", words, "-db", db, "-json"}, p.flags...)
	}, nil)
	c.httpCase("fuzz", claimVampi, paces3, func(o, db string, p claimPace) []string {
		return append([]string{"fuzz", "-u", o + "/FUZZ", "-w", words, "-db", db, "-json"}, p.flags...)
	}, nil)
	c.httpCase("params", claimJuice, paces3, func(o, db string, p claimPace) []string {
		return append([]string{"params", "-u", o + "/rest/products/search", "-w", params, "-db", db, "-json"}, p.flags...)
	}, nil)
}

// ---- budget and kill switch ----

// 9. A request budget, then one resume.
func (c *claims) caseBudget() {
	px, err := newCountProxy(claimJuice)
	must(err)
	defer px.close()
	db := c.caseFile("budget.db")
	led := db + ".ledger.jsonl"
	r := azExec(c.dir, 15*time.Minute, "run", "-url", px.origin, "-db", db, "-json", "-max-requests", "40")
	settle()
	t1 := httpTally("run", r, led, 0, px, 0)
	if len(t1.counter) > 40 {
		t1.extra = append(t1.extra, fmt.Sprintf("counter %d > the budget 40", len(t1.counter)))
	}
	l1, s1 := ledgerCount(led), px.n()
	r = azExec(c.dir, 15*time.Minute, "resume", "-db", db, "-json")
	settle()
	t2 := httpTally("resume", r, led, l1, px, s1)
	c.finish("budget -max-requests 40", "unpaced", t1, t2)
}

// killRun starts cmd, creates the kill file 3 s later, and returns the
// first process with how late its last request came after the file.
func (c *claims) killRun(px *countProxy, db string, args ...string) (azResult, time.Duration, []string) {
	p := azStart(c.dir, args...)
	time.Sleep(3 * time.Second)
	must(os.WriteFile(db+".stop", nil, 0o644))
	stopAt := time.Now()
	r := p.wait(5 * time.Minute)
	settle()
	var late time.Duration
	var after []string // the requests that came after the limit
	for _, s := range px.since(0) {
		d := s.At.Sub(stopAt)
		late = max(late, d)
		if d > 600*time.Millisecond && len(after) < 8 {
			after = append(after, fmt.Sprintf("+%.2fs %s", d.Seconds(), s.key()))
		}
	}
	return r, late, after
}

// killCase is cases 10 and 11: the file stops every request within 0.6 s,
// the process exits 4, and the three counts agree, before and after resume.
func (c *claims) killCase(name string, upFlags func(origin, db string) []string, resumeFlags []string) {
	px, err := newCountProxy(claimJuice)
	must(err)
	defer px.close()
	rate := rateOf(upFlags("", ""))
	db := c.caseFile(name + "-" + rate + ".db")
	led := db + ".ledger.jsonl"
	r, late, after := c.killRun(px, db, upFlags(px.origin, db)...)
	t1 := httpTally("run", r, led, 0, px, 0)
	if r.exit != 4 {
		t1.extra = append(t1.extra, fmt.Sprintf("exit %d, want 4 (the run was stopped by the file)", r.exit))
	}
	if late > 600*time.Millisecond {
		t1.extra = append(t1.extra, fmt.Sprintf("the last request came %.2fs after the file appeared (limit 0.6s): %s", late.Seconds(), strings.Join(after, "; ")))
	}
	t1.note = fmt.Sprintf("last request %.2fs after the file, exit %d", late.Seconds(), r.exit)
	l1, s1 := ledgerCount(led), px.n()
	_ = os.Remove(db + ".stop")
	r2 := azExec(c.dir, 15*time.Minute, append([]string{"resume", "-db", db, "-json"}, resumeFlags...)...)
	settle()
	t2 := httpTally("resume", r2, led, l1, px, s1)
	c.finish(name, "rate "+rate, t1, t2)
}

func rateOf(a []string) string {
	for i, s := range a {
		if s == "-rate" && i+1 < len(a) {
			return a[i+1]
		}
	}
	return "?"
}

// 10. The kill file on a run, at the spec's pace and at a slower one, where
// requests that waited for the pace are the ones that could still go out.
func (c *claims) caseKill() {
	for _, rate := range []string{"10", "2"} {
		c.killCase("kill switch run", func(o, db string) []string {
			return []string{"run", "-url", o, "-db", db, "-json", "-rate", rate}
		}, []string{"-max-requests", "80"})
	}
}

// 11. The kill file on Chrome.
func (c *claims) caseKillShots() {
	if !c.chrome {
		return
	}
	c.killCase("kill switch shots", func(o, db string) []string {
		return []string{"shots", "-u", o, "-db", db, "-json", "-rate", "5", "-dir", c.caseFile("kill-shots")}
	}, []string{"-max-requests", "60"})
}

// ---- TCP and UDP ----

// tcpL is a TCP listener that counts the connections it accepts.
type tcpL struct {
	ln      net.Listener
	mode    string // silent, ssh, http
	accepts atomic.Int64
	reqs    atomic.Int64 // HTTP requests it answered
}

func startTCP(mode string) *tcpL {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	must(err)
	l := &tcpL{ln: ln, mode: mode}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			l.accepts.Add(1)
			go l.serve(conn)
		}
	}()
	return l
}

func (l *tcpL) serve(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(6 * time.Second))
	switch l.mode {
	case "ssh":
		_, _ = conn.Write([]byte("SSH-2.0-OpenSSH_9.6 azhaq-bench\r\n"))
		_, _ = io.Copy(io.Discard, conn)
	case "http":
		br := bufio.NewReader(conn)
		for {
			req, err := http.ReadRequest(br)
			if err != nil {
				return
			}
			l.reqs.Add(1)
			_, _ = io.Copy(io.Discard, req.Body)
			_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 28\r\nServer: bench\r\n\r\n<html><title>b</title></html>"))
		}
	default:
		_, _ = io.Copy(io.Discard, conn)
	}
}

func (l *tcpL) port() int { return l.ln.Addr().(*net.TCPAddr).Port }

// udpL is a UDP socket that counts the datagrams it receives; dns answers
// with the query's ID and the QR bit set.
type udpL struct {
	pc   net.PacketConn
	dns  bool
	seen atomic.Int64
}

func startUDP(dns bool) *udpL {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	must(err)
	u := &udpL{pc: pc, dns: dns}
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			u.seen.Add(1)
			if dns && n >= 12 {
				resp := append([]byte(nil), buf[:n]...)
				resp[2] |= 0x80
				_, _ = pc.WriteTo(resp, from)
			}
		}
	}()
	return u
}

func (u *udpL) port() int { return u.pc.LocalAddr().(*net.UDPAddr).Port }

// freePorts returns n loopback TCP ports nothing listens on.
func freePorts(n int) []int {
	var ls []net.Listener
	var ports []int
	for i := 0; i < n; i++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		must(err)
		ls = append(ls, ln)
		ports = append(ports, ln.Addr().(*net.TCPAddr).Port)
	}
	for _, ln := range ls {
		ln.Close()
	}
	return ports
}

func joinPorts(ps []int) string {
	var s []string
	for _, p := range ps {
		s = append(s, strconv.Itoa(p))
	}
	return strings.Join(s, ",")
}

// portTally compares a ports run per ip:port: the ledger's lines with the
// accepts or datagrams. A closed port has nothing to count; it only must
// have been tried (and not tried more than once).
func portTally(label string, r azResult, ledgerPath, proto string, counts map[string]int, closed []string) tally {
	es := readLedger(ledgerPath)
	t := tally{label: label, exit: r.exit, summary: summaryRequests(r.stderr), ledgerOf: es}
	var led, cnt []string
	isClosed := map[string]bool{}
	for _, k := range closed {
		isClosed[k] = true
	}
	for _, e := range es {
		k := e.Target
		t.ledger = append(t.ledger, e.Kind+" "+k)
		if !isClosed[k] {
			led = append(led, e.Kind+" "+k)
		}
	}
	for k, n := range counts {
		for i := 0; i < n; i++ {
			cnt = append(cnt, proto+" "+k)
		}
	}
	t.counter = cnt
	oa, ob := diffMultiset(led, cnt)
	if len(oa)+len(ob) > 0 {
		t.extra = append(t.extra, fmt.Sprintf("open ports: ledger %d != counter %d", len(led), len(cnt)), listDiff("in the ledger", oa), listDiff("at the counter", ob))
	}
	for _, k := range closed {
		n := 0
		for _, e := range es {
			if e.Target == k {
				n++
			}
		}
		if n != 1 {
			t.extra = append(t.extra, fmt.Sprintf("closed %s: %d ledger lines, want 1", k, n))
		}
	}
	t.skipCounterEqual = true
	return t
}

// 7. ports over TCP listeners and closed ports, then UDP sockets.
func (c *claims) casePorts() {
	for _, p := range []struct {
		name string
		flag []string
	}{{"unpaced", nil}, {"rate 5", []string{"-rate", "5"}}} {
		// TCP
		var ls []*tcpL
		for _, m := range []string{"silent", "silent", "silent", "ssh", "http"} {
			ls = append(ls, startTCP(m))
		}
		closed := freePorts(3)
		var ports []int
		counts := map[string]int{}
		for _, l := range ls {
			ports = append(ports, l.port())
		}
		var closedKeys []string
		for _, cp := range closed {
			ports = append(ports, cp)
			closedKeys = append(closedKeys, fmt.Sprintf("127.0.0.1:%d", cp))
		}
		db := c.caseFile("ports-tcp-" + p.name + ".db")
		r := azExec(c.dir, 10*time.Minute, append([]string{"ports", "-host", "127.0.0.1", "-p", joinPorts(ports), "-db", db, "-json"}, p.flag...)...)
		time.Sleep(time.Second)
		for _, l := range ls {
			counts[fmt.Sprintf("127.0.0.1:%d", l.port())] = int(l.accepts.Load())
		}
		es := readLedger(db + ".ledger.jsonl")
		t := portTally("", r, db+".ledger.jsonl", "tcp", counts, closedKeys)
		var httpLed, httpReqs int
		for _, e := range es {
			if e.Kind == "http" {
				httpLed++
			}
		}
		for _, l := range ls {
			httpReqs += int(l.reqs.Load())
		}
		t.note = fmt.Sprintf("accepts %v; HTTP requests answered %d, http ledger lines %d", counts, httpReqs, httpLed)
		for _, l := range ls {
			l.ln.Close()
		}
		c.finish("ports -p", p.name, t)

		// UDP
		var us []*udpL
		for _, dns := range []bool{true, false, false, false} {
			us = append(us, startUDP(dns))
		}
		uports := []int{}
		ucounts := map[string]int{}
		for _, u := range us {
			uports = append(uports, u.port())
		}
		uclosed := freePorts(1)
		uports = append(uports, uclosed[0])
		db = c.caseFile("ports-udp-" + p.name + ".db")
		r = azExec(c.dir, 10*time.Minute, append([]string{"ports", "-host", "127.0.0.1", "-p", "none", "-pu", joinPorts(uports), "-db", db, "-json"}, p.flag...)...)
		time.Sleep(time.Second)
		for _, u := range us {
			ucounts[fmt.Sprintf("127.0.0.1:%d", u.port())] = int(u.seen.Load())
		}
		t = portTally("", r, db+".ledger.jsonl", "udp", ucounts, []string{fmt.Sprintf("127.0.0.1:%d", uclosed[0])})
		t.note = fmt.Sprintf("datagrams %v", ucounts)
		for _, u := range us {
			u.pc.Close()
		}
		c.finish("ports -pu", p.name, t)
	}
}

// ---- MCP ----

// mcpClient speaks newline-delimited JSON-RPC to azhaq mcp on stdio.
type mcpClient struct {
	cmd  *exec.Cmd
	in   io.WriteCloser
	out  *bufio.Scanner
	next int
	errb bytes.Buffer
}

func startMCP(dir string, args ...string) *mcpClient {
	m := &mcpClient{}
	m.cmd = exec.Command(azhaq, append([]string{"mcp"}, args...)...)
	m.cmd.Dir = dir
	m.cmd.Stderr = &m.errb
	in, err := m.cmd.StdinPipe()
	must(err)
	out, err := m.cmd.StdoutPipe()
	must(err)
	must(m.cmd.Start())
	m.in = in
	m.out = bufio.NewScanner(out)
	m.out.Buffer(make([]byte, 0, 1<<20), 64<<20)
	return m
}

func (m *mcpClient) write(method string, params any, notify bool) int {
	msg := map[string]any{"jsonrpc": "2.0", "method": method}
	if params != nil {
		msg["params"] = params
	}
	id := 0
	if !notify {
		m.next++
		id = m.next
		msg["id"] = id
	}
	raw, _ := json.Marshal(msg)
	_, _ = m.in.Write(append(raw, '\n'))
	return id
}

// read returns the responses to ids, in the order they come.
func (m *mcpClient) read(ids ...int) map[int]json.RawMessage {
	want := map[int]bool{}
	for _, id := range ids {
		want[id] = true
	}
	got := map[int]json.RawMessage{}
	for len(got) < len(ids) && m.out.Scan() {
		var r struct {
			ID     *int            `json:"id"`
			Result json.RawMessage `json:"result"`
			Error  json.RawMessage `json:"error"`
		}
		if json.Unmarshal(m.out.Bytes(), &r) != nil || r.ID == nil || !want[*r.ID] {
			continue
		}
		if r.Result != nil {
			got[*r.ID] = r.Result
		} else {
			got[*r.ID] = r.Error
		}
	}
	return got
}

func (m *mcpClient) init() {
	id := m.write("initialize", map[string]any{"protocolVersion": "2025-06-18", "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "azhaq-bench", "version": "0"}}, false)
	m.read(id)
	m.write("notifications/initialized", nil, true)
}

func (m *mcpClient) mapCall(url, ws string) int {
	return m.write("tools/call", map[string]any{"name": "azhaq_map", "arguments": map[string]any{"url": url, "workspace": ws}}, false)
}

func (m *mcpClient) stop() {
	_ = m.in.Close()
	done := make(chan struct{})
	go func() { _ = m.cmd.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		_ = m.cmd.Process.Kill()
		<-done
	}
}

// mcpSummary is "requests" of the summary inside a tool result's text, or -1.
func mcpSummary(raw json.RawMessage) (int, string) {
	var res struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
		IsError bool `json:"isError"`
	}
	_ = json.Unmarshal(raw, &res)
	var text string
	for _, c := range res.Content {
		text += c.Text
	}
	var o struct {
		Summary struct {
			Requests *int `json:"requests"`
		} `json:"summary"`
		Requests *int `json:"requests"`
	}
	if json.Unmarshal([]byte(text), &o) == nil {
		if o.Summary.Requests != nil {
			return *o.Summary.Requests, text
		}
		if o.Requests != nil {
			return *o.Requests, text
		}
	}
	return -1, text
}

// 8. azhaq mcp: the budget holds over calls, and over calls made at once.
func (c *claims) caseMCP() {
	// One budget of 60 over two calls.
	px, err := newCountProxy(claimJuice)
	must(err)
	dir := c.caseFile("mcp-60.d")
	m := startMCP(c.dir, "-allow", "127.0.0.1", "-max-requests", "60", "-dir", dir)
	m.init()
	id := m.mapCall(px.origin, "w")
	res := m.read(id)
	settle()
	sum, text := mcpSummary(res[id])
	n1 := px.n()
	led := filepath.Join(dir, "w.db.ledger.jsonl")
	t := tally{label: "first azhaq_map", summary: sum, ledgerOf: readLedger(led)}
	t.ledger = ledgerKeys(t.ledgerOf, px.origin)
	for _, s := range px.since(0) {
		t.counter = append(t.counter, s.key())
	}
	if n1 > 60 {
		t.extra = append(t.extra, fmt.Sprintf("counter %d > the budget 60", n1))
	}
	if sum < 0 {
		t.note = "result: " + clip(text, 200)
	}
	id = m.mapCall(px.origin, "w")
	res = m.read(id)
	settle()
	_, text2 := mcpSummary(res[id])
	t2 := tally{label: "second azhaq_map", summary: 0, ledgerOf: nil}
	if d := px.n() - n1; d != 0 {
		t2.extra = append(t2.extra, fmt.Sprintf("the second call sent %d requests", d))
	}
	if !strings.Contains(text2, "spent") {
		t2.extra = append(t2.extra, "its result does not say the budget is spent: "+clip(text2, 200))
	}
	m.stop()
	px.close()
	c.finish("mcp budget 60", "unpaced", t, t2)

	// A budget of 2, two calls at once.
	px, err = newCountProxy(claimJuice)
	must(err)
	dir = c.caseFile("mcp-2.d")
	m = startMCP(c.dir, "-allow", "127.0.0.1", "-max-requests", "2", "-dir", dir)
	m.init()
	a := m.mapCall(px.origin, "wa")
	b := m.mapCall(px.origin, "wb")
	res = m.read(a, b)
	settle()
	// A call refused because the budget is spent sent nothing: no summary.
	sent := func(raw json.RawMessage) (int, string) {
		n, text := mcpSummary(raw)
		if n < 0 && strings.Contains(text, "spent") {
			return 0, "refused: budget spent"
		}
		return n, clip(text, 120)
	}
	sa, na := sent(res[a])
	sb, nb := sent(res[b])
	var es []ledger.Entry
	for _, w := range []string{"wa", "wb"} {
		if _, err := os.Stat(filepath.Join(dir, w+".db.ledger.jsonl")); err == nil {
			es = append(es, readLedger(filepath.Join(dir, w+".db.ledger.jsonl"))...)
		}
	}
	t = tally{label: "two calls at once", summary: max(sa, 0) + max(sb, 0), ledgerOf: es, ledger: ledgerKeys(es, px.origin)}
	for _, s := range px.since(0) {
		t.counter = append(t.counter, s.key())
	}
	t.note = fmt.Sprintf("call 1: %d (%s); call 2: %d (%s)", sa, na, sb, nb)
	if sa < 0 || sb < 0 {
		t.summary = -1
	}
	if len(t.counter) > 2 {
		t.extra = append(t.extra, fmt.Sprintf("counter %d > the budget 2", len(t.counter)))
	}
	m.stop()
	px.close()
	c.finish("mcp budget 2", "unpaced", t)
}
