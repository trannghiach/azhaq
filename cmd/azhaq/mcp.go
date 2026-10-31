package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/trannghiach/azhaq/store"
)

// The MCP server speaks JSON-RPC over stdin and stdout, one message per
// line. Each tool runs azhaq itself with -json and hands back the summary
// and the rows, so a tool call behaves exactly like the command line.
// The scope, the request budget and the pace are fixed when the server
// starts: no tool argument can widen them.

var mcpVersions = []string{"2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"}

type mcpServer struct {
	exe     string
	dir     string   // where workspaces live
	lock    []string // scope flags added to every command that touches targets
	locked  bool     // a scope was given: active techniques may run
	rate    float64
	budget  int64 // requests to targets over the server's life; 0: none
	mu      sync.Mutex
	used    int64
	runs    map[string]runRecord // workspace → its latest command's outcome, for azhaq_status
	sending chan struct{}        // one command that touches targets at a time
	out     *json.Encoder
	outMu   sync.Mutex
	running map[string]context.CancelFunc // request id → its command
	dropped map[string]bool               // requests the client cancelled: no response
	calls   sync.WaitGroup                // requests in flight
	stopped bool                          // a stop signal came: no request starts
}

func cmdMCP(args []string) error {
	fs := newFlags("mcp")
	var allow, deny stringsFlag
	scopeSpec := fs.String("scope", "", "a program's scope every tool is held to: a file, or hackerone, bugcrowd, intigriti, yeswehack with -program")
	program := fs.String("program", "", "the program to take from -scope")
	fs.Var(&allow, "allow", "a domain or host the tools may touch (repeatable); with -scope, added to it")
	fs.Var(&deny, "deny", "a domain or host the tools must not touch (repeatable)")
	budget := fs.Int64("max-requests", 0, "requests to targets all tool calls together may send (0: no cap)")
	rate := fs.Float64("rate", 0, "requests per second to targets in every tool call (0: no pace)")
	dir := fs.String("dir", "azhaq-mcp", "directory for the workspaces the tools write")
	unlocked := fs.Bool("unlocked", false, "serve without a scope: any target a tool is given may be touched (port scans stay refused)")
	if err := parse(fs, args); err != nil {
		return err
	}
	if *scopeSpec == "" && len(allow) == 0 && !*unlocked {
		// An assistant names its own targets: without a scope, nothing
		// holds it to the program.
		return usagef("azhaq mcp holds an assistant to a scope: give -allow DOMAIN (repeatable) or -scope, or -unlocked to let it touch any target it names")
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(*dir, 0o755); err != nil {
		return err
	}
	s := &mcpServer{exe: exe, dir: *dir, rate: *rate, budget: *budget}
	if *scopeSpec != "" {
		sc, err := loadScope(*scopeSpec, *program)
		if err != nil {
			return err
		}
		allow = append(allow, sc.Allow...)
		deny = append(deny, sc.Deny...)
	}
	for _, a := range allow {
		s.lock = append(s.lock, "-allow", a)
	}
	for _, d := range deny {
		s.lock = append(s.lock, "-deny", d)
	}
	s.locked = len(allow) > 0
	fmt.Fprintf(os.Stderr, "azhaq mcp %s: %d allow and %d deny rules, budget %s, workspaces in %s\n", version, len(allow), len(deny), budgetText(*budget), *dir)
	ctx, stop := stopContext()
	defer stop()
	done := make(chan error, 1)
	go func() { done <- s.serve(os.Stdin, os.Stdout) }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		// As Ctrl-C ends a run: each command in flight is interrupted, so it
		// stops sending, seals its ledger and answers with its summary.
		s.cancelAll()
		s.calls.Wait()
		return nil
	}
}

// cancelAll interrupts every request in flight and starts no other.
func (s *mcpServer) cancelAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stopped = true
	for _, cancel := range s.running {
		cancel()
	}
}

func budgetText(n int64) string {
	if n <= 0 {
		return "none"
	}
	return fmt.Sprintf("%d requests", n)
}

type rpcMsg struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (s *mcpServer) serve(in io.Reader, out io.Writer) error {
	s.out = json.NewEncoder(out)
	s.mu.Lock()
	s.running, s.dropped = map[string]context.CancelFunc{}, map[string]bool{}
	s.mu.Unlock()
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 0, 1<<20), 64<<20)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var m rpcMsg
		if err := json.Unmarshal(line, &m); err != nil {
			s.send(rpcMsg{JSONRPC: "2.0", ID: json.RawMessage("null"), Error: &rpcError{-32700, "parse error: " + err.Error()}})
			continue
		}
		if m.Method == "" {
			continue // a response to something the server never asks
		}
		if len(m.ID) == 0 {
			s.notification(m)
			continue
		}
		// Known before it starts, so a cancellation sent right after the
		// request finds it.
		id := idKey(m.ID)
		ctx, cancel := context.WithCancel(context.Background())
		s.mu.Lock()
		if s.stopped {
			s.mu.Unlock()
			cancel()
			break
		}
		s.running[id] = cancel
		s.calls.Add(1)
		s.mu.Unlock()
		go func() {
			defer s.calls.Done()
			defer func() {
				cancel()
				s.mu.Lock()
				delete(s.running, id)
				delete(s.dropped, id)
				s.mu.Unlock()
			}()
			defer func() {
				// A bug in one tool call ends that call, not the server.
				if r := recover(); r != nil {
					s.fail(m.ID, -32603, fmt.Sprintf("internal error: %v", r))
				}
			}()
			s.request(ctx, m)
		}()
	}
	s.calls.Wait()
	return sc.Err()
}

// idKey is a request id as a map key: 7 and 7.0 or "a" written with
// other spacing are the same request.
func idKey(raw json.RawMessage) string {
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return string(raw)
	}
	b, _ := json.Marshal(v)
	return string(b)
}

func (s *mcpServer) send(m rpcMsg) {
	s.outMu.Lock()
	defer s.outMu.Unlock()
	m.JSONRPC = "2.0"
	_ = s.out.Encode(m)
}

// answer sends the response to a request, unless the client cancelled
// it: it does not expect one then.
func (s *mcpServer) answer(m rpcMsg) {
	s.mu.Lock()
	dropped := s.dropped[idKey(m.ID)]
	s.mu.Unlock()
	if !dropped {
		s.send(m)
	}
}

func (s *mcpServer) reply(id json.RawMessage, result any) {
	s.answer(rpcMsg{ID: id, Result: result})
}

func (s *mcpServer) fail(id json.RawMessage, code int, msg string) {
	s.answer(rpcMsg{ID: id, Error: &rpcError{code, msg}})
}

func (s *mcpServer) notification(m rpcMsg) {
	switch m.Method {
	case "notifications/cancelled":
		var p struct {
			RequestID json.RawMessage `json:"requestId"`
		}
		if json.Unmarshal(m.Params, &p) != nil || len(p.RequestID) == 0 {
			return
		}
		// The command is stopped and keeps what it found; the request
		// gets no response.
		id := idKey(p.RequestID)
		s.mu.Lock()
		cancel := s.running[id]
		if cancel != nil {
			s.dropped[id] = true
		}
		s.mu.Unlock()
		if cancel != nil {
			cancel()
		}
	}
}

func (s *mcpServer) request(ctx context.Context, m rpcMsg) {
	switch m.Method {
	case "initialize":
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		_ = json.Unmarshal(m.Params, &p)
		v := mcpVersions[1]
		for _, x := range mcpVersions {
			if x == p.ProtocolVersion {
				v = x
			}
		}
		s.reply(m.ID, map[string]any{
			"protocolVersion": v,
			"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
			"serverInfo":      map[string]any{"name": "azhaq", "title": "Azhaq recon", "version": version},
			"instructions":    s.instructions(),
		})
	case "ping":
		s.reply(m.ID, map[string]any{})
	case "shutdown":
		// Not MCP's (the client closes stdin), but clients built on the
		// language-server pattern send it: answered, and the server ends
		// when stdin does.
		s.reply(m.ID, map[string]any{})
	case "tools/list":
		s.reply(m.ID, map[string]any{"tools": mcpTools()})
	case "tools/call":
		var p struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
			Meta      struct {
				ProgressToken any `json:"progressToken"`
			} `json:"_meta"`
		}
		// Read as any: arguments that are not an object are refused by the
		// schema, which says what they should be.
		var args any
		err := json.Unmarshal(m.Params, &p)
		if err == nil && len(p.Arguments) > 0 {
			err = json.Unmarshal(p.Arguments, &args)
		}
		if err != nil {
			s.fail(m.ID, -32602, "invalid params: "+err.Error())
			return
		}
		if err := checkArgs(p.Name, args); err != nil {
			s.fail(m.ID, -32602, err.Error())
			return
		}
		a, _ := args.(map[string]any)
		res, err := s.call(ctx, p.Name, a, p.Meta.ProgressToken)
		if err != nil {
			s.reply(m.ID, toolText(err.Error(), true))
			return
		}
		s.reply(m.ID, res)
	default:
		s.fail(m.ID, -32601, "method not found: "+m.Method)
	}
}

func (s *mcpServer) instructions() string {
	lock := "No scope is locked: every target an argument names may be touched. Start the server with -allow or -scope to hold the tools to a program."
	if s.locked {
		lock = "The tools are held to a scope fixed at start; targets outside it are skipped and listed in each summary, never requested."
	}
	return strings.Join([]string{
		"Azhaq maps targets for security research: names, web services, pages, JavaScript routes, API operations, forms, parameters and access by role, in one graph per workspace. It never sends attack payloads.",
		lock,
		"Budget: " + budgetText(s.budget) + " for all calls together. Every result has a summary: results, failures (retryable or not), what was skipped and why, the limit that stopped the work; azhaq_resume continues a run a limit or a cancellation stopped.",
		"Typical flow: azhaq_plan to see what a run would send, azhaq_map to map a URL or domain into a workspace, azhaq_query and azhaq_show to read it, azhaq_roles to compare sessions, azhaq_export for Burp, Postman or ZAP.",
	}, " ")
}

// toolText is a tool result: one text block, compact JSON for data. The
// same data is not sent again as structuredContent: a client that reads
// both would pay for it twice.
func toolText(text string, isError bool) map[string]any {
	res := map[string]any{"content": []map[string]any{{"type": "text", "text": text}}}
	if isError {
		res["isError"] = true
	}
	return res
}

// run executes azhaq with args, with the server's limits, and returns its
// stdout lines and its JSON summary.
type cmdResult struct {
	lines   []string
	summary map[string]any
	stderr  string
}

// progressFirst and progressEvery pace the progress notifications of a
// call: the first early, so a client sees the call is alive, then
// regularly (some clients reset their timeout on each).
var progressFirst, progressEvery = time.Second, 5 * time.Second

func (s *mcpServer) run(ctx context.Context, progress any, touches bool, args ...string) (cmdResult, error) {
	if touches {
		// One at a time: calls made at once would each see the whole
		// budget left and each keep the pace, together exceeding both.
		s.mu.Lock()
		if s.sending == nil {
			s.sending = make(chan struct{}, 1)
		}
		sem := s.sending
		s.mu.Unlock()
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			return cmdResult{}, ctx.Err()
		}
		defer func() { <-sem }()
		args = append(args, s.lock...)
		if s.rate > 0 {
			args = append(args, "-rate", fmt.Sprint(s.rate))
		}
		if s.budget > 0 {
			s.mu.Lock()
			left := s.budget - s.used
			s.mu.Unlock()
			if left <= 0 {
				return cmdResult{}, fmt.Errorf("the request budget of this server (%d) is spent; restart azhaq mcp with a larger -max-requests", s.budget)
			}
			args = append(args, "-max-requests", fmt.Sprint(left))
		}
	}
	cmd := exec.Command(s.exe, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Start(); err != nil {
		return cmdResult{}, err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	t0 := time.Now()
	tick := time.NewTimer(progressFirst)
	defer tick.Stop()
	var waitErr error
wait:
	for {
		select {
		case waitErr = <-done:
			break wait
		case <-ctx.Done():
			// Interrupted, a run keeps what it found and says so.
			_ = cmd.Process.Signal(syscall.SIGINT)
			select {
			case waitErr = <-done:
			case <-time.After(10 * time.Second):
				_ = cmd.Process.Kill()
				waitErr = <-done
			}
			break wait
		case <-tick.C:
			tick.Reset(progressEvery)
			if progress != nil {
				took := time.Since(t0)
				s.send(rpcMsg{Method: "notifications/progress", Params: mustJSON(map[string]any{
					"progressToken": progress, "progress": took.Round(100 * time.Millisecond).Seconds(),
					"message": fmt.Sprintf("azhaq %s: working, %s", args[0], took.Round(time.Second)),
				})})
			}
		}
	}
	res := cmdResult{stderr: stderr.String()}
	for _, l := range strings.Split(stdout.String(), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			res.lines = append(res.lines, l)
		}
	}
	for _, l := range strings.Split(res.stderr, "\n") {
		var sum map[string]any
		if strings.HasPrefix(l, "{") && json.Unmarshal([]byte(l), &sum) == nil && sum["type"] == "summary" {
			res.summary = sum
		}
	}
	var runErr error
	switch {
	case res.summary != nil:
		if n, ok := res.summary["requests"].(float64); ok {
			s.mu.Lock()
			s.used += int64(n)
			s.mu.Unlock()
		}
		if msg, _ := res.summary["error"].(string); msg != "" {
			runErr = stderrError(msg, nil) // the command could not do its job
		}
		// else: the summary says how it went, exit code included
	case waitErr != nil:
		runErr = stderrError(res.stderr, waitErr)
	}
	s.noteRun(args[0], res, runErr)
	return res, runErr
}

// runRecord is a workspace's latest command in this server's session: a
// call's own outcome, which nothing on disk records (a workspace's
// database cannot say a call failed outright, only what work is left).
type runRecord struct {
	tool   string
	state  string // "complete", "stopped by a limit", "failed"
	detail string
	resume string
}

// noteRun keeps the outcome of a command that touched a workspace, for
// azhaq_status: complete, stopped by a limit (with what azhaq_resume would
// continue), or failed.
func (s *mcpServer) noteRun(tool string, r cmdResult, callErr error) {
	db, _ := r.summary["db"].(string)
	if db == "" {
		return // named no workspace: azhaq_scope, azhaq_workspaces and the like
	}
	ws := strings.TrimSuffix(filepath.Base(db), ".db")
	rec := runRecord{tool: tool}
	switch {
	case callErr != nil:
		rec.state, rec.detail = "failed", callErr.Error()
	default:
		if stopped, _ := r.summary["stopped"].(string); stopped != "" {
			rec.state, rec.detail = "stopped by a limit", stopped
		} else {
			rec.state = "complete"
		}
	}
	if _, ok := r.summary["resume"]; ok {
		rec.resume = s.resumeHint(ws)
	}
	s.mu.Lock()
	if s.runs == nil {
		s.runs = map[string]runRecord{}
	}
	s.runs[ws] = rec
	s.mu.Unlock()
}

// output runs a command that reads a workspace and returns its stdout as
// it is: an export is not lines to trim.
func (s *mcpServer) output(ctx context.Context, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, s.exe, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	raw, err := cmd.Output()
	if err != nil {
		return nil, stderrError(stderr.String(), err)
	}
	return raw, nil
}

// stderrError is the error a command printed, without what only makes
// sense on a command line: the "azhaq:" prefix and the pointer to its
// help.
func stderrError(stderr string, fallback error) error {
	var msg []string
	for _, l := range strings.Split(stderr, "\n") {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "{") {
			// A summary with -json: its error.
			var sum struct {
				Error string `json:"error"`
			}
			if json.Unmarshal([]byte(l), &sum) != nil {
				continue
			}
			l = sum.Error
		}
		if l == "" || strings.Contains(l, "azhaq help ") {
			continue
		}
		msg = append(msg, strings.TrimPrefix(l, "azhaq: "))
	}
	if len(msg) == 0 {
		if fallback == nil {
			fallback = errors.New("the command failed without saying why")
		}
		return fallback
	}
	return errors.New(strings.Join(msg, "\n"))
}

func mustJSON(v any) json.RawMessage {
	raw, _ := json.Marshal(v)
	return raw
}

// workspace is the database a tool call reads or writes: a name inside
// the server's directory, never a path elsewhere.
var workspaceName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

func (s *mcpServer) workspace(a map[string]any) (string, error) {
	name := wsName(a)
	if !workspaceName.MatchString(name) {
		return "", fmt.Errorf("workspace %q: letters, digits, dot, dash and underscore only", name)
	}
	return filepath.Join(s.dir, name+".db"), nil
}

// existing is the database of a workspace a tool reads: it must exist.
func (s *mcpServer) existing(a map[string]any) (string, error) {
	db, err := s.workspace(a)
	if err != nil {
		return "", err
	}
	if _, err := os.Stat(db); err != nil {
		return "", fmt.Errorf("there is no workspace %q; azhaq_workspaces lists them", wsName(a))
	}
	return db, nil
}

// wsName is the workspace an argument names, "default" when none.
func wsName(a map[string]any) string {
	name := strings.TrimSuffix(str(a, "workspace"), ".db")
	if name == "" {
		name = "default"
	}
	return name
}

func str(a map[string]any, k string) string {
	v, _ := a[k].(string)
	return strings.TrimSpace(v)
}

func strList(a map[string]any, k string) []string {
	switch v := a[k].(type) {
	case string:
		if v = strings.TrimSpace(v); v != "" {
			return []string{v}
		}
	case []any:
		var out []string
		for _, x := range v {
			if s, ok := x.(string); ok && strings.TrimSpace(s) != "" {
				out = append(out, strings.TrimSpace(s))
			}
		}
		return out
	}
	return nil
}

// num is a positive whole-number argument, at most 1<<30; anything else
// (absent, negative, a fraction, 1e19) is def.
func num(a map[string]any, k string, def int) int {
	if v, ok := a[k].(float64); ok && v > 0 && v == math.Trunc(v) {
		return int(min(v, 1<<30)) // past the end of anything: an offset beyond it is past its end, not the start
	}
	return def
}

func boolean(a map[string]any, k string) bool {
	v, _ := a[k].(bool)
	return v
}

// rows parses JSON lines, keeping at most limit.
func rows(lines []string, limit int) ([]any, bool) {
	var out []any
	for _, l := range lines {
		if len(out) == limit {
			return out, true
		}
		var v any
		if json.Unmarshal([]byte(l), &v) == nil {
			out = append(out, v)
		}
	}
	return out, false
}

// maxLimit caps the rows of one result, whatever limit asks: a larger
// answer fills a client's context instead of answering its question.
const maxLimit = 1000

// queryFields are the columns azhaq_query returns when fields names none:
// enough to pick the next question, without a full row's proof, scope and
// first_seen (100 rows of Juice Shop: 16 KB instead of 27).
const queryFields = "key,type,role,coverage,status,title,methods,params,count"

// listPrefix starts the name of a target list the server writes for a
// command: removed when the command is done, kept while the run it
// started can be resumed (azhaq resume reads it again).
const listPrefix = ".targets-"

func (s *mcpServer) call(ctx context.Context, name string, a map[string]any, progress any) (map[string]any, error) {
	if a == nil {
		a = map[string]any{}
	}
	limit := min(num(a, "limit", 100), maxLimit)
	ws := wsName(a)
	// A header that names a host would reach it through an address the lock
	// allows: the target is named by url or targets, never by a header.
	for _, h := range strList(a, "headers") {
		k, _, _ := strings.Cut(h, ":")
		for _, hh := range hostHeaders {
			if strings.EqualFold(strings.TrimSpace(k), hh) {
				return nil, fmt.Errorf("headers: %s is not accepted: it names the host a front end serves; give the target in url or targets", hh)
			}
		}
	}
	result := func(r cmdResult, extra map[string]any) (map[string]any, error) {
		s.forMCP(r.summary, ws)
		data := map[string]any{"summary": r.summary}
		for k, v := range extra {
			data[k] = v
		}
		raw, _ := json.Marshal(data)
		return toolText(string(raw), false), nil
	}
	listed := func(r cmdResult) (map[string]any, error) {
		got, cut := rows(r.lines, limit)
		extra := map[string]any{"rows": got}
		if cut {
			extra["truncated"] = fmt.Sprintf("%d rows, the first %d shown; narrow the question, or raise limit (at most %d)", len(r.lines), limit, maxLimit)
		}
		return result(r, extra)
	}
	// targets are the run flags for the targets the arguments name; list
	// is the file that holds a list of them, "" when there is none.
	targets := func() (args []string, list string, err error) {
		for _, u := range strList(a, "url") {
			args = append(args, "-url", u)
		}
		for _, d := range strList(a, "domain") {
			args = append(args, "-domain", d)
		}
		if boolean(a, "program_scope") {
			if !s.locked {
				return nil, "", errors.New("program_scope needs the server started with -scope")
			}
			args = append(args, s.scopeSeeds()...)
		}
		if ts := strList(a, "targets"); len(ts) > 0 {
			f, err := os.CreateTemp(s.dir, listPrefix+"*.txt")
			if err != nil {
				return nil, "", err
			}
			_, _ = f.WriteString(strings.Join(ts, "\n") + "\n")
			f.Close()
			args, list = append(args, "-list", f.Name()), f.Name()
		}
		if len(args) == 0 {
			return nil, "", errors.New("give url, domain or targets")
		}
		return args, list, nil
	}
	session := func() []string {
		var f []string
		if t := num(a, "timeout_seconds", 0); t > 0 {
			f = append(f, "-timeout", fmt.Sprintf("%ds", t))
		}
		if l, ok := a["login"].(map[string]any); ok && str(l, "url") != "" {
			f = append(f, "-login", str(l, "url"), "-login-user", str(l, "user"), "-login-pass", str(l, "password"))
		}
		for _, h := range strList(a, "headers") {
			f = append(f, "-header", h)
		}
		return f
	}
	runFlags := func() []string {
		var f []string
		if boolean(a, "passive") {
			f = append(f, "-passive")
		}
		if boolean(a, "browser") {
			f = append(f, "-browser")
		}
		if boolean(a, "graphql") {
			f = append(f, "-graphql")
		}
		if d, ok := a["depth"].(float64); ok && d >= 0 && d <= 1<<30 {
			f = append(f, "-depth", fmt.Sprint(int(d))) // 0 too: the targets alone
		}
		return append(f, session()...)
	}
	switch name {
	case "azhaq_scope":
		s.mu.Lock()
		used := s.used
		s.mu.Unlock()
		raw, _ := json.Marshal(map[string]any{"about": s.instructions(), "locked": s.locked, "rules": s.lock, "budget": s.budget, "used": used, "rate": s.rate})
		return toolText(string(raw), false), nil
	case "azhaq_plan":
		t, list, err := targets()
		if err != nil {
			return nil, err
		}
		if list != "" {
			defer os.Remove(list)
		}
		r, err := s.run(ctx, progress, true, append(append([]string{"plan", "-json"}, t...), runFlags()...)...)
		if err != nil {
			return nil, err
		}
		got, _ := rows(r.lines, 1)
		return result(r, map[string]any{"plan": got})
	case "azhaq_map":
		db, err := s.workspace(a)
		if err != nil {
			return nil, err
		}
		t, list, err := targets()
		if err != nil {
			return nil, err
		}
		r, err := s.run(ctx, progress, true, append(append([]string{"run", "-quiet", "-json", "-db", db}, t...), runFlags()...)...)
		if list != "" && (err != nil || r.summary["resume"] == nil) {
			os.Remove(list) // nothing will read it again
		}
		if err != nil {
			return nil, err
		}
		return s.mapped(ctx, r, db, limit, result)
	case "azhaq_resume":
		db, err := s.existing(a)
		if err != nil {
			return nil, err
		}
		list, err := s.resumable(db)
		if err != nil {
			return nil, err
		}
		r, err := s.run(ctx, progress, true, append([]string{"resume", "-db", db, "-quiet", "-json"}, session()...)...)
		if err != nil {
			return nil, err
		}
		if list != "" && r.summary["resume"] == nil {
			os.Remove(list) // the run is complete
		}
		return s.mapped(ctx, r, db, limit, result)
	case "azhaq_subdomains":
		ds := strList(a, "domain")
		if len(ds) == 0 {
			return nil, errors.New("give domain")
		}
		args := []string{"subs", "-json", "-silent"}
		for _, d := range ds {
			// Passive, but the sources learn what the assistant asks about:
			// the scope holds here too.
			if !s.allows(d) {
				return nil, fmt.Errorf("%s is outside the scope this server was started with", d)
			}
			args = append(args, "-d", d)
		}
		if boolean(a, "live") {
			args = append(args, "-live")
		}
		if a["workspace"] != nil {
			db, err := s.workspace(a)
			if err != nil {
				return nil, err
			}
			args = append(args, "-db", db)
		}
		r, err := s.run(ctx, progress, false, args...)
		if err != nil {
			return nil, err
		}
		return listed(r)
	case "azhaq_probe":
		ts := strList(a, "targets")
		if len(ts) == 0 {
			return nil, errors.New("give targets: URLs, hosts, host:port or addresses")
		}
		f, err := os.CreateTemp(s.dir, listPrefix+"*.txt")
		if err != nil {
			return nil, err
		}
		_, _ = f.WriteString(strings.Join(ts, "\n") + "\n")
		f.Close()
		defer os.Remove(f.Name())
		r, err := s.run(ctx, progress, true, "probe", "-json", "-silent", "-l", f.Name())
		if err != nil {
			return nil, err
		}
		return listed(r)
	case "azhaq_ports":
		if !s.locked {
			return nil, errors.New("port scans need a scope: start azhaq mcp with -allow or -scope")
		}
		hs := strList(a, "hosts")
		if len(hs) == 0 {
			return nil, errors.New("give hosts")
		}
		args := []string{"ports", "-json", "-silent"}
		for _, h := range hs {
			args = append(args, "-host", h)
		}
		if p := str(a, "ports"); p != "" {
			args = append(args, "-p", p)
		}
		for _, h := range hs {
			if !s.allows(h) {
				return nil, fmt.Errorf("%s is outside the scope this server was started with", h)
			}
		}
		// The lock is the scope; each connect counts against the server's
		// request budget and is paced at its -rate.
		r, err := s.run(ctx, progress, true, args...)
		if err != nil {
			return nil, err
		}
		return listed(r)
	case "azhaq_query":
		db, err := s.existing(a)
		if err != nil {
			return nil, err
		}
		args := []string{"query", "-db", db, "-json", "-limit", fmt.Sprint(limit)}
		for _, k := range []string{"type", "role", "coverage", "status", "method", "host", "match", "scope", "fields"} {
			if v := strList(a, k); len(v) > 0 {
				args = append(args, "-"+k, strings.Join(v, ","))
			}
		}
		if len(strList(a, "fields")) == 0 {
			args = append(args, "-fields", queryFields)
		}
		if boolean(a, "new") {
			args = append(args, "-new")
		}
		r, err := s.run(ctx, nil, false, args...)
		if err != nil {
			return nil, err
		}
		if notes, ok := r.summary["notes"].([]any); ok {
			for i, n := range notes {
				if t, ok := n.(string); ok {
					notes[i] = strings.ReplaceAll(t, "-limit ", "limit ") // the argument, not the flag
				}
			}
		}
		return listed(r)
	case "azhaq_show":
		db, err := s.existing(a)
		if err != nil {
			return nil, err
		}
		key := str(a, "key")
		if key == "" {
			return nil, errors.New("give key: a URL, hostname, address or domain")
		}
		r, err := s.run(ctx, nil, false, "show", "-db", db, "-json", key)
		if err != nil {
			return nil, err
		}
		got, _ := rows(r.lines, 1)
		if len(got) == 0 {
			return nil, stderrError(r.stderr, fmt.Errorf("%s is not in workspace %q", key, ws))
		}
		data := map[string]any{"entity": got[0]}
		raw, _ := json.Marshal(data)
		if len(raw) > maxShowBytes {
			// A GraphQL schema or a long page's facts: the export has them.
			trimPayloads(got[0])
			data["note"] = "large observation fields were left out; azhaq_export (graphql, sdl, openapi, jsonl) has them"
			raw, _ = json.Marshal(data)
		}
		return toolText(string(raw), false), nil
	case "azhaq_roles":
		roles, _ := a["roles"].([]any)
		if len(roles) < 2 {
			return nil, errors.New("give at least two roles: [" + roleAnon + "," + roleHeader + "," + roleLogin + "]")
		}
		db, err := s.workspace(a)
		if err != nil {
			return nil, err
		}
		args := []string{"roles", "-json", "-dir", strings.TrimSuffix(db, ".db") + "-roles"}
		if u := str(a, "login_url"); u != "" {
			args = append(args, "-login", u)
		}
		for _, x := range roles {
			r, _ := x.(map[string]any)
			n := str(r, "name")
			switch {
			case n == "":
				return nil, errors.New("every role needs a name")
			case str(r, "user") != "" && len(strList(r, "header")) > 0:
				// roles signs a role in or sends its headers, not both: one
				// of them would be dropped.
				return nil, fmt.Errorf("role %s: give header, or user and password, not both", n)
			case str(r, "user") != "":
				args = append(args, "-role-login", n+"="+str(r, "user")+":"+str(r, "password"))
			case len(strList(r, "header")) > 0:
				for _, h := range strList(r, "header") {
					args = append(args, "-role", n+"="+h)
				}
			default:
				args = append(args, "-role", n)
			}
		}
		if boolean(a, "all") {
			args = append(args, "-all")
		}
		for _, id := range strList(a, "ids") {
			args = append(args, "-id", id)
		}
		t, list, err := targets()
		if err != nil {
			return nil, err
		}
		if list != "" {
			defer os.Remove(list)
		}
		// The server's budget holds for roles too: each role's run and the
		// replay get an equal share of what is left.
		share := 0
		if s.budget > 0 {
			s.mu.Lock()
			left := s.budget - s.used
			s.mu.Unlock()
			if left <= 0 {
				return nil, fmt.Errorf("the request budget of this server (%d) is spent; restart azhaq mcp with a larger -max-requests", s.budget)
			}
			share = int(left) / (len(roles) + 1)
			if share < 1 {
				return nil, fmt.Errorf("%d requests are left of this server's budget: too few for %d roles", left, len(roles))
			}
			args = append(args, "-replay-max", fmt.Sprint(share))
		}
		args = append(args, "--")
		args = append(args, t...)
		args = append(args, runFlags()...)
		args = append(args, s.lock...)
		if s.rate > 0 {
			args = append(args, "-rate", fmt.Sprint(s.rate))
		}
		if share > 0 {
			args = append(args, "-max-requests", fmt.Sprint(share))
		}
		r, err := s.run(ctx, progress, false, args...)
		if err != nil {
			return nil, err
		}
		return listed(r)
	case "azhaq_export":
		db, err := s.existing(a)
		if err != nil {
			return nil, err
		}
		format := str(a, "format")
		if format == "" {
			format = "openapi"
		}
		if !slices.Contains(exportFormats, format) {
			return nil, fmt.Errorf("format %q: one of %s", format, strings.Join(exportFormats, ", "))
		}
		raw, err := s.output(ctx, "export", "-db", db, "-format", format)
		if err != nil {
			return nil, err
		}
		path := exportPath(db, format)
		if err := os.WriteFile(path, raw, 0o644); err != nil {
			return nil, err
		}
		abs, _ := filepath.Abs(path)
		return toolText(exportPart(abs, format, raw, num(a, "offset", 0)), false), nil
	case "azhaq_diff":
		db, err := s.existing(a)
		if err != nil {
			return nil, err
		}
		raw, err := s.output(ctx, "diff", "-db", db, "-jsonl", "-quiet")
		if err != nil {
			return nil, err
		}
		got, cut := rows(strings.Split(string(raw), "\n"), limit)
		data := map[string]any{"changes": got}
		if cut {
			data["truncated"] = true
		}
		out, _ := json.Marshal(data)
		return toolText(string(out), false), nil
	case "azhaq_workspaces":
		files, _ := filepath.Glob(filepath.Join(s.dir, "*.db"))
		var names []string
		for _, f := range files {
			names = append(names, strings.TrimSuffix(filepath.Base(f), ".db"))
		}
		sort.Strings(names)
		data := map[string]any{"workspaces": names, "dir": s.dir}
		out, _ := json.Marshal(data)
		return toolText(string(out), false), nil
	case "azhaq_status":
		return s.status()
	}
	return nil, fmt.Errorf("%w %q", errUnknownTool, name)
}

// mapped is what azhaq_map and azhaq_resume return: the run's summary and
// the highlights of its workspace, what a researcher reads first (what
// needs a session, the API).
func (s *mcpServer) mapped(ctx context.Context, r cmdResult, db string, limit int,
	result func(cmdResult, map[string]any) (map[string]any, error)) (map[string]any, error) {
	if ctx.Err() != nil {
		return result(r, nil) // cancelled: no one reads it
	}
	q, _ := s.run(ctx, nil, false, "query", "-db", db, "-json", "-role", "auth,forbidden,api,app", "-scope", "target", "-limit", fmt.Sprint(limit),
		"-fields", "key,type,role,coverage,status,title,methods,params,body")
	got, cut := rows(q.lines, limit)
	extra := map[string]any{"workspace": strings.TrimSuffix(filepath.Base(db), ".db"), "highlights": got}
	if cut || q.summary != nil && q.summary["notes"] != nil {
		extra["more"] = "call azhaq_query on this workspace for the rest of the map"
	}
	return result(r, extra)
}

// status is azhaq_status: the scope, the request budget and how much of it
// is used, the pace, and every workspace in this server's directory with
// its state, read-only and sending nothing (no command runs for it).
func (s *mcpServer) status() (map[string]any, error) {
	s.mu.Lock()
	used, runs := s.used, make(map[string]runRecord, len(s.runs))
	for k, v := range s.runs {
		runs[k] = v
	}
	s.mu.Unlock()
	files, _ := filepath.Glob(filepath.Join(s.dir, "*.db"))
	sort.Strings(files)
	workspaces := make([]map[string]any, 0, len(files))
	for _, f := range files {
		ws := strings.TrimSuffix(filepath.Base(f), ".db")
		workspaces = append(workspaces, s.workspaceStatus(ws, f, runs[ws]))
	}
	budget := map[string]any{"rate": s.rate}
	if s.budget > 0 {
		budget["limit"], budget["used"], budget["left"] = s.budget, used, max(0, s.budget-used)
	} else {
		budget["used"] = used
	}
	raw, _ := json.Marshal(map[string]any{
		"scope":      map[string]any{"locked": s.locked, "rules": s.lock},
		"budget":     budget,
		"workspaces": workspaces,
	})
	return toolText(string(raw), false), nil
}

// workspaceStatus is one workspace's row for azhaq_status: rec, when this
// session has already run a command for it (the only way to know a
// command failed outright); else what its database on disk shows left to
// do, the most azhaq_resume could tell without running anything.
func (s *mcpServer) workspaceStatus(ws, path string, rec runRecord) map[string]any {
	row := map[string]any{"name": ws}
	if rec.state != "" {
		row["state"] = rec.state
		if rec.detail != "" {
			row["detail"] = rec.detail
		}
		if rec.resume != "" {
			row["resume"] = rec.resume
		}
		return row
	}
	st, err := store.OpenExisting(path)
	if err != nil {
		row["state"], row["detail"] = "unknown", err.Error()
		return row
	}
	_, _, left, ok, err := st.Resumable()
	st.Close()
	if err != nil {
		row["state"], row["detail"] = "unknown", err.Error()
		return row
	}
	if ok && left > 0 {
		row["state"] = "stopped by a limit"
		row["detail"] = fmt.Sprintf("%d tasks left", left)
		row["resume"] = fmt.Sprintf("azhaq_resume {\"workspace\":%q} continues it", ws)
	} else {
		row["state"] = "complete"
	}
	return row
}

// resumable checks that a workspace has a run to continue, inside this
// server's lock, and returns the target list that run reads when it is a
// file of the server's, to remove once the run is complete.
func (s *mcpServer) resumable(db string) (string, error) {
	ws := strings.TrimSuffix(filepath.Base(db), ".db")
	st, err := store.OpenExisting(db)
	if err != nil {
		return "", err
	}
	_, args, _, ok, err := st.Resumable()
	st.Close()
	if err != nil {
		return "", err
	}
	if !ok {
		return "", fmt.Errorf("nothing to resume in workspace %q: every run finished", ws)
	}
	// The options the run was started with come back with it: a run
	// started elsewhere must not bring a wider scope than the server's.
	list := ""
	for i, arg := range args {
		k, v, inline := strings.Cut(strings.TrimLeft(arg, "-"), "=")
		if !strings.HasPrefix(arg, "-") {
			continue
		}
		if !inline && i+1 < len(args) {
			v = args[i+1]
		}
		switch k {
		case "list":
			if filepath.Dir(v) == filepath.Clean(s.dir) && strings.HasPrefix(filepath.Base(v), listPrefix) {
				list = v
			}
		case "scope", "program":
			if s.locked {
				return "", fmt.Errorf("the run in workspace %q was started with a program scope of its own, not this server's: map it again with azhaq_map", ws)
			}
		case "allow":
			if s.locked && !slices.Contains(s.allowRules(), v) {
				return "", fmt.Errorf("the run in workspace %q was started with a scope wider than this server's (%s): map it again with azhaq_map", ws, v)
			}
		case "ports":
			if !s.locked {
				return "", errors.New("the run scans ports, which need a scope: start azhaq mcp with -allow or -scope")
			}
		default:
			// Only what the tools of a server start comes back: a run started
			// elsewhere with -all-gets, -dirs or -dns-brute is not resumed here.
			if !mcpRunFlags[k] {
				return "", fmt.Errorf("the run in workspace %q was started with -%s, which no tool of this server starts: map it again with azhaq_map", ws, k)
			}
		}
	}
	return list, nil
}

// mcpRunFlags are the run options the tools of a server start runs with.
var mcpRunFlags = map[string]bool{
	"url": true, "domain": true, "cidr": true, "passive": true, "browser": true, "graphql": true, "depth": true, "timeout": true,
	"header": true, "login": true, "login-user": true, "max-requests": true, "rate": true, "deny": true, "quiet": true,
	"json": true, "probe": true, "no-favicon": true, "skip": true, "port-rate": true, "max-items": true, "live": true,
}

// forMCP rewrites what a summary says for the command line into what a
// client of the server can do: azhaq_resume continues a stopped run, and
// the next steps are tool calls.
// resumeHint is the azhaq_resume call that continues workspace ws, with a
// note when this server's own budget would refuse it right away.
func (s *mcpServer) resumeHint(ws string) string {
	hint := fmt.Sprintf(`azhaq_resume {"workspace":%q} continues it`, ws)
	s.mu.Lock()
	spent := s.budget > 0 && s.used >= s.budget
	s.mu.Unlock()
	if spent {
		hint += ", once azhaq mcp is restarted with a larger -max-requests: this server's budget is spent"
	}
	return hint
}

func (s *mcpServer) forMCP(sum map[string]any, ws string) {
	if sum == nil {
		return
	}
	if _, ok := sum["resume"]; ok {
		sum["resume"] = s.resumeHint(ws)
	}
	next, _ := sum["next"].([]any)
	var out []string
	for _, x := range next {
		n, _ := x.(string)
		switch {
		case strings.Contains(n, "-role auth,forbidden"):
			out = append(out, fmt.Sprintf(`azhaq_query {"workspace":%q,"role":["auth","forbidden"]}: what needs a session`, ws))
		case strings.Contains(n, "-role api"):
			out = append(out, fmt.Sprintf(`azhaq_query {"workspace":%q,"role":["api"],"fields":["key","methods","params","body"]}: the API routes`, ws))
		case strings.Contains(n, "-format openapi"):
			out = append(out, fmt.Sprintf(`azhaq_export {"workspace":%q,"format":"openapi"}: for Burp, Postman, ZAP`, ws))
		case strings.HasPrefix(n, "azhaq roles"):
			out = append(out, "azhaq_roles with two or more sessions: who may read what")
		case strings.Contains(n, "-type Hostname"):
			out = append(out, fmt.Sprintf(`azhaq_query {"workspace":%q,"type":["Hostname"]}: the names`, ws))
		}
		// The others take options no tool has (query -failed: the
		// summary's failed lists them).
	}
	if len(out) > 0 {
		sum["next"] = out
	} else {
		delete(sum, "next")
	}
}

// maxShowBytes bounds an azhaq_show answer.
const maxShowBytes = 24 << 10

// trimPayloads replaces each observation payload field longer than 2 KB
// with its size.
func trimPayloads(entity any) {
	m, _ := entity.(map[string]any)
	obs, _ := m["observations"].([]any)
	for _, o := range obs {
		om, _ := o.(map[string]any)
		p, _ := om["payload"].(map[string]any)
		for k, v := range p {
			if b, _ := json.Marshal(v); len(b) > 2<<10 {
				p[k] = fmt.Sprintf("(%d bytes, left out)", len(b))
			}
		}
	}
}

var exportFormats = []string{"openapi", "graphql", "sdl", "burp", "targets", "urls", "hosts", "names", "html", "graphml", "secrets", "jsonl"}

// exportPath is the file an export of db is written to, next to it:
// juice.html, juice.openapi.json, juice.urls.txt.
func exportPath(db, format string) string {
	base := strings.TrimSuffix(db, ".db")
	ext := exportExt(format)
	if ext == "."+format {
		return base + ext
	}
	return base + "." + format + ext
}

func exportExt(format string) string {
	switch format {
	case "openapi", "burp", "graphql":
		return ".json"
	case "sdl":
		return ".graphql"
	case "html":
		return ".html"
	case "graphml":
		return ".graphml"
	case "jsonl":
		return ".jsonl"
	}
	return ".txt"
}

// allowRules are the -allow rules of the server's lock.
func (s *mcpServer) allowRules() []string {
	var out []string
	for i := 0; i+1 < len(s.lock); i += 2 {
		if s.lock[i] == "-allow" {
			out = append(out, s.lock[i+1])
		}
	}
	return out
}

// allows: a host the server's lock lets a tool touch.
func (s *mcpServer) allows(host string) bool {
	if !s.locked {
		return true
	}
	var deny []string
	for i := 0; i+1 < len(s.lock); i += 2 {
		if s.lock[i] == "-deny" {
			deny = append(deny, s.lock[i+1])
		}
	}
	return scopeRules(s.allowRules(), deny).Allows(host)
}

// scopeSeeds are run flags that seed a run with the program's own scope.
func (s *mcpServer) scopeSeeds() []string {
	var out []string
	for _, rule := range s.allowRules() {
		r := strings.TrimPrefix(rule, "*.")
		switch {
		case strings.HasPrefix(r, "="):
			out = append(out, "-url", "https://"+strings.TrimPrefix(r, "=")+"/")
		case strings.Contains(r, "/"):
			out = append(out, "-cidr", r)
		default:
			out = append(out, "-domain", r)
		}
	}
	return out
}
