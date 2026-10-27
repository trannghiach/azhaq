package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
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
	out     *json.Encoder
	outMu   sync.Mutex
	running map[string]context.CancelFunc // request id → its command
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
	if err := parse(fs, args); err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(*dir, 0o755); err != nil {
		return err
	}
	s := &mcpServer{exe: exe, dir: *dir, rate: *rate, budget: *budget, running: map[string]context.CancelFunc{}}
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
	return s.serve(os.Stdin, os.Stdout)
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
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 0, 1<<20), 64<<20)
	var wg sync.WaitGroup
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
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.request(m)
		}()
	}
	wg.Wait()
	return sc.Err()
}

func (s *mcpServer) send(m rpcMsg) {
	s.outMu.Lock()
	defer s.outMu.Unlock()
	m.JSONRPC = "2.0"
	_ = s.out.Encode(m)
}

func (s *mcpServer) reply(id json.RawMessage, result any) {
	s.send(rpcMsg{ID: id, Result: result})
}

func (s *mcpServer) fail(id json.RawMessage, code int, msg string) {
	s.send(rpcMsg{ID: id, Error: &rpcError{code, msg}})
}

func (s *mcpServer) notification(m rpcMsg) {
	switch m.Method {
	case "notifications/cancelled":
		var p struct {
			RequestID json.RawMessage `json:"requestId"`
		}
		if json.Unmarshal(m.Params, &p) == nil {
			s.mu.Lock()
			cancel := s.running[string(p.RequestID)]
			s.mu.Unlock()
			if cancel != nil {
				cancel()
			}
		}
	}
}

func (s *mcpServer) request(m rpcMsg) {
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
	case "tools/list":
		s.reply(m.ID, map[string]any{"tools": mcpTools()})
	case "tools/call":
		var p struct {
			Name      string         `json:"name"`
			Arguments map[string]any `json:"arguments"`
			Meta      struct {
				ProgressToken any `json:"progressToken"`
			} `json:"_meta"`
		}
		if err := json.Unmarshal(m.Params, &p); err != nil {
			s.fail(m.ID, -32602, "invalid params: "+err.Error())
			return
		}
		ctx, cancel := context.WithCancel(context.Background())
		s.mu.Lock()
		s.running[string(m.ID)] = cancel
		s.mu.Unlock()
		defer func() {
			cancel()
			s.mu.Lock()
			delete(s.running, string(m.ID))
			s.mu.Unlock()
		}()
		res, err := s.call(ctx, p.Name, p.Arguments, p.Meta.ProgressToken)
		if errors.Is(err, errUnknownTool) {
			s.fail(m.ID, -32602, err.Error())
			return
		}
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
		"Budget: " + budgetText(s.budget) + " for all calls together. Every result has a summary: results, failures (retryable or not), what was skipped and why, the limit that stopped the work.",
		"Typical flow: azhaq_plan to see what a run would send, azhaq_map to map a URL or domain into a workspace, azhaq_query and azhaq_show to read it, azhaq_roles to compare sessions, azhaq_export for Burp, Postman or ZAP.",
	}, " ")
}

var errUnknownTool = errors.New("unknown tool")

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

func (s *mcpServer) run(ctx context.Context, progress any, touches bool, args ...string) (cmdResult, error) {
	if touches {
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
	tick := time.NewTicker(5 * time.Second)
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
			if progress != nil {
				s.send(rpcMsg{Method: "notifications/progress", Params: mustJSON(map[string]any{
					"progressToken": progress, "progress": time.Since(t0).Seconds(),
					"message": fmt.Sprintf("azhaq %s: working, %s", args[0], time.Since(t0).Round(time.Second)),
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
		if strings.HasPrefix(l, `{"type":"summary"`) {
			_ = json.Unmarshal([]byte(l), &res.summary)
		}
	}
	if res.summary != nil {
		if n, ok := res.summary["requests"].(float64); ok {
			s.mu.Lock()
			s.used += int64(n)
			s.mu.Unlock()
		}
		return res, nil // the summary says how it went, exit code included
	}
	if waitErr != nil {
		var msg []string
		for _, l := range strings.Split(res.stderr, "\n") {
			// The command line's pointer to its help means nothing here.
			if l = strings.TrimSpace(l); l != "" && !strings.Contains(l, "azhaq help ") {
				msg = append(msg, strings.TrimPrefix(l, "azhaq: "))
			}
		}
		if len(msg) == 0 {
			msg = []string{waitErr.Error()}
		}
		return res, errors.New(strings.Join(msg, "\n"))
	}
	return res, nil
}

func mustJSON(v any) json.RawMessage {
	raw, _ := json.Marshal(v)
	return raw
}

// workspace is the database a tool call reads or writes: a name inside
// the server's directory, never a path elsewhere.
var workspaceName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

func (s *mcpServer) workspace(a map[string]any) (string, error) {
	name := str(a, "workspace")
	if name == "" {
		name = "default"
	}
	name = strings.TrimSuffix(name, ".db")
	if !workspaceName.MatchString(name) {
		return "", fmt.Errorf("workspace %q: letters, digits, dot, dash and underscore only", name)
	}
	return filepath.Join(s.dir, name+".db"), nil
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

func num(a map[string]any, k string, def int) int {
	if v, ok := a[k].(float64); ok && v > 0 {
		return int(v)
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

func (s *mcpServer) call(ctx context.Context, name string, a map[string]any, progress any) (map[string]any, error) {
	if a == nil {
		a = map[string]any{}
	}
	limit := num(a, "limit", 100)
	result := func(r cmdResult, extra map[string]any) (map[string]any, error) {
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
			extra["truncated"] = fmt.Sprintf("%d rows, the first %d shown; raise limit or narrow the question", len(r.lines), limit)
		}
		return result(r, extra)
	}
	targets := func() ([]string, error) {
		var out []string
		for _, u := range strList(a, "url") {
			out = append(out, "-url", u)
		}
		for _, d := range strList(a, "domain") {
			out = append(out, "-domain", d)
		}
		if ts := strList(a, "targets"); len(ts) > 0 {
			f, err := os.CreateTemp(s.dir, "targets-*.txt")
			if err != nil {
				return nil, err
			}
			_, _ = f.WriteString(strings.Join(ts, "\n") + "\n")
			f.Close()
			out = append(out, "-list", f.Name())
		}
		if boolean(a, "program_scope") {
			if !s.locked {
				return nil, errors.New("program_scope needs the server started with -scope")
			}
			out = append(out, s.scopeSeeds()...)
		}
		if len(out) == 0 {
			return nil, errors.New("give url, domain or targets")
		}
		return out, nil
	}
	runFlags := func() []string {
		var f []string
		if boolean(a, "passive") {
			f = append(f, "-passive")
		}
		if boolean(a, "browser") {
			f = append(f, "-browser")
		}
		if d := num(a, "depth", 0); d > 0 {
			f = append(f, "-depth", fmt.Sprint(d))
		}
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
	switch name {
	case "azhaq_scope":
		raw, _ := json.Marshal(map[string]any{"about": s.instructions(), "locked": s.locked, "rules": s.lock, "budget": s.budget, "used": s.used, "rate": s.rate})
		return toolText(string(raw), false), nil
	case "azhaq_plan":
		t, err := targets()
		if err != nil {
			return nil, err
		}
		r, err := s.run(ctx, progress, true, append(append([]string{"plan", "-json"}, t...), runFlags()...)...)
		if err != nil {
			return nil, err
		}
		got, _ := rows(r.lines, 1)
		return result(r, map[string]any{"plan": got})
	case "azhaq_map":
		t, err := targets()
		if err != nil {
			return nil, err
		}
		db, err := s.workspace(a)
		if err != nil {
			return nil, err
		}
		r, err := s.run(ctx, progress, true, append(append([]string{"run", "-quiet", "-json", "-db", db}, t...), runFlags()...)...)
		if err != nil {
			return nil, err
		}
		// What a researcher reads first: what needs a session, the API.
		q, _ := s.run(ctx, nil, false, "query", "-db", db, "-json", "-role", "auth,forbidden,api,app", "-scope", "target", "-limit", fmt.Sprint(limit),
			"-fields", "key,type,role,coverage,status,title,methods,params,body")
		got, cut := rows(q.lines, limit)
		extra := map[string]any{"workspace": strings.TrimSuffix(filepath.Base(db), ".db"), "highlights": got}
		if cut || q.summary != nil && q.summary["notes"] != nil {
			extra["more"] = "call azhaq_query on this workspace for the rest of the map"
		}
		return result(r, extra)
	case "azhaq_subdomains":
		ds := strList(a, "domain")
		if len(ds) == 0 {
			return nil, errors.New("give domain")
		}
		args := []string{"subs", "-json", "-silent"}
		for _, d := range ds {
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
		f, err := os.CreateTemp(s.dir, "probe-*.txt")
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
		db, err := s.workspace(a)
		if err != nil {
			return nil, err
		}
		args := []string{"query", "-db", db, "-json", "-limit", fmt.Sprint(limit)}
		for _, k := range []string{"type", "role", "coverage", "status", "method", "host", "match", "scope", "fields"} {
			if v := strList(a, k); len(v) > 0 {
				args = append(args, "-"+k, strings.Join(v, ","))
			}
		}
		if boolean(a, "new") {
			args = append(args, "-new")
		}
		r, err := s.run(ctx, nil, false, args...)
		if err != nil {
			return nil, err
		}
		return listed(r)
	case "azhaq_show":
		db, err := s.workspace(a)
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
			return nil, errors.New(strings.TrimSpace(r.stderr))
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
			return nil, errors.New(`give at least two roles: [{"name":"anon"},{"name":"user","header":"Authorization: Bearer …"},{"name":"alice","user":"a@x.test","password":"…"}]`)
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
		t, err := targets()
		if err != nil {
			return nil, err
		}
		args = append(args, "--")
		args = append(args, t...)
		args = append(args, runFlags()...)
		args = append(args, s.lock...)
		if s.rate > 0 {
			args = append(args, "-rate", fmt.Sprint(s.rate))
		}
		r, err := s.run(ctx, progress, false, args...)
		if err != nil {
			return nil, err
		}
		return listed(r)
	case "azhaq_export":
		db, err := s.workspace(a)
		if err != nil {
			return nil, err
		}
		format := str(a, "format")
		if format == "" {
			format = "openapi"
		}
		path := strings.TrimSuffix(db, ".db") + "." + strings.ReplaceAll(format, "/", "_") + exportExt(format)
		cmd := exec.CommandContext(ctx, s.exe, "export", "-db", db, "-format", format)
		raw, err := cmd.Output()
		if err != nil {
			var ee *exec.ExitError
			if errors.As(err, &ee) {
				return nil, errors.New(strings.TrimSpace(string(ee.Stderr)))
			}
			return nil, err
		}
		if err := os.WriteFile(path, raw, 0o644); err != nil {
			return nil, err
		}
		abs, _ := filepath.Abs(path)
		text := fmt.Sprintf("wrote %s (%d bytes, %s)", abs, len(raw), format)
		if len(raw) <= 16<<10 {
			text += "\n" + string(raw)
		}
		return toolText(text, false), nil
	case "azhaq_diff":
		db, err := s.workspace(a)
		if err != nil {
			return nil, err
		}
		cmd := exec.CommandContext(ctx, s.exe, "diff", "-db", db, "-jsonl", "-quiet")
		raw, err := cmd.Output()
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
	}
	return nil, fmt.Errorf("%w %q", errUnknownTool, name)
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

// allows: a host the server's lock lets a tool touch.
func (s *mcpServer) allows(host string) bool {
	if !s.locked {
		return true
	}
	var allow, deny []string
	for i := 0; i+1 < len(s.lock); i += 2 {
		switch s.lock[i] {
		case "-allow":
			allow = append(allow, s.lock[i+1])
		case "-deny":
			deny = append(deny, s.lock[i+1])
		}
	}
	return scopeRules(allow, deny).Allows(host)
}

// scopeSeeds are run flags that seed a run with the program's own scope.
func (s *mcpServer) scopeSeeds() []string {
	var out []string
	for i := 0; i+1 < len(s.lock); i += 2 {
		if s.lock[i] != "-allow" {
			continue
		}
		r := strings.TrimPrefix(s.lock[i+1], "*.")
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
