package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/trannghiach/azhaq/store"
	"github.com/trannghiach/azhaq/types"
)

// The server answers the handshake, lists its tools with schemas, keeps
// the lock it was started with and refuses what it does not know.
// contract C10: azhaq_subdomains for a domain outside the lock is refused
// before any source is asked (the server here has no azhaq to run).
func TestMCPProtocol(t *testing.T) {
	s := &mcpServer{dir: t.TempDir(), lock: []string{"-allow", "example.com"}, locked: true, budget: 100, running: map[string]context.CancelFunc{}}
	in := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"azhaq_scope","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"azhaq_ports","arguments":{"hosts":["other.test"]}}}`,
		`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"azhaq_query","arguments":{"workspace":"../../etc/passwd"}}}`,
		`{"jsonrpc":"2.0","id":6,"method":"nope"}`,
		`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"nope"}}`,
		`{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"azhaq_query","arguments":{"workspace":"w","limt":2}}}`,
		`{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"azhaq_map","arguments":{"url":"https://example.com/","allow":["other.test"],"scope":"x"}}}`,
		`{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"azhaq_diff","arguments":{"workspace":"none"}}}`,
		`{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"azhaq_subdomains","arguments":{"domain":"outside.test"}}}`,
	}, "\n") + "\n"
	pr, pw := io.Pipe()
	go func() {
		_ = s.serve(strings.NewReader(in), pw)
		pw.Close()
	}()
	got := map[float64]map[string]any{}
	sc := bufio.NewScanner(pr)
	sc.Buffer(nil, 1<<20)
	for sc.Scan() {
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatalf("%v: %s", err, sc.Text())
		}
		if id, ok := m["id"].(float64); ok {
			got[id] = m
		}
	}
	res := func(id float64) map[string]any { r, _ := got[id]["result"].(map[string]any); return r }
	if v := res(1)["protocolVersion"]; v != "2025-03-26" {
		t.Errorf("negotiated %v", v)
	}
	tools, _ := res(2)["tools"].([]any)
	if len(tools) < 10 {
		t.Fatalf("tools %v", res(2))
	}
	for _, x := range tools {
		tool := x.(map[string]any)
		if tool["inputSchema"].(map[string]any)["type"] != "object" || tool["description"] == "" {
			t.Errorf("tool %v", tool["name"])
		}
	}
	var scope map[string]any
	_ = json.Unmarshal([]byte(res(3)["content"].([]any)[0].(map[string]any)["text"].(string)), &scope)
	if scope["locked"] != true || scope["budget"].(float64) != 100 {
		t.Errorf("scope %v", scope)
	}
	if _, twice := res(3)["structuredContent"]; twice {
		t.Errorf("the result is sent twice")
	}
	if res(4)["isError"] != true || !strings.Contains(res(4)["content"].([]any)[0].(map[string]any)["text"].(string), "outside the scope") {
		t.Errorf("a host outside the lock was not refused: %v", res(4))
	}
	if res(11)["isError"] != true || !strings.Contains(res(11)["content"].([]any)[0].(map[string]any)["text"].(string), "outside the scope") {
		t.Errorf("a passive lookup outside the lock was not refused: %v", res(11))
	}
	if res(5)["isError"] != true {
		t.Errorf("a workspace outside the directory was accepted: %v", res(5))
	}
	if e, _ := got[6]["error"].(map[string]any); e["code"].(float64) != -32601 {
		t.Errorf("unknown method %v", got[6])
	}
	if e, _ := got[7]["error"].(map[string]any); e["code"].(float64) != -32602 {
		t.Errorf("unknown tool %v", got[7])
	}
	// Arguments the schema does not name are refused, by name.
	if e, _ := got[8]["error"].(map[string]any); e["code"].(float64) != -32602 || !strings.Contains(e["message"].(string), `"limt"`) {
		t.Errorf("a misspelt argument passed: %v", got[8])
	}
	if e, _ := got[9]["error"].(map[string]any); e["code"].(float64) != -32602 || !strings.Contains(e["message"].(string), `"allow", "scope"`) {
		t.Errorf("arguments that would widen the lock passed: %v", got[9])
	}
	if text := res(10)["content"].([]any)[0].(map[string]any)["text"].(string); res(10)["isError"] != true || !strings.Contains(text, `no workspace "none"`) {
		t.Errorf("a missing workspace: %v", res(10))
	}
	names := map[string]bool{}
	for _, x := range tools {
		tool := x.(map[string]any)
		names[tool["name"].(string)] = true
		props := tool["inputSchema"].(map[string]any)["properties"].(map[string]any)
		if l, ok := props["limit"].(map[string]any); ok && !strings.Contains(l["description"].(string), "at most 1000") {
			t.Errorf("%s: the limit's cap is not said", tool["name"])
		}
	}
	if !names["azhaq_resume"] {
		t.Error("no azhaq_resume")
	}
}

// fakeAzhaq writes a shell script that stands in for azhaq: it records
// its arguments in dir/args and answers per command, from FAKE_SUMMARY,
// FAKE_ROWS and dir/export; with FAKE_SLOW it runs until interrupted,
// then says so as a run does.
func fakeAzhaq(t *testing.T, dir string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the stand-in is a shell script")
	}
	script := `#!/bin/sh
echo "$@" >> "$FAKE_DIR/args"
case "$1" in
run|resume)
	if [ -n "$FAKE_SLOW" ]; then
		trap 'kill $! 2>/dev/null; touch "$FAKE_DIR/stopped"; echo "{\"type\":\"summary\",\"command\":\"run\",\"exit\":4,\"requests\":3,\"stopped\":\"interrupted with 5 tasks left\",\"resume\":\"azhaq resume -db x.db\"}" >&2; exit 4' INT
		sleep 30 &
		wait
	fi
	echo "$FAKE_SUMMARY" >&2 ;;
query)
	i=0
	while [ $i -lt "${FAKE_ROWS:-0}" ]; do echo "{\"key\":\"u$i\"}"; i=$((i+1)); done
	echo '{"type":"summary","command":"query","exit":0,"notes":["9 rows matched; -limit 2 printed the first 2 (best first)"]}' >&2 ;;
export)
	cat "$FAKE_DIR/export" ;;
esac
`
	path := filepath.Join(dir, "azhaq")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FAKE_DIR", dir)
	return path
}

func callText(t *testing.T, s *mcpServer, tool string, args map[string]any) (string, bool) {
	t.Helper()
	res, err := s.call(context.Background(), tool, args, nil)
	if err != nil {
		return err.Error(), true
	}
	return res["content"].([]map[string]any)[0]["text"].(string), false
}

// A cancelled call stops its command, which keeps what it found, and gets
// no response; progress comes early when the client asks for it.
func TestMCPCancelAndProgress(t *testing.T) {
	dir := t.TempDir()
	s := &mcpServer{exe: fakeAzhaq(t, dir), dir: dir, lock: []string{"-allow", "127.0.0.1"}, locked: true, budget: 100}
	t.Setenv("FAKE_SLOW", "1")
	defer func(first time.Duration) { progressFirst = first }(progressFirst)
	progressFirst = 50 * time.Millisecond

	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	go func() {
		_ = s.serve(inR, outW)
		outW.Close()
	}()
	msgs := make(chan map[string]any, 16)
	go func() {
		sc := bufio.NewScanner(outR)
		for sc.Scan() {
			var m map[string]any
			_ = json.Unmarshal(sc.Bytes(), &m)
			msgs <- m
		}
		close(msgs)
	}()
	write := func(line string) { _, _ = io.WriteString(inW, line+"\n") }
	write(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"azhaq_map","arguments":{"url":"http://127.0.0.1/","workspace":"c"},"_meta":{"progressToken":"tok"}}}`)
	select {
	case m := <-msgs:
		p, _ := m["params"].(map[string]any)
		if m["method"] != "notifications/progress" || p["progressToken"] != "tok" {
			t.Fatalf("want progress first, got %v", m)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no progress notification")
	}
	write(`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1,"reason":"user"}}`)
	write(`{"jsonrpc":"2.0","id":2,"method":"ping"}`)
	inW.Close()
	for m := range msgs {
		if m["id"] == float64(1) {
			t.Errorf("a cancelled request got a response: %v", m)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "stopped")); err != nil {
		t.Error("the command was not interrupted")
	}
	if s.used != 3 {
		t.Errorf("the cancelled run's requests were not counted: %d", s.used)
	}
}

// A map a limit stopped points at azhaq_resume, keeps the target list the
// resume reads, and azhaq_resume continues it with the server's lock,
// pace and budget, then removes the list. A run started with a wider
// scope is not resumed.
func TestMCPMapAndResume(t *testing.T) {
	dir := t.TempDir()
	s := &mcpServer{exe: fakeAzhaq(t, dir), dir: dir, lock: []string{"-allow", "127.0.0.1"}, locked: true, budget: 50, rate: 5}
	t.Setenv("FAKE_SUMMARY", `{"type":"summary","command":"run","exit":4,"requests":20,"stopped":"the request budget of 50 is spent, 5 tasks left","resume":"azhaq resume -db x.db",`+
		`"next":["azhaq query -db x.db -role auth,forbidden   (what needs a session)","azhaq query -db x.db -failed   (every failed target, the list to retry)"]}`)
	text, isErr := callText(t, s, "azhaq_map", map[string]any{"targets": []any{"127.0.0.1:3001", "other.test"}, "workspace": "w"})
	var res struct {
		Summary map[string]any `json:"summary"`
	}
	if err := json.Unmarshal([]byte(text), &res); isErr || err != nil {
		t.Fatalf("%s %v", text, err)
	}
	if res.Summary["resume"] != `azhaq_resume {"workspace":"w"} continues it` {
		t.Errorf("resume %v", res.Summary["resume"])
	}
	if next := res.Summary["next"].([]any); len(next) != 1 || !strings.HasPrefix(next[0].(string), `azhaq_query {"workspace":"w","role":["auth","forbidden"]}`) {
		t.Errorf("next %v", next)
	}
	lists, _ := filepath.Glob(filepath.Join(dir, listPrefix+"*"))
	if len(lists) != 1 {
		t.Fatalf("the list a resume reads: %v", lists)
	}

	// The fake run wrote no workspace: one with a run left to resume.
	mkRun := func(name string, args ...string) {
		st, err := store.Open(filepath.Join(dir, name+".db"))
		if err != nil {
			t.Fatal(err)
		}
		defer st.Close()
		if err := st.BeginRun("r1", 4, 0); err != nil {
			t.Fatal(err)
		}
		_ = st.SetRunArgs(args)
		seed := types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": "http://127.0.0.1:3001/"}}
		if err := st.SaveTasks([]store.Task{{ID: "t1", Collector: "azhaq-http", Seed: seed}}, nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	mkRun("w", "-list", lists[0], "-allow", "127.0.0.1", "-quiet", "-json")
	t.Setenv("FAKE_SUMMARY", `{"type":"summary","command":"run","complete":true,"exit":0,"requests":12}`)
	text, isErr = callText(t, s, "azhaq_resume", map[string]any{"workspace": "w", "headers": []any{"Cookie: sid=1"}})
	if isErr {
		t.Fatal(text)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "args"))
	last := strings.Split(strings.TrimSpace(string(raw)), "\n")
	got := last[len(last)-2] // the resume; the query of the highlights follows
	want := "resume -db " + filepath.Join(dir, "w.db") + " -quiet -json -header Cookie: sid=1 -allow 127.0.0.1 -rate 5 -max-requests 30"
	if got != want {
		t.Errorf("resume ran\n %s\nwant\n %s", got, want)
	}
	if _, err := os.Stat(lists[0]); err == nil {
		t.Error("the target list of a complete run is left behind")
	}
	if s.used != 32 {
		t.Errorf("used %d", s.used)
	}

	mkRun("wide", "-url", "http://127.0.0.1/", "-allow", "evil.test")
	if text, isErr := callText(t, s, "azhaq_resume", map[string]any{"workspace": "wide"}); !isErr || !strings.Contains(text, "wider") {
		t.Errorf("a run with a wider scope was resumed: %s", text)
	}
	if text, isErr := callText(t, s, "azhaq_resume", map[string]any{"workspace": "nope"}); !isErr || !strings.Contains(text, `no workspace "nope"`) {
		t.Errorf("resume of no workspace: %s", text)
	}

	// A complete map leaves no list behind; graphql asks for the schemas.
	if _, isErr := callText(t, s, "azhaq_map", map[string]any{"targets": []any{"127.0.0.1:3001"}, "workspace": "w2", "graphql": true}); isErr {
		t.Fatal("map failed")
	}
	if raw, _ := os.ReadFile(filepath.Join(dir, "args")); !strings.Contains(string(raw), " -graphql") {
		t.Errorf("graphql was not passed on: %s", raw)
	}
	if lists, _ := filepath.Glob(filepath.Join(dir, listPrefix+"*")); len(lists) != 0 {
		t.Errorf("left behind: %v", lists)
	}
}

// An export is returned in pages of whole lines past 16 KB, offset counts
// lines, and it is written once with its own extension; limit is capped
// and query rows are compact by default.
func TestMCPExportAndLimit(t *testing.T) {
	dir := t.TempDir()
	s := &mcpServer{exe: fakeAzhaq(t, dir), dir: dir}
	_ = os.WriteFile(filepath.Join(dir, "w.db"), nil, 0o644)
	var export strings.Builder
	for i := range 3000 {
		fmt.Fprintf(&export, "https://app.test/%04d/é\n", i)
	}
	_ = os.WriteFile(filepath.Join(dir, "export"), []byte(export.String()), 0o644)

	var all strings.Builder
	offset, pages := 0, 0
	for part := 0; ; part++ {
		text, isErr := callText(t, s, "azhaq_export", map[string]any{"workspace": "w", "format": "urls", "offset": float64(offset)})
		head, body, _ := strings.Cut(text, "\n")
		if isErr || !strings.Contains(head, filepath.Join(dir, "w.urls.txt")+" on the server's machine") || !strings.Contains(head, "urls: 3000 lines") || len(body) > maxInline {
			t.Fatalf("part %d: %s (%d bytes)", part, head, len(body))
		}
		if want := fmt.Sprintf("this page holds lines %d to ", offset); !strings.Contains(head, want) || !strings.HasPrefix(body, fmt.Sprintf("https://app.test/%04d/é\n", offset)) {
			t.Fatalf("part %d does not start at line %d: %s\n%.40s", part, offset, head, body)
		}
		all.WriteString(body)
		pages++
		i := strings.Index(head, "with offset ")
		if i < 0 {
			if !strings.HasSuffix(head, ", the last") {
				t.Errorf("the last page does not say so: %s", head)
			}
			break
		}
		if _, err := fmt.Sscanf(head[i:], "with offset %d", &offset); err != nil || part > 10 {
			t.Fatalf("%s: %v", head, err)
		}
	}
	if all.String() != export.String() || pages < 4 {
		t.Errorf("the pages do not make the export: %d bytes of %d in %d pages", all.Len(), export.Len(), pages)
	}
	if text, _ := callText(t, s, "azhaq_export", map[string]any{"workspace": "w", "format": "urls", "offset": float64(3000)}); !strings.Contains(text, "offset 3000 is past its end") {
		t.Errorf("past the end: %s", text)
	}
	if _, err := os.Stat(filepath.Join(dir, "w.urls.txt")); err != nil {
		t.Error(err)
	}
	if text, isErr := callText(t, s, "azhaq_export", map[string]any{"workspace": "w", "format": "nope"}); !isErr || strings.Contains(text, "azhaq help") || !strings.Contains(text, "openapi") {
		t.Errorf("bad format: %s", text)
	}

	t.Setenv("FAKE_ROWS", "2")
	text, _ := callText(t, s, "azhaq_query", map[string]any{"workspace": "w", "limit": float64(100000)})
	raw, _ := os.ReadFile(filepath.Join(dir, "args"))
	if !strings.Contains(string(raw), "-limit 1000 -fields "+queryFields) {
		t.Errorf("query ran with %s", raw)
	}
	if !strings.Contains(text, "limit 2 printed") || strings.Contains(text, "-limit") {
		t.Errorf("query note %s", text)
	}
}

func TestExportPath(t *testing.T) {
	for format, want := range map[string]string{"html": "ws/j.html", "openapi": "ws/j.openapi.json", "jsonl": "ws/j.jsonl", "graphml": "ws/j.graphml", "urls": "ws/j.urls.txt", "sdl": "ws/j.sdl.graphql"} {
		if got := exportPath("ws/j.db", format); got != want {
			t.Errorf("%s: %s", format, got)
		}
	}
}

func TestStderrError(t *testing.T) {
	err := stderrError("azhaq: unknown -format \"x\"\nazhaq: azhaq help export shows its flags and examples\n", nil)
	if err.Error() != `unknown -format "x"` {
		t.Errorf("%q", err)
	}
	err = stderrError(`{"command":"diff","error":"no such db x.db","exit":1,"type":"summary"}`, nil)
	if err.Error() != "no such db x.db" {
		t.Errorf("%q", err)
	}
}
