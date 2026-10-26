package main

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"
)

// The server answers the handshake, lists its tools with schemas, keeps
// the lock it was started with and refuses what it does not know.
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
	if sc := res(3)["structuredContent"].(map[string]any); sc["locked"] != true || sc["budget"].(float64) != 100 {
		t.Errorf("scope %v", sc)
	}
	if res(4)["isError"] != true || !strings.Contains(res(4)["content"].([]any)[0].(map[string]any)["text"].(string), "outside the scope") {
		t.Errorf("a host outside the lock was not refused: %v", res(4))
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
}
