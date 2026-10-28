package main

import (
	"context"
	"encoding/json"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// Arguments of the wrong type are refused, naming the argument, what it
// takes and what was given; nested objects, enums, minimums and required
// fields too. Arguments that fit pass.
func TestMCPArgumentTypes(t *testing.T) {
	for _, c := range []struct{ tool, args, want string }{
		{"azhaq_roles", `{"url":"http://127.0.0.1:5002/","roles":["anon","alice=Authorization: Bearer x"]}`,
			`argument roles[0] of azhaq_roles must be an object {name, header, password, user}, such as {"name":"anon"}, {"name":"user","header":["Authorization: Bearer …"]} or {"name":"alice","user":"alice@example.com","password":"…"}, not the string "anon"`},
		{"azhaq_roles", `{"url":"http://127.0.0.1:5002/","roles":[{"name":"anon"},{"name":"bob","header":"Authorization: Bearer x"}]}`,
			`argument roles[1].header of azhaq_roles must be an array of strings, not the string "Authorization: Bearer x"`},
		{"azhaq_roles", `{"url":"http://127.0.0.1:5002/","roles":[{"name":"anon"}]}`, `argument roles of azhaq_roles must hold at least 2 items, not 1`},
		{"azhaq_roles", `{"url":"http://127.0.0.1:5002/","roles":[{"name":"anon"},{"nme":"bob"}]}`, `unknown property "nme" in roles[1] of azhaq_roles; it takes header, name, password, user`},
		{"azhaq_roles", `{"url":"http://127.0.0.1:5002/","roles":[{"name":"anon"},{"header":[]}]}`, `argument roles[1] of azhaq_roles needs "name", such as`},
		{"azhaq_roles", `{"url":"http://127.0.0.1:5002/","roles":[{"name":"anon"},{"name":"bob","user":"bob"}]}`, `argument roles[1] of azhaq_roles gives "user" without "password"`},
		{"azhaq_map", `{"url":"https://example.com/","login":{"url":"https://example.com/login","user":"a"}}`, `argument login of azhaq_map needs "password"`},
		{"azhaq_map", `{"url":["https://example.com/"]}`, `argument url of azhaq_map must be a string, not an array of 1`},
		{"azhaq_map", `{"targets":"example.com"}`, `argument targets of azhaq_map must be an array of strings, not the string "example.com"`},
		{"azhaq_map", `{"url":"https://example.com/","passive":"yes"}`, `argument passive of azhaq_map must be true or false, not the string "yes"`},
		{"azhaq_map", `{"url":"https://example.com/","depth":2.5}`, `argument depth of azhaq_map must be an integer of at least 0, not the number 2.5`},
		{"azhaq_query", `{"limit":"10"}`, `argument limit of azhaq_query must be an integer of at least 1, not the string "10"`},
		{"azhaq_query", `{"limit":0}`, `argument limit of azhaq_query must be an integer of at least 1, not the number 0`},
		{"azhaq_query", `{"fields":["key","titel"]}`, `argument fields[1] of azhaq_query must be one of key, type, role,`},
		{"azhaq_query", `{"scope":"all"}`, `argument scope of azhaq_query must be one of target, fanout, not the string "all"`},
		{"azhaq_query", `{"limt":2}`, `unknown argument "limt" for azhaq_query; it takes coverage, fields, host, limit, match, method, new, role, scope, status, type, workspace`},
		{"azhaq_query", `[]`, `the arguments of azhaq_query must be an object {`},
		{"azhaq_export", `{"format":"yaml"}`, `argument format of azhaq_export must be one of openapi, graphql, sdl, burp, targets, urls, hosts, names, html, graphml, secrets, jsonl, not the string "yaml"`},
		{"azhaq_export", `{"offset":-1}`, `argument offset of azhaq_export must be an integer of at least 0, not the number -1`},
		{"azhaq_show", `{}`, `azhaq_show needs the argument "key"`},
		{"azhaq_subdomains", `{"domain":"example.com"}`, `argument domain of azhaq_subdomains must be an array of strings, not the string "example.com"`},
		{"azhaq_ports", `{"hosts":["a.test", 7]}`, `argument hosts[1] of azhaq_ports must be a string, not the number 7`},
		{"azhaq_scope", `{"x":null}`, `unknown argument "x" for azhaq_scope; it takes none`},
		{"azhaq_workspaces", `{"workspace":null}`, `unknown argument "workspace" for azhaq_workspaces; it takes none`},
		{"azhaq_diff", `{"workspace":null}`, `argument workspace of azhaq_diff must be a string, not null`},
	} {
		var args any
		if err := json.Unmarshal([]byte(c.args), &args); err != nil {
			t.Fatal(err)
		}
		err := checkArgs(c.tool, args)
		if err == nil || !strings.HasPrefix(err.Error(), "invalid params: ") || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s %s:\n got %v\nwant %s", c.tool, c.args, err, c.want)
		}
	}
	for _, c := range []struct{ tool, args string }{
		{"azhaq_scope", ``},
		{"azhaq_scope", `{}`},
		{"azhaq_roles", `{"url":"http://127.0.0.1:5002/","roles":[{"name":"anon"},{"name":"bob","header":["Authorization: Bearer x"]},{"name":"alice","user":"a","password":"p"}],"ids":["alice:book_title=b"],"depth":0}`},
		{"azhaq_query", `{"workspace":"w","fields":["key","first_seen"],"scope":"target","limit":5,"new":true}`},
		{"azhaq_export", `{"workspace":"w","format":"burp","offset":0}`},
		{"azhaq_map", `{"targets":["a.test"],"login":{"url":"https://a.test/login","user":"u","password":"p"},"timeout_seconds":30}`},
	} {
		var args any
		if c.args != "" {
			_ = json.Unmarshal([]byte(c.args), &args)
		}
		if err := checkArgs(c.tool, args); err != nil {
			t.Errorf("%s %s: %v", c.tool, c.args, err)
		}
	}
	if err := checkArgs("nope", nil); err == nil || !strings.Contains(err.Error(), `unknown tool "nope"`) {
		t.Errorf("unknown tool: %v", err)
	}
}

// The server refuses them as a JSON-RPC error, as it does unknown
// arguments, before any command runs.
func TestMCPArgumentTypesOverRPC(t *testing.T) {
	s := &mcpServer{dir: t.TempDir(), exe: "/nonexistent"}
	got := rpcAll(t, s,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"azhaq_roles","arguments":{"url":"http://127.0.0.1:5002/","roles":["anon","alice=Authorization: Bearer x"]}}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"azhaq_roles","arguments":{"url":"http://127.0.0.1:5002/","roles":[{"name":"anon"},{"name":"bob","header":"Authorization: Bearer x"}]}}}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"azhaq_query","arguments":[1]}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"azhaq_scope"}}`,
	)
	for id, want := range map[float64]string{1: `roles[0] of azhaq_roles must be an object`, 2: `roles[1].header of azhaq_roles must be an array of strings, not the string`, 3: `must be an object`} {
		e, _ := got[id]["error"].(map[string]any)
		if e == nil || e["code"].(float64) != -32602 || !strings.Contains(e["message"].(string), want) {
			t.Errorf("%v: %v", id, got[id])
		}
	}
	if got[4]["error"] != nil {
		t.Errorf("a call without arguments: %v", got[4])
	}
}

func rpcAll(t *testing.T, s *mcpServer, lines ...string) map[float64]map[string]any {
	t.Helper()
	var out strings.Builder
	if err := s.serve(strings.NewReader(strings.Join(lines, "\n")+"\n"), &out); err != nil {
		t.Fatal(err)
	}
	got := map[float64]map[string]any{}
	for _, l := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("%v: %s", err, l)
		}
		if id, ok := m["id"].(float64); ok {
			got[id] = m
		}
	}
	return got
}

// Every example a tool's description or schema gives is valid under its
// schema: a {…} in a description is JSON that fits one of the tool's
// objects, examples fit their schema, and the calls the server suggests
// (in instructions, summaries, errors and docs/MCP.md) fit their tool.
func TestMCPExamplesFitSchemas(t *testing.T) {
	for _, tool := range mcpTools() {
		name := tool["name"].(string)
		schema := tool["inputSchema"].(map[string]any)
		var objects []map[string]any
		var texts []string
		walkSchema(schema, func(s map[string]any) {
			if s["type"] == "object" {
				objects = append(objects, s)
			}
			if d, ok := s["description"].(string); ok {
				texts = append(texts, d)
			}
			ex, _ := s["examples"].([]any)
			for _, x := range ex {
				if err := (argCheck{name}).value(s, roundTrip(x), "example"); err != nil {
					t.Errorf("%s: an example does not fit its schema: %v", name, err)
				}
			}
		})
		texts = append(texts, tool["description"].(string))
		found := 0
		for _, text := range texts {
			for i := 0; i < len(text); i++ {
				if text[i] != '{' {
					continue
				}
				dec := json.NewDecoder(strings.NewReader(text[i:]))
				var v map[string]any
				if err := dec.Decode(&v); err != nil {
					t.Errorf("%s: %.60q is not JSON: %v", name, text[i:], err)
					continue
				}
				found++
				fits := false
				for _, o := range objects {
					if (argCheck{name}).value(o, v, "") == nil {
						fits = true
					}
				}
				if !fits {
					t.Errorf("%s: %s fits none of its schema's objects", name, text[i:i+int(dec.InputOffset())])
				}
				i += int(dec.InputOffset()) - 1
			}
		}
		if name == "azhaq_roles" && found < 3 {
			t.Errorf("azhaq_roles shows %d roles", found)
		}
	}

	s := &mcpServer{dir: t.TempDir(), locked: true, budget: 10, used: 10}
	sum := map[string]any{"resume": "x", "next": []any{"azhaq query -db x.db -role auth,forbidden", "azhaq query -db x.db -role api",
		"azhaq export -db x.db -format openapi", "azhaq roles -role a -role b", "azhaq query -db x.db -type Hostname"}}
	s.forMCP(sum, "juice")
	texts := []string{s.instructions(), sum["resume"].(string)}
	for _, n := range sum["next"].([]string) {
		texts = append(texts, n)
	}
	_, err := s.call(context.Background(), "azhaq_roles", map[string]any{"roles": []any{map[string]any{"name": "a"}}}, nil)
	texts = append(texts, strings.Replace(err.Error(), "give at least two roles: ", `azhaq_roles {"url":"http://127.0.0.1:5002/","roles":`, 1)+"}")
	doc, _ := os.ReadFile("../../docs/MCP.md")
	texts = append(texts, strings.ReplaceAll(string(doc), `\"`, `"`))
	calls := 0
	for _, text := range texts {
		for _, m := range toolCall.FindAllStringSubmatchIndex(text, -1) {
			tool := text[m[2]:m[3]]
			var args any
			if err := json.NewDecoder(strings.NewReader(text[m[4]:])).Decode(&args); err != nil {
				t.Errorf("%s: %.80q is not JSON: %v", tool, text[m[4]:], err)
				continue
			}
			calls++
			if err := checkArgs(tool, args); err != nil {
				t.Errorf("%.120s: %v", text[m[0]:], err)
			}
		}
	}
	if calls < 8 {
		t.Errorf("%d suggested calls checked", calls)
	}
	for _, f := range strings.Split(queryFields, ",") {
		if !slices.Contains(queryColumns, f) {
			t.Errorf("the default field %s is not one fields takes", f)
		}
	}
}

var toolCall = regexp.MustCompile(`(azhaq_[a-z]+) (\{)`)

func walkSchema(s map[string]any, fn func(map[string]any)) {
	fn(s)
	if props, ok := s["properties"].(map[string]any); ok {
		for _, p := range props {
			if m, ok := p.(map[string]any); ok {
				walkSchema(m, fn)
			}
		}
	}
	if items, ok := s["items"].(map[string]any); ok {
		walkSchema(items, fn)
	}
}

// roundTrip is v as a call would send it: numbers as float64, lists as []any.
func roundTrip(v any) any {
	raw, _ := json.Marshal(v)
	var out any
	_ = json.Unmarshal(raw, &out)
	return out
}

// Every field a map row can carry is one azhaq_query's fields may name.
func TestQueryColumnsMatchRows(t *testing.T) {
	src, err := os.ReadFile("report.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(src)
	body = body[strings.Index(body, "func mapRowJSON"):]
	body = body[:strings.Index(body, "\n}\n")]
	found := regexp.MustCompile(`(?:set\(|")(\w+)"(?:, |: )`).FindAllStringSubmatch(body, -1)
	if len(found) < 15 {
		t.Fatalf("read %d fields of mapRowJSON", len(found))
	}
	for _, m := range found {
		if !slices.Contains(queryColumns, m[1]) {
			t.Errorf("a row's %q is not among azhaq_query's fields", m[1])
		}
	}
}

func TestNumClamps(t *testing.T) {
	if n := num(map[string]any{"offset": float64(1 << 31)}, "offset", 0); n != 1<<30 {
		t.Errorf("a huge offset is %d", n)
	}
	if n := num(map[string]any{"limit": 2.5}, "limit", 100); n != 100 {
		t.Errorf("a fraction is %d", n)
	}
}

// An assistant names its own targets: the server does not start without a
// scope unless told to.
func TestMCPNeedsAScope(t *testing.T) {
	err := cmdMCP([]string{"-dir", t.TempDir()})
	if exitCode(err) != exitUsage || !strings.Contains(err.Error(), "-unlocked") {
		t.Errorf("no scope: %v", err)
	}
}
