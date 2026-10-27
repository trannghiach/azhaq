package main

import (
	"encoding/json"
	"strings"

	"github.com/trannghiach/azhaq/scope"
)

func scopeRules(allow, deny []string) scope.Rules {
	return scope.Rules{Allow: allow, Deny: deny}
}

// Schema helpers for the tool list. The schemas are also what a call's
// arguments are checked against (mcp_schema.go).
func obj(props map[string]any, required ...string) map[string]any {
	s := map[string]any{"type": "object", "properties": props, "additionalProperties": false}
	if len(required) > 0 {
		s["required"] = required
	}
	return s
}

func prop(typ, desc string) map[string]any { return map[string]any{"type": typ, "description": desc} }

// whole is an integer argument of at least min.
func whole(min int, desc string) map[string]any {
	return map[string]any{"type": "integer", "minimum": min, "description": desc}
}

func strs1(desc string) map[string]any {
	return map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": desc}
}

func with(s map[string]any, k string, v any) map[string]any {
	s[k] = v
	return s
}

// queryColumns are the fields of a query row, what fields picks from.
var queryColumns = []string{"key", "type", "role", "coverage", "status", "title", "methods", "params", "body", "ops", "forms", "template", "count", "folded", "proof", "scope", "first_seen"}

var (
	pWorkspace = prop("string", "workspace name (a database in the server's directory); default \"default\". Runs into the same workspace can be compared with azhaq_diff.")
	pLimit     = whole(1, "rows at most in the result: default 100, at most 1000 (narrow the question for more)")
	pURL       = prop("string", "a URL to map, such as https://app.example.com/")
	pDomain    = prop("string", "a domain whose names to enumerate and map, such as example.com")
	pTargets   = strs1("targets, each a URL, host, host:port or IP address")
	pScope     = prop("boolean", "seed from the program scope the server was started with")
	pPassive   = prop("boolean", "send nothing to the targets: third-party sources and DNS only")
	pBrowser   = prop("boolean", "also load pages in Chrome to see the requests their scripts make (needs Chrome on the machine)")
	pDepth     = whole(0, "how many steps from the targets to follow; 0 maps the targets alone (default 4)")
	pTimeout   = whole(1, "stop after this many seconds and keep what was found")
	pHeaders   = strs1("request headers for every request, \"Name: value\" (a session cookie, an Authorization token, a bug bounty identification header)")
	pLogin     = with(with(obj(map[string]any{"url": prop("string", "the login page"), "user": prop("string", "user name or email"), "password": prop("string", "password")},
		"url", "user", "password"),
		"description", "sign in with Chrome before mapping; the session goes with every request"),
		"examples", []any{json.RawMessage(`{"url":"https://app.example.com/login","user":"alice@example.com","password":"…"}`)})
	// A role is anonymous, sends headers, or signs in: user and password
	// go together.
	pRole = with(with(obj(map[string]any{"name": prop("string", "role name"), "header": strs1("headers its requests carry, \"Name: value\""),
		"user": prop("string", "user to sign in as at login_url"), "password": prop("string", "its password")}, "name"),
		"dependentRequired", map[string][]string{"user": {"password"}, "password": {"user"}}),
		"examples", []any{json.RawMessage(roleAnon), json.RawMessage(roleHeader), json.RawMessage(roleLogin)})
)

// The examples of a role, as written (raw, so the name comes first), in
// the schema, its errors and the tool's description alike.
const (
	roleAnon   = `{"name":"anon"}`
	roleHeader = `{"name":"user","header":["Authorization: Bearer …"]}`
	roleLogin  = `{"name":"alice","user":"alice@example.com","password":"…"}`
)

func annotations(readOnly, openWorld bool, title string) map[string]any {
	return map[string]any{"title": title, "readOnlyHint": readOnly, "destructiveHint": false, "idempotentHint": readOnly, "openWorldHint": openWorld}
}

func mcpTools() []map[string]any {
	planProps := map[string]any{"url": pURL, "domain": pDomain, "targets": pTargets, "program_scope": pScope,
		"passive": pPassive, "browser": pBrowser, "depth": pDepth, "timeout_seconds": pTimeout, "headers": pHeaders, "login": pLogin}
	mapProps := map[string]any{"workspace": pWorkspace, "limit": pLimit}
	for k, v := range planProps {
		mapProps[k] = v
	}
	return []map[string]any{
		{"name": "azhaq_scope", "title": "Scope and budget",
			"description": "What this server may touch (the scope fixed at start), its request budget and how much of it is used. Call it first on a program.",
			"inputSchema": obj(map[string]any{}), "annotations": annotations(true, false, "Scope and budget")},
		{"name": "azhaq_plan", "title": "Plan a run",
			"description": "What azhaq_map would take, leave out of the scope (and why), run and send for these targets, without sending anything: collectors per target, built-in paths, active techniques, limits.",
			"inputSchema": obj(planProps), "annotations": annotations(true, false, "Plan a run")},
		{"name": "azhaq_map", "title": "Map a target",
			"description": "Map a URL, a domain or a list of targets into a workspace: names and their addresses, web services, pages, routes the JavaScript calls (method, query and body fields), API descriptions and their operations, forms, parameters, what needs a session (401) or is refused (403). GETs only; found URLs that look like they change something (logout, delete, save) are listed, not requested. Returns the summary (failures, skipped targets, limits hit) and the highlights: auth-gated, forbidden and API routes. Read the rest with azhaq_query. A run the budget, timeout_seconds or a cancellation stopped continues with azhaq_resume; mapping again starts over.",
			"inputSchema": obj(mapProps), "annotations": annotations(false, true, "Map a target")},
		{"name": "azhaq_resume", "title": "Resume a run",
			"description": "Continue the run of a workspace that a limit (the request budget, timeout_seconds) or a cancellation stopped, where it stopped: the answers it got are not asked for again. Holds to the server's scope and pace and spends what is left of its budget. Returns the summary and the highlights, like azhaq_map. A workspace keeps no session: give headers or login again if the run had them.",
			"inputSchema": obj(map[string]any{"workspace": pWorkspace, "headers": pHeaders, "login": pLogin, "timeout_seconds": pTimeout, "limit": pLimit}),
			"annotations": annotations(false, true, "Resume a run")},
		{"name": "azhaq_subdomains", "title": "Find subdomains",
			"description": "Subdomains of domains from passive sources (certificate transparency, archives, DNS datasets), each with the sources that gave it; with live, only names that resolve (wildcard answers left out). Nothing is sent to the targets.",
			"inputSchema": obj(map[string]any{"domain": strs1("domains such as example.com"), "live": prop("boolean", "only names that resolve"),
				"workspace": prop("string", "also keep the names in this workspace (a database in the server's directory), to map or query later; none by default"), "limit": pLimit}, "domain"),
			"annotations": annotations(true, true, "Find subdomains")},
		{"name": "azhaq_probe", "title": "Probe web services",
			"description": "Which targets serve the web, like httpx: URL, status, title, technologies, web server, CDN, the address connected to. One GET per service.",
			"inputSchema": obj(map[string]any{"targets": pTargets, "limit": pLimit}, "targets"), "annotations": annotations(false, true, "Probe web services")},
		{"name": "azhaq_ports", "title": "Scan ports",
			"description": "Open TCP ports of hosts inside the locked scope (connect scan, no root), with banners. Only when the server was started with -allow or -scope.",
			"inputSchema": obj(map[string]any{"hosts": strs1("hosts or addresses"), "ports": prop("string", "top-100 (default), top-1000, full, or a list such as 22,80,8000-8100"), "limit": pLimit}, "hosts"),
			"annotations": annotations(false, true, "Scan ports")},
		{"name": "azhaq_query", "title": "Query a workspace",
			"description": "The rows of a workspace's map that match, best first: by entity type (URL, Hostname, IPAddress, Domain), role (app, auth, forbidden, api, page, live, sibling, unresolved, dead), coverage (visited, hint, catchall, error, skipped), status (200, 401, 4xx), method (GET, POST), host, text, what the last run saw first (new). fields picks the columns: " +
				strings.Join(queryColumns, ", ") + " (default " + strings.ReplaceAll(queryFields, ",", ", ") + ").",
			"inputSchema": obj(map[string]any{"workspace": pWorkspace, "type": strs1("entity types"), "role": strs1("roles"), "coverage": strs1("coverage values"),
				"status": strs1("statuses: 200, 401, 4xx"), "method": prop("string", "routes with this method"), "host": prop("string", "on this host or under this domain"),
				"match": prop("string", "keys that contain this text"), "scope": with(prop("string", "target (what was asked about) or fanout (found on the way)"), "enum", []string{"target", "fanout"}),
				"new":    prop("boolean", "only what the last run saw first"),
				"fields": map[string]any{"type": "array", "items": map[string]any{"type": "string", "enum": queryColumns}, "description": "columns to return"}, "limit": pLimit}),
			"annotations": annotations(true, false, "Query a workspace")},
		{"name": "azhaq_show", "title": "Show one entity",
			"description": "Everything a workspace knows about one URL, hostname, address or domain: its row, what found it, what it leads to, every observation (status, headers, title, technologies, parameters, the calls that reach it).",
			"inputSchema": obj(map[string]any{"workspace": pWorkspace, "key": prop("string", "the URL, hostname, address or domain")}, "key"),
			"annotations": annotations(true, false, "Show one entity")},
		{"name": "azhaq_roles", "title": "Compare sessions",
			"description": "Map the target once per role, ask every endpoint any role reached with every other role, fill path parameters with identifiers the roles' answers held (each role's own objects first), and list where the answers differ, worst first: anyone reads sensitive fields (passwords, secrets, keys), a role reads another role's object, an object every signed-in role reads alike, the same answer for a session that never found the URL, signed-in only, only one role reads it, some roles refused, different fields. Each role is an object: " +
				roleAnon + " is anonymous, " + roleHeader + " sends those headers, " + roleLogin + " signs in at login_url with Chrome.",
			"inputSchema": obj(map[string]any{"url": pURL, "targets": pTargets, "program_scope": pScope,
				"workspace": prop("string", "where the roles' maps are kept: a database per role in <workspace>-roles in the server's directory; default \"default\""),
				"roles":     map[string]any{"type": "array", "description": "two or more sessions", "minItems": 2, "items": pRole},
				"login_url": prop("string", "the login page, for roles that sign in"), "all": prop("boolean", "also list endpoints that answer every role alike"),
				"ids":     strs1("identifiers to fill routes with, [ROLE:]NAME=VALUE: alice:book_title=aliceBook says that book is alice's, so another role reading it is reported"),
				"browser": pBrowser, "depth": pDepth, "timeout_seconds": pTimeout, "limit": pLimit}, "roles"),
			"annotations": annotations(false, true, "Compare sessions")},
		{"name": "azhaq_export", "title": "Export a workspace",
			"description": "A workspace in another tool's format: openapi (the target's own description where it serves one, plus what scripts call and forms send), graphql (introspection JSON, for InQL or Burp), sdl (GraphQL schema), burp (scope), targets (web services, for nuclei -l), urls, hosts, names, html, graphml, secrets, jsonl. Writes the whole export to a file next to the workspace on the server's machine (juice.openapi.json, juice.html) and returns it a page of about 16 KB at a time, each page a document of its own: an OpenAPI description with some of the paths, an introspection result or SDL with some of the definitions, whole lines. The result says how many paths, definitions or lines there are, which ones the page holds, and the offset of the next page.",
			"inputSchema": obj(map[string]any{"workspace": pWorkspace, "format": map[string]any{"type": "string", "enum": exportFormats, "description": "default openapi"},
				"offset": whole(0, "the first unit of the page, counted as the result counts them: paths for openapi, definitions for graphql and sdl, scope entries for burp, rows for html, nodes and edges for graphml, lines for the others")}),
			"annotations": annotations(true, false, "Export a workspace")},
		{"name": "azhaq_diff", "title": "What changed",
			"description": "What the last run into a workspace saw that the run before it did not, and what it no longer saw.",
			"inputSchema": obj(map[string]any{"workspace": pWorkspace, "limit": pLimit}), "annotations": annotations(true, false, "What changed")},
		{"name": "azhaq_workspaces", "title": "List workspaces",
			"description": "The workspaces this server has written.",
			"inputSchema": obj(map[string]any{}), "annotations": annotations(true, false, "List workspaces")},
	}
}
