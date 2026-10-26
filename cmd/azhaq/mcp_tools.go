package main

import "github.com/trannghiach/azhaq/scope"

func scopeRules(allow, deny []string) scope.Rules {
	return scope.Rules{Allow: allow, Deny: deny}
}

// Schema helpers for the tool list.
func obj(props map[string]any, required ...string) map[string]any {
	s := map[string]any{"type": "object", "properties": props, "additionalProperties": false}
	if len(required) > 0 {
		s["required"] = required
	}
	return s
}

func prop(typ, desc string) map[string]any { return map[string]any{"type": typ, "description": desc} }

func strs1(desc string) map[string]any {
	return map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": desc}
}

var (
	pWorkspace = prop("string", "workspace name (a database in the server's directory); default \"default\". Runs into the same workspace can be compared with azhaq_diff.")
	pLimit     = prop("integer", "rows at most in the result (default 100)")
	pURL       = prop("string", "a URL to map, such as https://app.example.com/")
	pDomain    = prop("string", "a domain whose names to enumerate and map, such as example.com")
	pTargets   = strs1("targets, each a URL, host, host:port or IP address")
	pScope     = prop("boolean", "seed from the program scope the server was started with")
	pPassive   = prop("boolean", "send nothing to the targets: third-party sources and DNS only")
	pBrowser   = prop("boolean", "also load pages in Chrome to see the requests their scripts make (needs Chrome on the machine)")
	pDepth     = prop("integer", "how many steps from the targets to follow (default 4)")
	pTimeout   = prop("integer", "stop after this many seconds and keep what was found")
	pHeaders   = strs1("request headers for every request, \"Name: value\" (a session cookie, an Authorization token, a bug bounty identification header)")
	pLogin     = map[string]any{"type": "object", "description": "sign in with Chrome before mapping; the session goes with every request",
		"properties": map[string]any{"url": prop("string", "the login page"), "user": prop("string", "user name or email"), "password": prop("string", "password")},
		"required":   []string{"url", "user", "password"}}
)

func annotations(readOnly, openWorld bool, title string) map[string]any {
	return map[string]any{"title": title, "readOnlyHint": readOnly, "destructiveHint": false, "idempotentHint": readOnly, "openWorldHint": openWorld}
}

func mcpTools() []map[string]any {
	mapProps := map[string]any{"url": pURL, "domain": pDomain, "targets": pTargets, "program_scope": pScope, "workspace": pWorkspace,
		"passive": pPassive, "browser": pBrowser, "depth": pDepth, "timeout_seconds": pTimeout, "headers": pHeaders, "login": pLogin, "limit": pLimit}
	return []map[string]any{
		{"name": "azhaq_scope", "title": "Scope and budget",
			"description": "What this server may touch (the scope fixed at start), its request budget and how much of it is used. Call it first on a program.",
			"inputSchema": obj(map[string]any{}), "annotations": annotations(true, false, "Scope and budget")},
		{"name": "azhaq_plan", "title": "Plan a run",
			"description": "What azhaq_map would take, leave out of the scope (and why), run and send for these targets, without sending anything: collectors per target, built-in paths, active techniques, limits.",
			"inputSchema": obj(mapProps), "annotations": annotations(true, false, "Plan a run")},
		{"name": "azhaq_map", "title": "Map a target",
			"description": "Map a URL, a domain or a list of targets into a workspace: names and their addresses, web services, pages, routes the JavaScript calls (method, query and body fields), API descriptions and their operations, forms, parameters, what needs a session (401) or is refused (403). GETs only; found URLs that look like they change something (logout, delete, save) are listed, not requested. Returns the summary (failures, skipped targets, limits hit) and the highlights: auth-gated, forbidden and API routes. Read the rest with azhaq_query.",
			"inputSchema": obj(mapProps), "annotations": annotations(false, true, "Map a target")},
		{"name": "azhaq_subdomains", "title": "Find subdomains",
			"description": "Subdomains of a domain from passive sources (certificate transparency, archives, DNS datasets), each with the sources that gave it; with live, only names that resolve (wildcard answers left out). Nothing is sent to the target.",
			"inputSchema": obj(map[string]any{"domain": strs1("domains such as example.com"), "live": prop("boolean", "only names that resolve"), "workspace": pWorkspace, "limit": pLimit}, "domain"),
			"annotations": annotations(true, true, "Find subdomains")},
		{"name": "azhaq_probe", "title": "Probe web services",
			"description": "Which targets serve the web, like httpx: URL, status, title, technologies, web server, CDN, the address connected to. One GET per service.",
			"inputSchema": obj(map[string]any{"targets": pTargets, "limit": pLimit}, "targets"), "annotations": annotations(false, true, "Probe web services")},
		{"name": "azhaq_ports", "title": "Scan ports",
			"description": "Open TCP ports of hosts inside the locked scope (connect scan, no root), with banners. Only when the server was started with -allow or -scope.",
			"inputSchema": obj(map[string]any{"hosts": strs1("hosts or addresses"), "ports": prop("string", "top-100 (default), top-1000, full, or a list such as 22,80,8000-8100"), "limit": pLimit}, "hosts"),
			"annotations": annotations(false, true, "Scan ports")},
		{"name": "azhaq_query", "title": "Query a workspace",
			"description": "The rows of a workspace's map that match, best first: by entity type (URL, Hostname, IPAddress, Domain), role (app, auth, forbidden, api, page, live, sibling, unresolved, dead), coverage (visited, hint, catchall, error, skipped), status (200, 401, 4xx), method (GET, POST), host, text, what the last run saw first (new). fields picks the columns: key, type, role, coverage, status, title, methods, params, body, ops, forms, scope, first_seen.",
			"inputSchema": obj(map[string]any{"workspace": pWorkspace, "type": strs1("entity types"), "role": strs1("roles"), "coverage": strs1("coverage values"),
				"status": strs1("statuses: 200, 401, 4xx"), "method": prop("string", "routes with this method"), "host": prop("string", "on this host or under this domain"),
				"match": prop("string", "keys that contain this text"), "scope": prop("string", "target or fanout"), "new": prop("boolean", "only what the last run saw first"),
				"fields": strs1("columns to return"), "limit": pLimit}),
			"annotations": annotations(true, false, "Query a workspace")},
		{"name": "azhaq_show", "title": "Show one entity",
			"description": "Everything a workspace knows about one URL, hostname, address or domain: its row, what found it, what it leads to, every observation (status, headers, title, technologies, parameters, the calls that reach it).",
			"inputSchema": obj(map[string]any{"workspace": pWorkspace, "key": prop("string", "the URL, hostname, address or domain")}, "key"),
			"annotations": annotations(true, false, "Show one entity")},
		{"name": "azhaq_roles", "title": "Compare sessions",
			"description": "Map the target once per role, ask every endpoint any role reached with every other role, fill path parameters with identifiers the roles' answers held, and list where the answers differ: signed-in only, refused for some roles, different fields, an object every signed-in role reads alike, the same answer for a session that never found the URL. Each role is {name} (anonymous), {name, header: \"Authorization: Bearer …\"} or {name, user, password} (signs in at login_url with Chrome).",
			"inputSchema": obj(map[string]any{"url": pURL, "targets": pTargets, "program_scope": pScope, "workspace": pWorkspace,
				"roles": map[string]any{"type": "array", "description": "two or more sessions", "items": map[string]any{"type": "object",
					"properties": map[string]any{"name": prop("string", "role name"), "header": strs1("headers its requests carry"), "user": prop("string", "user to sign in as"), "password": prop("string", "its password")},
					"required":   []string{"name"}}},
				"login_url": prop("string", "the login page, for roles that sign in"), "all": prop("boolean", "also list endpoints that answer every role alike"),
				"browser": pBrowser, "depth": pDepth, "timeout_seconds": pTimeout, "limit": pLimit}, "roles"),
			"annotations": annotations(false, true, "Compare sessions")},
		{"name": "azhaq_export", "title": "Export a workspace",
			"description": "Write a workspace in another tool's format next to it and return the file: openapi (the target's own description where it serves one, plus what scripts call and forms send), burp (scope), targets (web services, for nuclei -l), urls, hosts, names, html, graphml, secrets, jsonl.",
			"inputSchema": obj(map[string]any{"workspace": pWorkspace, "format": map[string]any{"type": "string", "enum": []string{"openapi", "burp", "targets", "urls", "hosts", "names", "html", "graphml", "secrets", "jsonl"}}}),
			"annotations": annotations(true, false, "Export a workspace")},
		{"name": "azhaq_diff", "title": "What changed",
			"description": "What the last run into a workspace saw that the run before it did not, and what it no longer saw.",
			"inputSchema": obj(map[string]any{"workspace": pWorkspace, "limit": pLimit}), "annotations": annotations(true, false, "What changed")},
		{"name": "azhaq_workspaces", "title": "List workspaces",
			"description": "The workspaces this server has written.",
			"inputSchema": obj(map[string]any{}), "annotations": annotations(true, false, "List workspaces")},
	}
}
