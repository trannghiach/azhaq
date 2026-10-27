# Azhaq over MCP

`azhaq mcp` serves Azhaq to any client of the Model Context Protocol (Claude Code, Claude Desktop, Cursor, and others) over stdin and stdout. Each tool runs Azhaq itself and returns the same summary and rows the command line prints with `-json`, so what a tool call does is what a command does.

The **scope**, the **request budget** and the **pace** are fixed when the server starts. No tool argument can widen them: targets outside the scope are skipped and listed in the summary, and once the budget is spent every tool that sends requests refuses.

```
azhaq mcp -scope hackerone -program security -max-requests 20000 -rate 5
azhaq mcp -allow example.com -deny admin.example.com -max-requests 5000
```

| Flag | Meaning |
| --- | --- |
| `-scope`, `-program` | a program's scope (a file, or `hackerone`, `bugcrowd`, `intigriti`, `yeswehack` with `-program`) |
| `-allow`, `-deny` | domains and hosts the tools may and may not touch (repeatable) |
| `-max-requests` | requests to targets all tool calls together may send |
| `-rate` | requests per second to targets in every call |
| `-dir` | where the workspaces (databases) go; default `azhaq-mcp` |

Without `-allow` or `-scope` the server is unlocked: any target a tool is given may be touched, and port scans are refused.

## Adding it to a client

Claude Code:

```
claude mcp add azhaq -- azhaq mcp -allow example.com -max-requests 5000 -rate 5
```

Any client that takes a JSON configuration:

```json
{"mcpServers": {"azhaq": {"command": "azhaq", "args": ["mcp", "-scope", "hackerone", "-program", "security", "-max-requests", "20000"]}}}
```

## Tools

| Tool | What it does |
| --- | --- |
| `azhaq_scope` | the scope, budget and pace fixed at start, and how much of the budget is used |
| `azhaq_plan` | what a map would take, leave out and send, without sending anything |
| `azhaq_map` | map a URL, a domain or a list into a workspace; returns the summary and the highlights (auth-gated, forbidden, API routes) |
| `azhaq_resume` | continue the run of a workspace that the budget, `timeout_seconds` or a cancellation stopped, where it stopped, with the server's scope, pace and what is left of its budget; returns what `azhaq_map` returns. A workspace keeps no session: give `headers` or `login` again. A run started with a scope wider than the server's is not resumed |
| `azhaq_subdomains` | subdomains from passive sources, with the sources of each name; `live` for names that resolve |
| `azhaq_probe` | web services of targets, like httpx |
| `azhaq_ports` | open TCP ports (locked servers only) and what serves them; each connect counts against the budget and follows the pace |
| `azhaq_query` | rows of a workspace's map by type, role, coverage, status, method, host, text, newness; chosen fields (by default key, type, role, coverage, status, title, methods, params, count) |
| `azhaq_show` | everything about one URL, host or name, with the evidence (fields over 2 KB are left out when the answer would pass 24 KB; the export has them) |
| `azhaq_roles` | the access matrix of several sessions (headers or Chrome sign-in); `ids` names a role's own objects (`alice:book_title=aliceBook`) so another role reading them is reported |
| `azhaq_export` | a workspace as OpenAPI, GraphQL introspection JSON or SDL, Burp scope, nuclei targets, URL or host lists, HTML, GraphML: the export itself, 16 KB per call (`offset` gets the next part) |
| `azhaq_diff` | what the last run into a workspace added and lost |
| `azhaq_workspaces` | the workspaces written so far |

Results are one text block of compact JSON (not repeated as `structuredContent`), carry at most `limit` rows (100 by default, never more than 1000) and say when there are more, so a client's context does not fill with one call: ask `azhaq_query` the next question instead. Summaries speak in tool calls: a run a limit stopped says `"resume":"azhaq_resume {\"workspace\":\"juice\"} continues it"`, and its next steps are `azhaq_query` and `azhaq_export` calls.

Workspaces and exports are files in the server's `-dir`, on the machine the server runs on: `azhaq_export` writes `juice.openapi.json`, `juice.html` and so on next to `juice.db` and returns the content too, so a client on another machine gets it from the result. A list of targets given to a tool is written there while the command runs, and kept only while the run it started can be resumed.

An argument a tool's schema does not name is refused with a JSON-RPC error (`-32602`, `invalid params: unknown argument "limt" for azhaq_query; it takes …`), not dropped. Calls send progress notifications when the client gives a `progressToken`: the first after a second, then every 5 seconds. A call the client cancels (`notifications/cancelled`) stops its command, which keeps what it found (`azhaq_resume` continues it), and gets no response.
