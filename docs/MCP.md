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
| `azhaq_subdomains` | subdomains from passive sources, with the sources of each name; `live` for names that resolve |
| `azhaq_probe` | web services of targets, like httpx |
| `azhaq_ports` | open TCP ports (locked servers only) |
| `azhaq_query` | rows of a workspace's map by type, role, coverage, status, method, host, text, newness; chosen fields |
| `azhaq_show` | everything about one URL, host or name, with the evidence |
| `azhaq_roles` | the access matrix of several sessions (headers or Chrome sign-in) |
| `azhaq_export` | a workspace as OpenAPI, Burp scope, nuclei targets, URL or host lists, HTML, GraphML |
| `azhaq_diff` | what the last run into a workspace added and lost |
| `azhaq_workspaces` | the workspaces written so far |

Results carry at most `limit` rows (100 by default) and say when there are more, so a client's context does not fill with one call: ask `azhaq_query` the next question instead. Long calls send progress notifications when the client asks for them, and a cancelled call stops its command, which keeps what it found.
