# Azhaq over MCP

`azhaq mcp` serves Azhaq to any client of the Model Context Protocol (Claude Code, Claude Desktop, Cursor, and others) over stdin and stdout. Each tool runs Azhaq itself and returns the same summary and rows the command line prints with `-json`, so what a tool call does is what a command does.

The **scope**, the **request budget** and the **pace** are fixed when the server starts. No tool argument can widen them: targets outside the scope are skipped and listed in the summary, a subdomain lookup for a domain outside it is refused (the passive sources would learn what the assistant asks about), and once the budget is spent every tool that sends requests refuses.

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

Without `-allow` or `-scope` the server does not start (exit 2), unless `-unlocked` says so: then any target a tool is given may be touched, and port scans are refused.

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
| `azhaq_status` | a compact status: the scope (locked, allow and deny rules), the request budget (limit, used, left) and the pace, and every workspace this server's directory holds, each with its state (`complete`, `stopped by a limit` with tasks left and the `azhaq_resume` call that continues it, or `failed`, for a workspace this session ran a command for; a workspace from before this session, or one no call here has touched, shows what its database on disk says is left to do). Sends nothing and starts no command |
| `azhaq_plan` | what a map would take, leave out and send, without sending anything |
| `azhaq_map` | map a URL, a domain or a list into a workspace; returns the summary and the highlights (auth-gated, forbidden, API routes). `browser` loads pages in Chrome too; `graphql` asks each GraphQL endpoint for its schema (an introspection POST, counted; recovered from validation errors where introspection is off) |
| `azhaq_resume` | continue the run of a workspace that the budget, `timeout_seconds` or a cancellation stopped, where it stopped, with the server's scope, pace and what is left of its budget; returns what `azhaq_map` returns. A workspace keeps no session: give `headers` or `login` again. A run started with a scope wider than the server's is not resumed |
| `azhaq_subdomains` | subdomains from passive sources, with the sources of each name; `live` for names that resolve |
| `azhaq_probe` | web services of targets, like httpx: each answer as the target gave it (a redirect is not followed; `final_url` is not set), a target with no answer as a row with `failed: true` |
| `azhaq_ports` | open TCP ports (locked servers only) and what serves them, with `product` and `version` where the port names one (a port that waits is asked up to 24 more connects, each counted); each connect counts against the budget and follows the pace. UDP ports are not scanned over MCP |
| `azhaq_query` | rows of a workspace's map by type, role, coverage, status, method, host, text, newness; chosen fields (by default key, type, role, coverage, status, title, methods, params, count) |
| `azhaq_show` | everything about one URL, host or name, with the evidence (fields over 2 KB are left out when the answer would pass 24 KB; the export has them) |
| `azhaq_roles` | the access matrix of several sessions; each role is an object: `{"name":"anon"}`, `{"name":"user","header":["Authorization: Bearer …"]}` (headers, always a list) or `{"name":"alice","user":"alice@example.com","password":"…"}` (signs in with Chrome at `login_url`); `ids` names a role's own objects (`alice:book_title=aliceBook`) so another role reading them is reported |
| `azhaq_export` | a workspace as OpenAPI, GraphQL introspection JSON or SDL, Burp scope, nuclei targets, URL or host lists, HTML, GraphML: written to a file, and returned a page at a time, each page a document of its own (below) |
| `azhaq_diff` | what the last run into a workspace added and lost |
| `azhaq_workspaces` | the workspaces written so far |

What the tools do not start, on purpose: anything that sends a write or a body the client chooses (`roles -replay-writes`, `-browser-writes`, `fuzz`), path and parameter wordlists (`-dirs`, `-params`, which can also send bodies with `-params-method`), DNS brute force and permutations, and UDP scans. Run those from the command line, where the person running them sees the flags.

Results are one text block of compact JSON (not repeated as `structuredContent`). A result carries at most `limit` rows (100 by default, never more than 1000) and says when there are more, so one call does not fill a client's context: ask `azhaq_query` the next question instead. A summary names its next steps as tool calls rather than shell commands: a run a limit stopped says `"resume":"azhaq_resume {\"workspace\":\"juice\"} continues it"`, and its `next` entries are `azhaq_query` and `azhaq_export` calls.

For example, `azhaq_roles {"url":"http://127.0.0.1:5002/","roles":[{"name":"anon"},{"name":"user","header":["Authorization: Bearer …"]}]}` compares an anonymous session with a token's.

`azhaq_export` returns an export a page of about 16 KB at a time, and every page is a document of its own, cut between units, never inside one: an OpenAPI description with some of the paths (whole path items, with the components they refer to), an introspection result or SDL with some of the definitions (keyed or headed by endpoint, as the export is), a Burp options file with some of the scope entries, the HTML report or the GraphML graph with some of its rows, nodes and edges, and whole lines for the other formats. `offset` counts those units, not bytes. The result says how many there are, which ones the page holds and the offset of the next page: `wrote …/juice.openapi.json on the server's machine (52363 bytes, openapi: 82 paths); this page holds paths 0 to 45 of 82 (/.well-known/csaf/provider-metadata.json to /rest/continue-code/apply/{id}). For the rest call azhaq_export again with offset 46, …`, so `azhaq_export {"workspace":"juice","format":"openapi","offset":46}` gets the next one. A unit larger than 16 KB is a page alone; an export that fits is returned whole, as written.

Workspaces and exports are files in the server's `-dir`, on the machine the server runs on: `azhaq_export` writes `juice.openapi.json`, `juice.html` and so on next to `juice.db` and returns the content too, so a client on another machine gets it from the result. A list of targets given to a tool is written there while the command runs, and kept only while the run it started can be resumed.

Each workspace has its ledger next to it, `juice.db.ledger.jsonl`: one line for each request or connection the tools sent to a target for that workspace, each line holding the hash of the one before (`azhaq ledger -verify FILE` checks it, and `-csv` prints it for a client). The file `juice.db.stop` is the workspace's kill switch: while it exists, a call that uses the workspace sends nothing more and ends stopped (`the kill switch: kill file … exists`), and `azhaq_resume` continues once the file is removed. No tool argument turns either off.

A call's arguments are checked against the tool's `inputSchema`, the one `tools/list` publishes: an argument it does not name, a value of the wrong type (a string where a list goes, a role that is not an object), a value outside its list or under its minimum, a missing field, at any depth, is refused with a JSON-RPC error (`-32602`) that names the argument, what it takes and what was given, not dropped or guessed: `invalid params: unknown argument "limt" for azhaq_query; it takes …`, `invalid params: argument roles[0] of azhaq_roles must be an object …, not the string "anon"`. One string where a list of strings goes is taken as a list of one (`{"role":"auth"}` is `{"role":["auth"]}`). Calls send progress notifications when the client gives a `progressToken`: the first after a second, then every 5 seconds. A call the client cancels (`notifications/cancelled`) stops its command, which keeps what it found (`azhaq_resume` continues it), and gets no response.
