# Azhaq over MCP

`azhaq mcp` serves Azhaq to any client of the Model Context Protocol (Claude Code, Claude Desktop, Cursor, and others) over stdin and stdout. Each tool runs Azhaq itself and returns the same summary and rows the command line prints with `-json`. What a tool call does is what a command does.

## What is fixed when the server starts

The **scope**, the **request budget** and the **pace** are fixed at start. No tool argument can widen them:

- Targets outside the scope are skipped and listed in the summary.
- Paths a `-deny-path` rule matches are never requested by any tool, and are listed as skipped. azhaq has no path rule of its own: every other GET found in scope is requested.
- A subdomain lookup for a domain outside the scope is refused, because the passive sources would learn what the assistant asks about.
- Once the budget is spent, every tool that sends requests refuses.

See [Concepts](CONCEPTS.md) for scope, budget and pace.

```
azhaq mcp -scope hackerone -program security -max-requests 20000 -rate 5
azhaq mcp -allow example.com -deny admin.example.com -max-requests 5000
```

Every flag is described on the [`azhaq mcp` page](commands/mcp.md#flags): `-scope` with `-program`, `-allow`, `-deny`, `-deny-path`, `-max-requests`, `-rate`, `-dir` (default `azhaq-mcp`) and `-unlocked`.

Without `-allow` or `-scope` the server does not start (exit 2), unless `-unlocked` says so. Then any target a tool is given may be touched, and port scans are refused.

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
| `azhaq_scope` | The scope, budget and pace fixed at start, and how much of the budget is used. |
| `azhaq_status` | A compact status of the server and each workspace. Sends nothing and starts no command. |
| `azhaq_plan` | What a map would take, leave out and send, without sending anything. |
| `azhaq_map` | Maps a URL, a domain or a list into a workspace. Returns the summary and the highlights. |
| `azhaq_resume` | Continues the stopped run of a workspace, where it stopped. |
| `azhaq_subdomains` | Subdomains from passive sources, with the sources of each name. `live` keeps names that resolve. |
| `azhaq_probe` | Web services of targets, like httpx. |
| `azhaq_ports` | Open TCP ports and what serves them (locked servers only). |
| `azhaq_query` | Rows of a workspace's map, filtered, with chosen fields. |
| `azhaq_show` | Everything about one URL, host or name, with the evidence. |
| `azhaq_roles` | The access matrix of several sessions. |
| `azhaq_export` | A workspace in a standard format, written to a file and returned a page at a time. |
| `azhaq_diff` | What the last run into a workspace added and lost. |
| `azhaq_workspaces` | The workspaces written so far. |

### Tool details

**`azhaq_status`**

- Reports the scope (locked, allow and deny rules), the request budget (limit, used, left) and the pace.
- Lists every workspace this server's directory holds, each with its state: `complete`, `stopped by a limit` or `failed`.
- `stopped by a limit` comes with the tasks left and the `azhaq_resume` call that continues it.
- Those states are for a workspace this session ran a command for. A workspace from before this session, or one no call here has touched, shows what its database on disk says is left to do.
- Sends nothing and starts no command.

**`azhaq_map`**

- Returns the summary and the highlights: auth-gated routes, forbidden routes and API routes.
- `browser` loads pages in Chrome too.
- `graphql` asks each GraphQL endpoint for its schema. That is an introspection POST, and it is counted. Where introspection is off, the schema is recovered from validation errors.

**`azhaq_resume`**

- Continues a workspace that the budget, `timeout_seconds` or a cancellation stopped, where it stopped.
- Uses the server's scope, pace and what is left of its budget. Returns what `azhaq_map` returns.
- A workspace keeps no session: give `headers` or `login` again.
- A run started with a scope wider than the server's is not resumed.

**`azhaq_probe`**

- Returns each answer as the target gave it. A redirect is not followed, and `final_url` is not set.
- A target with no answer is a row with `failed: true`.

**`azhaq_ports`**

- Scans TCP ports only. UDP ports are not scanned over MCP.
- Rows carry `product` and `version` where the port names one.
- A port that waits is asked up to 24 more connects, each counted.
- Each connect counts against the budget and follows the pace.

**`azhaq_query`**

- Filters by type, role, coverage, status, method, host, text and newness.
- The default fields are key, type, role, coverage, status, title, methods, params and count. Choose others with the fields argument.

**`azhaq_show`**

- Fields over 2 KB are left out when the answer would pass 24 KB. The export has them.

**`azhaq_roles`**

Each role is an object, in one of three forms:

- `{"name":"anon"}`
- `{"name":"user","header":["Authorization: Bearer …"]}`, where `header` is always a list
- `{"name":"alice","user":"alice@example.com","password":"…"}`, which signs in with Chrome at `login_url`

`ids` names a role's own objects (`alice:book_title=aliceBook`), so another role reading them is reported.

For example, `azhaq_roles {"url":"http://127.0.0.1:5002/","roles":[{"name":"anon"},{"name":"user","header":["Authorization: Bearer …"]}]}` compares an anonymous session with a token's.

**`azhaq_export`**

Formats: OpenAPI, GraphQL introspection JSON or SDL, Burp scope, nuclei targets, URL or host lists, HTML and GraphML. The file is written on the server's machine and returned a page at a time: see [Exports in pages](#exports-in-pages).

## What the tools do not start

These are left out on purpose. Run them from the command line, where the person running them sees the flags.

- Anything that sends a write or a body the client chooses: `roles -replay-writes`, `-browser-writes` and `fuzz`.
- Path and parameter wordlists: `-dirs` and `-params`, which can also send bodies with `-params-method`.
- DNS brute force and permutations.
- UDP scans.

## Results

- A result is one text block of compact JSON. It is not repeated as `structuredContent`.
- A result carries at most `limit` rows: 100 by default, never more than 1000. It says when there are more.
- This keeps one call from filling a client's context: ask `azhaq_query` the next question instead.
- A summary names its next steps as tool calls, not shell commands. A run a limit stopped says `"resume":"azhaq_resume {\"workspace\":\"juice\"} continues it"`, and its `next` entries are `azhaq_query` and `azhaq_export` calls.

## Exports in pages

`azhaq_export` returns an export a page of about 16 KB at a time. Every page is a document of its own, cut between units and never inside one. What a unit is depends on the format:

| Format | A page holds some of its |
| --- | --- |
| OpenAPI | paths: whole path items, with the components they refer to |
| GraphQL introspection or SDL | definitions, keyed or headed by endpoint, as the export is |
| Burp options file | scope entries |
| HTML report, GraphML graph | rows, nodes and edges |
| other formats | whole lines |

- `offset` counts those units, not bytes.
- A unit larger than 16 KB is a page alone.
- An export that fits is returned whole, as written.

The result says how many units there are, which ones the page holds and the offset of the next page:

```
wrote …/juice.openapi.json on the server's machine (52363 bytes, openapi: 82 paths); this page holds paths 0 to 45 of 82 (/.well-known/csaf/provider-metadata.json to /rest/continue-code/apply/{id}). For the rest call azhaq_export again with offset 46, …
```

So `azhaq_export {"workspace":"juice","format":"openapi","offset":46}` gets the next page.

## Workspaces, ledger and kill switch

Workspaces and exports are files in the server's `-dir`, on the machine the server runs on.

- `azhaq_export` writes `juice.openapi.json`, `juice.html` and so on next to `juice.db`. It returns the content too, so a client on another machine gets it from the result.
- A list of targets given to a tool is written there while the command runs. It is kept only while the run it started can be resumed.

Each workspace has two more files, described in [Concepts](CONCEPTS.md):

- The ledger, `juice.db.ledger.jsonl`, has one line for each request, connection or query the tools sent for that workspace, to targets, third-party sources and resolvers. Each line holds the hash of the one before. `azhaq ledger -verify FILE` checks it, and `-csv` prints it for a client.
- `juice.db.stop` is the workspace's kill switch. While it exists, a call that uses the workspace sends nothing more and ends stopped (`the kill switch: kill file … exists`). `azhaq_resume` continues once the file is removed.

No tool argument turns either off.

## Arguments, progress and cancelling

A call's arguments are checked against the tool's `inputSchema`, the one `tools/list` publishes. These are refused with a JSON-RPC error (`-32602`), not dropped or guessed:

- an argument the schema does not name;
- a value of the wrong type, such as a string where a list goes or a role that is not an object;
- a value outside its list or under its minimum;
- a missing field.

The check applies at any depth. The error names the argument, what it takes and what was given:

```
invalid params: unknown argument "limt" for azhaq_query; it takes …
invalid params: argument roles[0] of azhaq_roles must be an object …, not the string "anon"
```

One string where a list of strings goes is taken as a list of one: `{"role":"auth"}` is `{"role":["auth"]}`.

- Calls send progress notifications when the client gives a `progressToken`: the first after a second, then every 5 seconds.
- A call the client cancels (`notifications/cancelled`) stops its command, which keeps what it found, and gets no response. `azhaq_resume` continues it.
