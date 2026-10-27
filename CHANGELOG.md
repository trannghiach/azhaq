# Changelog

## v0.6.1

### Changed

- `azhaq resume` no longer asks again what the stopped run asked: a run keeps its answers (and its path guesses) in the workspace until it is complete. Juice Shop capped at 50 requests and resumed until done: 211 requests in all, against 982 before and 205 for one run.
- `probe -json`: `status_code` is the first answer, as httpx prints it (a 302 stays 302); `final_status_code` and `final_url` say where an in-scope redirect ended.
- `-scope` given with targets of your own filters them; it adds the program's targets only when you give none.
- `query` prints every row that matches unless `-limit` is given.
- `diff` counts as removed only what answered before; names and URLs that were only heard of and not heard of again are `not_seen_again`, with the sources that failed.
- Names under a domain you gave are `live`, not `sibling`.
- A route scripts only call with POST or PUT is a `hint` when a GET answers 404 or 405, not `gone`.
- A query value that names a page (`index.jsp?content=about.htm`) is not folded into a template; `-per-template N` sets how many URLs of one template are requested.
- MCP results are sent once, as compact JSON (no `structuredContent` copy).
- subdomain.center is out of the default sources: it answers 500 random names per call.
- Catch-all and calibration paths are random names that do not name the tool.

### New

- `subs -w WORDLIST` and `subs -permute`: DNS brute force and permutations of the names found.
- `ports` scans IPv6 addresses too where they are reachable, and takes `-allow`, `-scope`, `-deny` and `-max-requests`; each connect counts against the request budget. `dirs` and `params` take `-allow` and `-all-gets`.
- `roles`: a cross-tenant test. Each role's own objects (an identifier only its answers held, or one given with `-id ROLE:NAME=VALUE`) are asked with every other role: `bob reads alice's object`. Answers are compared by nested JSON fields; sensitive fields (passwords, secrets, keys, card numbers, a token several sessions share) are named, and `anyone reads sensitive fields` is listed by default. New verdicts: `only one role reads it`, `roles read the same sensitive fields`. Rows carry `owner`, `readers`, `sensitive`.
- `query -failed`: every failed target, the list to retry; summaries name up to 100 targets per failure.
- `-dirs-rate 0` (and `dirs -rate 0`): no pace but the threads, as ffuf.
- `show HOSTNAME` lists the name's web services and the error of one that failed.
- `export -format graphql` (introspection JSON) and `-format sdl`; `-graphql` keeps the whole schema and the map lists each query, mutation and subscription with its arguments; OpenAPI exports carry the GraphQL endpoint as one POST with `x-azhaq-graphql`.
- `export -format burp` writes the run's scope as resolved when it started, excludes included.
- Script calls inline in a page with a page-relative path (`xhr.open("GET", "util/status.jsp?host=" + h)`) are read.

### Fixed

- With a session, `dirs` and `params` no longer send words that read like an action (`delete`, `reset-db`, `logout`); they are listed as skipped. Summaries no longer list as skipped a URL a guess requested.
- URLs carrying a scanner's payload kept by an archive (`/etc/passwd`, `;curl …oast.live`, `<script>`, SQL) never enter the map.
- OpenAPI exports are valid: operationIds are unique, every path parameter is declared, same-shape templates are one path.
- MCP port scans count against the server's request budget and follow its `-rate`.
- `roles`: a 4xx, or an error answered with 200, is a refusal (an owner-only object was `signed-in only`). With `-json`, stderr holds the summary only.
- `watch` exits with its run's code.
- With `-json`, every line on stderr is JSON: failures and limits are in the summary, and an error is a summary with `error` and `exit`.
- A name behind a CDN is scanned on its web ports only on every address, IPv6 included (CloudFront's IPv6 ranges read as plain AWS).
- A GraphQL server that refuses the full introspection query for any reason but having introspection off is asked for the names.
- `plan` and options refused as a usage error leave no database file behind.
- `show URL -json` (flags after the argument) works for every command.
- Hosts on a provider's shared domain (an S3 bucket, `*.herokuapp.com`) are not enumerated or looked up in RDAP as if they were the tenant's domain.

## v0.6.0

Every line Azhaq prints can now be trusted by whatever reads it, a person, a script or an assistant.

### Breaking changes

- `run -json` prints the map as JSON lines on stdout; the summary is one JSON object on **stderr** (`"type":"summary"`). `run` no longer prints `db …`, the stats line and a JSON summary on stdout.
- Exit codes: 0 complete, 1 error, 2 usage, 3 finished with failures, 4 stopped by a limit. `-fail-on-errors` and `-fail-on-capped` now only widen what counts (fan-out failures, depth caps).
- `probe -json` uses httpx's meanings: `host` is the name (it was the address), `host_ip` the address, `a`/`aaaa` the addresses the name resolved to, plus `port`, `scheme`, `path`, `input` as given. Empty fields are left out. The favicon is hashed only with `-favicon`, and probe sends one request per service (no catch-all check).
- Requests to targets carry a current browser's User-Agent instead of `azhaq/VERSION` (`-header 'User-Agent: …'` replaces it).
- Found URLs whose names say a GET would change something (`logout`, `delete`, `save`, `reset`, `create`, …) are no longer requested (`-all-gets` restores it). `logout` left the built-in paths.
- `roles -jsonl` rows carry `answers`, `verdict`, `found_by` and `template`; which rows are listed follows the verdicts (`-all` lists every endpoint).
- Default subdomain sources: crt.sh is read from `/json` natively; riddler, recon.cloud, sub.md, threatminer and certificatedetails.com are out of the default set, reconeer needs a key.
- Names nobody resolved are `unresolved`, not `live`.

### New

- `azhaq help COMMAND`, `help -json` (every command and flag), `--version`, `azhaq docs` (offline documentation).
- A summary on every command: failures (retryable or not), unreachable targets, skipped targets and requests with the reason, the limit that stopped the work, the command that resumes it. `-timeout` everywhere.
- Scope, pace and budget flags on every command that sends requests; targets outside the scope are listed, never requested.
- `azhaq plan`: everything a run would take, skip, run and send, without sending anything.
- Scripts: the requests they make (method, query names, body fields) worked out from literals, template literals and variables.
- API descriptions: per-operation parameters by location, body fields, security; the document kept; parameterless GETs asked; Swagger UI pages that build their document's URL at run time.
- `export -format openapi` keeps the target's own description and adds what scripts call and forms send. New `-format names`.
- `roles`: an access matrix; every endpoint asked with every session, path parameters filled from identifiers in the answers, answers compared by status, size, body and JSON fields.
- `azhaq query` and `azhaq show`.
- `azhaq ingest` reads subfinder, dnsx, httpx, katana, naabu, nuclei, gau and ffuf output and Azhaq's own export.
- `azhaq mcp`: an MCP server with the scope and budget locked at start.
- `watch` reports removed URLs and pages that answer differently, and ignores query values that change on every request.
- `subs -db` keeps every name; `subs -json` gives each name's sources.
- `-browser` reaches the pages of hash-routed apps and carries the login's sessionStorage.
- HTTP connects to the addresses the run resolved, IPv6 first where routable.
- Release checksums are signed with sigstore.

### Fixed

- A failed request is `error`, not `visited`; failures and refusals are never silent.
- The catch-all check compares JSON by fields and size.
- Error pages are not crawled for links; junk URLs (`NaN`, cut-off archive links, scanner payloads) stay out.
- Free-text scope entries are one skipped entry; registrars are not owners; parser tables are not secrets.
