# Changelog

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
