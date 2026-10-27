# Changelog

## v0.6.3

### Changed

- `roles` catches every signed-in session dead at once (tokens copied together expire together): when no signed-in role reads anything the anonymous role is refused, each is judged alone. It exited 0 with the access-control rows silently gone. The note quotes what the site said when the role asks again (`the site said "Signature expired. Please log in again."`).
- A JSON Web Token a role carries is read for its `exp` before anything is sent: an expired one is said at once, and the run's end says whether the session died or the site still took it (`check that it verifies token expiry`).
- A name every resolver answers SERVFAIL or REFUSED for, on two passes, is dead (`result` `servfail`), not a failure: one lame delegation among 1,500 names made `subs -live` exit 3.
- MCP arguments are checked against the schema `tools/list` publishes: a wrong type, a missing field or a value outside an enum is refused with -32602, naming the argument, what it takes and what was given (`roles[0] … must be an object …, not the string "anon"`). Tool descriptions and schemas agree.
- MCP `azhaq_export` pages by unit (OpenAPI paths with the components they use, GraphQL types, SDL definitions, Burp scope entries, HTML rows, GraphML nodes, lines), so each page parses on its own; `offset` counts units.
- A route found only in scripts, by a call whose method is unknown or not GET, is `hint` when a GET answers 404, not `gone`.
- `azhaq plan` counts the queries to third-party sources (the subdomain sources, archives, RDAP, keyed engines) and bounds the requests to the targets (about 34 per web service before its links, and the cap that applies), instead of claiming to print exactly what a run sends.
- A bare `/exec/` page (DVWA's) is requested: without a query it only asks what to run.

### New

- `roles -role-cmd 'alice=./token.sh alice'`: a role whose headers a command prints, run before its run and again before the replay, for tokens that live minutes.
- Where each route was found: `found_in` names the script, `line:column` and the call as written (`main.js:6472:88  this.http.post(…/rest/2fa/verify…)`), in `show`, `query -json` and `run -json`.
- A method is followed through one wrapper function: `logQuery('/logger')` with `logQuery(url) { fetch(url, {method: "post"}) }` gives `POST /logger`.
- Markdown links a page's scripts render (DVNA's lessons) are read as links.
- The summary suggests `-browser` when a target page leaves its links to its scripts and the map is thin.
- `ports` asks a port that neither accepted nor refused a connect once more (when few did), waits for the greeting of a service that speaks first (a loaded sshd), and counts silent ports in `filtered` (`filtered_ports` lists up to 64) with a summary note.

### Fixed

- `ingest` of httpx, katana and ffuf output feeds `export -format targets`, `burp`, `html` and `openapi` like a run's own rows (`targets` printed nothing after an httpx ingest). katana's POST requests and forms are routes and forms; ffuf's `-json` lines are read.
- `query -fields body` holds every operation's body fields, those from an OpenAPI description too.
- JavaScript string noise left the map: `/pQ`, `/SQ`, `/juice-shop/juice-shop`, `..` paths; a version prefix alone (`/v3`) stays only when something answers there.
- `help dirs` named a `run` flag (`-dirs-threads`) for `-rate 0`; the README's roles section says where `-dir` keeps each role's database.

## v0.6.2

### Changed

- Without a scope, a redirect is followed only within the site (the same registrable domain or address). A redirect to a third party is recorded with its `Location`; its page is never reported as the target's (`probe` reported a CDN's title and technologies for a host that redirected there).
- A third-party source that fails while other sources answered for the same domain is listed with `"partial": true` and no longer makes the exit code 3; `-fail-on-errors` (now also on `subs` and `urls`) counts it.
- subdomain.center is back in the default sources, behind a check: a name only it gave is kept when it resolves, not to a wildcard. rapiddns, thc and hudsonrock join the default keyless sources.
- `query` lists every name as its own row (the map still folds names nobody resolved).
- `scope` prints text; `-json` gives the object.
- MCP: `azhaq_query` returns compact rows by default; `limit` is capped at 1,000; unknown arguments are refused (-32602); export returns its content (16 KB per call, `offset` for more) and names files right (`.html`, not `.html.html`).

### New

- MCP `azhaq_resume`: continues a workspace's run stopped by the budget, a timeout or a cancel. Summaries point at it instead of a command line.
- `ports` names services that wait to be asked: one `HEAD / HTTP/1.0` on the open connection (`http`, with the `Server` header as banner), else a TLS handshake (`tls`, `https`, and the certificate's `subject_cn` and `subject_an`). `run -ports` hands HTTP and HTTPS ports on with the right scheme. A name's IPv6 addresses that cannot be reached are said in the summary.
- `watch` and `diff` see a JSON listing grow or shrink (`/users/v1: [200] 5 items → [200] 6 items`).
- `roles` finds each role's own objects without `-id`: it learns who each role is (JWT claims, its `/me`-like answer, what a Chrome sign-in left in storage and the login's answer) and which list items are whose (an `owner`, `user`, `userId`, `email` … field), then asks the other roles for them: `[u1 reads u2's object]` on VAmPI's books and Juice Shop's baskets and users.
- `roles` says when a role's session looks dead (refused wherever a session matters) and exits 3.

### Fixed

- `roles`: a redirect to a login page is a refusal (cookie-session apps were all `status differs`); URLs found by `-paths` are compared with their real bodies (they were 0 bytes, so a users API with password hashes was missed); a flag only one role gets in list items is not a field difference; the summary counts listed rows apart from the others.
- `probe` dropped a host whose front page another target redirected to (tesla.com → www.tesla.com): it was answered from the redirect, and reported for neither. Every target now ends as a row, a failure or a skip; one that has none is listed as failed.
- `dirs` reported 1,048,576 as the length of a larger body; it reports the whole body's length, as ffuf.
- `ports` never asks a raw printing port (9100–9107) anything: it would print the request. A second name on the same address has its web and TLS ports asked again under its own name (Host header, SNI). A TLS port is handed on to the HTTP collector.
- MCP: arguments out of range are taken as their default (a huge `offset` ended the server); a failing call ends that call, not the server; `azhaq_roles` holds to the server's budget; `azhaq_resume` refuses a run started with options no tool of the server starts (`-all-gets`, `-dirs`, …).
- `roles` prints redirect targets without their query, fragment or path parameters (they can carry a role's credentials), never takes a session's id for a user's, and calls a session dead only where the anonymous visitor was asked to sign in (401, 403, a sign-in page).
- `diff -db` on a workspace with one run says so instead of printing nothing.
- MCP: no response is sent for a cancelled request; progress notifications start after a second; error texts no longer carry command-line hints; temporary target lists are removed.
- "tasks left" in a stopped run's summary is "tasks known and not done": the count can grow as a resume finds more.

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
