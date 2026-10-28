# Changelog

## v0.7.2

### New

- `-get-words exec,import` requests the URLs left alone for these words only (finer than `-all-gets`).
- A JSON listing's first item is asked at the route a REST API reads it at (`/api/Challenges` → `/api/Challenges/1`): the item route is proved by its answer, and `roles` gets an object to replay across sessions.
- `-no-paths` turns off the built-in path checks; `plan` counts them.
- `urls -urls-source` (and `-json`) says which source gave each URL.
- A site with a sign-in form and no session given suggests `-login` in a `next:` line.

### Changed

- `roles -replay-writes` claims a write on another role's object only when it is proven: the owner's object is read as the owner before and after, and must have changed the way the write asks (or be gone). A 2xx that changed nothing is `answered 2xx but changed nothing of the owner's`; a POST to a collection is `creates in another role's collection`; both are listed with `-all` only. Routes that only take a write (`PUT /users/v1/{username}/email`) are filled with each role's identifiers without a HAR.
- A static document (a PDF, an image) no longer tops `roles` as the same answer for a session that did not find it.
- A name is called dead only when a second resolver, of another operator, agrees.
- An origin that leaves 5 requests in a row unanswered is stopped for the run: what was left for it is `capped`, listed under "left alone" with the reason, and `azhaq resume` retries it (exit 4).
- Work is ordered by value: front pages and API paths first, other pages next, archived URLs last; archived static files (images behind query strings, media hosts) are listed and never requested.
- A directory named after a verb (`/vulnerabilities/exec/`, `/admin/user/add/`) is a section with a form, and is requested; `/exec`, `/import_paste` and a directory under an API path (`/api/jobs/run/`) are still left alone.

### Fixed

- A path in a directory past the 24 whose unknown-path answer is asked is compared with the nearest directory above it, not the site's root: Juice Shop's `/rest/…` error page for unknown paths is no longer taken for a route.
- `params -rate 0` (`-params-rate 0`) sends without a pace, as arjun does: five lab pages and 6,453 names in 0.9 s; 0 used to mean the default 20 a second.
- MCP tools take a single string where a list of strings is expected.
- The release archives carry the recipes, concepts and troubleshooting pages and the benchmark's README.

## v0.7.1

### Fixed

- Chrome keeps the scope it started with; a later reset of the run's settings raced with the requests it was still deciding.
- The run's resolver is swapped whole: a request a finished run left behind (a source past its deadline) raced the next run's reset.
- `golang.org/x/net` v0.62.0 (GO-2026-6866, GO-2026-6860 in its HTML parser).

## v0.7.0

### Changed

- Chrome is held to the scope: every request a page, frame or worker makes is intercepted, and one to a host outside the scope (without one, outside the site) is refused before it leaves, WebSockets included; refused URLs are listed as skips (`outside the scope (Chrome)`), and Chrome's requests count against `-max-requests`. A sign-in that goes to an identity provider outside the scope says so (`add it with -allow`). This covers `-browser`, `-login`, `roles -role-login` and `shots`. Windows a page opens are closed, Chrome's requests keep to `-rate`, WebRTC sends nothing past the guard, and the local relay Chrome connects through serves Chrome alone.
- `azhaq mcp` does not start without `-allow` or `-scope`, unless `-unlocked` says so.
- `params` checks every signal against a control of random names and values: a page that echoes its query string (Juice Shop's error page) no longer reports every name in the wordlist; a page that answers names it does not read is noted and not searched.
- `roles` claims "reads another role's object" only for an identifier of that kind of object (Juice Shop's `bid` is a basket's, not a basket item's), lets the object's own answer decide (an owner or reference field that names another role clears the claim), and says why in `owner_by`.
- A crt.sh failure is never partial: it makes the exit code 3.
- A query value that switches something (`?phpids=on`, `=off`, `=enable`, …) is left alone like a state-changing name.
- An `http://` URL of a site the run was given as `https://` (from an archive, a link) is mapped as https when the http front page redirects there or serves the same page: the budget is not spent twice.
- A link's query names belong to the link's row, not to the page that holds it.
- Links and forms honour `<base href>`; an export never lists a URL left alone as state-changing as an operation.

### New

- `roles` results you can trust and replay: each cross read says how sure it is (`proved`, `likely`, `guess`) and why (`evidence`); a made-up identifier of the same shape is asked as a control, and a route that answers it like a real object is `answers any identifier`; access that works both ways is said; each session is checked on a canary during the replay and renewed (`-role-cmd`, `-role-login`), and what it answered while possibly dead is `session_suspect`; the site's `200 Access denied` page is learned as a refusal (or given with `-refusal`); `azhaq roles show -dir DIR URL` prints the kept answers side by side, a field-level diff and a curl per role with its session as a shell variable.
- Scripts on other hosts the scope allows (a CDN, `api.example.com`) are read, and the routes they call there are mapped on their own host, with the script that names them; without a scope, hosts of the same site.
- The views of an app's router (Angular, React Router, Vue Router): rows of kind `client-route` (`http://app/#/administration`), with the `guard` that protects a view (`canActivate`); never requested.
- Build manifests: Next.js `_buildManifest.js` and `_ssgManifest.js` (`/admin/users/[userId]` as `/admin/users/{userId}`), Create React App, Vite, Angular service worker and Nuxt.
- Source maps without a comment: the `SourceMap` header, or `<script>.map` guessed (at most 10 per origin, kept only when it is a source map).
- WebSocket endpoints (`new WebSocket`, socket.io) as rows of kind `websocket`, never requested as pages.
- Chrome is GET-only by default: a page's own POST, PUT, PATCH, DELETE and beacons are refused before they leave, mapped as the route's operation (`source: browser`) and listed as left alone; `-browser-writes` lets them go.
- API descriptions are looked for under each API base a run's routes reveal (`/identity/api/v2/openapi.json`, springdoc's `v3/api-docs` and `swagger-config`, springfox's `swagger-resources`), not only at the root: up to 8 bases per origin, 10 requests each.
- Map rows name the parameters worth trying first (`watch`: `returnUrl (redirect)`, `file (file)`, `cmd (command)`, `isAdmin (debug)`, …).
- Subdomain takeover candidates in the summary of `subs -live`, `dns`, `probe` and `run`: a CNAME to a name on Azure, Elastic Beanstalk or Fly.io that does not resolve, a CNAME to a domain nobody registered, or a hosting service's page for a name nobody claimed (GitHub Pages, S3, Heroku, Shopify, …), each with its evidence.
- GraphQL with introspection turned off: the root fields, their types and required arguments, read from the server's validation errors (`"recovered":"suggestions"`); no document asked can pass validation, so nothing runs. Endpoints that run queries sent with GET are marked `get_queries`.
- Docs: `azhaq docs recipes`, `concepts` and `troubleshooting`.
- `roles -replay-writes post,put,patch[,delete]` asks each role's writes with every other role's session: its own from a HAR (`-har alice=alice.har`), and the PUT and PATCH (an empty object, the owner's first; a server that replaces on PUT may clear the owner's own object) and DELETE its routes take on its objects; `[bob writes alice's object]` on Juice Shop's basket items. Opt-in, inside the scope you name; `-dry-writes` lists them without sending.
- `run -stream` prints the names, URLs, answers and open ports as they are found, before the ranked map.
- `dirs` prints and keeps each hit as it is found, so a stopped run keeps them; a drop-in run given `-db` resumes with `azhaq resume` (the workspace keeps its target list).
- Forms with an empty or `#` action submit to their page; forms carry their encoding and file inputs, and `export -format openapi` holds every form (GET forms as query parameters, POST forms as urlencoded or multipart bodies) and the pages found with a query string.
- The summary suggests `-graphql` when a GraphQL endpoint was found and not introspected.

### Fixed

- `ingest` skips and counts the lines it cannot read instead of refusing the file; katana's request-only records (headless) are read.
- Apache and nginx directory-listing sort links (`?C=N;O=D`) are no separate URLs.
- An OpenAPI description's state-changing GET (`/createdb`) is `skipped` with its word and listed as left alone, like a link's.
- Docs: the port scan's one `HEAD /` to a silent port; the drop-ins' targets are their scope; workers repeat what they share.

## v0.6.3

### Changed

- `roles` catches every signed-in session dead at once (tokens copied together expire together): when no signed-in role reads anything the anonymous role is refused, each is judged alone. It exited 0 with the access-control rows silently gone. The note quotes what the site said when the role asks again (`the site said "Signature expired. Please log in again."`).
- A JSON Web Token a role carries is read for its `exp` before anything is sent: an expired one is said at once, and the run's end says whether the session died or the site still took it (`check that it verifies token expiry`).
- A name answered SERVFAIL on every attempt, by two resolvers or more, on two passes, is dead (`result` `servfail`), not a failure: one lame delegation among 1,500 names made `subs -live` exit 3.
- MCP arguments are checked against the schema `tools/list` publishes: a wrong type, a missing field or a value outside an enum is refused with -32602, naming the argument, what it takes and what was given (`roles[0] … must be an object …, not the string "anon"`). Tool descriptions and schemas agree.
- MCP `azhaq_export` pages by unit (OpenAPI paths with the components they use, GraphQL types, SDL definitions, Burp scope entries, HTML rows, GraphML nodes, lines), so each page parses on its own; `offset` counts units.
- A route found only in scripts, by a call whose method is unknown or not GET, is `hint` when a GET answers 404, not `gone`.
- `azhaq plan` counts the queries to third-party sources (the subdomain sources, archives, RDAP, keyed engines) and bounds the requests to the targets (about 34 per web service before its links, and the cap that applies), instead of claiming to print exactly what a run sends.

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
