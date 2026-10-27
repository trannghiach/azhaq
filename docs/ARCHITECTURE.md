# Architecture

Azhaq takes seeds, runs every collector that accepts each seed's type, and stores what they report in a SQLite graph. Facts a collector reports can become new seeds, so a run expands outward until it hits its depth or item limit.

```
seeds ──► Plan ──► Run ──► observations ──► graph (SQLite)
            ▲                    │
            └──── next seeds ◄───┘
```

## Data model

**Seeds** have a type and a set of keys. Collectors exist today for `URL`, `Hostname`, `Domain`, `Organization` and `CloudAccount`. `IPAddress` is stored as an entity but has no collector of its own. `Prefix`, `Certificate`, `Email` and `Application` are defined but unused.

**Entities** are graph nodes, unique on `(type, key)`. Keys are normalized before lookup (lowercase hostnames, cleaned URLs), so the same hostname found by CT, DNS, a crawl and a certificate SAN is one entity.

**Observations** are facts attached to an entity: collector, source, kind (`url`, `dns`, `ct`, `form`, `params`, …), a JSON payload, confidence and timestamp. They are append-only. A later observation does not replace an earlier one.

**Edges** are derived from observations and seeds:

| Edge | Meaning |
| --- | --- |
| `FOUND` | a URL was found on another URL |
| `ON_HOST` | a URL belongs to a hostname or IP |
| `IN_DOMAIN` | a hostname belongs to a registrable domain (eTLD+1) |
| `RESOLVES_TO` | a hostname resolves to an IP |
| `CNAME` | a hostname is an alias of another |

Identity rules that keep the graph honest:

- Hostnames on shared platforms (`appspot.com`, `herokuapp.com`, `web.app`, …) stop at the tenant, so two tenants are two sites.
- Hosts that share an IP are not merged.
- TLS SANs are only followed within the seed's eTLD+1, which ignores CDN and proxy default certificates.

## Collectors and the catalog

A collector is one interface:

```go
type Collector interface {
	Name() string
	Inputs() []types.SeedType
	Outputs() []string
	Run(ctx context.Context, seed types.Seed, emit func(types.Observation) error) (types.RunMeta, error)
}
```

`Run` only reports: it calls `emit` for each fact and returns follow-up seeds in `RunMeta.NextHints`. It never writes the graph or schedules work.

All collectors register in one in-process catalog (`catalog`, filled by `collectors.RegisterAll`). Planning is a lookup, `catalog.Where(seed.Type)`, so the engine and CLI never name a collector. Adding a capability means writing a collector and registering it.

A collector may also implement:

- `catalog.Informer` (`Info()`), which says what it contacts. `Passive` collectors only ask third parties and DNS resolvers; `Touch` collectors (the default) send requests to the target; `Active` collectors send guesses (brute force, permutations) and name the flag that enables them. `After` names a collector that must finish with the same seed first: HTTP and TLS wait for `azhaq-dns`, and when DNS returns `RunMeta.Drop` (no address, or a wildcard answer) they skip the name.
- `catalog.Batcher` (`BatchSize`, `RunBatch`), for work that is much cheaper in bulk. DNS resolves up to 256 names per call; each name still gets its own entity, idempotency key and hints.
- `catalog.Skipper` (`Skip(seed) bool`), to decline a seed when it would return at once: a script it has already parsed, an origin whose paths it has already swept, a URL that cannot be an API description. Skipped seeds do not spend the item budget.

A collector can also hand over seeds before it returns with `catalog.Hint(ctx, seeds...)`. The subdomain collector does this as each source answers, so DNS starts on the fast sources' names while a slow source is still running.

## Engine

`engine` exposes four operations:

- **Plan** turns seeds into work items, one per matching collector.
- **Run** executes one work item. It upserts the seed entity, passes an `emit` function that writes each observation and its edges to the store, then returns the collector's hints plus derived seeds (URL → hostname → eTLD+1). Each item has an idempotency key, a hash of collector, seed type and seed key. An item already in the store is skipped, so retries are free.
- **Ingest** writes facts produced outside Azhaq (connector JSONL) straight into the graph.
- **RunLocal** is the built-in scheduler the CLI uses. A workflow engine can call `Plan` and `Run` directly and do its own scheduling instead.

`emit` writes synchronously, so a fast collector cannot outrun the store and memory stays flat.

### Scheduling (`RunLocal`)

Work flows instead of moving in waves. A seed's work items are queued as soon as the seed appears, a free worker takes the next one, and the hints it returns are queued at once. A slow item, such as a CT log taking 25 seconds, holds back nothing else. Up to `-parallel` items (default 16) run at a time; each batch collector may run 4 batches at once on top.

Limits:

- `-depth` (default 4) bounds how many hints away from the seeds a seed may be.
- `-max-items` (default 2048) caps ordinary work items.
- `-max-names` (default 20,000) caps the names handed to batch collectors (DNS), so a domain with thousands of subdomains does not spend the item budget on resolution.
- `-max-requests` caps the requests sent to targets, and `-rate` paces them over all hosts. Every request to a target asks `fetch.Spend` first: GETs and each redirect hop, path and parameter guesses, the GraphQL query, and a page loaded in Chrome (whose subresources are counted after the load). `-daily-requests` gives a program (`-program`, else the run's targets) a number of requests per UTC day, counted over the runs in the database (table `spend`); a run starts with what is left.

A request the budget refuses fails with `neterr.ErrBudget`. The engine marks every task's context, so a refusal counts even when a collector takes the failed request for a missing page: the task ends `capped`, is not marked done, drops nothing that waits on it, and the run is marked `capped`. Under a budget a task's reports are held until it ends, and those of a task the budget stopped are dropped: a refused catch-all check would otherwise turn an application's index page into findings.

### Resuming (`azhaq resume`)

The scheduler records its frontier in the store (table `tasks`): every task it plans (collector, seed, depth), in the same transaction as the tasks that finished, so a task's hints are never lost between it ending and them being recorded. A task is done when it ran (with or without an error), was dropped, or was skipped; one that was cancelled or stopped by the request budget is not. The run's options are stored with it, without the database or the values that carry a session (`-cookie`, `-login-pass`, headers named like a credential).

`azhaq resume -db FILE` takes the latest run with tasks left (interrupted by Ctrl-C or a kill, or stopped by `-max-requests`, `-daily-requests` or `-max-items`), runs it again with its stored options plus any given, and rebuilds the queues from the tasks: done tasks count against the item budget, the others are queued again, behind the task they wait for when that is not done either. Their done-marks are cleared, so a task that ran but whose end was not recorded runs again whole; observations are stored once per run, so it reports nothing twice. Tasks the budget stopped before run last, one at a time and cheapest first (by the requests they had sent), so a path sweep that needs more than the budget does not starve cheaper work; once the budget is spent, tasks that would contact targets are kept back. A resume in which no task finished says the budget is smaller than any task left needs.

### Workers (`-serve`, `azhaq worker`)

A run started with `-serve ADDR` lends its work to `azhaq worker` processes, on the same machine or others, over HTTP with a bearer token. The run's process keeps the database, the scheduler, the budgets and its own `-parallel` slots; a worker claims one task at a time per slot (`POST /v1/claim`, a long poll), runs the collector in-process without a store (`engine.Execute`) and sends back what it reported, its hints and the requests it sent (`POST /v1/done`), which the run stores as if it had run the task itself (`Engine.Record`). Workers take only tasks that contact targets: third-party sources (and their keys), batch DNS and `Local` collectors (screenshots, `-browser`) stay with the run. A worker gets the run's options without seeds, outputs or sessions, the files they name (wordlists), the scope as `-allow`/`-deny` rules and the session as headers (`GET /v1/run`). A task a worker holds longer than its lease (15 minutes) is queued again; tasks lent when the run stops are left for `azhaq resume`. The request budget counts every process's requests; `-rate` and `-host-parallel` apply per process.

Items on the seed's own host or IP run before fan-out items, but part of the item budget is reserved for fan-out: one eighth, at least 24 items once the budget is 48 or more, and never more than half. Without it, a large application would spend the entire budget before any domain-level collector ran.

The run's policy is applied when items are planned: `-passive` keeps only `Passive` collectors; an `Active` collector needs its flag, an `-allow` scope and a seed inside it; `-skip` removes collectors by name.

A seen-set prevents running the same seed twice, and `-allow` / `-deny` / `-scope` filter hints before they are queued. A scope entry is a domain with its subdomains (`example.com`, `*.example.com`), one host (`=api.example.com`), or an address range (`10.0.0.0/8`). When a scope is set, the shared HTTP client also refuses any request to a host outside it, and stops following a redirect at the first hop that leaves it (the hop is recorded with its `Location`); the path, parameter and GraphQL modules use their own clients without redirects, on seeds the scope already admitted.

Collectors that read a page (crawl, scripts, API descriptions, paths, GraphQL) run after `azhaq-http` has answered for the same URL: a URL that does not answer is dropped, and so is every task waiting behind it. A target given as `host:port` or an IP address goes on as the scheme that answered. A target given as `https://host/` that archives or links name over plain http (`http://host/…`, or another name of its domain) gets one request to `http://host/` first: when it redirects to https on the same host, serves the same front page, or nothing answers on port 80, those URLs are the https site's and are requested and mapped as https; otherwise `http://host/` is a service of its own and its URLs stay as they are. A directory listing's sort links (Apache's and nginx's `?C=N;O=D`, `?C=M&O=A`) are the same listing and are neither requested nor listed. URLs that differ only by an ID or a query value share a template (`/catalog/product?productId={n}`); at most 3 URLs per template are fetched, and the rest stay in the graph as found. Work left over when a limit is reached is stored and the run is marked `capped`.

## HTTP

All HTTP collectors share one client (`internal/fetch`):

- Redirects are not followed automatically. Each hop is recorded, and the status stored is that of the URL that was requested, so `/admin → 303 → /login` records `/admin` as 303.
- At most 4 requests are in flight per host (`-host-parallel`). Concurrent requests for the same URL share one fetch.
- Bodies are capped at 2 MiB, or 16 MiB for JavaScript, JSON and source maps, where bundles of several MB are normal. `-delay` adds a pause before each uncached request.
- `-cookie` and `-header` are added to every request, which lets a run reuse a session you already have; `-login` gets one with Chrome. Azhaq stores cookie names but never their values.
- Headers must arrive within 10 seconds, as in httpx; CDN edges and bot managers often answer slowly. The whole request, body included, gets 30 seconds, so a large bundle on a slow link still arrives.

### Probing

`azhaq-http` probes a hostname over HTTPS and falls back to HTTP; with `-web-ports` it tries each port, HTTPS first except on port 80. A `host:port` or IP address from `-list` becomes a URL with the same fallback. For each answer it stores, besides status, title and headers:

- `tech`: wappalyzer fingerprints of the final response's headers and body, as `Name` or `Name:version`. `internal/wappalyzer` is wappalyzergo's passive matcher with one change: each pattern's regexp compiles the first time its literal prefilter passes. Upstream compiles all of them at load, and because it bounds `+` and `*` to 250 repetitions, which Go unrolls, that held about 80 MB; on first use it is a few MB. A test runs both matchers over a page built for each of the 7,642 fingerprints and requires identical results;
- `favicon`: on a site's front page, the MurmurHash3 of the icon's base64 encoding, the value Shodan indexes as `http.favicon.hash`. The icon is the page's `<link rel=icon>` (`.ico` first) or `/favicon.ico`, at most two requests, and only on the same site;
- `length`, `words`, `lines` of the final body (counted like httpx), `ms` for the whole redirect chain, and `ip`, the address the request connected to (left out behind a proxy);
- `final_status` when the request was redirected.

`azhaq-dns` adds `cdn` and `cdn_type` (`cdn`, `waf` or `cloud`) from cdncheck's embedded ranges: by address, then by CNAME target. Nothing here makes an extra lookup.

`-probe` keeps a run to this: only `azhaq-dns` and `azhaq-http` run, on the listed targets and nothing they lead to, and the output is one line per web service instead of the map.

### Scripts

`azhaq-js` reads each page's inline scripts and same-origin script files, then the chunks those import by name or through a webpack chunk map: it evaluates the bundle's chunk-name function (`n.u=e=>"static/js/"+e+"."+{…}[e]+".chunk.js"`) for each chunk ID the bundle knows. In every script it looks for:

- URL and path strings. Strings that name no route are dropped: pieces of a parser table or a minified name (`/pQ`, `/SQ`: one segment of one or two letters with a capital) and a package named after its owner (`/juice-shop/juice-shop`: a slug with a hyphen or a dot, twice). Short routes in lower case (`/v1`, `/me`, `/id`), a locale (`/en/US`) and a word twice (`/admin/admin`) are kept; a version prefix alone (`/v3`) is requested, and stays in the map only when something answers there;
- the requests scripts make through an HTTP client (`this.http.post(…)`, `$.get`), `fetch`, `XMLHttpRequest`, `$.ajax` and `axios`: the method, the path with run-time parts as `{name}`, and the query and body names. A request made inside a function that takes the URL as a parameter is read where the function is called, one level deep: `logQuery('/logger', …)` with `function logQuery(url, params){ fetch(url, {method: "post", …}) }` is `POST /logger`. The function's parameter defaults count (`method = "POST"`, also for a call that passes `undefined`), and so does a prefix it puts on the parameter before the request (`url = API_ROOT + url`); any other change to the parameter, or a name the script declares twice (`usersApi.request` and `ordersApi.request`), and the function is not followed. A request whose path has a placeholder for the parameter stays a route of its own (`/api/accounts/{id}` besides `/api/accounts/me`). A path relative to the page counts only for `fetch`, `XMLHttpRequest` and `$.ajax`, as without a helper, and jQuery sends a GET's `data` as its query. When a request's method is a value known only at run time, the route is listed without one;
- paths joined from constants where the request is made, such as `og+sg.LOGIN` with `og="identity/"` and `sg={LOGIN:"api/auth/login",…}`. A name counts only if the script binds it once, so a short minified name reused across modules is not guessed at. Placeholders such as `<videoId>` become `{videoId}`;
- GraphQL operation names, from query documents or the parsed form bundlers emit;
- credentials: keys of AWS (with the secret key next to an access key id, which makes the pair high), Google, GitHub, GitLab, Slack, Discord and Slack webhooks, Stripe, SendGrid, Mailgun, Twilio, OpenAI and Anthropic; private keys; JWTs; variables bundlers inline (`REACT_APP_…`, `NEXT_PUBLIC_…`, `VITE_…`); and values of eight or more characters assigned to secret-sounding names, kept only when they look random (entropy) and not like a label or placeholder. Values are stored whole; the HTML report shortens them.

Well-known library builds served from the app's own origin (`react-dom.development.js`, `jquery-3.6.0.min.js`, `swagger-ui-bundle.js`) are not fetched: they are large and hold no routes of the app, only stray strings.

A script that names a same-origin source map has the map read: the map is recorded with the app's own source files (libraries left out), and those sources are scanned like scripts. An exposed source map is worth knowing about on its own.

Each route found in a script keeps where: the script's URL (the page's for an inline script, with the page's line numbers), the line and column, and up to 120 bytes of code: the call as written, or a string with what surrounds it, with credentials blanked (an inline script of a signed-in page can hold the session). Up to three places per route per page, calls first; a route read from a source map's original file names that file.

`azhaq-openapi` also reads a description written into a script, as Swagger UI's `swagger-ui-init.js` carries it.

### Sessions and roles

`-cookie` and `-header` apply to every request of a run, and so does the session `-login` gets: Chrome fills and submits the login form, and the cookies the site sets and a JSON Web Token the page stores become a `Cookie` and an `Authorization` header (`internal/browser/login.go`). While a session is set, URLs that look like a logout are not requested, by the HTTP collectors or by `-browser`. A role of `azhaq roles` is headers (`-role`) or an account to sign in with (`-role-login`). `azhaq roles` runs the same seeds once per role, in turn, each with its own database. Then it replays: every URL any role reached (on the run's hosts, a GET whose name does not say it changes something) is asked with each role that did not reach it, through that role's session, and GET routes with path parameters are filled with the values of identifier-like fields (`id`, `username`, `*_id`, `*_title`, …) the roles' own JSON answers held: values given with `-id` first, then each role's own (a value only that role's answers held), then shared ones. Each endpoint then has an answer per role (status, length, body hash, nested JSON field paths, whether it is an error, which fields hold secrets), a 2xx that is not an error counts as reading it, and a verdict names the difference: anyone reads sensitive fields, a role reads another role's object, an object every signed-in role reads alike, roles read the same sensitive fields, the same answer for a role that never found the URL, signed-in only, only one role reads it, some roles refused, different fields, an object anyone reads, status differs, different data, the same for all.

### Catch-all responses

Many applications answer every path: a single-page app serves its index for any route, some servers return a "not found" page with status 200, others redirect every unknown path to a login page. Without a check, each of those paths would look like a real page.

Before a non-root URL counts as visited, `fetch.CatchAll` compares its response with the answer for a random path in the same directory (`/rest/user/azhaq-…` for `/rest/user/login`). The responses match when the status is the same and either the redirect target or the body is the same once the requested path is removed from it, so error pages that echo the path still match. Bodies that differ only by a token or timestamp match on title, line count and word count. Each directory is probed once per run, up to 24 directories per origin.

A matching response is stored with `"catchall": true` and shown as `catchall` in the map. The crawler and the JavaScript reader skip such pages, and the path sweep drops them.

## DNS

`internal/dnsr` resolves through a pool of recursive resolvers (six public ones by default, or `-resolvers FILE`). Queries go round robin with a rate limit per resolver (`-dns-rate`, default 100 per second); a timeout, SERVFAIL or REFUSED moves the query to another resolver, and a truncated answer is retried over TCP. Each name is resolved once per run. Special-use names (`localhost`, `*.test`, `*.local`) and single labels go to the system resolver instead, so `/etc/hosts` and local DNS still work.

A name is a wildcard answer when one of its parent zones answers for random labels and the name's addresses, or its CNAME target, are what the random labels got. Each zone is probed once per run. Real hosts in a wildcard zone are kept when their addresses differ; a real host that shares the wildcard's address is dropped, the same trade-off other resolvers make.

## Subdomain sources

`azhaq-subdomains` asks every selected source at once and records each one's count, time and error. Most sources are subfinder's source packages, run in-process: Azhaq supplies the HTTP client, a limiter with subfinder's per-source rates, and keys from the provider file. Cert Spotter (usable without a key) and Chaos are implemented in Azhaq. A source that needs a key is skipped, and listed as skipped, when none is configured. When every source that ran failed and nothing was found, the result is marked `degraded` rather than reported as zero.

The default set is subfinder's default set: the fast sources. `-all-sources` adds slower ones such as Common Crawl and the Wayback Machine.

A domain the engine derives from a URL or hostname (`-url https://app.example.com/` implies `example.com`) gets 15 seconds per source instead of 45, here and for historical URLs: the run is about the application, and one slow source would otherwise hold up its map. A domain given with `-domain` gets the full time. Sources that ignore their deadline (subfinder's crt.sh tries a Postgres connection first) are reported as timed out two seconds after it and no longer waited for.

## Path guessing

`-dirs FILE` (active, needs `-allow`) guesses paths on each web service's front page, then in each directory it finds, down to `-dirs-depth` levels. Before a directory is swept, it is asked for names that cannot exist, in the shapes ffuf's auto-calibration uses (a random word, `admin…`, `.htaccess…`, a random directory, and one per extension). A guess is dropped when it answers like one of those: same status and the same size, or the same word and line counts, or a size that differs only by the length of the path the page echoes, or the same redirect. Statuses default to ffuf's (`200-299,301,302,307,401,403,405,500`). A directory is a path that redirects to itself with a trailing slash.

The sweep has its own client: no cache, no redirects followed, bodies read only to count them, 20 requests in flight and 100 per second per host (`-dirs-threads`, `-dirs-rate`). Hits become URLs for the other collectors. With a session, logout-like words are skipped.

## Parameters

`-params FILE` (active, needs `-allow`) looks for query parameters each page reads but does not link, the way arjun does. The page is asked twice with one random name: that answer is the reference, and the difference between the two is the page's own noise (a page that changes too much by itself is skipped). It is then asked once with 250 random names. Names go out 250 per request, each with a random value. A request whose answer differs from the reference by status, by size beyond the noise, or by carrying one of the values back marks its group, which is halved until single names remain; a name found by size or status is confirmed with one more request, a reflected value names its parameter directly. A page that answers the 250 random names otherwise than one (an error page that prints the query string back, a server that refuses a long query) is judged against controls instead: a group whose answer differs from the reference is asked again with random names of the same lengths and random values, and only what that control does not show counts. A value counts as reflected when it comes back more often than the control's values do, a size is compared with the values taken out of both answers, and a group whose control gets another status too (414 for a long query) is split without being searched, and so are the groups that come after it. A page where most names of a group, or nearly every name tried alone, still change the answer reports no names and a note instead (`… answers names it does not read (16 of 16 names tried changed the answer): not searched for parameters`). GET only: guessing names on a POST could submit something. At most 20 pages per host, 20 requests per second per host.

## Networks

`-asn` seeds an autonomous system: `azhaq-asn` lists the prefixes it announces (RIPEstat, no key) and the holder's name. `-cidr` seeds a range directly. `azhaq-prefix` expands IPv4 prefixes into addresses, at most `-max-ips` (4,096) for the whole run, and says so when a range is cut short. Each address gets a reverse DNS lookup (`azhaq-ptr`), an HTTP probe and a TLS handshake without SNI; names in reverse DNS and on certificates become hostnames to resolve and probe. Reverse names a provider derives from the address (`ec2-192-0-2-7…`, `7.2.0.192.static…`) and shared platforms are recorded but not followed, and names found this way are not enumerated as domains: on shared hosting they may belong to neighbours. Ask for a domain with `-domain`.

## Rendering pages

Static extraction reads what scripts contain; `-browser` also runs them. `azhaq-render` loads pages (not scripts, assets or API routes) in the run's Chrome, up to 30 per host, and records every same-origin request the page sends while it loads, which for a single-page app are its API calls with their real paths and query strings, and the links and forms of the document once rendered. Those become URLs for the other collectors. It shares the browser, tab limit and session headers with screenshots.

Without `-browser`, the crawler reads what a page leaves for its scripts to render where it can: links written in Markdown in the page's text (`[User Search](/app/usersearch)`, which a converter such as showdown turns into links in the browser) are followed like links. It also notes `{{templates}}` in the text and an empty shell (a mount point such as `<div id="root">` or `<app-root>`, scripts, and next to no text). The run's summary suggests `-browser` when a page of the target carries Markdown links, three or more template expressions, or is an empty shell while the map of its origin has fewer than 10 routes; a server-built site, or a single-page app whose scripts gave up their routes, gets no suggestion.

## Screenshots

`-screenshots DIR` starts one headless Chrome found on the machine (`AZHAQ_CHROME`, or `google-chrome`, `chromium` on the path) and drives it over the DevTools protocol (chromedp). Each web service's front page opens in its own tab, four at a time (`-tabs`), with the run's `-cookie` and `-header` values. The load event gets 15 seconds; a page that never finishes loading is captured as far as it got, 1.5 seconds after navigation, within 30 seconds. The PNG goes to `DIR/scheme_host_port.png`, and a 64-bit difference hash goes with it: the HTML export groups pages whose hashes are at most 8 bits apart, so thirty copies of one login portal are one row. A name and its URL are one page and are taken once.

## Ports

`-ports` (active, needs `-allow`) scans hosts in scope with full TCP connects, so it needs no root and leaves complete handshakes in the target's logs, like `naabu -scan-type c`. Lists are nmap's top 100 or top 1000 TCP ports (as naabu ships them), `full`, or ranges. Connection attempts share one rate across all hosts (`-port-rate`, default 300 per second), 100 at a time, 1.5 seconds each. A name resolves to at most two IPv4 addresses, and each address is scanned once however many names point to it. An address in a CDN or WAF range gets ports 80, 443, 8080 and 8443 only: the edge answers for thousands of customers.

An open port is read for 1.5 seconds: the first line a service sends (`SSH-2.0-…`, `220 … ESMTP`) names it; binary greetings are marked as such. Ports that stay silent or answer like HTTP become URLs for `azhaq-http`, HTTPS first.

## Historical URLs

`azhaq-urls` asks every archive at once for the URLs of a domain and its subdomains, and records each one's count, pages, time and error:

- the Wayback Machine's CDX API, page by page (`showNumPages`, then each page), one request per second;
- Common Crawl's newest index, paged the same way;
- AlienVault OTX's URL list, 500 per page;
- urlscan.io's search, 100 per page (a key from the provider file raises the limits);
- arquivo.pt, one request; it often serves what the Wayback Machine refuses.

A 429 or 503 is retried after 2, 5 and 10 seconds, or the server's `Retry-After` up to 20 seconds; after that the source stops, keeps the pages it read and is reported as rate limited. Each source has 3 minutes and 50 pages. Any failed source marks the result `degraded`, so a refused archive never reads as "no URLs".

URLs are normalized, kept when they belong to the domain, and deduplicated. `-urls FILE` receives all of them. The graph receives the summary and one URL per template (`/product?id={v}` stands for every product page), parameters, API routes and server-side pages first, at most 200 per domain; the first 40 are fetched when the run is not passive. Static assets are counted and left out of the graph.

## Storage

The graph lives in SQLite through `modernc.org/sqlite`, a pure-Go driver, so the binary builds without CGO. Each run gets its own file unless `-db` or `AZHAQ_DB` names one. Every run has its own ID, and the store records which entities and edges each run saw. `azhaq diff` compares two runs from that record.

A database can hold many runs: `-db FILE` on every run of a target makes it a workspace. Work is deduplicated within a run, not across runs, so each run collects afresh; reads during a run see only that run's entities, observations and edges, while `export` sees all of them with their first and last sighting. After a run into a workspace, and with `azhaq diff -db FILE`, the last two runs are compared.

Diffs compare facts, not bytes: body hashes and sizes, response times, the address that answered, the session a run was given, each subdomain source's timing, and response header values (rate-limit counters, request IDs) are left out, while header names, statuses, titles and everything else count. Each database records the seeds it was run with. After a run, the CLI diffs against the previous run of the same seeds in the current directory (tracked in `.azhaq-index`), and `azhaq diff` on two runs with different seeds says so before the result.

## The map

`azhaq run` prints the graph as a ranked map: the seed host, live application pages, auth-gated URLs, APIs, other pages, then hints and fan-out. Each URL row has a coverage and a role.

| Coverage | Meaning |
| --- | --- |
| `visited` | fetched, and the response is the URL's own |
| `catchall` | fetched, but the answer is the one any path gets |
| `error` | requested, no answer (timeout, refused, reset) |
| `gone` | requested, answered 404 or 410: found in an archive or a link, not there now |
| `hint` | found (in a link, script, archive or API description) but not fetched; also a route scripts call only with POST or PUT whose GET answers like an unknown path, and a route only scripts name, with no GET call among them, whose GET answers 404 |
| `skipped` | found (in a link, script, archive or API description), and deliberately not requested: its name says a GET would change something (`word` names the verb) |
| `capped` | left over when the run hit its item or depth limit |

Roles: `app` (the site root), `auth` (401), `forbidden` (403), `api`, `page`, `script`, `asset`. Routes list their methods, and below the row, each operation with its query names and body fields, from API descriptions and from the calls scripts make. A GraphQL endpoint read with `-graphql` keeps the whole introspection result (types, fields, arguments, input objects, enums, directives); its row lists each query, mutation and subscription with its signature (`query pastes(public: Boolean, limit: Int): [PasteObject]`), and `azhaq export -format graphql` or `-format sdl` writes the schema. A run that found an endpoint and did not introspect it (no `-graphql`, or its host outside the scope) suggests the run that would: `next: azhaq run -url ORIGIN/ -graphql -allow HOST …`. Hostnames are `live` (a seed host), `sibling`, `unresolved` (from a source or a list, not looked up), `dead` (no address) or `wildcard`; dead, wildcard and unresolved names are folded into one summary line each.

### What is requested

A found URL is requested with GET when it is on the run's hosts and in scope, has no unfilled parameter, and its path (or an `action=` value) does not start with a verb that does something: logout, delete, remove, reset, create, save, update, change, send, run, import, … (`webextract.StateChanging`). Those are kept as `skipped`, with the word, and listed under `left alone` in the summary, whatever found them: a link, a script's call, an API description; `-all-gets` requests them too. API description operations are asked when they are GETs that need no path or query parameter; the same verbs keep them out (VAmPI's `GET /createdb` resets its database). With a session (`-cookie`, an `Authorization` header, a header that carries a token), path and parameter guesses that read that way are not sent either, and are listed as `skipped`. Junk that is not a URL never enters the graph: path segments such as `NaN` or `undefined` from a script that ran without its data, links cut short in archives, dot segments a browser would have resolved (`http://site/..`), and URLs that carry a scanner's payload (path traversal, `/etc/passwd`, command or template injection, SQL, `<script>`, out-of-band callback domains such as `oast.live`), decoded twice since archives keep them encoded (`webextract.Payload`). Nothing can replay what is not stored.

A run keeps the answers it gets (`responses` in the workspace, bodies gzipped) and the guesses `dirs` made, and the owner of each piece of once-per-run work (the built-in path sweep of an origin, `catalog.Claim`). `azhaq resume` reads them back: what the stopped run asked is not asked again or counted, and the same task does the same sweep. They are dropped once the run has nothing left to resume.

Requests to targets carry a current browser's User-Agent (CDN bot managers hold other requests open without an answer) and connect to the addresses the run's own resolver found for the name, IPv6 first where the machine has a route for it and IPv4 alongside after 300 ms, so `host_ip` is always one of the name's addresses. Third-party sources get `azhaq/VERSION` as User-Agent.

Rows that share a URL template are folded into one line with a count. Forms appear indented under the first row that has them, with their method, action (a form whose action is empty or `#` submits to its own page), `multipart` for a multipart POST, and field names, followed by the query names of the URL itself; the query names of a page's links are on the links' rows. `azhaq export` keeps every entity unfolded and adds `template`, `methods`, `params` and `forms` fields.

## Connectors

Data Azhaq should not collect itself, such as paid internet indexes, comes in through connectors. A connector is a separate program that reads seeds on stdin and writes JSONL facts on stdout. It runs out of process, so its SDK, API keys and terms of service never become part of Azhaq. See [CONNECTOR.md](CONNECTOR.md).

## Design choices

- **In-process collectors, no wrapped tools.** Collectors speak their protocols directly or use permissively licensed Go libraries in-process (subfinder's source packages for subdomain sources, miekg/dns for DNS, wappalyzergo's matcher and cdncheck for fingerprints). Azhaq never shells out to subfinder, dnsx or similar tools, so every fact lands in one graph with its source. CI fails on GPL, AGPL, SSPL or unknown licenses.
- **Go.** Recon is I/O-bound. Go gives one static binary, cheap concurrency and a small memory footprint, and it embeds easily as a library in a worker process.
- **A browser only when asked.** JavaScript routes are extracted from script text, which covers bundled single-page apps. `-browser`, `-screenshots` and `-login` drive a Chrome already installed on the machine; Azhaq downloads none.
- **Map only.** Azhaq records what exists. It sends no payloads and does not test for vulnerabilities. Every request to a target is a GET, except Chrome submitting a login form when given an account and GraphQL introspection (a POST) with `-graphql`. Operations read from an API description or a script call are mapped with their method and fields; only the parameterless GETs among them are asked.
- **Every outcome said.** Each command ends with a summary: what failed and whether it is worth retrying, targets that never answered, what was left alone and why, the limit that stopped the work. The exit code says the same (0 complete, 3 finished with failures, 4 stopped by a limit), so a script or an assistant never has to guess whether an empty result is an honest zero.

## Limitations

- Requests to a target are limited by concurrency per host (4 by default) and an optional delay; path guessing, parameter discovery and port scans also have a rate. Third-party sources and DNS resolvers have rate limits.
- Organization seeds rarely expand, because public RDAP has no search by organization name.
- Routes built at run time from anything but constants, template literals and variables assigned once (user input, server responses, functions of several variables) are seen only with `-browser`, and only those a page requests while it loads: Azhaq does not click.
- Routes only the server knows (admin APIs no page mentions) are found only by the path sweep or an API description.
- One SQLite file holds a run, written by the run's own process; workers send their results to it rather than writing a shared store.

## Layout

```
bench/                    comparison with reference tools (go run ./bench)
catalog/                  collector registry and interfaces (public)
cmd/azhaq/                CLI
cmd/azhaq-index-fixture/  example connector used by tests
collectors/               registers the built-in collectors (public)
engine/                   Plan, Run, Ingest, scheduler, identity, map view (public)
scope/                    -allow / -deny rules (public)
store/                    SQLite graph, runs and diff (public)
types/                    seeds, observations, entities (public)
internal/
  collectors/             one package per collector
  connector/              JSONL protocol for external collectors
  dnsr/                   resolver pool and wildcard detection
  fetch/                  shared HTTP client
  fingerprint/            technologies, CDN ranges, favicon hash
  limit/                  rate limits per host, source or resolver
  normalize/              seed and hostname normalization
  webextract/             HTML and JavaScript URL extraction
fixtures/                 inputs for tests and the demo
```
