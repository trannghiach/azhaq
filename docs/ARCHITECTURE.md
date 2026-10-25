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

**Observations** are facts attached to an entity: collector, source, kind (`url`, `dns`, `ct`, `form`, `param`, …), a JSON payload, confidence and timestamp. They are append-only. A later observation does not replace an earlier one.

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

Items on the seed's own host or IP run before fan-out items, but part of the item budget is reserved for fan-out: one eighth, at least 24 items once the budget is 48 or more, and never more than half. Without it, a large application would spend the entire budget before any domain-level collector ran.

The run's policy is applied when items are planned: `-passive` keeps only `Passive` collectors; an `Active` collector needs its flag, an `-allow` scope and a seed inside it; `-skip` removes collectors by name.

A seen-set prevents running the same seed twice, and `-allow` / `-deny` filter hints before they are queued. URLs that differ only by an ID or a query value share a template (`/catalog/product?productId={n}`); at most 3 URLs per template are fetched, and the rest stay in the graph as found. Work left over when a limit is reached is stored and the run is marked `capped`.

## HTTP

All HTTP collectors share one client (`internal/fetch`):

- Redirects are not followed automatically. Each hop is recorded, and the status stored is that of the URL that was requested, so `/admin → 303 → /login` records `/admin` as 303.
- At most 4 requests are in flight per host (`-host-parallel`). Concurrent requests for the same URL share one fetch.
- Bodies are capped at 2 MiB, or 16 MiB for JavaScript, JSON and source maps, where bundles of several MB are normal. `-delay` adds a pause before each uncached request.
- `-cookie` and `-header` are added to every request, which lets a run reuse a session you already have. Azhaq never logs in, and it stores cookie names but never their values.
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

- URL and path strings;
- paths joined from constants where the request is made, such as `og+sg.LOGIN` with `og="identity/"` and `sg={LOGIN:"api/auth/login",…}`. A name counts only if the script binds it once, so a short minified name reused across modules is not guessed at. Placeholders such as `<videoId>` become `{videoId}`;
- GraphQL operation names, from query documents or the parsed form bundlers emit.

Well-known library builds served from the app's own origin (`react-dom.development.js`, `jquery-3.6.0.min.js`, `swagger-ui-bundle.js`) are not fetched: they are large and hold no routes of the app, only stray strings.

A script that names a same-origin source map has the map read: the map is recorded with the app's own source files (libraries left out), and those sources are scanned like scripts. An exposed source map is worth knowing about on its own.

`azhaq-openapi` also reads a description written into a script, as Swagger UI's `swagger-ui-init.js` carries it.

### Sessions and roles

`-cookie` and `-header` apply to every request of a run. While one is set, URLs that look like a logout are not requested. `azhaq roles` runs the same seeds once per role, in turn, each with its own database, and compares the first status each URL answered with: endpoints whose status differs between roles are printed, and URLs a role never reached show `-`.

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
| `hint` | found (in a link, script, archive or API description) but not fetched |
| `capped` | left over when the run hit its item or depth limit |

Roles: `app` (the site root), `auth` (401), `forbidden` (403), `api`, `page`, `script`, `asset`. API description rows also list their methods. Hostnames are `live` (a seed host), `sibling`, `dead` (no address) or `wildcard`; dead and wildcard names are folded into one summary line each.

Rows that share a URL template are folded into one line with a count. Forms appear indented under the first row that has them, with their method, action and field names, followed by the page's other parameter names. `azhaq export` keeps every entity unfolded and adds `template`, `methods`, `params` and `forms` fields.

## Connectors

Data Azhaq should not collect itself, such as paid internet indexes, comes in through connectors. A connector is a separate program that reads seeds on stdin and writes JSONL facts on stdout. It runs out of process, so its SDK, API keys and terms of service never become part of Azhaq. See [CONNECTOR.md](CONNECTOR.md).

## Design choices

- **In-process collectors, no wrapped tools.** Collectors speak their protocols directly or use permissively licensed Go libraries in-process (subfinder's source packages for subdomain sources, miekg/dns for DNS, wappalyzergo's matcher and cdncheck for fingerprints). Azhaq never shells out to subfinder, dnsx or similar tools, so every fact lands in one graph with its source. CI fails on GPL, AGPL, SSPL or unknown licenses.
- **Go.** Recon is I/O-bound. Go gives one static binary, cheap concurrency and a small memory footprint, and it embeds easily as a library in a worker process.
- **No browser.** JavaScript routes are extracted from script text. That covers bundled single-page apps without shipping Chromium.
- **Map only.** Azhaq records what exists. It sends no payloads and does not test for vulnerabilities. Operations read from an API description are mapped and never called, since a GET in a spec can still change state. GraphQL introspection, a POST, runs only with `-graphql`.

## Limitations

- No collector for IP ranges or service scanning yet.
- Requests to a target are limited by concurrency per host (2) and an optional delay, not by a rate. Third-party sources and DNS resolvers have rate limits.
- Organization seeds rarely expand, because public RDAP has no search by organization name.
- Routes built at run time from anything but constants (user input, server responses, functions of several variables) are not visible without a browser.
- Routes only the server knows (admin APIs no page mentions) are found only by the path sweep or an API description.
- One SQLite file per run suits a CLI. Many concurrent writers would need another store.

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
