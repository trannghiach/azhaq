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

All collectors register in one in-process catalog (`internal/catalog`, filled by `collectors.RegisterAll`). Planning is a lookup, `catalog.Where(seed.Type)`, so the engine and CLI never name a collector. Adding a capability means writing a collector and registering it.

A collector may also implement:

- `catalog.Informer` (`Info()`), which says what it contacts. `Passive` collectors only ask third parties and DNS resolvers; `Touch` collectors (the default) send requests to the target; `Active` collectors send guesses (brute force, permutations) and name the flag that enables them. `After` names a collector that must finish with the same seed first: HTTP and TLS wait for `azhaq-dns`, and when DNS returns `RunMeta.Drop` (no address, or a wildcard answer) they skip the name.
- `catalog.Batcher` (`BatchSize`, `RunBatch`), for work that is much cheaper in bulk. DNS resolves up to 256 names per call; each name still gets its own entity, idempotency key and hints.
- `catalog.Skipper` (`Skip(seed) bool`), to decline a seed when it would return at once: a script it has already parsed, an origin whose paths it has already swept, a URL that cannot be an API description. Skipped seeds do not spend the item budget.

A collector can also hand over seeds before it returns with `catalog.Hint(ctx, seeds...)`. The subdomain collector does this as each source answers, so DNS starts on the fast sources' names while a slow source is still running.

## Engine

`internal/engine` exposes four operations:

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
- At most 2 requests are in flight per host. Concurrent requests for the same URL share one fetch.
- Bodies are capped at 2 MiB, or 16 MiB for JavaScript, JSON and source maps, where bundles of several MB are normal. `-delay` adds a pause before each uncached request.
- `-cookie` and `-header` are added to every request, which lets a run reuse a session you already have. Azhaq never logs in, and it stores cookie names but never their values.

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

## Storage

The graph lives in SQLite through `modernc.org/sqlite`, a pure-Go driver, so the binary builds without CGO. Each run gets its own file unless `-db` or `AZHAQ_DB` names one. Every run has its own ID, and the store records which entities and edges each run saw. `azhaq diff` compares two runs from that record.

Diffs compare facts, not bytes: body hashes, the session a run was given, and response header values (rate-limit counters, request IDs) are left out, while header names, statuses, titles and everything else count. Each database records the seeds it was run with. After a run, the CLI diffs against the previous run of the same seeds in the current directory (tracked in `.azhaq-index`), and `azhaq diff` on two runs with different seeds says so before the result.

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

- **In-process collectors, no wrapped tools.** Collectors speak their protocols directly or use permissively licensed Go libraries in-process (subfinder's source packages for subdomain sources, miekg/dns for DNS). Azhaq never shells out to subfinder, dnsx or similar tools, so every fact lands in one graph with its source. CI fails on GPL, AGPL, SSPL or unknown licenses.
- **Go.** Recon is I/O-bound. Go gives one static binary, cheap concurrency and a small memory footprint, and it embeds easily as a library in a worker process.
- **No browser.** JavaScript routes are extracted from script text. That covers bundled single-page apps without shipping Chromium.
- **Map only.** Azhaq records what exists. It sends no payloads and does not test for vulnerabilities. Operations read from an API description are mapped and never called, since a GET in a spec can still change state.

## Limitations

- No collector for IP ranges or service scanning yet.
- Requests to a target are limited by concurrency per host (2) and an optional delay, not by a rate. Third-party sources and DNS resolvers have rate limits.
- Organization seeds rarely expand, because public RDAP has no search by organization name.
- JavaScript that builds routes at runtime is not visible without a browser. Chunk names computed at runtime (webpack chunk maps) are not followed; chunks imported by name are.
- API descriptions embedded in a Swagger UI script rather than served as a document are not read.
- One SQLite file per run suits a CLI. Many concurrent writers would need another store.

## Layout

```
bench/                    comparison with reference tools (go run ./bench)
cmd/azhaq/                CLI
cmd/azhaq-index-fixture/  example connector used by tests
internal/
  catalog/                collector registry
  collectors/             one package per collector
  connector/              JSONL protocol for external collectors
  dnsr/                   resolver pool and wildcard detection
  engine/                 Plan, Run, Ingest, scheduler, identity, map view
  fetch/                  shared HTTP client
  limit/                  rate limits per host, source or resolver
  normalize/              seed and hostname normalization
  scope/                  -allow / -deny rules
  store/                  SQLite graph and run diff
  webextract/             HTML and JavaScript URL extraction
fixtures/                 inputs for tests and the demo
```
