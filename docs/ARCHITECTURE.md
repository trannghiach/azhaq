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

A collector may also implement `catalog.Skipper` (`Skip(seed) bool`) to decline a seed at plan time when it would return at once: a script it has already parsed, an origin whose paths it has already swept, a URL that cannot be an API description. Skipped seeds do not spend the item budget.

## Engine

`internal/engine` exposes four operations:

- **Plan** turns seeds into work items, one per matching collector.
- **Run** executes one work item. It upserts the seed entity, passes an `emit` function that writes each observation and its edges to the store, then returns the collector's hints plus derived seeds (URL → hostname → eTLD+1). Each item has an idempotency key, a hash of collector, seed type and seed key. An item already in the store is skipped, so retries are free.
- **Ingest** writes facts produced outside Azhaq (connector JSONL) straight into the graph.
- **RunLocal** is the built-in scheduler the CLI uses. A workflow engine can call `Plan` and `Run` directly and do its own scheduling instead.

`emit` writes synchronously, so a fast collector cannot outrun the store and memory stays flat.

### Scheduling (`RunLocal`)

The scheduler runs in waves, one per depth level, with up to 8 work items in parallel. It is bounded by `-depth` (default 4) and `-max-items` (default 512).

It runs in two passes:

1. **Seed origin.** Items on the seed's own host or IP run first. Hints pointing elsewhere are held back.
2. **Fan-out.** Held hints and the seed's domain (CT, CDX, RDAP, sibling DNS) run next.

Part of the item budget is reserved for the fan-out pass: one eighth, at least 24 items once the budget is 48 or more, and never more than half. Without it, a large application would spend the entire budget before any domain-level collector ran.

A seen-set prevents running the same seed twice, and `-allow` / `-deny` filter hints before they are queued. URLs that differ only by an ID or a query value share a template (`/catalog/product?productId={n}`); at most 3 URLs per template are fetched, and the rest stay in the graph as found. `-passive` drops every collector that contacts the target (`http`, `crawl`, `js`, `openapi`, `paths`, `tls`). Hints left unprocessed when the budget runs out are stored and the run is marked `capped`.

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

Roles: `app` (the site root), `auth` (401), `forbidden` (403), `api`, `page`, `script`, `asset`. API description rows also list their methods.

Rows that share a URL template are folded into one line with a count. Forms appear indented under the first row that has them, with their method, action and field names, followed by the page's other parameter names. `azhaq export` keeps every entity unfolded and adds `template`, `methods`, `params` and `forms` fields.

## Connectors

Data Azhaq should not collect itself, such as paid internet indexes, comes in through connectors. A connector is a separate program that reads seeds on stdin and writes JSONL facts on stdout. It runs out of process, so its SDK, API keys and terms of service never become part of Azhaq. See [CONNECTOR.md](CONNECTOR.md).

## Design choices

- **Native collectors, no wrapped tools.** Every collector implements its protocol or public API directly (HTTP, DNS, CT logs, Wayback CDX, RDAP). Azhaq does not shell out to subfinder, httpx or similar tools. That keeps one graph model and a dependency tree that is only MIT/BSD/Apache-licensed; CI fails on any other license.
- **Go.** Recon is I/O-bound. Go gives one static binary, cheap concurrency and a small memory footprint, and it embeds easily as a library in a worker process.
- **No browser.** JavaScript routes are extracted from script text. That covers bundled single-page apps without shipping Chromium.
- **Map only.** Azhaq records what exists. It sends no payloads and does not test for vulnerabilities. Operations read from an API description are mapped and never called, since a GET in a spec can still change state.

## Limitations

- No collector for IP ranges or service scanning yet.
- Politeness is per-host concurrency plus an optional delay. There is no per-source rate limiter.
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
  engine/                 Plan, Run, Ingest, scheduler, identity, map view
  fetch/                  shared HTTP client
  normalize/              seed and hostname normalization
  scope/                  -allow / -deny rules
  store/                  SQLite graph and run diff
  webextract/             HTML and JavaScript URL extraction
fixtures/                 inputs for tests and the demo
```
