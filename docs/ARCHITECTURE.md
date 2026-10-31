# Architecture

This page is for contributors. It explains how Azhaq works inside, one component at a time. For what a command prints, see [Output](OUTPUT.md) and the [command pages](commands/).

Azhaq takes seeds, runs every collector that accepts each seed's type, and stores what they report in a SQLite graph. Facts a collector reports can become new seeds. So a run expands outward until it hits its depth or item limit.

```
seeds ──► Plan ──► Run ──► observations ──► graph (SQLite)
            ▲                    │
            └──── next seeds ◄───┘
```

## Data model

Four kinds of record make up the graph: seeds, entities, observations and edges.

**Seeds** have a type and a set of keys. Collectors exist today for these seed types:

- `URL`
- `Hostname`
- `Domain`
- `IPAddress`: ports, TLS, reverse DNS and the network
- `Prefix` and `ASN`: announced prefixes, and the reverse DNS of a range
- `Organization`
- `CloudAccount`

`Certificate`, `Email` and `Application` are defined but unused.

**Entities** are graph nodes, unique on `(type, key)`. Keys are normalized before lookup: hostnames are lower-cased and URLs cleaned. So the same hostname found by CT, DNS, a crawl and a certificate SAN is one entity.

**Observations** are facts attached to an entity. Each has these parts:

- the collector and the source;
- the kind (`url`, `dns`, `ct`, `form`, `params`, …);
- a JSON payload;
- a confidence and a timestamp.

Observations are append-only. A later observation does not replace an earlier one.

**Edges** are derived from observations and seeds:

| Edge | Meaning |
| --- | --- |
| `FOUND` | a URL was found on another URL |
| `ON_HOST` | a URL belongs to a hostname or IP |
| `IN_DOMAIN` | a hostname belongs to a registrable domain (eTLD+1) |
| `RESOLVES_TO` | a hostname resolves to an IP |
| `CNAME` | a hostname is an alias of another |

### Identity rules

These rules keep the graph honest:

- Hostnames on shared platforms (`appspot.com`, `herokuapp.com`, `web.app`, …) stop at the tenant, so two tenants are two sites.
- Hosts that share an IP are not merged.
- TLS SANs are only followed within the seed's eTLD+1. This ignores CDN and proxy default certificates.

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

`Run` only reports. It calls `emit` for each fact and returns follow-up seeds in `RunMeta.NextHints`. It never writes the graph or schedules work.

All collectors register in one in-process catalog (`catalog`, filled by `collectors.RegisterAll`). Planning is a lookup, `catalog.Where(seed.Type)`, so the engine and CLI never name a collector. Adding a capability means writing a collector and registering it.

### Optional interfaces

A collector may also implement these:

- `catalog.Informer` (`Info()`) says what the collector contacts:
  - `Passive` collectors only ask third parties and DNS resolvers.
  - `Touch` collectors send requests to the target. This is the default.
  - `Active` collectors send guesses, such as brute force and permutations, and name the flag that enables them.
  - `After` names a collector that must finish with the same seed first. HTTP and TLS wait for `azhaq-dns`. When DNS returns `RunMeta.Drop` (no address, or a wildcard answer), they skip the name.
- `catalog.Batcher` (`BatchSize`, `RunBatch`) is for work that is much cheaper in bulk. DNS resolves up to 256 names per call, and each name still gets its own entity, idempotency key and hints.
- `catalog.Skipper` (`Skip(seed) bool`) declines a seed that would return at once. Examples are a script it has already parsed, an origin whose paths it has already swept, and a URL that cannot be an API description. Skipped seeds do not spend the item budget.

### Handing over seeds early

A collector can hand over seeds before it returns, with `catalog.Hint(ctx, seeds...)`. The subdomain collector does this as each source answers. So DNS starts on the fast sources' names while a slow source is still running.

Sources Azhaq does not query itself can be plugged in as external programs: see [CONNECTOR.md](CONNECTOR.md).

## Collectors at a glance

| Collector | Collects |
| --- | --- |
| `azhaq-http` | the answer of each web service: status, redirect chain, title, technologies, favicon hash, sizes, time, headers |
| `azhaq-crawl` | same-origin links, forms and the pages scripts open |
| `azhaq-js` | the requests, routes, router views, WebSocket endpoints and credentials that scripts hold |
| `azhaq-openapi` | OpenAPI 3 and Swagger 2 documents, with each operation's parameters |
| `azhaq-graphql` | GraphQL endpoints; with `-graphql`, the schema by introspection |
| `azhaq-paths` | the built-in paths: `robots.txt`, sitemaps, API description locations, … |
| `azhaq-dns` | A, AAAA and CNAME chains, the CDN or WAF in front, MX, TXT and NS; marks dead and wildcard names |
| `azhaq-tls` | certificates and their names |
| `azhaq-subdomains` | names from passive sources and from the name history of earlier runs |
| `azhaq-urls` | historical URLs from the Wayback Machine, Common Crawl, OTX, urlscan and Arquivo, junk left out |
| `azhaq-dns-brute`, `azhaq-permute`, `azhaq-dirs`, `azhaq-params`, `azhaq-ports` | the active techniques |
| `azhaq-asn`, `azhaq-prefix`, `azhaq-ptr` | networks, their addresses and reverse DNS names |
| `azhaq-render`, `azhaq-shots` | Chrome: rendered pages and their requests; screenshots |
| `azhaq-search` | Shodan, FOFA and Netlas, with keys |
| `azhaq-rdap` | registration data and nameservers |
| `azhaq-cloud` | domains, hosts and URLs from a local cloud inventory |

### Details by collector

**`azhaq-http`**

- Collects status, redirect chain, title, technologies, favicon hash, length, words, lines, time and the address connected to.
- Also collects headers, cookie names and JSON field names.
- Flags catch-all answers. See [Catch-all responses](#catch-all-responses).

**`azhaq-crawl`**

- Reads same-origin links. A directory listing's sort links are not read.
- Reads the pages a tag's scripts open. These are the URL-like strings of a `javascript:` link and of an inline `on*` handler, such as `popUp('view_source.php?id=…')`.
- Reads the URL-like strings of a `data-*-url`, `data-href` or `data-src` attribute.
- Reads forms, including script-driven ones, with their encoding and file inputs.
- Reads links inside JSON answers.
- Reads links written in Markdown that the page renders in the browser.

**`azhaq-js`**

- Reads the requests scripts make: method, path, query names and body fields. They are worked out from literals, template literals and assigned variables, and through a helper that takes the URL.
- Keeps the script, line and code each request was found in.
- Reads other routes and links in scripts, chunks, build manifests and source maps. A source map can be named, given in a header, or guessed.
- Reads joined constants, the views of the app's router with their guards, WebSocket endpoints, GraphQL operation names and credentials.
- Includes scripts on other hosts of the scope. Without a scope, it includes those of the page's registrable domain.
- The details are under [Scripts](#scripts).

**`azhaq-openapi`**

- Reads OpenAPI 3 and Swagger 2 documents in JSON, in YAML, or embedded in Swagger UI.
- Collects each operation's parameters by location, its body fields and its security.
- Reads a Swagger UI page's document even when the page builds its URL at run time.
- Asks the parameterless GETs.

**`azhaq-paths`**

- Asks the built-in paths: `robots.txt`, sitemaps, API description locations and more.
- API description locations are asked one at a time, and no longer once an origin has served a description. See [Path checks](#path-checks).

**`azhaq-dns`**

- Marks dead and wildcard names and never probes them.
- See [Dead and wildcard names](#dead-and-wildcard-names) for how a name is judged.

**`azhaq-subdomains`**

- Takes names from passive sources: certificate transparency, archives and DNS datasets. More come with API keys. `azhaq plan` shows the sources a run would ask.
- Also takes names from the name history of earlier runs.
- Keeps the sources of each name, each source's count or error, and how complete the result is. See [Subdomain sources](#subdomain-sources).

## Run options

`azhaq run` and the commands built on it share one set of options. Each option, with its default, is in the [`run` flags table](commands/run.md#flags). A source's key may also come from `$SOURCE_API_KEY` or `$VAR` in the provider file, as in subfinder: see [`subs`](commands/subs.md).

This list says which part of Azhaq each group of options drives:

- **Chrome:** `-browser`, `-interact`, `-interact-clicks`, `-browser-writes`, `-tabs`. See [Rendering pages](#rendering-pages) and [Chrome and the scope](#chrome-and-the-scope).
- **Session:** `-login`, `-login-user`, `-login-pass`, `-cookie`, `-header`. See [Sessions and roles](#sessions-and-roles).
- **Screenshots:** `-screenshots`. See [Screenshots](#screenshots).
- **Seeds:** `-list`, `-asn`, `-cidr`. See [Networks](#networks).
- **Probing only:** `-probe`, `-web-ports`, `-no-follow`. See [Probing](#probing).
- **Passive:** `-passive`. See [Planning and scope](#planning-and-scope).
- **Subdomain sources:** `-sources`, `-exclude-sources`, `-all-sources`, `-providers`, `-source-rate`, `-source-rates`, `-max-results`, `-max-time`, `-max-body`, `-source-proxy`, `-no-history`. See [Subdomain sources](#subdomain-sources).
- **DNS:** `-resolvers`, `-dns-rate`. See [DNS](#dns).
- **Paths you rule out:** `-deny-path REGEX` (repeatable). See [Paths you rule out](#paths-you-rule-out).
- **Active techniques:** `-dns-brute`, `-permute`, `-dirs`, `-params`, `-ports`, `-ports-udp`, `-graphql`. Each is held to the targets given, or to the scope `-allow` or `-scope` names.
- **Ledger and kill switch:** `-ledger`, `-kill-file`. See [The request ledger and the kill switch](#the-request-ledger-and-the-kill-switch).
- **Scheduling:** `-depth`, `-max-items`, `-parallel`, `-host-parallel`, `-delay`, `-v`. See [Scheduling](#scheduling-runlocal).

### Packages and workers

A run started with `-serve ADDR` lends its tasks to `azhaq worker -server URL` processes on other machines. They send back what they found. Each worker keeps its own HTTP cache, so requests the workers share are repeated. See [Workers](#workers--serve-azhaq-worker).

The catalog, engine, store and types are public Go packages. Use them to run Azhaq in-process and to add collectors. The API may change before 1.0.

## Engine

`engine` exposes four operations:

- **Plan** turns seeds into work items, one per matching collector.
- **Run** executes one work item. It upserts the seed entity and passes an `emit` function that writes each observation and its edges to the store. It then returns the collector's hints plus derived seeds (URL → hostname → eTLD+1).
- **Ingest** writes facts produced outside Azhaq (connector JSONL) straight into the graph.
- **RunLocal** is the built-in scheduler the CLI uses. A workflow engine can call `Plan` and `Run` directly and do its own scheduling instead.

Each work item has an idempotency key, a hash of the collector, the seed type and the seed key. An item already in the store is skipped, so retries are free.

`emit` writes synchronously. So a fast collector cannot outrun the store, and memory stays flat.

### Scheduling (`RunLocal`)

Work flows instead of moving in waves. A seed's work items are queued as soon as the seed appears. A free worker takes the next one, and the hints it returns are queued at once. A slow item, such as a CT log taking 25 seconds, holds back nothing else.

Up to `-parallel` items (default 16) run at a time. Each batch collector may run 4 batches at once on top.

Limits:

- `-depth` (default 4) bounds how many hints away from the seeds a seed may be.
- `-max-items` (default 2048) caps ordinary work items.
- `-max-names` (default 20,000) caps the names handed to batch collectors (DNS). A domain with thousands of subdomains then does not spend the item budget on resolution.
- `-max-requests` caps the requests sent to targets, and `-rate` paces them over all hosts. See [The request budget](#the-request-budget).
- `-daily-requests` gives a program a number of requests per UTC day. The program is `-program`, else the run's targets. Requests are counted over the runs in the database (table `spend`), and a run starts with what is left.

### The request budget

Every request to a target asks `fetch.Spend` first. This covers:

- GETs and each redirect hop;
- path and parameter guesses;
- the GraphQL query;
- a page loaded in Chrome.

Every other request Chrome sends is counted as it leaves (`fetch.Take`). That means a page's scripts, images and calls, a redirect, a login and a WebSocket's handshake. These are paced by `-rate` like the run's own requests, and refused once the budget is spent. A page or a screenshot that lost requests to the budget ends `capped`. `azhaq resume` loads it again.

A request the budget refuses fails with `neterr.ErrBudget`. The engine marks every task's context, so a refusal counts even when a collector takes the failed request for a missing page. Such a task:

- ends `capped`;
- is not marked done;
- drops nothing that waits on it.

The run is marked `capped` too.

Under a budget, a task's reports are held until it ends, and those of a task the budget stopped are dropped. Otherwise a refused catch-all check would turn an application's index page into findings.

### Origins that stop answering

An origin is a scheme, a host and a port. It is stopped for the rest of the run when 5 requests in a row get no answer. A request counts when it connects refused, connects without a route, or times out, with no answer between them.

- Its remaining requests are refused with `neterr.ErrOriginDown`, instead of each taking a timeout.
- The tasks that asked end `capped`. They are left for `azhaq resume`, which tries the origin again.
- The summary lists them under `skipped` with `ORIGIN stopped answering after 5 timeouts`, and names the origin in `stopped`.
- Any answer starts the count over. A request the run itself cancelled does not count.
- Only the 5 timeouts are failures.
- The check of `http://host/` for a host given as https treats a stopped origin as nothing listening.

### Planning and scope

The run's policy is applied when items are planned:

- `-passive` keeps only `Passive` collectors.
- Active techniques run only on request: an `Active` collector needs its flag and a seed inside the scope. The scope is the `-allow` or `-scope` given or, when there is none, the targets given.
- `-skip` removes collectors by name.
- A seen-set prevents running the same seed twice.
- `-allow`, `-deny` and `-scope` filter hints before they are queued.

A scope entry is a domain, a host or an address range: [Concepts](CONCEPTS.md#scope) has the syntax.

When a scope is set:

- The shared HTTP client refuses any request to a host outside it.
- The client stops following a redirect at the first hop that leaves the scope. The hop is recorded with its `Location`.
- The path, parameter and GraphQL modules use their own clients without redirects, on seeds the scope already admitted.
- Chrome is held to the same scope: see [Chrome and the scope](#chrome-and-the-scope).

### Order of work

Items on the seed's own host or IP run before fan-out items. Part of the item budget is reserved for fan-out: one eighth, at least 24 items once the budget is 48 or more, and never more than half. Without the reserve, a large application would spend the entire budget before any domain-level collector ran.

Within a host, work runs by what it is worth under a budget:

1. The service and its front page.
2. Its API and description paths.
3. The pages that links and scripts name.
4. What only an archive lists.

So a program run spends `-max-requests` on the front pages and APIs of its hosts before it spends any on archived URLs. A front page found late goes ahead of archived URLs queued before it. Work left over when a limit is reached is stored, and the run is marked `capped`.

Other rules that shape the queue:

- Collectors that read a page run after `azhaq-http` has answered for the same URL. These are crawl, scripts, API descriptions, paths and GraphQL. A URL that does not answer is dropped, and so is every task waiting behind it.
- A target given as `host:port` or an IP address goes on as the scheme that answered.
- A directory listing's sort links are the same listing, and are neither requested nor listed. Apache's and nginx's are `?C=N;O=D` and `?C=M&O=A`.
- URLs that differ only by an ID or a query value share a template, such as `/catalog/product?productId={n}`. Every URL of a template is fetched; `-per-template N` limits it, and the rest stay in the graph as found.

#### A site named over http and https

A target given as `https://host/` may be named over plain http by archives or links, as `http://host/…` or as another name of its domain. It then gets one request to `http://host/` first.

Those URLs are the https site's, and are requested and mapped as https, when any of these holds:

- `http://host/` redirects to https on the same host.
- It serves the same front page. If the answer is a redirect, both redirects must end at the same page. Two applications can each send their visitors to their own `/login`.
- Nothing listens on port 80: the connection is refused, there is no route, the name has no address, or a connect times out twice.

Otherwise, `http://host/` is a service of its own and its URLs stay as they are. This includes a slow answer and one that is not HTTP.

### Resuming (`azhaq resume`)

The scheduler records its frontier in the store, in the table `tasks`: every task it plans, with its collector, seed and depth. They are recorded in the same transaction as the tasks that finished. So a task's hints are never lost between it ending and them being recorded.

A task is done when it ran, with or without an error, was dropped, or was skipped. One that was cancelled or stopped by the request budget is not done.

The run's options are stored with it. The database is left out, and so are the values that carry a session: `-cookie`, `-login-pass` and headers named like a credential.

`azhaq resume -db FILE` takes the latest run with tasks left. That is a run interrupted by Ctrl-C or a kill, or stopped by `-max-requests`, `-daily-requests` or `-max-items`. It then:

1. runs it again with its stored options plus any given;
2. rebuilds the queues from the tasks;
3. counts done tasks against the item budget;
4. queues the others again, behind the task they wait for when that is not done either;
5. clears their done-marks.

So a task that ran but whose end was not recorded runs again whole. Observations are stored once per run, so it reports nothing twice.

Tasks the budget stopped before run last, one at a time and cheapest first, by the requests they had sent. So a path sweep that needs more than the budget does not starve cheaper work. Once the budget is spent, tasks that would contact targets are kept back. A resume in which no task finished says the budget is smaller than any task left needs.

### The request ledger and the kill switch

`internal/ledger` keeps a tamper-evident record of what a run sends to a target. Each entry is one JSON line with these fields: `seq`, `time`, `kind`, `method`, `target`, `host`, `rule`, `collector`, `prev` and `hash`.

- `hash` is the sha256 of `prev` and the entry's JSON without `hash`. An edited, removed or reordered line breaks the chain from there on.
- A line is flushed before the request goes, so a crash loses nothing that was sent.
- `Open` continues the chain of a file that exists. `azhaq resume` and later runs into the workspace append to the same file. `azhaq roles` opens one ledger in its `-dir` for all its runs.
- `Match` names the scope rule that allows each host, from the run's `-allow` and `-scope`.

The hooks are where a request leaves the process:

| Hook | Records | `kind` |
| --- | --- | --- |
| `fetch.Client` and `fetch.Do` | every target-facing transport | `http` |
| `portscan` and `tlscol` | connects | `tcp` |
| `portscan` and `tlscol` | datagrams | `udp` |
| the browser | the requests it lets Chrome send | `chrome` |

DNS queries and the third-party sources are not targets and are not recorded. Neither are the requests of a connector, which Azhaq does not send.

`fetch.SetKill` watches for the kill file every 100 ms (`fetch.KillCheck`). Once it sees the file, it also ends every wait for the pace (`fetch.Pace`). So a request counted before the file appeared is not sent after it.

Once the file exists, `Spend`, `Take` and `Spent` refuse with `neterr.ErrKilled`, which is also an `ErrBudget`. So every collector that leaves work for `azhaq resume` on a spent budget does so here. The run ends with exit 4, and `stopped` names the kill switch.

Without a workspace of its own, a run has no default ledger or kill file. This is a drop-in command without `-db`.

### Workers (`-serve`, `azhaq worker`)

A run started with `-serve ADDR` lends its work to `azhaq worker` processes, on the same machine or others, over HTTP with a bearer token. The run's process keeps the database, the scheduler, the budgets and its own `-parallel` slots.

A worker:

1. claims one task at a time per slot, with `POST /v1/claim`, a long poll;
2. runs the collector in-process without a store (`engine.Execute`);
3. sends back what it reported, its hints and the requests it sent, with `POST /v1/done`.

The run stores that as if it had run the task itself (`Engine.Record`).

- Workers take only tasks that contact targets. Third-party sources and their keys, batch DNS and `Local` collectors (screenshots, `-browser`) stay with the run.
- A worker gets the run's options without seeds, outputs or sessions. It also gets the files they name, such as wordlists, the scope as `-allow` and `-deny` rules, and the session as headers (`GET /v1/run`).
- A task a worker holds longer than its lease (15 minutes) is queued again. Tasks lent when the run stops are left for `azhaq resume`.
- The request budget counts every process's requests. `-rate` and `-host-parallel` apply per process.

## HTTP

All HTTP collectors share one client (`internal/fetch`):

- Redirects are not followed automatically. Each hop is recorded. The status stored is that of the URL that was requested, so `/admin → 303 → /login` records `/admin` as 303.
- At most 10 requests are in flight per host (`-host-parallel`, katana's concurrency). Concurrent requests for the same URL share one fetch.
- Bodies are capped at 2 MiB. The cap is 16 MiB for JavaScript, JSON and source maps, where bundles of several MB are normal.
- `-delay` adds a pause before each uncached request.
- `-cookie` and `-header` are added to every request, which lets a run reuse a session you already have. `-login` gets one with Chrome. Azhaq stores cookie names but never their values.
- Headers must arrive within 10 seconds, as in httpx, because CDN edges and bot managers often answer slowly. The whole request, body included, gets 30 seconds, so a large bundle on a slow link still arrives.

### Paths you rule out

`-deny-path REGEX` is the user's own rule for paths, and the only one: azhaq has no default and decides nothing about a URL by its name. The rules are part of the scope (`scope.Rules.DenyPath`, compiled once). A regex is checked at start; a bad one is a usage error, exit 2, before any request. `DeniedPath(url)` matches each against the path as sent and decoded, with and without the query, so an escaped dot or slash does not step round it.

One rule set, enforced where every request passes:

- `fetch.DeniedBy` is set from the rules. `fetch.DoReq` and `SubmitForm` refuse a URL it matches with `neterr.Denied` before the cache, the budget or the network, and a redirect to one is recorded with its `Location` and not followed.
- `ledger.Transport`, which every HTTP client of a run sends through (the fuzz sender, the path sweep, parameter search, the roles' replays), refuses it too, giving back the request it had counted.
- Chrome's Fetch domain fails the request (`internal/browser/scope.go`), pages and scripts alike.
- The scheduler keeps a matching URL seed out of the queue; the path sweep leaves a matching word unsent; `fuzz` does not send a matching input; a parameter search skips a matching page.
- Each URL kept out is told to `fetch.OnDenied`, which the engine writes as a `skipped` observation (`-deny-path REGEX`), so it is `skipped` in the map and listed in the summary. `fuzz` counts its inputs per rule.
- `roles` holds the rules over each replay it sets up (`holdDeny`), `azhaq mcp -deny-path` hands them to every tool call, and `plan` prints them.

### Probing

`azhaq-http` probes a hostname over HTTPS and falls back to HTTP. With `-web-ports` it tries each port, HTTPS first except on port 80. A `host:port` or IP address from `-list` becomes a URL with the same fallback.

For each answer it stores these fields, besides status, title and headers:

- `tech`: wappalyzer fingerprints of the final response's headers and body, as `Name` or `Name:version`. See [Technology matching](#technology-matching).
- `favicon`: on a site's front page, the MurmurHash3 of the icon's base64 encoding. This is the value Shodan indexes as `http.favicon.hash`. The icon is the page's `<link rel=icon>` (`.ico` first) or `/favicon.ico`. At most two requests are made, and only on the same site.
- `length`, `words` and `lines` of the final body, counted like httpx.
- `ms` for the whole redirect chain.
- `ip`, the address the request connected to. It is left out behind a proxy.
- `final_status`, when the request was redirected.

`azhaq-dns` adds `cdn` and `cdn_type` (`cdn`, `waf` or `cloud`) from cdncheck's embedded ranges: by address, then by CNAME target. Nothing here makes an extra lookup.

#### Technology matching

`internal/wappalyzer` is wappalyzergo's passive matcher with one change: each pattern's regexp compiles the first time its literal prefilter passes.

- Upstream compiles all patterns at load. It bounds `+` and `*` to 250 repetitions, which Go unrolls, so that held about 80 MB.
- Compiling on first use takes a few MB.
- A test runs both matchers over a page built for each of the 7,642 fingerprints and requires identical results.

#### `-probe`

`-probe` keeps a run to this: only `azhaq-dns` and `azhaq-http` run, on the listed targets and nothing they lead to. The output is one line per web service instead of the map.

#### `azhaq probe`

`azhaq probe` runs `-probe` with httpx's settings (`httpcol.Spec`):

- No redirect is followed unless `-fr`. Then `-maxr` counts as httpx counts it, at most N-1 hops, within the site or, with `-fhr`, the host.
- There is no `Accept` header, and one connection per request, as httpx sends.
- TLS is 1.0 and up.
- A bare `host:port` is asked over plain HTTP first on 8080 and on ports above 1024. It is asked over TLS when the plain request is answered 400.
- The scheme order, `-p` ports (also for addresses), `-path`, `-nf` and `-pa` work as in httpx.
- A name that resolves only through a wildcard answer is probed, not dropped.

Every answer keeps its request and response as they went over the wire (`fetch.Result.Raw`). These read it: the matchers (`internal/probefilter`), `-hash`, `-sr`, `-irr`, `-tls-grab` and `-debug-*`. `-tls-grab` reads the handshake the request made, with no extra connection.

A request that a method, body or header changes is a request of its own. This covers `-x`, `-body`, `-rr`, `-vi` and `-pa`. Its answer is cached and kept under a key that holds them (`fetch.DoReq`), so it never answers for the plain GET.

Some options send extra requests, and each is counted and paced like any other:

- `-jarm`, `-http2`, `-pipeline` and `-vhost` send extra requests.
- `-tls-probe` and `-csp-probe` raise the depth, so the names a certificate or a policy gives are probed too, inside the scope.

`-kb` classifies pages with the dit model. The model is read from `~/.dit/model.json` or `$AZHAQ_DIT_MODEL`, and is never downloaded.

### Scripts

`azhaq-js` reads each page's inline scripts and script files. It then reads the chunks those import by name or through a webpack chunk map. For each chunk ID the bundle knows, it evaluates the bundle's chunk-name function:

```
n.u=e=>"static/js/"+e+"."+{…}[e]+".chunk.js"
```

#### Scripts on other hosts

A script on another host is read as Chrome would load it for the page:

- With a scope, it is read when the scope allows its host.
- Without a scope, it is read when its host is on the page's registrable domain. A bundle on `cdn.example.com` is read for `www.example.com`. An address matches only itself.

Those requests count against `-max-requests` and are paced by `-rate` like any other.

A crawl follows links within its scope: the page's own origin, which `crawl` and `-crawl-scope` widen. See [Crawling](#crawling). What a script on one host names on another host follows these rules:

- What a script calls on another host it may request, such as `https://api.example.com/v1/orders`, is a row of that host, found in that script. So is an API path it names there.
- A page of another host that a script merely names is left to that host.
- A path a script on another host names, such as `"/api/me"`, is the page's, where the request goes.

#### Paths joined to a base

A script may join a path to a base it does not spell out, such as `this.host + "/orders"` with `this.host` set elsewhere. When a call builds it under a prefix, such as `/rest/order-history/orders`, it is not a route of the root. The call's row says where its base put it, and the root is not asked.

A path of an API description written into a script, such as Swagger UI's `swaggerDoc`, is the description's, under its servers. `azhaq-openapi` reads it, and also reads a description written as Swagger UI's `swagger-ui-init.js` carries it.

#### What it looks for

In every script, `azhaq-js` looks for the things below.

##### URL and path strings

Strings that name no route are dropped:

- pieces of a parser table or a minified name, such as `/pQ` or `/SQ`: one segment of one or two letters with a capital;
- a package named after its owner, such as `/juice-shop/juice-shop`: a slug with a hyphen or a dot, twice.

These are kept:

- short routes in lower case, such as `/v1`, `/me` and `/id`;
- a locale, such as `/en/US`;
- a word twice, such as `/admin/admin`.

A version prefix alone, such as `/v3`, is requested. It stays in the map only when something answers there.

##### Requests scripts make

The calls read are those through an HTTP client (`this.http.post(…)`, `$.get`), `fetch`, `XMLHttpRequest`, `$.ajax` and `axios`. Each gives the method, the path with run-time parts as `{name}`, and the query and body names.

A request made inside a function that takes the URL as a parameter is read where the function is called, one level deep. For example, `logQuery('/logger', …)` with this function is `POST /logger`:

```js
function logQuery(url, params){ fetch(url, {method: "post", …}) }
```

What the function may change:

- The function's parameter defaults count. That is `method = "POST"`, also for a call that passes `undefined`.
- A prefix it puts on the parameter before the request counts, as in `url = API_ROOT + url`.
- Any other change to the parameter stops the function being followed.
- So does a name the script declares twice, such as `usersApi.request` and `ordersApi.request`.

More rules:

- A request whose path has a placeholder for the parameter stays a route of its own: `/api/accounts/{id}` besides `/api/accounts/me`.
- A path relative to the page counts only for `fetch`, `XMLHttpRequest` and `$.ajax`, as without a helper. jQuery sends a GET's `data` as its query.
- When a request's method is a value known only at run time, the route is listed without one.

##### Paths joined from constants

Paths joined from constants where the request is made are read, such as `og+sg.LOGIN` with `og="identity/"` and `sg={LOGIN:"api/auth/login",…}`.

- A name counts only if the script binds it once. So a short minified name reused across modules is not guessed at.
- Placeholders such as `<videoId>` become `{videoId}`.

##### GraphQL operation names

These come from query documents or the parsed form bundlers emit.

##### Router views

The views of the app's router are read from its route table:

- Angular: `{path:'admin', component: …, canActivate: [AdminGuard]}`, lazy `loadChildren` and `loadComponent`, and `children` joined to their parent.
- React Router: `<Route path>` as written or as compiled, and `createBrowserRouter`.
- Vue Router: `meta.requiresAuth` and `beforeEnter`.

Whether the app routes by the hash decides their URLs. The signs are `useHash`, `withHashLocation`, `createWebHashHistory`, `HashRouter` and `mode: 'hash'`. With the hash, a view is `http://host/#/administration`. Otherwise it is the path from the page's `<base href>`.

- Views are `client-route` rows with their guard.
- A string that names a view is that view's, not a page to request.
- A view after the hash is never requested.
- A view in the path is asked for once, since the server may answer it itself, with a sign-in's 401 or a page it renders. It keeps the server's role then, with the guard noted beside it.

##### WebSocket endpoints

These are read from:

- `new WebSocket(…)` and `SockJS`, with the URL worked out where the script builds it;
- `ws://` and `wss://` URLs;
- socket.io's `io(url, {path})`, with its namespace;
- socket.io's default `/socket.io`, when the library is in the bundle and the app's call is not readable.

They are `websocket` rows on the page's site. They are never requested, and their paths (`/socket.io`, `/engine.io`) are not pages.

##### Credentials

Keys are read for these services: AWS, Google, GitHub, GitLab, Slack, Discord, Stripe, SendGrid, Mailgun, Twilio, OpenAI and Anthropic. Slack and Discord webhooks are read too. An AWS secret key next to an access key id makes the pair high.

Also read:

- private keys;
- JWTs;
- variables bundlers inline, such as `REACT_APP_…`, `NEXT_PUBLIC_…` and `VITE_…`;
- values of eight or more characters assigned to secret-sounding names. They are kept only when they look random (entropy) and not like a label or placeholder.

Values are stored whole. The HTML report shortens them.

#### Libraries that are not fetched

Well-known library builds served from the app's own origin are not fetched. Examples are `react-dom.development.js`, `jquery-3.6.0.min.js` and `swagger-ui-bundle.js`. They are large and hold no routes of the app, only stray strings.

#### Source maps

A script can name a source map in its last line, or in a `SourceMap` (or `X-SourceMap`) header. The map is then read when the run may request it. It is recorded with the app's own source files, libraries left out, and those sources are scanned like scripts.

A script file that names none has `main.js.map` asked for next to `main.js`, for up to 10 scripts per origin. It is kept only when it is a source map: JSON with `sources` and `mappings`. The observation that records it says `"guessed": true`.

An exposed source map is worth knowing about on its own.

#### Build manifests

Build manifests list what a page's scripts do not name:

- **Next.js:** `_buildManifest.js` and `_ssgManifest.js`. They are asked for at `/_next/static/<buildId>/` when the page has Next.js's scripts and `__NEXT_DATA__`. Chunks are named from `/_next/`. Dynamic pages are kept as templates: `/admin/users/[userId]` becomes `/admin/users/{userId}` and `[...slug]` becomes `{slug}`. `/_app` and `/_error` are left out.
- **Create React App:** `asset-manifest.json`, when the page loads `static/js/main.<hash>.js`.
- **Vite:** `.vite/manifest.json` and `manifest.json`, when a script carries Vite's preload helper.
- **Angular:** `ngsw.json`, when a script registers `ngsw-worker.js`.
- **Nuxt:** the build meta at `/_nuxt/builds/meta/<id>.json`, with its prerendered pages and route rules.

Each is asked for once per run. A JSON one is a `manifest` row. The scripts it lists are read, and its maps and pages are kept.

#### Where a route was found

Each route found in a script keeps where it was found:

- the script's URL: the page's for an inline script, with the page's line numbers;
- the line and column;
- up to 120 bytes of code. This is the call as written, or a string with what surrounds it. Credentials are blanked, since an inline script of a signed-in page can hold the session.

A route keeps up to three places per page, calls first. A route read from a source map's original file names that file.

### Crawling

`azhaq-crawl` reads each page's links from its markup and headers.

`crawl` is `run` with these turned off:

- the subdomain, archive, certificate, RDAP and cloud collectors;
- the 32 path checks;
- the favicon;
- the source-map guesses, which ask `main.js.map` next to a script that names none.

`-sweep` turns them back on. So `crawl` sends what a crawler sends: the pages it finds, the scripts they load and the routes they name.

#### Sinks

A link is read from these tags and attributes:

| Tag | Attributes read |
| --- | --- |
| `a`, `area` | `href`, `ping` |
| `img` | `src`, `srcset`, `dynsrc`, `longdesc`, `lowsrc` |
| `source` | `src`, `srcset` |
| `video` | `src`, `poster` |
| `script` | `src` |
| `object` | `data`, `codebase`, and `param` values that are paths |
| `body`, `table`, `td`, `th` | `background` |
| `blockquote`, `q` | `cite` |
| `button`, `input` | `formaction` |

Also read:

- the tags `link`, `base`, `iframe`, `frame`, `embed`, `audio`, `track` and `applet`;
- `input type=image`, `html manifest` and a `<meta http-equiv=refresh>`;
- GET `form` actions and `hx-get`;
- the `Link`, `Content-Location` and `Refresh` headers;
- then the URL-like strings of `javascript:` links, `on*` handlers and `data-*-url` attributes.

`hx-post`, `hx-put` and `hx-patch` are listed as routes with their method and never asked. Where a URL was read, meaning the tag, the attribute and the page, is kept for `-jsonl`.

A page lists every link it has. Nothing is cut at a number of links. The requests are bounded by the templates (`-per-template`) and by `-max-items`. The summary reports it when `-max-items` stops the run.

#### Text

katana's string patterns are read over every page, script and JSON answer (`internal/webextract/barestr.go`).

- A string that names a page of the application is a URL, asked like a link. Examples are `users.php`, `admin/` and `./notes/x.html`.
- Every other string is kept as a rejected candidate with its reason, and is never requested.
- `crawl -rejected` lists the rejected candidates, and the summary counts them.
- A relative string is resolved against the page, as a browser does for a fetch. Where its reading against the script's own file differs, that reading is kept as a rejected candidate.

The reasons for rejecting a string are:

- a media type;
- an expression or a template;
- a script or style file name;
- library code;
- another host;
- a link outside the crawl's scope;
- a string named in an error page;
- a pattern in `robots.txt`.

#### Scope

A link is followed when `crawl`'s scope allows it. By default that is the registrable domain of the start URL and its subdomains. An address matches only itself, and only its port. Then `-allow` and `-deny` apply.

- `-fs rdn|fqdn|dn|REGEX` picks katana's field scope.
- `-cs` and `-cos` are URL regexes.
- `-ns` removes the field scope.
- Links outside the scope are counted in the summary and listed by `-do`.

#### Forms

Every form is a `forms` entry of its page.

- A GET form is asked once with neutral values in its fields. Hidden fields, ticked boxes and selects get the page's own values. Text gets `azhaq`, an email gets `azhaq@example.org`, and a number gets `1`. `-no-form-fill` does not fill GET forms.
- A POST form is sent only with `-submit-forms`, with the same values, urlencoded. It changes data on the target.
- Each submission is one request of the budget and the pace, and is in the ledger. It is held to `-allow`, `-deny` and the crawl's scope.
- A POST form is not sent when it uploads a file, posts outside the crawl's scope, or its address matches a `-deny-path` rule. Its name decides nothing.
- The summary says how many POST forms were sent and which were not.

#### Politeness

- `crawl` waits and asks again when a host answers 429 or 503. The wait is 1 s doubling to 30 s, or `Retry-After`, up to three times. The summary names the hosts and the requests that still got it.
- It asks once more after a timeout or reset from a host that had answered.
- It carries the cookies the target sets.
- It paces each host with `-hrl` besides `-rate`.

### Sessions and roles

`-cookie` and `-header` apply to every request of a run. So does the session `-login` gets. Chrome fills and submits the login form. The cookies the site sets and a JSON Web Token the page stores become a `Cookie` and an `Authorization` header (`internal/browser/login.go`). Nothing is guessed from a URL's name, a logout link included: it is requested like any other. What keeps the session honest is a check (`internal/fetch/session.go`):

- The run asks a page with its session and without it before it starts (`cmd/azhaq/session.go`: the page `-login` ended on, else a target) and keeps one whose answers differ (status, and the path a redirect goes to). If none differs, only a response that expires a cookie the run sends ends the session as far as the run can tell.
- `Spend`, which every request to a target passes through, counts requests and asks the check every 50, and at once after an answer that looks like the end of the session (a 401, a redirect to the sign-in page, a response that expires a session cookie, which also names the URL). `fetch.EndCheck` asks it once more when the work ends. While it runs, other requests wait; the sign-in's own requests pass.
- A failed check with `-login` renews the session (a new Chrome sign-in, whose headers are set whole with `fetch.SetExtra`). `fetch.DoReq` has kept the GETs sent since the last good check; they leave the cache, the scheduler (`redoSession`) drops what the touching collectors reported of them and runs their tasks again, so their stored answers are the signed-in ones. The URL whose answer ended the session is not asked again. A note says what was done.
- A failed check with `-cookie` or `-header`, or a fifth loss, sets `neterr.SessionLost`: `Spend` refuses every later request with it, the summary lists it as a failure (`azhaq-session`) and the exit code is 3.
- Path and parameter sweeps (`dirs`, `params`) are counted by the check, not recorded: their requests since the last good check are named in the note and not repeated.
- `roles` has its own canaries (`roles_canary.go`): see [roles](commands/roles.md).

A role of `azhaq roles` is headers (`-role`) or an account to sign in with (`-role-login`). `azhaq roles` works in two phases:

1. It runs the same seeds once per role, in turn, each with its own database.
2. It replays. Every URL any role reached is asked with each role that did not reach it, through that role's session. The URLs are those on the run's hosts, as GETs.

GET routes with path parameters are filled with the values of identifier-like fields the roles' own JSON answers held. The fields are `id`, `username`, `*_id`, `*_title` and more. The order of values is:

1. values given with `-id`;
2. each role's own values, which only that role's answers held;
3. shared values.

Each endpoint then has an answer per role: status, length, body hash, nested JSON field paths, whether it is an error, and which fields hold secrets. A 2xx that is not an error counts as reading it. A verdict then names the difference between the roles' answers. The verdicts are listed in [Concepts](CONCEPTS.md) and on the [`roles` page](commands/roles.md).

The evidence of a roles run is a second database, `roles.db`, in its `-dir`. Its `meta` table records when the run saved it (`saved_at`), which `azhaq report` quotes as the run date. `azhaq report` (`cmd/azhaq/report_cmd.go`) reads it and sends nothing.

### Catch-all responses

Many applications answer every path:

- a single-page app serves its index for any route;
- some servers return a "not found" page with status 200;
- others redirect every unknown path to a login page.

Without a check, each of those paths would look like a real page.

Before a non-root URL counts as visited, `fetch.CatchAll` compares its response with the answer for a random path in the same directory. For `/rest/user/login`, the random path is `/rest/user/azhaq-…`.

- The responses match when the status is the same, and either the redirect target or the body is the same once the requested path is removed from it. So error pages that echo the path still match.
- Bodies that differ only by a token or timestamp match on title, line count and word count.
- Each directory is probed once per run, up to 24 directories per origin.

A matching response is stored with `"catchall": true` and shown as `catchall` in the map. The crawler and the JavaScript reader skip such pages, and the path sweep drops them.

### Path checks

The built-in path checks are `azhaq-paths`. They ask 32 paths per web service, and `-no-paths` turns them off. They include the places an API description sits:

- `openapi.json`, `swagger.json` and `api-docs`;
- `v3/api-docs`, `v2/api-docs` and `swagger/v1/swagger.json`;
- the YAML names, `api/openapi.json`, `api/swagger.json` and `swagger`.

Under each API base the run found, such as `/rest/` or `/v3/`, the same names are asked again. This is up to 8 bases per origin.

These are asked one at a time, likeliest first. They stop at the first answer that is an OpenAPI or Swagger document with paths, or the Swagger UI or ReDoc page that loads one.

- Once an origin has served a description, here or through `azhaq-openapi`, its other locations are not asked. The summary says so: `path checks: 28 skipped (an API description was already found)`.
- Every other check is still asked. Only a check whose answer is already known is skipped.
- A Swagger UI whose script carries the document, such as Juice Shop's `/api-docs/`, is read from that script. The names next to it are not guessed.

A page that is byte for byte what the site root answers for a made-up path is the catch-all answer. This is a single-page app's shell. In a directory whose own baseline has not been asked, that baseline is not requested. A directory with answers of its own is still asked.

On Juice Shop a default `azhaq run` sends 148 requests, for the same 70 of 77 known routes.

## Notifications

`internal/notify` sends messages and knows no target. `Client` is the one place a notification leaves from. It has:

- a pace, `-rate-limit`, which is a token bucket;
- a timeout of 30 seconds a try;
- three tries on a 429, a 5xx or a connection that failed. `Retry-After` is honoured up to a minute, and the back-off doubles otherwise;
- a refusal of any redirect to another host;
- the scrubbing of every error.

Errors are scrubbed like this:

- A transport error is cut down to what went wrong. The `url.Error` that wraps the whole URL is not wrapped.
- The request URL's path and query are removed from the text of an error. So is every secret a provider registered: webhook URLs, tokens, keys, passwords and header values.
- Of a failed answer, only a bare error code such as `channel_not_found` is kept, since a server may echo anything.

The providers are `slack`, `discord`, `pushover`, `googlechat`, `smtp`, `teams`, `telegram`, `custom` and `gotify`. They read notify's `provider-config.yaml` and build the requests that projectdiscovery/notify and its shoutrrr dependency build.

`chunk.go` holds notify's two splitters: one message per line, and `-bulk`. `Split` cuts a text to a service's limit for the webhooks of `watch`. `watch` sends through the same client and counts a delivery that failed as exit 3.

## DNS

`internal/dnsr` resolves through a pool of recursive resolvers. Six public ones are the default.

### Resolvers

One parser, `dnsr.ParseResolvers`, reads `-resolvers` for every command. It takes a file with one resolver per line, or a comma list. A resolver is `ADDR`, or `ADDR:PORT` over UDP. It can also carry a prefix before its address:

- `udp:` or `tcp:`;
- `dot:`, DNS over TLS on port 853;
- `doh:URL`, DNS over HTTPS as in RFC 8484, with POST or with `:get`.

How the pool behaves:

- Queries go round robin. Only the queries in flight pace them, unless `-dns-rate` sets a rate per resolver.
- A resolver that leaves a third of its recent queries unanswered is asked one turn in sixteen until it answers again.
- A timeout, SERVFAIL or REFUSED moves the query to another resolver. `-retry` sets the attempts, 3 by default.
- Every question carries an EDNS0 buffer of 4,096 bytes, as dnsx asks, so a long answer arrives over UDP. A truncated answer, or one larger than the buffer, is retried over TCP.
- `-proxy socks5://` sends every query over TCP through the proxy.
- Each name is resolved once per run.
- Special-use names (`localhost`, `*.test`, `*.local`) and single labels go to the system resolver instead, so `/etc/hosts` and local DNS still work.
- In `dns`, naming resolvers with `-r` sends every name to them, as dnsx does.

### `azhaq dns`

`azhaq dns` does not go through the engine.

- `Pool.Lookup` asks the record types the flags select, one question each. It keeps what the answers say in dnsx's `DNSData` shape (`dnsr.Data`).
- A bounded set of workers (`-t`, 100) takes names from the input as it is read. So a list of any size is asked in constant memory.
- `-rl` paces names, not queries, as dnsx does.
- An A question whose answer has no address is put to a second resolver once, before the name is called dead. `-retry 1` turns that off.
- `-axfr` connects over TCP to the name servers of the name, whose addresses it asks, and to the resolvers given. It connects only to those the scope allows.
- `-trace` asks the root servers and follows the delegations.
- With `-db`, the names that have records are written to a workspace as `azhaq-dns` observations.

### Dead and wildcard names

A name is dead when two resolvers agree:

- One resolver's NXDOMAIN or empty answer is checked with another.
- A resolver whose NXDOMAINs another has confirmed 64 times in a row is checked on one answer in 16. After the first answer it gets wrong, it is checked every time again.
- A name that is only a CNAME is not dead.

A name is a wildcard answer when one of its parent zones answers for random labels. The name's addresses, or its CNAME target, must be what the random labels got. Each zone is probed once per run.

Real hosts in a wildcard zone are kept when their addresses differ. A real host that shares the wildcard's address is dropped. Other resolvers make the same trade-off.

## Subdomain sources

`azhaq-subdomains` asks every selected source at once and records each one's count, time, requests and error.

### Retries and failures

- crt.sh's public PostgreSQL is asked first, for the names of the domain with subfinder's `LIMIT 10000`, within a quarter of the source's time and a `statement_timeout` to match, which leaves most of the time to the JSON API when the database hangs. A page of exactly 10000 rows is full: the rest is asked without the limit, within 60% of the time left, then from the JSON API, and the row's note says which gave the names. The JSON API is asked when the database fails or gives nothing; the source's row notes why. A SOCKS5 proxy carries the database connection; an HTTP proxy cannot, so the JSON API is used and the note says so.
- The JSON API is asked again up to three times, after 1, 2 and 4 s. It is not asked again once 12 s have passed, since every other source waits for it.
- A source that answers 429 is asked again after its `Retry-After`. When it gives none, the pause is 2, 4 and 8 s. This happens at most three times and not for longer than 30 s. The row says how many requests were retried and whether the source gave up.
- An answer that is an error with a 200 status is read as one, not as an empty list. Examples are a quota line such as hackertarget's `API count exceeded`, a JSON object holding an `error` or only a `message`, and a page titled `Just a moment...`. A source that gave no names after one failed, with the server's words in its `error`.
- A source that needs a key is skipped, and listed as skipped, when none is configured.
- When every source that ran failed and nothing was found, the result is marked `degraded` rather than reported as zero. The `subs` summary is also `degraded` when any source in the default set failed: see [Degraded](commands/subs.md#degraded).

### Which sources

Most sources are subfinder's source packages, run in-process. Azhaq supplies the HTTP client, a limiter with subfinder's per-source rates, and keys from the provider file.

crt.sh, Cert Spotter and Chaos are implemented in Azhaq. Cert Spotter is usable without a key. It then reads the first page of issuances and says so. With a key it pages with `after=` until a page is empty.

The default set is keyless: anubis, certspotter, crt.sh, crtname, hackertarget, hudsonrock, rapiddns, scanmalware, shodanct, subdomain.center and thc. Keyed sources join it when their key is configured. `-all-sources` adds slower ones.

### subdomain.center

subdomain.center pads its answer with random names. For tesla.com each call gives a random 500 of about 6,300. A name only it gave is kept when it resolves.

- Without a key it is asked again while its last round gave a name that resolves and no other source had. There are at most 12 rounds.
- A round's new names are looked up before the next round is asked. Each is looked up once, and one resolver's NXDOMAIN is enough.
- With `-dns-rate`, the guesses cost at most half what the other sources' names did, and not less than 1,000.
- Without `-live` the guesses are not looked up. The source is asked once, and its names are listed unverified.

### Name history

Azhaq keeps the names it has kept for a domain, and asks that file as a source called `history`. The [`subs` page](commands/subs.md#name-history) describes it for users:

- where the file lives, and what it holds;
- the limit of 200,000 names per domain, and which names go first;
- how `-live` and `unverified` treat a stored name;
- `-no-history`.

Two details belong to the implementation:

- The file is written through a temporary file and a rename. A file that does not parse is set aside as `.bad`.
- `history` is a verified source, like subdomain.center. The [coverage estimate](#coverage-estimate) leaves verified sources out.

### Coverage estimate

The payload's `coverage` has `observed`, `estimated` and `share`. It is a Chao1 estimate over how many independent sources gave each name, and it leaves out the verified sources. A sampled source's row has `population_estimate`, a Schnabel estimate. [commands/subs.md](commands/subs.md#coverage-estimate) gives the formulas.

Tests run `subs` offline with `subcol.UseTestSources`, which replaces the source list with fakes.

### Time bounds

A domain the engine derives from a URL or hostname gets 15 seconds per source instead of the usual bound. For example, `-url https://app.example.com/` implies `example.com`. The run is about the application, and one slow source would otherwise hold up its map. This applies here and for historical URLs.

- The usual bound is `-source-timeout`, 30 seconds, which is subfinder's limit, for subdomain sources. It is 3 minutes for each archive.
- A domain given with `-domain` gets the full time.
- Sources that ignore their deadline are reported as timed out two seconds after it, and are no longer waited for.

## Path guessing

`-dirs FILE` is active. `@common` is the built-in SecLists `common.txt` (MIT, 4,750 words). The targets given are its scope unless `-allow` or `-scope` names one.

### Where it sweeps

It guesses paths from where each URL given starts: the path it has, or `/` for a bare host. A URL another collector found is swept only from the front page. Then it sweeps each directory it finds, down to `-dirs-depth` levels. A directory is a path that redirects to itself with a trailing slash.

### Calibration

Before a directory is swept, it is asked for names that cannot exist. The shapes are the ones ffuf's auto-calibration uses:

- a random word;
- `admin…`;
- `.htaccess…`;
- a random directory;
- one name per extension.

These go at the sweep's pace and together, up to `-dirs-threads` at once. So a slow service is waited on for one round trip, not one per shape.

A guess is dropped when it answers like a calibration answer. That means any of these:

- the same status and the same size;
- when the not-found answers differ in size among themselves, the same word and line counts;
- when their bodies or redirects repeat the path asked, a size that differs only by the length of the path, or a redirect that repeats it;
- the same redirect.

Statuses default to ffuf's: `200-299,301,302,307,401,403,405,500`. `-dirs-mc`, `-dirs-ms`, `-dirs-mw`, `-dirs-ml` and `-dirs-mr` are ffuf's matchers. `-dirs-fc`, `-dirs-fs`, `-dirs-fw`, `-dirs-fl` and `-dirs-fr` are ffuf's filters. They are `internal/fuzz`'s, as `fuzz` uses them, and are applied before the calibration.

### The sweep's client

The sweep has its own client:

- It has no cache and follows no redirects.
- It reads bodies only to count them. A body is kept, up to 1 MB, only for `-mr` and for the calibration's check that a page repeats its path.
- It keeps one connection per thread, with 40 requests in flight and no pace beyond that, as ffuf does. `-dirs-threads` and `-dirs-rate` set them.

Hits become URLs for the other collectors. A sweep hands them to the engine in batches, which write each batch in one transaction. So a target that answers every guess is not slowed by the workspace.

## Fuzzing

`azhaq fuzz` is not a collector. `internal/fuzz` is ffuf's engine.

### What the engine has

- **A request template with keywords.** The keywords are `FUZZ`, or `-w FILE:KEYWORD`. They can stand in the URL (host included), the method, the headers (`Host` too) and the body.
- **Wordlists.** They are files, or the output of `-input-cmd`, made when the input is reached.
- **Modes.** The wordlists run through the template as clusterbomb, pitchfork, or sniper with `§` marks. Sniper becomes one template for each marked place.
- **Encoders** applied to the words (`encode.go`, in process).
- **Matchers and filters** over the answers: status, size, words, lines, regexp and time to the first byte.
- **Auto-calibration**, with strategies, per host with `-ach`.
- **Recursion**, redirect-based or greedy. It is a queue of jobs, each with an optional time limit.

### Same results as ffuf

Counts, match rules and calibration follow ffuf 2.3, so a command line moved from ffuf gives the same results. Counts work like this:

- words are spaces plus one;
- lines are newlines plus one;
- the body is decoded when the server compressed it.

A command line that gives its own filters does not calibrate.

### Sending and scope

Sending is behind `fuzz.Sender`, so the engine runs against a fake in tests. The real sender sends through `internal/fetch`. So every request spends the run's budget, is paced by `-rate`, goes in the ledger and stops at the kill file.

`-replay-proxy` copies go through a second client that has no ledger, budget or pace. It is the user's proxy, not a target.

The host of `-u` is the scope unless `-allow`, `-deny` or `-scope` say otherwise. For example, `FUZZ.example.com` gives `example.com`. An input whose host is outside the scope is not sent, and is counted in the summary.

Five requests in a row to an origin with no answer stop the run. `-se`, `-se-after`, `-sf` and `-sa` change what stops it.

### Resuming and control

A stopped run goes on from a high-water mark and the few answers past it. It keeps no flag for each input of the product, so two 300,000-word lists in clusterbomb need no memory for the product.

`-control FILE` reads lines added to a file while the run goes. They can pause the run or change the rate, the filters and the queue.

### Preflight, postflight and reports

Preflight and postflight files (`flight.go`) wrap the sender:

- Each request file is sent through the same client, with its budget, pace, ledger and scope.
- Values are read by regexp, or by form field, meta tag, cookie or header.
- A value that would change a request's scheme, host or port is refused.

Reports (`report.go`) follow ffuf's files. With `-db`, the matches go into the workspace as ffuf's do.

## Parameters

`-params FILE` is active. The targets given are its scope unless `-allow` or `-scope` names one. It looks for query parameters each page reads but does not link, the way arjun does.

### The wordlists

FILE is a wordlist, or one of these names for a list built into the binary:

| Name | Names in it |
| --- | --- |
| `small` | 1,000 |
| `medium` | 3,000 |
| `large` | 6,500, the default of the `params` command |

Each list holds:

- SecLists' `Discovery/Web-Content/burp-parameter-names.txt`: MIT, Copyright (c) 2018 Daniel Miessler. The licence is kept in `internal/collectors/paramcol/data/LICENSE-SecLists`.
- Names Azhaq's own passes found: query strings of archived URLs, and forms and API bodies of its lab apps.

The likelier names come first.

### The reference answer

The page is asked twice with one random name. That answer is the reference, and the difference between the two is the page's own noise.

A page is not searched, and the summary says why, when it:

- changes too much by itself;
- is not text, HTML, JSON or XML;
- answers 405 to a body method;
- matches a `-deny-path` rule.

Names the reference answer itself holds go first. They are:

- the `name` and `id` of its form fields;
- the variables its scripts set empty;
- the keys of its objects;
- the words of a short plain reply.

### Groups

The page is then asked once with as many random names as a group holds. Names go out in groups of at most 500 names and, in a query, about 7.6 KB. Each name has a random value.

A server may answer the crowd with another status, such as a query that is too long. It is then asked with fewer names until it answers as it did for one. That size, in names and bytes, is the group size for the page.

Up to 5 groups are in flight at once (`-params-threads`, or `params -t`). The rate limit (`-rate`) is shared by all of them.

### Finding the names

A request marks its group when its answer differs from the reference in any of these ways:

- by status;
- by size beyond the noise;
- by its header names;
- by the path of its `Location`;
- by its line count beyond the noise;
- by carrying one of the values back;
- by printing a name of 5 or more characters between quotes or spaces that the reference does not.

A marked group is halved until single names remain.

- When the first half of a flagged group changes nothing, the second is split without being asked first.
- A name found by size, status, headers, location or lines is confirmed with one more request.
- A reflected value or a printed name names its parameter directly. A printed name is asked once alone.

### Pages that answer the crowd differently

A page may answer the random crowd otherwise than one name. Examples are an error page that prints the query string back, and a server that refuses a long query. It is judged against controls instead:

- A group whose answer differs from the reference is asked again with random names of the same lengths and random values. Only what that control does not show counts.
- A value counts as reflected when it comes back more often than the control's values do.
- A size is compared with the values taken out of both answers.
- A group whose control gets another status too, such as 414 for a long query, is split without being searched. So are the groups that come after it.

### Pages that answer names they do not read

Sometimes most names of a group, or nearly every name tried alone, change the answer. Then as many random names made like them, letters and as long, are asked once.

- If they change nothing, the page reads those names. They are a short list taken from its own scripts, and they are kept.
- If they change it too, the page answers names it does not read. That group's names are dropped, the search stops there, and a note says so.

The note reads `… answers names it does not read (16 of 16 names tried changed the answer): not searched for parameters`. It reads `not searched further` when earlier groups found names, which stay.

### Toggle names

After the list, about 70 toggle names not found yet are asked once. Examples are `debug`, `test`, `admin`, `verbose` and `source`. Each is asked with each of the values `1`, `true`, `yes` and `on`, one request per value. A page that reads `debug` only when it is `true` is found. The row says which value (`values`).

### Waits and failures

Nothing is dropped without a word.

- A 429, 418 or 503 that the page did not give for unknown names before is waited out. The wait is its `Retry-After` up to 30 s, else 1, 2 and 4 s. Every request to that host waits.
- If it persists, the page fails with the names found so far kept and a note. The exit code is 3.
- A request that gets no answer, even after one retry of a timeout, fails the page the same way. The names of its group are not judged.
- A page not searched is named in a note. That covers a page that changes by itself, is not text, or has more pages than `-params-per-host`.
- A request that times out is asked again with 5 s more, up to 20 s (`params -T`).

### Pace

- `params -d SECONDS` waits before each request, one at a time.
- `-stable` is one at a time with 3 to 9 s before each, and 30 s after a refused connection.
- There is no pace unless `-params-rate` (per host) or `-rate` is given.

### Methods and writes

The method is GET by default. `-params-method POST`, `JSON` or `XML` (`params -X`) send the names in a form, a JSON object or an XML document instead. At most 500 names go in one request.

A body method may change data on the target. So it is refused unless `-params-writes` is given and `-allow` or `-scope` names the targets, or there is one target.

- Every such request is counted in the budget, paced and in the ledger.
- The page's row says how many were sent (`writes`), and the summary says writes were sent.
- A name that cannot be an XML element is not sent, and is counted in a note.
- `-params-include` is sent with every request. For a body it can be a form, a JSON object or XML, or a template with `$arjun$` where the names go.

### Limits

At most 20 pages per host are searched (`-params-per-host`).

## Networks

`-asn` seeds an autonomous system. `azhaq-asn` lists the prefixes it announces (RIPEstat, no key) and the holder's name. `-cidr` seeds a range directly.

`azhaq-prefix` expands IPv4 prefixes into addresses. It makes at most `-max-ips` (4,096) for the whole run, and says so when a range is cut short.

Each address gets:

- a reverse DNS lookup (`azhaq-ptr`);
- an HTTP probe;
- a TLS handshake without SNI.

Names in reverse DNS and on certificates become hostnames to resolve and probe.

Reverse names a provider derives from the address, such as `ec2-192-0-2-7…` and `7.2.0.192.static…`, and shared platforms are recorded but not followed. Names found this way are not enumerated as domains, because on shared hosting they may belong to neighbours. Ask for a domain with `-domain`.

## Rendering pages

Static extraction reads what scripts contain. `-browser` also runs them.

`azhaq-render` loads pages in the run's Chrome, up to 30 per host. It loads pages, not scripts, assets or API routes. It records:

- every same-origin request the page sends while it loads. For a single-page app, these are its API calls with their real paths and query strings;
- the links and forms of the document once rendered.

These become URLs for the other collectors. It shares the browser, tab limit and session headers with screenshots.

A page read this way is loaded without its images, fonts and media, socket.io's polling and the tab's icon. A screenshot has them. They are not sent and not counted, because they name no route. A request to a host outside the scope is still listed.

The writes a page sends, such as a POST, a DELETE or a beacon, are not sent but mapped, with their method and names. See [Chrome and the scope](#chrome-and-the-scope).

### Clicking (`-interact`)

`-interact`, with `-browser`, clicks each rendered page's buttons, links, tabs and menus. It makes up to `-interact-clicks` clicks, 12 by default. It puts the page back after each, by history, else by loading it again.

It finds what only a click brings:

- the requests a click's script sends, which are the API calls;
- the route the address goes to: a path after `pushState`, or a route after the hash, which is a `client-route` row;
- the links the changed page shows.

A click sends nothing a page load does not:

- The writes it would send are refused and mapped like any other. `-browser-writes` is a separate choice.
- A button or link is clicked whatever its words say, as in katana: a link's GET is requested. What a click would write is refused by its method.
- `mailto:`, `tel:`, `javascript:` and downloads are not clicked.
- Chrome stays held to the scope and the budget.

The summary says:

- how many clicks were made, and on how many pages;
- how many routes they found;
- how many candidates were not clicked (downloads, mail and phone links);
- how many writes were mapped.

Azhaq does not attach to a Chrome that is already running (katana's `-cwu`). A Chrome it did not start would not be behind the scope guard and the ledger.

### Without `-browser`

Without `-browser`, the crawler reads what a page leaves for its scripts to render, where it can:

- Links written in Markdown in the page's text are followed like links. An example is `[User Search](/app/usersearch)`, which a converter such as showdown turns into links in the browser.
- It notes `{{templates}}` in the text.
- It notes an empty shell: a mount point such as `<div id="root">` or `<app-root>`, scripts, and next to no text.

The run's summary suggests `-browser` when a page of the target:

- carries Markdown links;
- carries three or more template expressions;
- is an empty shell while the map of its origin has fewer than 10 routes.

A server-built site, or a single-page app whose scripts gave up their routes, gets no suggestion.

## Chrome and the scope

Chrome goes only where the run's own requests may (`internal/browser/scope.go`). This covers `-browser`, `-screenshots`, `-login` and `-role-login`.

### Requests the browser makes

When Chrome starts, every request of the browser is paused through the DevTools Fetch domain. That covers pages, frames, workers and service workers alike. The domain is enabled for the whole browser before any tab opens.

- A request is sent on when its host is in the scope. This is the predicate the HTTP client uses, `fetch.Allow`.
- Without a scope, a request is sent on when its host is in the site of a page Chrome was pointed at. This is how a redirect without a scope is followed. The site is `fetch.Site`: the registrable domain, or the address.
- Any other request is failed (`BlockedByClient`) before it leaves the machine.
- `data:`, `blob:` and `about:` URLs pass, as nothing is sent.

### Connections the Fetch domain does not see

What connects without a request the Fetch domain sees is stopped by a SOCKS5 proxy on loopback. This covers a WebSocket, a preconnect, and Chrome's own update and sign-in services. Chrome makes every connection through it, loopback ones too. It connects only to hosts the same predicate admits (`internal/browser/guard.go`). Chrome is also started with the flags that turn its background networking off (component and extension updates, sync, field trials, domain reliability, safe browsing, the time service). A current Chrome still reaches for accounts.google.com and update.googleapis.com at start-up whatever the flags say, so the guard refuses those connections and counts them: the summary says `Chrome's own services reached for N connections outside the scope (…); all were refused, none was sent`.

1. The guard connects once Chrome has sent its first bytes, as the run's own requests would.
2. TLS goes through the environment's `HTTPS_PROXY`. Plain HTTP goes through `HTTP_PROXY`, whatever the port. Without a proxy, it connects directly with the run's DNS answers.
3. Those bytes also tell a WebSocket's handshake: a request asking for the upgrade, or a TLS hello offering HTTP/1.1 only, which Chrome sends for WebSockets alone. The guard counts and paces it, and refuses it once the budget is spent.

Limits of the guard:

- A WebSocket over an HTTP/2 connection Chrome already has (RFC 8441) is not seen.
- WebRTC is kept from sending UDP outside the proxy.
- A window a page opens is closed as it opens, because it would outlive its page, unpaced. This covers `window.open`, and a link or a form to `_blank`.

### Who may use the guard

Chrome cannot authenticate to a SOCKS proxy, so the guard checks who connects.

- **On Linux** it relays only for the Chrome it was started for. The socket at the other end of each connection is looked up in `/proc/net/tcp`. It must be held open by Chrome's browser process, or one it started (`/proc/PID/fd`). A socket of another user, or one another process holds, is refused.
- **Where it cannot tell**, another local process may use it, to hosts in the scope, while that Chrome runs. This is the case when `/proc/net` or Chrome's processes cannot be read, as on a hardened system or with a confined Chrome. It is also the case on other systems. What that process sends is neither counted nor paced.

The guard listens on a random loopback port. It starts with Chrome and stops with it.

### Proxies

Chrome's own proxy setting sends every connection to the guard, loopback targets too. Its default of leaving `localhost` and loopback addresses out of a proxy is turned off. The guard sends them on as the run's own requests go: through `-proxy`, or `-chrome-proxy`, else the environment's.

- To an HTTP proxy, it sends each plain `http://` request as a proxy request, `GET http://host/path`. So the proxy reads it as it reads the run's own.
- A page over TLS goes through a CONNECT tunnel, the one thing a proxy can be asked for it.
- A SOCKS proxy gets the connection.

### Writes

Chrome sends GET, HEAD and OPTIONS only. OPTIONS is a CORS preflight. Any other method is paused like every request and failed (`BlockedByClient`) before it leaves. It is not counted (`internal/browser/writes.go`). This covers what a page, a frame or a worker sends:

- a `fetch` or an XHR that POSTs, PUTs, PATCHes or DELETEs;
- a beacon, which is a POST;
- a form a script submits with POST.

Otherwise a page that tracks, saves or deletes as it loads would change data on the target behind a run that only maps.

The sign-in is the exception. Until the session is read, the tab of `-login` and `-role-login` sends every method it would. That is not only its form or XHR call with the credentials, but whatever else the page's own scripts send meanwhile. For example, Juice Shop's sign-in page opens a socket whose polling sends `POST /socket.io/…`. All of it is counted, paced and in the ledger, same as any other request. The pages after the sign-in send no writes.

What a refused write would have sent is not lost:

- Its method, the names in its query and the names its body sends become an operation on its route, with `source` `browser`, as a script's call does.
- The names in a body are a JSON object's keys, also in a beacon's `text/plain` string, or a urlencoded or multipart form's fields. A value is never kept.
- So the route is in the map as a `hint` with that method and in the OpenAPI export. It is not fetched for it.
- The summary lists it as not sent, by method and URL without its query:

```
{"target":"POST http://127.0.0.1:3001/api/track","reason":"a page's script would send a write"}
```

A form a script posts is stopped as a user stops a navigation (`Aborted`). The page stays as it was, and its links, forms and screenshot are its own, not Chrome's error page.

`-browser-writes` lets every page send its writes as a user's browser would, still inside the scope and the budget. They change data on the target. They are mapped alike and not listed. `run`, `crawl`, `shots` and the runs inside `roles` take it.

### What the summary lists

What Chrome was refused is listed in the run's summary as skips, without its query string:

```
{"target":"http://localhost:8897/ext.js","reason":"outside the scope (Chrome)"}
```

The reason is `outside the site (Chrome)` without a scope. A skip is listed on the page that asked for it, for the first 100 URLs of the run. A note gives the number of requests when there were more.

What no page claims is listed at the end of the run without one:

- a service worker's requests;
- a beacon a page sends as its tab closes, once per URL;
- the refusals of a capped page, which is dropped to be loaded again.

A write among those is listed, not mapped.

A page that went outside the scope is not read, and its screenshot is not taken, because what it shows is Chrome's error. This covers a redirect and a script setting `location`.

A sign-in that goes to an identity provider outside the scope fails and names it: `the sign-in went to sso.example.com, outside the scope: add it with -allow sso.example.com`.

### Downloads

Chrome saves nothing to disk (`internal/browser/downloads.go`). Every download is denied for the whole browser (`Browser.setDownloadBehavior`, before the first tab opens). This covers:

- a URL that is a file, such as an archive, a key store or a program;
- an `<a download>` a page clicks as it loads;
- an answer with `Content-Disposition: attachment`.

The request itself was sent, in the scope, paced and counted like any other. Only what it answered is dropped, and nothing lands in the user's Downloads folder.

Each refused download is listed like a request outside the scope, under `Chrome would download it`. The entry has its URL without the query, and the name Chrome would have saved it under:

```
{"target":"http://127.0.0.1:3001/ftp/incident-support.kdbx (incident-support.kdbx)","reason":"Chrome would download it"}
```

It is listed on the page that began it, or at the end of the run for the sign-in's.

## Screenshots

`-screenshots DIR` starts one headless Chrome found on the machine and drives it over the DevTools protocol (chromedp). Chrome is found as `AZHAQ_CHROME`, or `google-chrome` or `chromium` on the path.

### Timing

Each web service's front page opens in its own tab, six at a time (`-tabs`), with the run's `-cookie` and `-header` values.

- The load event gets 15 seconds.
- A page that never finishes loading is captured as far as it got, 1.5 seconds after navigation, within 30 seconds.
- With `-rate`, those times run from when the page last moved, not from when it started. A request of it let go, or an answer heard, counts as moving.
- With `-rate`, tabs open only as many at once as the pace can fund: `-rate` times 30 s, over the requests a page makes. A page of 40 requests at 2 a second takes 20 seconds and is whole.

After the wait, the picture is taken once two things hold:

- nothing of the page waits for its turn;
- nothing it shows is still on its way: images, styles, scripts, fonts, media and frames.

This must hold for 0.3 s. Under a pace it is 0.7 s and one pace interval. The wait runs up to 5 s more, and under a pace up to three times `-shot-timeout`. A single-page app asks for its images only after a script's request has been answered. At a low rate that comes seconds after the load event.

A script's own requests that stay open, such as a long poll, are not waited for.

A picture taken too early is saved as `partial`, with a note, and the run exits 3. That means some of the page's images, styles or scripts had not come back, or requests of the page still waited for their turn.

The tab's `/favicon.ico` is not fetched. A dialog (`alert`, `confirm`, `beforeunload`) is accepted. Chrome may open the ports it refuses by default (`-unsafe-ports`).

### What a screenshot is

- `-shot-size WxH` sets the size, 1440x900 by default.
- `-shot-fullpage` takes the whole page, up to 16384 pixels tall.
- `-shot-wait` is the wait after the load event, 1.5 s by default.
- `-shot-timeout` is 30 s. With `-rate`, it is how long a page may go without moving.
- `-shot-format png|jpeg` and `-shot-quality` set the format.
- `-shot-js FILE` runs on the page before the picture. It runs on the target's page.
- `-shot-codes 200,301` takes only pages that answered so. The others get a note.
- `-shot-html` keeps the rendered page.

Chrome itself is set with:

- `-chrome PATH`;
- `-chrome-proxy URL`, http or socks5, for Chrome's own connections only. `-proxy` takes the run's own requests and Chrome's;
- `-chrome-profile DIR`, a user data directory that is kept. Sessions in it go with the pages. They are the target's only if the scope says so.

The run's `-H` and `-cookie` values and its user agent go with every request.

### Targets (`shots`)

`shots` takes these as targets:

- URLs, with path and query kept;
- hosts and `host:port`;
- address ranges such as `192.0.2.0/28`, up to `-max-ips`;
- `-p` ports: numbers, ranges, `small` (80 and 443), `medium` and `large`;
- `-no-http`, `-no-https` and `-random`;
- `-nmap FILE`, an `nmap -oX` file of open web services, with `-service` and `-hostnames`;
- `-nessus FILE`.

A name with several ports is a picture per web port that answers. A name with no port is tried on https, then http, and shot once. A name and its URL are one page and are taken once.

### What is stored

What Chrome saw of each page is in its row: headers, TLS, technologies, console and network log. See the `shots` row in [commands/shots.md](commands/shots.md). It is read from events Chrome sends anyway.

- `export -format html` embeds each picture, 560 pixels wide, in the one file.
- The PNG goes to `DIR/scheme_host_port.png`.
- A 64-bit perceptual hash goes with it: `p:` and 16 hex digits, a discrete cosine transform of the picture, as `pHash` is.
- The HTML export groups pages whose hashes are at most 10 bits apart from any member of the group. So thirty copies of one login portal are one row, and a login form, the nginx default page and an admin page are three.
- A hash from an earlier run has no `p:` and is not compared with these.

A page's images, scripts and styles each count against `-max-requests`. When too few are left, Chrome is refused them, no image is saved, and a note says what the page needs and what was left:

```
screenshot of URL not taken: the page needs about 26 requests and 8 were left (raise -max-requests)
```

The figure is how many requests the page made when it was cut short.

A run starts one Chrome and opens up to 6 tabs in it at once (`-tabs N`). Each page is a tab, not a browser.

### The gallery

`azhaq gallery` (`internal/gallery`) is the interactive view of those rows.

- It opens each workspace read-only.
- It reads every `azhaq-shots` screenshot row once into an index. The index holds a page's URL, title, status, technologies, headers as text, hash and file paths. The newest row of a URL stands for it.
- It groups the hashes with the same rule as the HTML export (`shotcol.Cluster`, 10 bits), and sorts the pages once per order. So a filter is a pass over memory.
- The long parts of a row, the network log and console, stay in the database until a detail view reads them.
- The text of kept pages (`-shot-html`) is read into the search in the background.
- Pictures are found from the row's `file_path`, `file`, or beside the database. Only a PNG or JPEG is served. Thumbnails are made on first request and kept in memory.
- The page and its script and style are embedded (`go:embed`) and served from the same address. A policy lets the browser load nothing else.

The package has no HTTP client and opens no connection but the one it listens on. A test drives every endpoint with the pages' URLs pointing at a counting listener, and asserts it was never reached.

## Ports

`-ports` is active. The targets given are its scope unless `-allow` or `-scope` names one.

### The TCP scan

It scans hosts in scope with full TCP connects. So it needs no root, and it leaves complete handshakes in the target's logs, like `naabu -scan-type c`. The scan type is the scanner's `Detect` and dial functions. There is no raw scan.

- **Ports.** The lists are nmap's top 100 or top 1000 TCP ports, as naabu ships them, `full`, or ranges.
- **Rate.** Connection attempts share one rate across all hosts. `-port-rate` sets it, 1500 per second by default, which is naabu's for a connect scan. This machine's loopback is not paced unless a rate is given.
- **Concurrency.** As many connects are in flight as the rate allows, up to 20,000 and the process's file limit (`-port-workers`). Each connect gets 1.5 seconds (`-port-timeout`).
- **Addresses.** A name resolves to at most two IPv4 and two IPv6 addresses, with the A and AAAA queries only. `-port-all-ips` takes all, and `-port-ip 4|6` takes one family. Each address is scanned once, however many names point to it.
- **Order.** The ports of a host are asked in tiers with `-port-order random`: nmap's top 100, the rest of its top 1000, and the others. Each tier is shuffled by a seed.
- **Retries.** A port that did not answer is asked again by the rule of `-port-retries`.
- **Discovery.** `-port-discover first|only` asks each address a connect to 80 and 443 first.
- **CDN and WAF ranges.** An address in one gets ports 80, 443, 8080 and 8443 only, because the edge answers for thousands of customers. `-port-cdn-full` lifts that.

A `Prefix` seed is scanned by `azhaq-ports` itself. It goes address by address in blocks of 256, without expanding the prefix into seeds or asking reverse DNS. So a range has no size cap. The addresses that answer are followed by the other collectors.

### Reading an open port

An open port is read for 1.5 seconds. The first line a service sends names it, such as `SSH-2.0-…`, `220 … ESMTP`, a Telnet option negotiation or an IRC `NOTICE AUTH`. Binary greetings are marked as such.

Ports that stay silent or answer like HTTP become URLs for `azhaq-http`, HTTPS first.

The greeting and the HTTP head (`Server`, `X-Powered-By`) also give `product` and `version`. For a web port whose head names no product, or refused the HEAD with a 405 or 501, there is one more request. It is a `GET /` for a small JSON or text body, or an HTML page's title and generator. The code is in `internal/portscan/services.go`.

### Identifying a silent port

A port that stays silent is identified by what it answers. The code is in `internal/portscan/identify.go`. The protocols are in `proto_db.go`, `proto_msg.go`, `proto_dir.go` and `proto_net.go`. Each is written from its public specification, named in a comment.

Every step is a connect that is paced, counted by `fetch.Take` and recorded in the ledger. The steps are:

1. The request of a protocol whose usual port this is, on the connection already open.
2. The `HEAD /`.
3. For an answer that is not text, a TLS handshake. A greeting inside the tunnel is read before the `HEAD`, so IMAPS, POP3S, SMTPS and LDAPS are named.
4. One request of each of the remaining protocols, on a connection of its own, the likeliest first.

The protocols of step 4, in order, are:

Redis, PostgreSQL, MongoDB, memcached, MQTT, AMQP, DNS over TCP, LDAP, SMB, SQL Server, Kafka, RDP, ZooKeeper, Cassandra, Oracle TNS, SIP, RTSP, SOCKS5, X11, STOMP and XMPP.

#### The window of protocols

- A window of them is asked at a time: 3, then 6, then 12. So a port that answers none costs three waits and not one for each.
- The window is as wide as the scan's free workers allow. `identify.go` takes up to 11 beside the port's own and gives them back when the port is named. So a sweep that is busy asks them one at a time.
- Of the protocols that answer, the first in the list is the port's, whichever answered sooner. One that has answered calls off the later ones of its window.
- The first answer a protocol's reader recognises ends it.

#### Waiting for the `HEAD`

A `HEAD` that has not been answered after half a second, or twenty round trips if that is longer, is waited on to the end of its wait. Beside it, the TLS handshake and the list are asked:

- The handshake starts at once.
- The list starts a quarter of a second later, or eight round trips if that is longer. So a TLS server calls it off before it connects.
- A protocol of the list that answers ends the wait for the `HEAD`.
- A `HEAD` that answers in time is the port's, whatever the others found.

All of it counts the same connects. So a quick service may cost a few more than one asked down the list in turn.

#### Limits

- An open port costs at most 24 connects after the first.
- A request waits twenty round trips for its answer: at least half a second, at most the banner wait.
- After six open ports of one address that no request could name, the rest of that address's silent ports are not run down the list. The row's `unprobed` and the summary count them. A firewall that accepts every connect would otherwise cost thousands.
- A request carries no credential and changes nothing.
- The raw printing ports, 9100 to 9107, are never asked anything.
- A port that closes the connection without a word is `tcpwrapped`.

### The UDP scan

`-ports-udp` (`ports -udp`, `-pu`) asks UDP ports on the same addresses (`internal/portscan/udp.go`). Each port gets one datagram on a connected socket. The datagram is the harmless request of the protocol the port usually carries. The code is in `udp_proto.go` and `udp_proto2.go`. The protocols are:

DNS, NTP, SNMP v1 and v3, SSDP, mDNS, NetBIOS, IKE, STUN, memcached, BACnet, CoAP, TFTP, rpcbind, the SQL Server Browser, SIP, NAT-PMP, Ubiquiti discovery and ASF-RMCP.

For any other port, the datagrams are, in order:

1. a DNS query;
2. an SNMP get;
3. memcached's version;
4. an empty datagram.

The kernel turns an ICMP port unreachable into `ECONNREFUSED`. TFTP answers from a port of its own. So it is read on a socket that is not connected. On Linux that socket uses `IP_RECVERR`, so a refusal still reaches it.

What a result means:

- A reply is `open`, with what it names.
- A refusal is `closed`. Only an ICMP unreachable for that port says so. Silence never does.
- A port that stayed silent is asked again, every way its protocol has, before it is `open|filtered`.

A host that refused some ports and answered nothing on a few others is probably rate-limiting its ICMP replies. Linux sends about one a second. Up to 80 such silent ports are asked again one at a time at that pace. More are left `open|filtered`, and counted in `udp_limited` and the summary. Loopback is not rate-limited and is not paced.

Each datagram takes `fetch.Take`, is paced and goes in the ledger as `udp`. An address in a CDN or WAF range is not asked.

The `ports` row keeps these fields:

- `udp_open`, `udp_open_filtered`, `udp_closed`, `udp_scanned` and `udp_limited`;
- `udp_unlisted`: silent ports past 64 on one address, which `udp_services` then leaves out;
- `udp_services`.

The range row counts the addresses of a range that answered no UDP port, instead of a row each. The fields are `udp_silent_addresses` and `udp_silent_ports`.

## Historical URLs

`azhaq-urls` asks every archive at once for the URLs of a domain. It asks for its subdomains too, unless the run asks for the host alone. `urls` asks for the host alone by default, as gau does. `run` asks for the subdomains. It records each archive's count, pages, time and error.

### The archives

- **The Wayback Machine's CDX API:** page by page, with `showNumPages` and then each page, one request per second.
- **Common Crawl:** the newest index, paged the same way.
- **AlienVault OTX:** the URL list, 500 per page.
- **urlscan.io:** the search, 100 per page. A key from the provider file raises the limits.
- **arquivo.pt:** one request. It often serves what the Wayback Machine refuses.

### Retries and limits

A 429 or 503 is asked again after the server's `Retry-After`, in seconds or as a date, however long it is. When it names none, the waits are 2, 5, 10, 20 and then 30 seconds. This goes on for as long as the archive's time and the run's `-timeout` allow. The archive's time is `-urls-timeout`, 3 minutes.

A network error, such as a refused or dropped connection, is asked again 3 times with the same waits. `-urls-retries N` makes both a count instead.

A wait longer than the time left ends the request at once, with the reason. It does not run to the deadline and end in a bare timeout:

```
failed after 2 tries, 429 Too Many Requests, Retry-After 2m0s; the 2m0s to wait is more than the 45s left
```

A source that still fails stops and keeps the pages it read. It is reported with its tries and the server's words, such as `failed after 4 tries, 429 Too Many Requests`. Its row has `requests`, `retried` and `waited_seconds`. The summary says what each archive gave.

- Each source has 3 minutes (`-urls-timeout`) and 50 pages (`-urls-pages`). A source that stops at the page limit is marked `capped`.
- There is a pause between a source's requests (`-urls-pause`).
- The run's own `-timeout` ends the sources a few seconds before it. So their summary is still recorded, marked as cut short.

### Filters

The Wayback Machine, Common Crawl and arquivo.pt are sent the status, type and date filters in the query, as gau sends them. The flags are `-mc`, `-fc`, `-mt`, `-ft`, `-from` and `-to`. urlscan.io takes dates in its query and judges the status and type it records for each page; OTX judges its `httpcode`. A status that is not recorded is not matched by `-mc` and not named by `-fc`. OTX takes no type or date.

An archive that cannot apply a filter is asked all the same, and its URLs are kept unfiltered, as gau keeps them. Its row in the summary says `unfiltered` and by which flags, and a note gives the count.

OTX is asked as a hostname for a name with a subdomain. For `-subs` it is asked as the registered domain, as gau does.

### Failures

- Any failed source marks the result `degraded`. So a refused archive never reads as "no URLs".
- A 200 whose body is an error is a refusal too. That covers a quota line and a JSON error. An example is `web.archive.org answered 200 with an error, not URLs: …`.
- An empty answer, or Common Crawl's `No Captures found`, is not a refusal.

### What is kept

The URLs are grouped by template. Pages are listed first, and at most 40 of them go on as hints. The scheduler requests the hints after the application's own pages.

Static assets are listed after the pages, marked `asset`, and never requested. A URL is an asset when:

- it is a file by its extension;
- its extension sits on an earlier path segment, such as `/x_original.png/<hash>`;
- an archive cut it short of its extension, such as `photo.?123`;
- it is on a host whose first label says it serves media, such as `photos`, `images`, `static`, `cdn` or `fonts`.

URLs are normalized and deduplicated. They are kept when they belong to the domain, meaning the host alone, or its subdomains too.

A URL on the domain that is junk is left out and counted by reason in the summary's `junk`. Junk covers:

- a scanner's payload or probe kept by an archive. Among them are a NUL byte, and a query that is only punctuation or a dot and an extension, such as `?.` or `?.tst`;
- a script's `NaN`;
- a link cut at its sentence's end.

`-urls-blacklist` and `-urls-fp` leave some out by extension and by host and path.

`-urls FILE` receives all of the URLs, and is written whatever ended the run. The `urls` command hands the collector a function that is called for each new URL as its page arrives. That is how it prints before the slowest archive has answered. `-urls-raw` hands it every row as the archive gave it.

The graph receives the summary and one URL per template. For example, `/product?id={v}` stands for every product page. Parameters, API routes and server-side pages come first, at most 200 per domain. The first 40 are fetched when the run is not passive. Static assets are counted and left out of the graph.

## Storage

The graph lives in SQLite through `modernc.org/sqlite`, a pure-Go driver, so the binary builds without CGO. Each run gets its own file unless `-db` or `AZHAQ_DB` names one.

Every run has its own ID, and the store records which entities and edges each run saw. `azhaq diff` compares two runs from that record.

### Workspaces

A database can hold many runs. `-db FILE` on every run of a target makes it a workspace.

- Work is deduplicated within a run, not across runs, so each run collects afresh.
- Reads during a run see only that run's entities, observations and edges.
- `export` sees all of them, with their first and last sighting.
- After a run into a workspace, and with `azhaq diff -db FILE`, the last two runs are compared.

### What a diff compares

Diffs compare facts, not bytes. These are left out:

- body hashes and sizes;
- response times;
- the address that answered;
- the session a run was given;
- each subdomain source's timing;
- response header values, such as rate-limit counters and request IDs.

Header names, statuses, titles and everything else count.

Each database records the seeds it was run with. After a run, the CLI diffs against the previous run of the same seeds in the current directory, tracked in `.azhaq-index`. `azhaq diff` on two runs with different seeds says so before the result.

## The map

`azhaq run` prints the graph as a ranked map: the seed host, live application pages, auth-gated URLs, APIs, other pages, then hints and fan-out. Each URL row has a coverage and a role.

[Concepts](CONCEPTS.md) defines the coverage values (`visited`, `catchall`, `error`, `gone`, `hint`, `skipped` and `capped`), the kinds of URL and the host statuses. Two coverage rules are specific to the engine:

- `hint` also covers a route that scripts call only with POST or PUT, whose GET answers like an unknown path. It also covers a route only scripts name, with no GET call among them, whose GET answers 404.
- `capped` also covers a URL left over because its origin stopped answering.

Dead, wildcard and unresolved names are folded into one summary line each.

Routes list their methods. Below the row, each operation is listed with its query names and body fields, from API descriptions and from the calls scripts make.

### GraphQL

A GraphQL endpoint read with `-graphql` keeps the whole introspection result: types, fields, arguments, input objects, enums and directives.

- Its row lists each query, mutation and subscription with its signature, such as `query pastes(public: Boolean, limit: Int): [PasteObject]`.
- `azhaq export -format graphql` or `-format sdl` writes the schema.
- A run that found an endpoint and did not introspect it suggests the run that would. That happens with no `-graphql`, or when its host is outside the scope: `next: azhaq run -url ORIGIN/ -graphql -allow HOST …`.

### What is requested

A found URL is requested with GET when all of these hold:

- it is on the run's hosts and in scope;
- it has no unfilled parameter;
- no `-deny-path` rule matches its path or query.

A name decides nothing: azhaq cannot know what a GET does on the server, so `/logout`, `/createdb` and `?action=delete` are requested like any other URL. A URL a `-deny-path` rule matches is kept as `skipped`, with the rule, and listed under `skipped` in the summary, whatever found it: a link, a script's call, an API description, a wordlist or Chrome.

- API description operations are asked when they are GETs that need no path or query parameter. VAmPI's `GET /createdb`, which resets its database, is asked; `-deny-path '^/createdb$'` keeps it out.
- Path and parameter guesses are sent with a session as without one.

### Junk that never enters the graph

Junk that is not a URL never enters the graph:

- path segments such as `NaN` or `undefined`, from a script that ran without its data;
- links cut short in archives;
- dot segments a browser would have resolved, such as `http://site/..`;
- URLs that carry a scanner's payload, decoded twice since archives keep them encoded. The payloads are path traversal, `/etc/passwd`, command or template injection, SQL, `<script>`, and out-of-band callback domains such as `oast.live`;
- a scanner's own marks that an archive kept. These are its test files and tagged parameters, such as `acunetix_xsl_inclusion_test.xsl`, `netsparker(0).txt`, `?invicti=`, `nessus_test`, `bxss.me` and `xss.rocks`;
- a random-named executable at the root, such as `/7zSo1DIz.exe`. The name is letters and digits with a digit and the case changing twice. `Setup64.exe` and `winrar.exe` stay (`webextract.Payload`).

Nothing can replay what is not stored.

### What a run keeps for `azhaq resume`

A run keeps the answers it gets (`responses` in the workspace, bodies gzipped) and the guesses `dirs` made. It also keeps the owner of each piece of once-per-run work, such as the built-in path sweep of an origin (`catalog.Claim`).

`azhaq resume` reads them back. What the stopped run asked is not asked again or counted, and the same task does the same sweep. They are dropped once the run has nothing left to resume.

### Request headers and addresses

- Requests to targets carry a current browser's User-Agent, because CDN bot managers hold other requests open without an answer.
- Requests connect to the addresses the run's own resolver found for the name. IPv6 goes first where the machine has a route for it, and IPv4 alongside after 300 ms. So `host_ip` is always one of the name's addresses.
- Third-party sources get `azhaq/VERSION` as User-Agent.
- A wordlist sweep (`dirs`, `fuzz`) sends ffuf's headers besides: no `Accept` (`fetch.ApplySweepHeaders`). So a server that negotiates its answer by it gives the size ffuf counts.

### Rows and forms

Rows that share a URL template are folded into one line with a count.

Forms appear indented under the first row that has them. A form shows its method, its action, `multipart` for a multipart POST, and its field names. The query names of the URL itself follow. The query names of a page's links are on the links' rows.

- A form whose action is empty submits to its own page.
- A form whose action is `#` submits to the page's `<base href>`, or to its own page without one.
- Links and actions resolve against `<base href>` as browsers do. On a route after a `#`, the page is the app's front page.

`azhaq export` keeps every entity unfolded and adds the fields `template`, `methods`, `params` and `forms`.

## Connectors

Data Azhaq should not collect itself, such as paid internet indexes, comes in through connectors. A connector is a separate program that reads seeds on stdin and writes JSONL facts on stdout. It runs out of process, so its SDK, API keys and terms of service never become part of Azhaq. See [CONNECTOR.md](CONNECTOR.md).

## Design choices

**In-process collectors, no wrapped tools.**

- Collectors speak their protocols directly, or use permissively licensed Go libraries in-process. These are subfinder's source packages for subdomain sources, miekg/dns for DNS, lib/pq for crt.sh's PostgreSQL, and wappalyzergo's matcher and cdncheck for fingerprints.
- Azhaq never shells out to subfinder, dnsx or similar tools. So every fact lands in one graph with its source.
- CI fails on GPL, AGPL, SSPL or unknown licenses.

**Go.**

- Recon is I/O-bound. Go gives one static binary, cheap concurrency and a small memory footprint. It embeds easily as a library in a worker process.
- Start-up work is kept small. The CDN and WAF ranges are read the first time an address is checked (`internal/cdnranges`). The patterns of `internal/webextract` compile when first used. So `azhaq version` runs in about 16 MB.

**A browser only when asked.**

- JavaScript routes are extracted from script text, which covers bundled single-page apps.
- `-browser`, `-screenshots` and `-login` drive a Chrome already installed on the machine. Azhaq downloads none, and that Chrome saves nothing to disk.
- Chrome is held to the run's scope and budget like every other request.

**Map only.** Azhaq records what exists. It sends no payloads and does not test for vulnerabilities.

Requests to a target are GETs, except these:

- Chrome sends GET, HEAD and CORS preflights (OPTIONS) for what a page loads.
- `crawl -submit-forms` sends POST forms, which change data.
- `params -X` sends names in a body.
- `probe -x`, `-body` and `-rr` send the methods, body or request you give.
- The sign-in tab of `-login` and `-role-login` sends every method until the session is read. That is its own sign-in request and whatever else the page's scripts send meanwhile.
- GraphQL introspection with `-graphql` is a POST.
- `-browser-writes` and `roles -replay-writes` send what they are asked for.
- `ports` sends connects, one `HEAD /` or protocol request, and UDP datagrams.
- `azhaq fuzz` sends the method and body you give it, with your wordlist's words in them.

The requests of `crawl -submit-forms`, `params -X` and `probe -x`, `-body` and `-rr` can change data on the target. They are counted, paced and in the ledger, and the summary says they were sent.

The writes a page's scripts would send are mapped and listed, not sent. Operations read from an API description or a script call are mapped with their method and fields. Only the parameterless GETs among them are asked.

**Every outcome said.**

- Each command ends with a summary. It says what failed and whether it is worth retrying, which targets never answered, what was not requested and why, and the limit that stopped the work.
- The exit code says the same: 0 complete, 3 finished with failures, 4 stopped by a limit. So a script or an assistant never has to guess whether an empty result is an honest zero.

## Limitations

- Requests to a target are limited by concurrency per host (10 by default, `-host-parallel`) and an optional delay. Path guessing, parameter discovery and port scans also have a rate. Third-party sources and DNS resolvers have rate limits.
- Organization seeds rarely expand, because public RDAP has no search by organization name.
- Routes built at run time from anything but constants, template literals and variables assigned once are seen only with `-browser`. Examples are user input, server responses and functions of several variables. Only the routes a page requests while it loads are seen, unless `-interact` clicks its buttons and menus.
- Routes only the server knows, such as admin APIs no page mentions, are found only by the path sweep or an API description.
- One SQLite file holds a run, written by the run's own process. Workers send their results to it rather than writing a shared store.

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
  cdnranges/              CDN, WAF and cloud address ranges, read on first use
  dnsr/                   resolver pool and wildcard detection
  fetch/                  shared HTTP client, request budget and pace, kill switch
  fingerprint/            technologies, CDN ranges, favicon hash
  fuzz/                   the engine of azhaq fuzz
  hunt/                   the ranking behind azhaq hunt
  ledger/                 the hash-chained record of what a run sent
  portscan/               TCP and UDP port scans, services, products and versions
  limit/                  rate limits per host, source or resolver
  normalize/              seed and hostname normalization
  webextract/             HTML and JavaScript URL extraction
fixtures/                 inputs for tests and the demo
```
