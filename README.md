# Azhaq

Azhaq is a reconnaissance engine written in Go. Give it a URL, a domain, a list of hosts, an organization name or a cloud asset inventory, and it maps what is reachable from there: hosts, web services and the technologies behind them, URLs, forms, API routes and operations, DNS records, certificates, historical URLs and registration data. Everything goes into one SQLite graph, deduplicated across sources. Running it again shows what changed.

It maps and does not attack: no payloads, no fuzzing, no vulnerability checks.

## Why

A typical recon pipeline chains several tools (a subdomain finder, an HTTP prober, a crawler, an archive fetcher) and ends with separate lists that overlap. Azhaq does the same collection natively and keeps one graph:

- a hostname seen by CT logs, DNS, a crawl and a TLS certificate is one node, with all four observations attached;
- a second run against the same target prints a diff instead of a new dump;
- it is a single static binary with no external tools, no browser and no CGO.

## Install

Download a binary for Linux, macOS or Windows from the [releases](https://github.com/trannghiach/azhaq/releases) (checksums and SBOMs alongside), or:

```
go install github.com/trannghiach/azhaq/cmd/azhaq@latest      # Go 1.26 or newer
docker run --rm -v "$PWD:/work" -u "$(id -u)" ghcr.io/trannghiach/azhaq run -domain example.com -passive
```

or from a clone: `go build -o azhaq ./cmd/azhaq`.

## Usage

Only scan systems you are authorized to test.

```
azhaq run -url https://app.example.com/      # map an application and its domain
azhaq run -domain example.com -passive       # subdomains, without touching the hosts
azhaq run -list hosts.txt -probe             # one line per web service, like httpx
azhaq run -domain example.com -passive -urls urls.txt   # also every archived URL, like gau
```

`-probe` resolves and fetches each target once and prints status, title, technologies, CDN, address and favicon hash:

```
probe
  https://ginandjuice.shop/ [200] [Home - Gin & Juice Shop] [Amazon ALB,Amazon Web Services] [cloud:aws] [34.249.203.140] [favicon:1165564288]
  http://rest.vulnweb.com/ [200] [Invicti Vulnerable REST API] [Apache HTTP Server:2.4.25,Debian,PHP:7.1.26] [cloud:aws] [18.215.71.186]
```

Try it offline against a built-in fixture:

```
$ azhaq run -demo
...
map
  IPAddress 127.0.0.1  target  addr
  URL http://127.0.0.1:43905/  target  visited  app  status=200 title=Azhaq fixture
  URL http://127.0.0.1:43905/api/status  target  visited  api  status=200 via=paths
  URL http://127.0.0.1:43905/app.js  target  visited  script  status=200
  URL http://127.0.0.1:43905/auth  target  visited  page  status=200 title=Auth
  URL http://127.0.0.1:43905/login  target  visited  page  status=200 title=Login via=paths
      form GET /auth
entities=6 observations=12 edges=9 errors=0 degraded=0
```

Each URL row says whether it was `visited`, only found (`hint`), or answered with the page every unknown path gets (`catchall`, typical of single-page apps), followed by a role such as `app`, `auth` (401), `forbidden` (403), `api` or `script`. Pages that differ only by an ID are folded into one template row, for example `/catalog/product?productId={n}  (18 urls)`. Forms are listed under the page that has them. [The map](docs/ARCHITECTURE.md#the-map) has the details.

Common options:

| Option | Effect |
| --- | --- |
| `-domain D`, `-org NAME`, `-cloud FILE`, `-in seeds.jsonl` | start from a domain, an organization, a cloud inventory or a list of seeds |
| `-list FILE` | targets one per line (`-` for stdin): a URL is fetched as given, a host over HTTPS then HTTP, `host:port` or an IP address over HTTPS falling back to HTTP |
| `-probe` | only resolve and fetch the targets themselves: no crawl, no enumeration, no redirect or CNAME targets |
| `-web-ports 80,443,8080` | ports to probe on each hostname (default: 443, falling back to 80) |
| `-no-tech` | skip technology fingerprints (about 30 MB of memory) |
| `-urls FILE` | write every historical URL found for the run's domains, one per line (what gau prints) |
| `-passive` | only third-party sources and DNS resolution; nothing is sent to the hosts |
| `-allow D` / `-deny D` | keep the run inside, or out of, a domain |
| `-cookie N=V`, `-header 'K: V'` | reuse a session you already have |
| `-paths FILE` | extra paths to probe, merged with the built-in list |
| `-sources A,B`, `-exclude-sources A,B`, `-all-sources` | choose subdomain sources (default: the fast set that needs no key, plus keyed sources you have keys for) |
| `-providers FILE` | API keys per source, in subfinder's `provider-config.yaml` format (default `~/.config/azhaq/providers.yaml`, else subfinder's file) |
| `-resolvers FILE`, `-dns-rate N` | DNS resolvers and queries per second per resolver (default: six public resolvers, 100/s) |
| `-dns-brute FILE`, `-permute` | active: resolve a wordlist under the domain, or variations of names found; both need `-allow` |
| `-graphql` | active: read the schema of GraphQL endpoints with an introspection query; needs `-allow` |
| `-depth N`, `-max-items N`, `-max-names N` | expansion limits (default 4, 2048 work items, 20,000 names resolved) |
| `-parallel N`, `-host-parallel N`, `-delay D`, `-skip A,B` | work in flight (default 16), requests in flight per host (default 4), pause before each request, collectors not to run |
| `-db FILE` | graph file to write (default: a new timestamped file per run); reuse it to keep a workspace of runs |
| `-json` / `-obs` | JSON summary, or the full observation log |

Other commands:

```
azhaq roles  -role anon -role 'user=Authorization: Bearer …' -- -url URL
                                   # one run per session; endpoints whose status differs
azhaq plan   -url URL              # show which collectors would run
azhaq export [-db FILE]            # dump the graph as JSONL
azhaq diff   -a OLD.db -b NEW.db   # compare two runs of the same seeds
azhaq ingest -in facts.jsonl       # load facts from another tool
azhaq bench                        # timing and memory on the fixture
```

### In a pipeline

Each step of the usual chain has a command that reads targets from flags, a file or stdin and writes one result per line (`-json` for JSONL with the field names of the tool it stands in for, `-silent` to drop progress, `-o FILE` to keep a copy):

```
azhaq subs -d example.com -silent | azhaq dns -silent | azhaq probe -silent    # subfinder | dnsx | httpx
azhaq crawl -u https://app.example.com/ -silent                               # katana
azhaq urls -d example.com -silent                                             # gau
azhaq probe -l hosts.txt -json > probe.jsonl                                  # httpx -json fields
```

What a run found exports for the tools that come after it:

```
azhaq export -format targets  > targets.txt   # web services, for nuclei -l
azhaq export -format openapi  > api.json      # API routes as OpenAPI 3, for Burp's API scan, Postman or ZAP
azhaq export -format burp     > scope.json    # a Burp project options file with the hosts in scope
azhaq export -format html     > report.html   # one self-contained page
azhaq export -format urls | hosts             # plain lists
```

### Watching a target over time

Give every run of a target the same `-db` file and it becomes a workspace: each run redoes the work, entities keep the time they were first and last seen, and after each run Azhaq prints what changed since the previous one. `azhaq diff -db FILE` repeats that comparison, and `azhaq export -db FILE` lists everything with its first and last sighting.

```
azhaq run -domain example.com -passive -db example.db    # every day, from cron
azhaq diff -db example.db                                 # what appeared or vanished since the last run
```

### Comparing sessions

`azhaq roles` runs the same target once per session and lists the endpoints whose answer depends on who asks. Azhaq never logs in: you give each role the cookie or header it should send, and a role with none is anonymous.

```
$ azhaq roles -role anon -role "user=Authorization: Bearer $TOKEN" -- -url http://localhost:3000/
roles  anon  user  (12 endpoints differ; databases in azhaq-roles-20261025-181500)
  401 → 200  http://localhost:3000/api/Users
  401 → 200  http://localhost:3000/rest/user/authentication-details
  ...
```

While a run carries a session, it does not request URLs that look like a logout (`/logout`, `/signout`, …), so the session lasts the whole run.

### As a library

The catalog, engine, store and types are public packages, so a worker or a tool of your own can run Azhaq in-process and add collectors of its own (`catalog.Collector`):

```go
st, _ := store.Open("example.db")
cat := catalog.New()
collectors.RegisterAll(cat, nil)
eng := &engine.Engine{Cat: cat, Store: st}
budgets := engine.DefaultBudgets()
budgets.Passive = true
err := eng.RunLocal(ctx, []types.Seed{{Type: types.TypeDomain, Keys: map[string]string{"domain": "example.com"}}}, budgets)
```

The API may still change before 1.0.

## Collectors

| Collector | Input | Collects |
| --- | --- | --- |
| `azhaq-http` | URL, hostname | status, redirect chain, title, technologies (wappalyzer fingerprints), favicon hash (Shodan's `http.favicon.hash`), length, word and line counts, response time, address, headers, cookie names (not values); flags catch-all answers |
| `azhaq-crawl` | URL | same-origin links, forms (including script-driven `data-action` forms), parameter names, links inside JSON responses |
| `azhaq-js` | URL | routes from each page's inline and same-origin scripts, the chunks they import or name in a webpack chunk map, and the app's own files in exposed source maps; paths joined from constants (`"identity/" + API.LOGIN`); GraphQL operation names; tagged as API or page |
| `azhaq-openapi` | URL | operations, methods and parameter names from OpenAPI 3 and Swagger 2 documents (JSON or YAML), including one embedded in a Swagger UI script; never calls them |
| `azhaq-graphql` | URL | GraphQL endpoints, recognised from one GET; with `-graphql` (active), queries, mutations and types through introspection |
| `azhaq-paths` | URL | common paths and API description locations, `robots.txt`, sitemaps; drops catch-all answers |
| `azhaq-dns` | hostname | A/AAAA and CNAME chain through a pool of resolvers, in batches; the CDN, WAF or cloud in front (by address and CNAME); MX, TXT and NS for registrable domains; names that do not resolve or only answer through a wildcard record are marked and never probed |
| `azhaq-tls` | hostname | certificate details and SANs within the same domain |
| `azhaq-subdomains` | domain | hostnames from 50+ passive sources (certificate transparency, search engines, archives, DNS datasets), with each source's count or error recorded |
| `azhaq-dns-brute` | domain | `-dns-brute`: names from a wordlist that resolve, wildcard answers removed |
| `azhaq-permute` | hostname | `-permute`: numbered, prefixed and suffixed variations of live names that resolve |
| `azhaq-urls` | domain | historical URLs of the domain and its subdomains from the Wayback Machine (paged), Common Crawl, AlienVault OTX, urlscan.io (a key from the provider file raises its limits) and arquivo.pt; one row per URL template in the graph, every URL with `-urls FILE`; a source that refuses or rate limits marks the result `degraded` |
| `azhaq-rdap` | domain, organization | registration data and nameservers |
| `azhaq-cloud` | cloud inventory file | domains, hosts and URLs from a local JSON inventory |

Sources Azhaq does not query itself, such as paid search engines like Shodan, can be plugged in as external programs. See [docs/CONNECTOR.md](docs/CONNECTOR.md).

## Benchmark

`go run ./bench` runs Azhaq and the tools it replaces on the same targets: Juice Shop, VAmPI and crAPI in Docker, ginandjuice.shop, and the live names of hackerone.com, tesla.com and vulnweb.com. Latest run (2026-10-25, all 21 checks pass):

| Job | Replaces | Azhaq | Reference |
| --- | --- | --- | --- |
| Live subdomains, 3 domains, no keys | subfinder + dnsx | 516 in 77 s | 504 in 94 s |
| DNS brute force, 5,000 words | dnsx / puredns | 3 of 3 in 39 s | 3 in 69 s |
| Wildcard zone, 3 real names of 50 | dnsx | 3 found, 0 fake | 50 without `-wd` |
| Probing 533 live hosts | httpx | 376 answered, status/title/tech agree on all 376, 114 s | 376 answered, 133 s |
| Known routes: Juice Shop, VAmPI, ginandjuice, crAPI | katana + jsluice | 45/45, 12/12, 3/3, 32/40 | 0/45, 1/12, 2/3, 0/40 |
| Historical URLs, 3 domains | gau | 7,319, including all 2,341 of gau's | 2,341 |
| Memory, Juice Shop | katana | 223 MB (57 MB with `-no-tech`) | 61 MB |

The memory row is a loss: technology fingerprints cost about 170 MB. [bench/README.md](bench/README.md) has what is measured, every table and the caveats (rate-limited archives, the sources that failed).

## Documentation

- [Architecture](docs/ARCHITECTURE.md): data model, scheduling, identity rules, limitations
- [Connector protocol](docs/CONNECTOR.md): feeding external data into the graph

## License

[MIT](LICENSE). Dependencies are MIT, BSD, Apache or Unlicense licensed, and CI checks it. Most subdomain sources are [subfinder](https://github.com/projectdiscovery/subfinder)'s (MIT, ProjectDiscovery), run in-process; technology fingerprints come from [wappalyzergo](https://github.com/projectdiscovery/wappalyzergo), whose passive matcher is included in `internal/wappalyzer` with its regexps compiled on first use, and CDN ranges from [cdncheck](https://github.com/projectdiscovery/cdncheck) (both MIT, ProjectDiscovery).
