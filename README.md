# Azhaq

Azhaq is a reconnaissance engine written in Go. Give it a URL, a domain, a list of hosts, an organization name or a cloud asset inventory, and it maps what is reachable from there: hosts, web services and the technologies behind them, URLs, forms, API routes and operations, DNS records, certificates, historical URLs and registration data. Everything goes into one SQLite graph, deduplicated across sources. Running it again shows what changed.

It maps and does not attack: no payloads, no fuzzing, no vulnerability checks.

## Why

A typical recon pipeline chains several tools (a subdomain finder, an HTTP prober, a crawler, an archive fetcher) and ends with separate lists that overlap. Azhaq does the same collection natively and keeps one graph:

- a hostname seen by CT logs, DNS, a crawl and a TLS certificate is one node, with all four observations attached;
- a second run against the same target prints a diff instead of a new dump;
- it is a single static binary with no external tools and no CGO; screenshots, and pages that only render in a browser, use a Chrome already on the machine, and only when asked.

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
| `-browser` | also load pages in Chrome: the requests their scripts send (a single-page app's API calls) and the links and forms of the rendered page, up to 30 pages a host |
| `-screenshots DIR`, `-tabs N` | a screenshot of each web service's front page, with Chrome or Chromium installed on the machine (`AZHAQ_CHROME` to point at one); the HTML report groups look-alike pages |
| `-asn AS64500`, `-cidr 192.0.2.0/24`, `-max-ips N` | start from networks: an AS's announced prefixes, address ranges (up to 4,096 addresses per run by default), their reverse DNS names, certificates and web services |
| `-scope FILE\|PLATFORM`, `-program NAME` | start from a bug bounty program's scope and stay inside it (see above) |
| `-domain D`, `-org NAME`, `-cloud FILE`, `-in seeds.jsonl` | start from a domain, an organization, a cloud inventory or a list of seeds |
| `-list FILE` | targets one per line (`-` for stdin): a URL is fetched as given, a host over HTTPS then HTTP, `host:port` or an IP address over HTTPS falling back to HTTP |
| `-probe` | only resolve and fetch the targets themselves: no crawl, no enumeration, no redirect or CNAME targets |
| `-web-ports 80,443,8080` | ports to probe on each hostname (default: 443, falling back to 80) |
| `-no-tech` | skip technology fingerprints (about 30 MB of memory) |
| `-urls FILE` | write every historical URL found for the run's domains, one per line (what gau prints) |
| `-urls-timeout D` | time each archive source gets per domain (default 3m); the Wayback Machine's answer for a large domain takes several minutes, and what arrived by then is kept |
| `-passive` | only third-party sources and DNS resolution; nothing is sent to the hosts |
| `-allow D` / `-deny D` | keep the run inside, or out of, a domain |
| `-cookie N=V`, `-header 'K: V'` | reuse a session you already have |
| `-login URL -login-user U -login-pass P` | sign in on a login page with Chrome first (the password may come from `$AZHAQ_LOGIN_PASS`); the cookies the site sets and a token the page stores go with every request |
| `-paths FILE` | extra paths to probe, merged with the built-in list |
| `-sources A,B`, `-exclude-sources A,B`, `-all-sources` | choose subdomain sources (default: the fast set that needs no key, plus keyed sources you have keys for) |
| `-providers FILE` | API keys per source, in subfinder's `provider-config.yaml` format (default `~/.config/azhaq/providers.yaml`, else subfinder's file) |
| `-resolvers FILE`, `-dns-rate N` | DNS resolvers and queries per second per resolver (default: six public resolvers, 100/s) |
| `-dns-brute FILE`, `-permute` | active: resolve a wordlist under the domain, or variations of names found; both need `-allow` |
| `-graphql` | active: read the schema of GraphQL endpoints with an introspection query; needs `-allow` |
| `-dirs FILE`, `-dirs-ext`, `-dirs-depth`, `-dirs-rate`, `-dirs-mc` | active: guess paths on each web service from a wordlist, calibrated against paths that cannot exist; needs `-allow` |
| `-params FILE`, `-params-per-host N`, `-params-rate N` | active: find query parameters pages read but do not link (GET only); needs `-allow` |
| `-ports top-100\|top-1000\|full\|LIST`, `-port-rate N` | active: TCP connect scan of hosts in scope, with banners; open ports that may serve HTTP are probed; needs `-allow` |
| `-depth N`, `-max-items N`, `-max-names N` | expansion limits (default 4, 2048 work items, 20,000 names resolved) |
| `-parallel N`, `-host-parallel N`, `-delay D`, `-skip A,B` | work in flight (default 16), requests in flight per host (default 4), pause before each request, collectors not to run |
| `-max-requests N`, `-rate N`, `-daily-requests N` | requests to targets this run may send, requests per second over all hosts, and requests a day for the program (`-program`, else the run's targets), counted over the runs in `-db`; work the budget stops is left for `azhaq resume` |
| `-db FILE` | graph file to write (default: a new timestamped file per run); reuse it to keep a workspace of runs |
| `-json` / `-obs` | JSON summary, or the full observation log |

Other commands:

```
azhaq roles  -role anon -role 'user=Authorization: Bearer …' -- -url URL
azhaq roles  -login URL -role anon -role-login 'member=USER:PASS' -role-login 'owner=USER:PASS' -- -url URL
                                   # one run per session; endpoints whose status differs
azhaq resume -db FILE              # continue a run that was interrupted or stopped by a budget
azhaq worker -server URL -token T  # take work from a run started with -serve ADDR
azhaq plan   -url URL              # show which collectors would run
azhaq export [-db FILE]            # dump the graph as JSONL
azhaq diff   -a OLD.db -b NEW.db   # compare two runs of the same seeds
azhaq ingest -in facts.jsonl       # load facts from another tool
azhaq bench                        # timing and memory on the fixture
```

### In a pipeline

Each step of the usual chain has a command that reads targets from flags, a file or stdin and writes one result per line (`-json` for JSONL, with the field names of subfinder, dnsx and httpx where those apply; `-silent` to drop progress; `-o FILE` to keep a copy):

```
azhaq subs -d example.com -silent | azhaq dns -silent | azhaq probe -silent    # subfinder | dnsx | httpx
azhaq crawl -u https://app.example.com/ -silent                               # katana
azhaq urls -d example.com -silent                                             # gau
azhaq ports -host scanme.nmap.org -p top-1000 -silent                         # naabu (connect scan)
azhaq dirs -u https://app.example.com/ -w common.txt -e php,bak              # ffuf -ac, feroxbuster with -depth
azhaq params -u https://app.example.com/search -w burp-parameter-names.txt    # arjun (GET)
azhaq asn -a AS64500 -silent                                                  # asnmap (RIPEstat, no key)
azhaq shots -l hosts.txt -dir screenshots                                     # gowitness
azhaq probe -l hosts.txt -json > probe.jsonl                                  # httpx -json fields
```

What a run found exports for the tools that come after it:

```
azhaq export -format targets  > targets.txt   # web services, for nuclei -l
azhaq export -format openapi  > api.json      # API routes as OpenAPI 3, for Burp's API scan, Postman or ZAP
azhaq export -format burp     > scope.json    # a Burp project options file with the hosts in scope
azhaq export -format html     > report.html   # one self-contained page
azhaq export -format graphml  > graph.graphml # Gephi, yEd, Cytoscape
azhaq export -format secrets                  # credentials found in scripts, worst first
azhaq export -format urls | hosts             # plain lists
```

### A bug bounty program

`-scope` takes a program's scope and makes it the run's: wildcards are enumerated as domains, hosts and URLs are probed as given, out-of-scope entries are excluded, and no request goes to a host outside it, not even a redirect target. It reads HackerOne's scope CSV export, a Burp project options file, plain lines (`*.example.com`, `app.example.org:8443`, `10.0.0.0/24`, `!excluded.example.com`), or the current scope of any public program on HackerOne, Bugcrowd, Intigriti or YesWeHack, from [bounty-targets-data](https://github.com/arkadiyt/bounty-targets-data):

```
azhaq scope -scope hackerone -program security          # see what a run would take
azhaq run -scope hackerone -program security -db h1.db
azhaq run -scope acme-scope.csv -ports top-100 -dirs common.txt -db acme.db
```

Entries a run cannot use (mobile apps, source code, wildcards outside the leftmost label) are listed as skipped.

### Watching a target over time

Give every run of a target the same `-db` file and it becomes a workspace: each run redoes the work, entities keep the time they were first and last seen, and after each run Azhaq prints what changed since the previous one. `azhaq watch` runs that for you and reports only what a person watching cares about: new names that resolve, new web services, new URLs, open ports that changed, and what disappeared. It posts to Slack, Discord, Telegram or any JSON webhook, and stays quiet when nothing changed.

```
azhaq watch -db acme.db -notify https://hooks.slack.com/services/… -- -scope acme-scope.csv    # once, from cron
azhaq watch -db acme.db -every 24h -notify "https://api.telegram.org/bot…/sendMessage?chat_id=…" -- -domain acme.com
azhaq new -db acme.db -since 72h        # what the workspace first saw in the last three days
azhaq diff -db acme.db                  # the full difference between the last two runs
```

### Budgets and resuming

A program's rules often cap the traffic: `-rate 10` paces requests to its targets, `-max-requests 5000` stops a run after that many, and `-daily-requests 20000 -program NAME` spreads a day's allowance over the runs in a workspace (`-db`). Work a budget stops is not lost: `azhaq resume -db FILE` continues the run where it stopped, and so it does after Ctrl-C or a crash.

```
$ azhaq run -url https://app.example.com/ -db app.db -max-requests 2000
azhaq: 412 tasks left; azhaq resume -db app.db continues the run
$ azhaq resume -db app.db                  # the stored options, a fresh -max-requests 2000
$ azhaq resume -db app.db -cookie sid=…    # sessions are not stored: give them again
```

A run stopped and resumed finds what an uninterrupted one does: on Juice Shop, 40 requests per process and 46 resumes give the same 147 URLs as one run, and so does a run killed with `kill -9` and resumed.

### Workers

One run can use several machines (more addresses, more bandwidth): start it with `-serve`, and point `azhaq worker` processes at it. The run keeps the database, the scope and the budgets, and lends workers the tasks that contact targets; each worker sends back what it found.

```
$ azhaq run -scope h1.csv -dirs common.txt -allow example.com -db x.db -parallel 4 -serve 10.0.0.5:7777
azhaq: workers can join with: AZHAQ_WORKER_TOKEN=… azhaq worker -server http://10.0.0.5:7777
$ AZHAQ_WORKER_TOKEN=… azhaq worker -server http://10.0.0.5:7777 -slots 8     # on each worker
```

The token and the run's session headers travel over that connection: keep it on a private network or an SSH tunnel. On Juice Shop, a run with two workers maps the same 147 URLs as one process.

### Comparing sessions

`azhaq roles` runs the same target once per session and lists the endpoints whose answer depends on who asks. Give each role the cookie or header it should send (`-role`), or an account to sign in with (`-role-login`, on the `-login` page); a role with neither is anonymous.

```
$ azhaq roles -role anon -role "user=Authorization: Bearer $TOKEN" -- -url http://localhost:3000/
roles  anon  user  (12 endpoints differ; databases in azhaq-roles-20261025-181500)
  401 → 200  http://localhost:3000/api/Users
  401 → 200  http://localhost:3000/rest/user/authentication-details
  ...

$ azhaq roles -login http://localhost:8080/login -role anon \
    -role-login member=member@acme.test:$PW -role-login owner=owner@acme.test:$PW -- -url http://localhost:8080/
roles  anon  member  owner  (7 endpoints differ; databases in azhaq-roles-20261025-201200)
  401 → 403 → 200  http://localhost:8080/api/orgs/1/billing
  401 → 403 → 403  http://localhost:8080/api/orgs/2/settings
  ...
```

Signing in (`-login`) opens the page in Chrome, waits for a password field (a single-page app draws its form late), fills the field before it and the password the way typing would, submits the form, and waits for the page to move on. The cookies the site set and a JSON Web Token the page stored in `localStorage` or `sessionStorage` then go with every request, and Chrome keeps the session for `-browser`. A form still there after submitting is an error: wrong credentials, a CAPTCHA or a second step. Logins that need more than a user name and a password (multi-step, one-time codes, SSO) take `-cookie` or `-header`.

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
| `azhaq-js` | URL | credentials in scripts (cloud and SaaS keys, tokens, webhooks, private keys, build variables, values assigned to secret-sounding names); routes from each page's inline and same-origin scripts, the chunks they import or name in a webpack chunk map, and the app's own files in exposed source maps; paths joined from constants (`"identity/" + API.LOGIN`); GraphQL operation names; tagged as API or page |
| `azhaq-openapi` | URL | operations, methods and parameter names from OpenAPI 3 and Swagger 2 documents (JSON or YAML), including one embedded in a Swagger UI script; never calls them |
| `azhaq-graphql` | URL | GraphQL endpoints, recognised from one GET; with `-graphql` (active), queries, mutations and types through introspection |
| `azhaq-paths` | URL | common paths and API description locations, `robots.txt`, sitemaps; drops catch-all answers |
| `azhaq-dns` | hostname | A/AAAA and CNAME chain through a pool of resolvers, in batches; the CDN, WAF or cloud in front (by address and CNAME); MX, TXT and NS for registrable domains; names that do not resolve or only answer through a wildcard record are marked and never probed |
| `azhaq-tls` | hostname | certificate details and SANs within the same domain |
| `azhaq-subdomains` | domain | hostnames from 50+ passive sources (certificate transparency, search engines, archives, DNS datasets), with each source's count or error recorded |
| `azhaq-dns-brute` | domain | `-dns-brute`: names from a wordlist that resolve, wildcard answers removed |
| `azhaq-permute` | hostname | `-permute`: numbered, prefixed and suffixed variations of live names that resolve |
| `azhaq-dirs` | URL | `-dirs`: paths from a wordlist (and word.ext) that answer differently from a path that cannot exist, directories swept to `-dirs-depth` |
| `azhaq-params` | URL | `-params`: query parameters a page reads, found by sending names in groups with random values and halving the groups that change the answer (status, size, a value reflected back); GET only |
| `azhaq-asn`, `azhaq-prefix`, `azhaq-ptr` | ASN, prefix, IP | an AS's announced prefixes (RIPEstat), the addresses in a prefix, their reverse DNS names; addresses found this way are probed over HTTP and TLS, and names on their certificates followed |
| `azhaq-render` | URL | `-browser`: pages loaded in Chrome; the same-origin requests they send and the links and forms they render |
| `azhaq-shots` | URL, hostname | `-screenshots`: a PNG of the front page as Chrome renders it, with a perceptual hash to group look-alikes |
| `azhaq-search` | domain | hosts and services Shodan, FOFA and Netlas have seen for the domain (keys `shodan`, `fofa` as `email:key`, `netlas` in the provider file); without keys each is listed as skipped |
| `azhaq-ports` | hostname, IP | `-ports`: open TCP ports by full connect (no root), with the first line each service sends; a CDN or WAF address gets its web ports only; ports that may serve HTTP go to `azhaq-http` |
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
