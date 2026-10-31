# azhaq plan

Show what a run would do and send, without sending anything.

## Synopsis

```
azhaq plan (-url URL | -domain D | -list FILE | -scope … -program P) [run flags]
```

`plan` takes the flags of [`run`](run.md#flags).

## Examples

```
# What a run of one app would do and send
azhaq plan -url https://app.example.com/

# The same for a program's scope, with a path wordlist
azhaq plan -scope bugcrowd -program tesla -dirs words.txt
```

## What it does

`plan` reads the seeds and flags as `run` does, and stops before anything is sent. It prints:

1. The collectors that would run on each seed.
2. The seeds left out of scope.
3. The active techniques you asked for.
4. What is sent to the targets: the GET requests for pages, and besides them each port scan, UDP probe, POST body and sign-in that is planned.
5. The third-party source queries, counted.
6. A bound on the requests to the targets: what each web service costs, and the cap.

## Output

Plain text prints the same parts, one block each. `-json` prints one object.

| Field | Meaning |
| --- | --- |
| `targets` | Each seed, with the collectors that would run on it. |
| `skipped` | The seeds left out of scope. |
| `collectors` | What each collector does, and to whom. |
| `active` | The active techniques asked for. |
| `builtin_paths` | The built-in path checks on each web service. |
| `limits` | The options that bound the run. |
| `sends` | What goes to the targets, one line for each kind. |
| `requests` | What is known of the requests before any is sent. See below. |

`requests` has these fields:

| Field | Meaning |
| --- | --- |
| `source_queries` | Per collector, the queries to third-party sources about the targets listed. See [Details](#source-queries). |
| `source_queries_total` | The sum of `source_queries`. |
| `source_queries_not_counted` | The collectors that do not say which sources they ask before they run. |
| `found_domains_asked` | `true` when domains found on the way would be asked about too. |
| `max_names` | The most names that are looked up. |
| `per_web_service` | What each web service costs before its links, scripts and archived URLs are followed. |
| `cap` | The most requests to the targets. 0 is no cap. |
| `cap_by` | The option that set `cap`: `-max-requests` or `-daily-requests`. |
| `passive` | `true` when nothing goes to the targets. |

## Summary and exit codes

The summary and the exit codes are the shared ones: see [the summary](../OUTPUT.md#the-summary) and [exit codes](../OUTPUT.md#exit-codes).

## Details

### Source queries

- `source_queries` counts one query for each source asked. A source may page through its answer, so a query can take more than one request.
- None of the built-in collectors is in `source_queries_not_counted`. A connector may be.
- `found_domains_asked` is about domains found on the way. They are asked about inside the scope. Without a scope, they are asked about within `-depth` and `-max-items`.

### The requests to the targets are a bound

- The plan gives a bound, not a count. How many names resolve and answer is known only by asking.
- At most `max_names` names are looked up.
- `per_web_service` covers a web service's page, the favicon and the built-in paths. It does not cover what its links, scripts and archived URLs lead to.
- `cap` is set by `cap_by`. With `-daily-requests`, a plan does not take off what the day's runs already spent.

## Flags

<!-- flags:begin plan -->
| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-all-gets` | bool |  | also request found URLs that look like a GET would change something (logout, delete, reset, save…); by default they are listed, not requested |
| `-all-sources` | bool |  | also run slower subdomain sources outside the default set |
| `-allow` | string, repeatable |  | a domain, host or address range the run may touch; with any -allow, nothing else is requested |
| `-asn` | string, repeatable |  | seed an autonomous system: its announced prefixes |
| `-backoff` | bool |  | when a host answers 429 or 503, wait (1 s doubling to 30 s, or its Retry-After) and ask again, up to 3 times; the summary says which hosts did |
| `-browser` | bool |  | also load pages in Chrome: the requests their scripts send and the links of the rendered page (needs Chrome) |
| `-browser-writes` | bool |  | let pages in Chrome send their writes (POST, PUT, DELETE…, beacons, forms posted on load) as a user's browser would: they change data on the target; by default Chrome sends only GET, HEAD and OPTIONS outside signing in, and maps the writes it does not send |
| `-chrome` | string |  | the Chrome or Chromium to run (default $AZHAQ_CHROME, else the first found) |
| `-chrome-profile` | string |  | a Chrome user data directory to use and keep: sessions it holds go with the pages (default: a temporary one) |
| `-chrome-proxy` | string |  | send Chrome's own connections through this http or socks5 proxy (default: -proxy, else the environment's); a plain http:// request reaches an http proxy as a proxy request, a page over TLS as a CONNECT tunnel |
| `-cidr` | string, repeatable |  | seed an address range such as 192.0.2.0/24 |
| `-cloud` | string |  | CloudAccount JSON inventory (local file) |
| `-cookie` | string, repeatable |  | Cookie name=value (repeatable; sent as one Cookie header) |
| `-cookie-jar` | bool |  | carry the cookies targets set (Set-Cookie) on the requests that follow, as a browser does; -cookie and -header values go first |
| `-crawl-any-host` | bool |  | follow links to any host, within -allow and -deny (katana's -ns) |
| `-crawl-in` | string, repeatable |  | follow only URLs that match this regex |
| `-crawl-out` | string, repeatable |  | never follow URLs that match this regex |
| `-crawl-scope` | string |  | the hosts a crawl follows links to: rdn (the start host's registrable domain and its subdomains), fqdn (the host only), dn (hosts that name its domain keyword) or a regex on the host (default: rdn for a name, the origin itself for an address) |
| `-daily-requests` | int |  | requests a day to the program's targets (-program, else this run's targets), counted over the runs in -db |
| `-db` | string |  | the workspace, a SQLite file (default: a new azhaq-TIME-PID.db in the current directory, or $AZHAQ_DB; query, show and export read it afterwards) |
| `-delay` | duration |  | pause before each uncached fetch |
| `-demo` | bool |  | run against the built-in fixture server (no internet) |
| `-deny` | string, repeatable |  | a domain, host or address range the run must not touch, even when given as a target |
| `-depth` | int | `4` | max fan-out waves (0 = seed wave only, not unlimited) |
| `-dirs` | string |  | guess paths on each web service from this wordlist, or @common for the built-in one (active; the targets given are the scope unless -allow) |
| `-dirs-depth` | int | `1` | directory levels to sweep; 2 also sweeps directories found |
| `-dirs-ext` | string |  | also try each word with these extensions, comma-separated (php,bak) |
| `-dirs-fc` | string |  | hide these statuses |
| `-dirs-fl` | string |  | hide these line counts |
| `-dirs-fr` | string |  | hide answers whose headers or body match this regular expression |
| `-dirs-fs` | string |  | hide these response sizes |
| `-dirs-fw` | string |  | hide these word counts |
| `-dirs-mc` | string |  | report only these statuses (comma-separated, ranges, or all; default ffuf's: 200-299,301,302,307,401,403,405,500) |
| `-dirs-ml` | string |  | report only these line counts |
| `-dirs-mr` | string |  | report only answers whose headers or body match this regular expression |
| `-dirs-ms` | string |  | report only these response sizes (values and ranges, 100-200) |
| `-dirs-mw` | string |  | report only these word counts |
| `-dirs-rate` | float |  | path guesses per second per host (0: no limit but -dirs-threads, as ffuf) |
| `-dirs-threads` | int | `40` | path guesses in flight per service (as ffuf) |
| `-dns-brute` | string |  | resolve WORD.domain for each word in this file (active; the targets given are the scope unless -allow) |
| `-dns-rate` | float |  | DNS queries per second per resolver (0: no pace but the queries in flight, as dnsx) |
| `-domain` | string, repeatable |  | seed Domain, for subdomain discovery |
| `-exclude-sources` | string |  | subdomain sources never to run, comma-separated |
| `-exec` | string |  | connector command (seeds on stdin, facts on stdout) |
| `-facts` | string |  | JSONL connector facts to ingest before native collectors |
| `-fail-on-capped` | bool |  | exit 4 also when the run hit -depth with hints left |
| `-fail-on-errors` | bool |  | exit 3 on every failure: also fan-out (a source for the domain of a URL) and a source that failed while others answered |
| `-fill-forms` | bool |  | ask the action of each GET form with neutral values in its fields (a search box gets a word): one GET request per form; a form that posts is not sent unless -submit-forms (crawl) |
| `-get-words` | string |  | request found URLs left alone for these words only, comma-separated (exec,import): finer than -all-gets |
| `-graphql` | bool |  | read the schema of GraphQL endpoints with an introspection query (active; the targets given are the scope unless -allow) |
| `-graphql-wordlist` | string |  | extra probe words (one per line), tried and recombined with the built-in ones when a GraphQL endpoint's introspection is off and its schema has to be recovered from validation errors |
| `-header` | string, repeatable |  | extra request header K: V |
| `-host-parallel` | int |  | requests in flight per host (default 10, as katana) |
| `-host-rate` | float |  | requests per second to each host, besides -rate over all (0: none) |
| `-in` | string |  | JSONL seeds |
| `-interact` | bool |  | with -browser: click the buttons, links and menus of each page (up to -interact-clicks) to find what only a click brings; writes a click would send are mapped, not sent, and a click on log out, delete, … is not made |
| `-interact-clicks` | int | `12` | clicks -interact makes on each page |
| `-json` | bool |  | print the map as JSON lines, and the summary as one JSON object on stderr |
| `-kill-file` | string |  | stop all sending, at once, when this file exists, and exit 4; azhaq resume works once it is removed (default DB.stop) |
| `-known-files` | string |  | ask each web service only for its robots.txt and sitemaps and read every entry (all, robotstxt or sitemapxml); replaces the 32 built-in paths |
| `-ledger` | string |  | write every request and connection to a target to this file, a chain of hashes that azhaq ledger -verify checks (default DB.ledger.jsonl next to the workspace; off: none; with a temporary database, only when given) |
| `-list` | string |  | targets, one per line: URL, host, host:port or IP (- for stdin) |
| `-login` | string |  | sign in on this page with Chrome before the run; its cookies and token go with every request (needs -login-user and -login-pass) |
| `-login-pass` | string |  | password for -login (default $AZHAQ_LOGIN_PASS) |
| `-login-user` | string |  | user name or email for -login |
| `-max-body` | int |  | largest response body read from a subdomain source, in bytes (default 33554432), as subfinder -rsr |
| `-max-host-requests` | int |  | requests one host may be sent (0: no cap); the rest of its work is left for azhaq resume |
| `-max-ips` | int | `4096` | addresses expanded from -asn and -cidr prefixes, for the whole run |
| `-max-items` | int |  | max collector invocations (default 2048) |
| `-max-names` | int |  | max hostnames resolved (default 20000) |
| `-max-requests` | int |  | requests to targets this run may send (0: no cap); the work left over is for azhaq resume |
| `-max-response-size` | int |  | bytes read of a page or document (default 2097152; scripts and JSON get 16 MiB) |
| `-max-results` | int |  | most names one paging subdomain source gives (0: no cap), as subfinder -mr |
| `-max-time` | duration |  | wait this long for all subdomain sources of a domain, then go on with what they gave (0: -source-timeout and a short grace bound the wait), as subfinder -max-time |
| `-no-favicon` | bool |  | do not hash the favicon of front pages (one or two requests less per web service) |
| `-no-follow` | bool |  | do not follow redirects: each URL is asked once and its redirect recorded with the Location (httpx's default) |
| `-no-history` | bool |  | do not read or write the name history (names earlier runs found, kept under $AZHAQ_DATA_DIR, else ~/.local/share/azhaq; with -live each is checked by DNS in the run) |
| `-no-map-guess` | bool |  | do not ask for main.js.map next to a script that names no source map (a map a script or a header names is still read) |
| `-no-paths` | bool |  | do not ask each web service for the 32 built-in paths (robots.txt, sitemaps, API descriptions, .git/HEAD, backup, admin, …): some programs count that as scanning |
| `-no-tech` | bool |  | skip technology fingerprints (saves about 30 MB of memory) |
| `-obs` | bool |  | also print the observation log |
| `-org` | string |  | seed Organization name |
| `-parallel` | int |  | work items in flight (default 16) |
| `-params` | string |  | find query parameters pages read, from this wordlist or small, medium or large for a built-in one (active; the targets given are the scope unless -allow) |
| `-params-chunk` | int |  | names per parameter request at most (0: 500, and about 7.6 KB in a query; fewer where the server refuses a long query) |
| `-params-delay` | duration |  | wait before each parameter request, one at a time (arjun -d) |
| `-params-include` | string |  | sent with every parameter request: a query for GET; for a body a form, a JSON object or XML, or a template with $arjun$ where the names go |
| `-params-method` | string | `GET` | how names are sent: GET (query), POST (form body), JSON or XML. A body sends requests that may change data on the target: -params-writes must say it is wanted |
| `-params-per-host` | int | `20` | pages searched for parameters per host |
| `-params-rate` | float |  | parameter requests per second per host (0: no limit, as arjun) |
| `-params-stable` | bool |  | one parameter request at a time, 3 to 9 s apart, and 30 s after a refused connection (arjun --stable) |
| `-params-targets` | string |  | file of JSON: pages that are asked otherwise ({"URL":{"method":"POST","include":"a=1","header":["Name: value"]}}), as params -i writes it |
| `-params-threads` | int | `5` | parameter requests in flight per page (as arjun -t); 1 with -params-delay and -params-stable |
| `-params-timeout` | duration | `15s` | wait for each parameter request; one that times out is asked again with 5 s more, up to 20 s (arjun -T) |
| `-params-writes` | bool |  | let -params-method POST, JSON or XML send bodies (they may change data on the target); needs -allow or -scope, or a single target |
| `-passive` | bool |  | skip HTTP/crawl/JS/paths/TLS (no handshake to the target) |
| `-path-climb` | bool |  | also list and ask the parent directories of each link a page names (/a/b/c: /a/b/ and /a/) |
| `-paths` | string |  | extra path wordlist (one path per line) |
| `-per-template` | int |  | URLs of one template (/product?id={n}) to request; the rest are listed (default 3) |
| `-permute` | bool |  | resolve variations of found names (active; the targets given are the scope unless -allow) |
| `-port-all-ips` | bool |  | scan every address of a name, not the first two of each family |
| `-port-cdn-full` | bool |  | scan CDN and WAF addresses in full, not only their web ports |
| `-port-detect` | string | `all` | what is asked of an open port: all (its banner, then HTTP and TLS, then one request of each protocol that waits to be asked, each on its own connection, several at once while the scan has workers free: at most 24 connects after the first), banner (what it says on the one connection) or none (connect and close) |
| `-port-discover` | string |  | ask first whether an address is up, by a connect to 80 and 443: first (scan the ones that answer) or only (list them, scan nothing) |
| `-port-ip` | string |  | the address families of a name to scan: 4 or 6 (default both) |
| `-port-min-rate` | float |  | port connection attempts per second at least: raises -port-rate to this when lower |
| `-port-order` | string | `random` | the order a host's ports are asked in: random (the likeliest ports first, each tier shuffled) or asc |
| `-port-payload` | string |  | send this to each open TCP port before reading what it says (\r and \n are CR and LF) |
| `-port-proxy` | string |  | connect to TCP ports through this SOCKS5 proxy (host:port); a port is then asked its banner only, and UDP is not sent |
| `-port-proxy-auth` | string |  | user:password for -port-proxy |
| `-port-rate` | float |  | port connection attempts per second (0: 1500, as naabu's connect scan, and 127.0.0.1 unpaced) |
| `-port-retries` | int | `-1` | more passes over the ports that neither accepted nor refused: n passes over all of them, 0 none (default: one, when few did not answer) |
| `-port-seed` | int |  | make the random port order repeat (0: a new one each run) |
| `-port-source-ip` | string |  | connect from this local address |
| `-port-threshold` | int |  | stop asking a host after this many open ports: it answers every port (0: no limit) |
| `-port-timeout` | duration |  | wait this long for one port to accept or refuse a connect (0: 1.5s) |
| `-port-unnamed` | int |  | after this many open ports of an address that no protocol probe could name, ask its other silent ports their banner only (0: 6; -1: no limit; each probe is a connect) |
| `-port-workers` | int |  | port connects in flight at once, over all hosts (0: as many as the rate allows, up to 20000) |
| `-ports` | string |  | scan TCP ports: top-100, top-1000, full or a list of ports, ranges and these names, such as 22,80,8000-8100 or top-100,8888 (active; the targets given are the scope unless -allow) |
| `-ports-on` | string, repeatable |  | scan only these ports on a host: HOST=22,80 |
| `-ports-udp` | string |  | ask UDP ports (active): top (about 25 common ones), full or a list of ports, ranges and these names, such as 53,123,161,1-1024 or top,5354; a reply is open, an ICMP unreachable closed, neither open\|filtered (-ports none: UDP only) |
| `-probe` | bool |  | resolve and fetch each target once, print one line per web service, no crawl or enumeration |
| `-program` | string |  | the program to take from a -scope list (handle, name or URL) |
| `-providers` | string |  | API keys per source, YAML (default ~/.config/azhaq/providers.yaml, else subfinder's provider-config.yaml) |
| `-proxy` | string |  | send requests to targets through this proxy (http://, https:// or socks5://); Chrome too (default: $HTTP_PROXY, $HTTPS_PROXY) |
| `-quiet` | bool |  | print no map and no progress lines (a line every 10 s while the run works), only the summary (on stderr) |
| `-rate` | float |  | requests per second to targets, over all hosts (0: no pace) |
| `-request-timeout` | duration |  | time one request gets, headers and body (default: 10 s for headers, 30 s in all; not -timeout, the run's bound) |
| `-resolvers` | string |  | DNS resolvers: a file with one per line, or a comma list; each is ADDR, ADDR:PORT or udp:, tcp:, dot:, doh:URL[:get] and then the address (default: public resolvers) |
| `-retry` | int |  | ask again this many times when a host that answered before gives no answer (a timeout, a reset) |
| `-scope` | string |  | a program's scope: a file (HackerOne CSV, bounty-targets JSON, Burp options, lines) or hackerone, bugcrowd, intigriti, yeswehack |
| `-screenshots` | string |  | save a screenshot of each web service's front page in this directory (needs Chrome) |
| `-seal-to` | string |  | when the run ends, append the ledger's seal as one JSON line ({"time","ledger","seal","entries"}) to this file, or POST it to this URL: kept where the run's own files are not, so azhaq ledger -verify -seal can tell the ledger from one with lines removed and the rest re-chained to look intact |
| `-serve` | string |  | let azhaq worker processes take this run's work, at this address (127.0.0.1:7777) |
| `-shot-codes` | string |  | take only pages that answer with these statuses, comma-separated (default: any); the others are listed as skipped |
| `-shot-format` | string | `png` | screenshot format: png or jpeg |
| `-shot-fullpage` | bool |  | screenshot the whole page, not only the first screen (up to 16384 pixels tall) |
| `-shot-html` | bool |  | keep each page's rendered HTML beside its screenshot |
| `-shot-js` | string |  | a file of JavaScript to run on each page before its screenshot (it runs on the target's page) |
| `-shot-quality` | int | `80` | jpeg quality, 1 to 100 |
| `-shot-size` | string | `1440x900` | screenshot size in pixels, WIDTHxHEIGHT |
| `-shot-timeout` | duration | `30s` | time a page gets: with -rate, how long it may go without a request let go or an answer, not in all |
| `-shot-wait` | duration | `1.5s` | wait after a page's load event for scripts that draw after it, before the screenshot (0: none) |
| `-skip` | string |  | collectors not to run, comma-separated (see azhaq plan) |
| `-source-proxy` | string |  | send every subdomain source request through this proxy URL, as subfinder -proxy (else HTTP_PROXY and HTTPS_PROXY) |
| `-source-rate` | float |  | requests per second to each subdomain source, as subfinder -rl (0: each source's own pace); a source's lower own pace stays |
| `-source-rates` | string |  | pace single subdomain sources, as subfinder -rls: name=N/unit, comma-separated, unit s, m or h (hackertarget=10/m,crtsh=1/s) |
| `-source-timeout` | duration | `30s` | give each subdomain source this long, 30s as subfinder does; a slower one (crt.sh) is abandoned, listed as failed, and the names the others gave are kept; -source-timeout 60s or more waits for crt.sh on a large domain (not -timeout, the run's bound) |
| `-sources` | string |  | subdomain sources to run, comma-separated (default: the default set; none: no source, for a DNS-only run) |
| `-stream` | bool |  | also print each name, service, URL and open port as it is found (found lines, before the ranked map) |
| `-submit-forms` | bool |  | also submit POST forms with neutral values (crawl): CHANGES DATA on the target, each submission counts as a request and is in the ledger, the summary says how many; held to -allow, -deny and the crawl's scope |
| `-tabs` | int | `6` | Chrome tabs open at once for screenshots and -browser (gowitness -t) |
| `-timeout` | duration |  | stop after this long and keep what was found; azhaq resume continues (0: no limit) |
| `-unsafe-ports` | bool | `true` | let Chrome open the ports it refuses by default (6000, 6666, 10080 and others); -unsafe-ports=false keeps its refusal |
| `-url` | string |  | seed URL |
| `-urls` | string |  | write every archived URL of the run's domains to this file, one per line |
| `-urls-archive` | string, repeatable |  | ask NAME's archive at this address instead of its own, as NAME=URL (a mirror or a test server; repeatable) |
| `-urls-blacklist` | string |  | leave out URLs whose path ends in these extensions, comma-separated (png,jpg,svg) |
| `-urls-fc` | string |  | leave out URLs the archive recorded with these HTTP status codes, comma-separated; the archives that keep no status (OTX, urlscan.io) are asked all the same and their URLs kept, with a note |
| `-urls-fp` | bool |  | keep one URL for each host and path, dropping the variants that differ by parameters |
| `-urls-from` | string |  | only captures from this time on: YYYY, YYYYMM, YYYYMMDD or YYYYMMDDhhmmss; OTX, which dates no capture, is asked all the same and its URLs kept, with a note |
| `-urls-ft` | string |  | leave out URLs the archive recorded with these MIME types, comma-separated; the archives that keep no type (OTX, urlscan.io) are asked all the same and their URLs kept, with a note |
| `-urls-max` | int | `500000` | URLs kept for each domain (0: no cap); the summary counts the ones past it |
| `-urls-mc` | string |  | keep only URLs the archive recorded with these HTTP status codes, comma-separated (200,301); the archives that keep no status (OTX, urlscan.io) are asked all the same and their URLs kept, as gau keeps them, with a note |
| `-urls-mt` | string |  | keep only URLs the archive recorded with these MIME types, comma-separated (text/html); the archives that keep no type (OTX, urlscan.io) are asked all the same and their URLs kept, with a note |
| `-urls-pages` | int | `50` | pages read from each archive for a domain (0: no cap); an archive that stops at the cap says so in the summary |
| `-urls-pause` | duration |  | pause between the requests of one archive (default: 1 s for the Wayback Machine and Common Crawl, 0.5 s for OTX, 2 s for urlscan.io; 0 for none) |
| `-urls-proxy` | string |  | send the archive requests through this proxy: http://HOST:PORT, https:// or socks5:// |
| `-urls-raw` | bool |  | print the archived URLs exactly as the archives gave them: no normalising, junk filter or deduplication |
| `-urls-retries` | int |  | times an archive request is asked again after a 429, 503 or network error, after its Retry-After (seconds or a date, however long) or 2, 5, 10, 20, then 30 s; 0 makes the first refusal final (default: a 429 or 503 is asked again until the archive's time, -urls-timeout, or the run's is spent, a network error 3 times; a wait longer than the time left ends the request at once, with the reason) |
| `-urls-source` | bool |  | with -urls: each line is the URL, a tab, and the archive that gave it |
| `-urls-sources` | string |  | ask only these archives, comma-separated: wayback, commoncrawl, otx, urlscan, arquivo (default: all) |
| `-urls-subs` | bool | `true` | ask the archives for the subdomains of each domain too (false: only the name itself, as gau does without --subs) |
| `-urls-timeout` | duration | `3m0s` | time each archive source gets per domain (the Wayback Machine's answer for a large domain takes several minutes) |
| `-urls-to` | string |  | only captures up to this time, in the same form |
| `-v` | bool |  | print a line for every finished task, not only failures |
| `-web-ports` | string |  | ports to probe on each hostname, comma-separated (default: 443, falling back to 80) |
| `-web-scheme` | string |  | try a name or an address over this scheme only, http or https (default: https, then http) |
| `-worker-token` | string |  | the token workers give (default $AZHAQ_WORKER_TOKEN, else a new one) |
<!-- flags:end -->
