# Azhaq

Azhaq is a reconnaissance engine for security research, written in Go. Point it at a URL, a domain, a list of hosts or a bug bounty program's scope, and it maps what is reachable from there: names and their addresses, web services and the technologies behind them, pages, the routes an application's JavaScript calls (with their methods, query parameters and body fields), API descriptions and their operations, forms, parameters, ports, certificates, historical URLs, and which of it needs a session or answers differently for different users. Everything goes into one SQLite graph per workspace, deduplicated across sources, and the next run says what changed.

It is built to be driven by scripts and assistants as much as by people: every command prints its results on stdout, a summary of what failed, what was skipped and why on stderr, and an exit code that says whether the work is complete. `azhaq mcp` serves it to MCP clients with the scope and the request budget locked.

It maps and does not attack: no payloads, no vulnerability checks. Requests are GETs, except Chrome signing in when you give it an account, and GraphQL introspection with `-graphql`. Found URLs whose names say a GET would do something (`/logout`, `/rest/saveLoginIp`, `/createdb`) are listed, not requested; with a session, path and parameter guesses that read that way are not sent either. URLs that carry a scanner's payload (an archive keeps `/etc/passwd`, `;curl …oast.live`, `<script>`) never enter the map, so nothing replays them.

## At a glance

| You want | Run | In place of |
| --- | --- | --- |
| One web app or API mapped: pages, the routes its JavaScript calls with methods and body fields, API descriptions, forms | `azhaq run -url https://app/ -db app.db` (`-browser` for an app its scripts draw) | katana + jsluice, reading bundles by hand |
| Who may read what across sessions: IDOR/BOLA, data only some roles should see | `azhaq roles -role anon -role 'alice=Authorization: Bearer …' -role 'bob=…' -- -url https://app/` | Autorize, diffing Burp histories |
| A program's attack surface, within its scope | `azhaq run -scope hackerone -program NAME -db prog.db` | a script around the tools below |
| Subdomains, resolved | `azhaq subs -d example.com -live` | subfinder \| dnsx |
| Web services probed | `azhaq probe -l hosts.txt -json` | httpx |
| Paths, parameters, ports, archived URLs | `azhaq dirs`, `azhaq params`, `azhaq ports`, `azhaq urls` | ffuf -ac, arjun, naabu, gau |
| What changed since the last run | `azhaq watch -db prog.db -- RUN FLAGS` | cron and diff |
| An assistant doing the recon, inside a scope and a budget | `azhaq mcp -allow example.com -max-requests 5000` | |
| What a run would send, before it sends anything | `azhaq plan` with the run's flags | |

## Install

Download a binary for Linux, macOS or Windows from the [releases](https://github.com/trannghiach/azhaq/releases) (checksums and SBOMs alongside), or:

```
go install github.com/trannghiach/azhaq/cmd/azhaq@latest      # Go 1.26 or newer
docker run --rm -v "$PWD:/work" -u "$(id -u)" ghcr.io/trannghiach/azhaq run -domain example.com -passive
```

The checksums file is signed with [sigstore](https://www.sigstore.dev/) by the release workflow; to check a download:

```
cosign verify-blob --bundle checksums.txt.sigstore.json checksums.txt \
  --certificate-identity-regexp '^https://github\.com/trannghiach/azhaq/\.github/workflows/release\.yml@refs/tags/v' --certificate-oidc-issuer https://token.actions.githubusercontent.com
sha256sum --ignore-missing -c checksums.txt
```

`azhaq version` prints the version; `azhaq help` lists the commands; `azhaq help COMMAND` shows one with its flags and examples; `azhaq help -json` describes every command and flag for a program to read; `azhaq docs` prints the documentation, offline.

## A first map

Only scan systems you are authorized to test.

```
$ azhaq run -url http://localhost:3000/ -db juice.db
  URL http://localhost:3000/api/Users  target  visited  auth  POST  status=401 title=UnauthorizedError: No Authorization header was found
  URL http://localhost:3000/rest/products/search  target  visited  api  GET  status=200
      GET  ?q
  URL http://localhost:3000/rest/2fa/verify  target  hint  api  POST
      POST  body tmpToken totpToken
  URL http://localhost:3000/b2b/v2/orders  target  hint  api  POST
      POST  body cid orderLines orderLinesData
  …
azhaq run: 181 map rows (156 URLs, 71 api, 11 auth, 1 forbidden) · 202 requests · 4.2 s · db juice.db
  - left alone, looks like a GET would change something: …/rest/saveLoginIp, …/rest/user/change-password, …
  next: azhaq query -db juice.db -role auth,forbidden   (what needs a session)
  next: azhaq export -db juice.db -format openapi > api.json   (for Burp, Postman, ZAP)
```

That is OWASP Juice Shop: the routes come from the calls its Angular bundle makes (`this.http.post(\`${host}/rest/2fa/verify\`, {tmpToken, totpToken})`), which string matching does not see. `azhaq show -db juice.db http://localhost:3000/rest/2fa/verify` says where each was found: `` main.js:6472:88  this.http.post(`${F$.hostServer}/rest/2fa/verify`,{tmpToken:…,totpToken:t}) ``. Each URL row says whether it was `visited`, only found (`hint`), answered with the page every unknown path gets (`catchall`, a single-page app's shell), failed (`error`), answered 404 (`gone`, often an archived URL), or was deliberately not requested (`skipped`), then its role: `app`, `auth` (401), `forbidden` (403), `api`, `page`, `script`. Pages that differ only by an ID fold into one template row (`/catalog/product?productId={n}  (18 urls)`); forms and the operations of a route are indented below it.

What a default run sends to a target: a GET to each target, to the 32 built-in paths of each web service (`robots.txt`, sitemaps, `.well-known/*`, API description locations, `admin`, `backup`, `.git/HEAD`, …), to the routes its pages, scripts and API descriptions name (GETs only, parameterless ones only, none that look state-changing), and to up to 40 URL templates per domain from web archives. `azhaq plan` with the same flags prints this for your targets without sending anything: the collectors each target gets, the queries to third-party sources about them, counted (the subdomain sources, the archives, RDAP, keyed scan engines), and a bound on the requests to the targets. That bound is not a count: how many names resolve and answer is known only by asking, so the plan gives what each web service costs before its links are followed (about 34 requests: its page, the favicon, the built-in paths) and the cap that applies, `-max-requests` or `-daily-requests`.

Requests carry a current browser's User-Agent, as httpx and katana do: CDN bot managers hold other requests open without an answer. `-header 'User-Agent: …'` replaces it, and `-header 'X-Bug-Bounty: me'` adds a program's identification header.

## What every command prints

- **stdout**: results only, one per line, or one JSON object per line with `-json`.
- **stderr**: failures as they happen (three per kind), a progress line every 30 s on long runs, and a summary at the end: what came out, what failed (collector, source, error, whether it is worth retrying, up to 100 targets; `azhaq query -failed` lists every one), targets that never answered, what was left alone and why, the limit that stopped the work and the command that resumes it. With `-json` the summary is one JSON object with `"type":"summary"`, and nothing else is printed on stderr.
- **exit code**: 0 complete, 1 error, 2 usage (nothing was sent), 3 finished with failures (the results are usable; the summary says what failed), 4 stopped by a limit (`azhaq resume -db FILE` continues).

```
$ azhaq subs -d vulnweb.com -silent -json 2>summary.json | jq -r .host
$ jq .failed summary.json
[{"collector":"azhaq-subdomains","source":"crtsh","error":"timeout","retryable":true,"count":1,"targets":["vulnweb.com"]}]
```

A failure on fan-out (a subdomain source that failed for the domain of the URL you mapped) is listed with `"fanout": true` and does not make the map of what you asked about incomplete. [docs/OUTPUT.md](docs/OUTPUT.md) (`azhaq docs output`) describes every field.

## Reading a workspace

A run's database is a workspace: query it instead of re-running, export it for the next tool, and run into it again to see what changed.

```
azhaq query -db juice.db -role auth                                 # what needs a session
azhaq query -db juice.db -role api -method POST -fields key,body -json
azhaq query -db juice.db -type URL -status 5xx
azhaq query -db h1.db -type Hostname -new                           # names the last run saw first
azhaq show  -db juice.db http://localhost:3000/rest/2fa/verify      # everything about one URL: what found it, every observation

azhaq export -db juice.db -format openapi > api.json   # Burp, Postman, ZAP
azhaq export -db h1.db -format targets | nuclei -l -   # web services
azhaq export -db h1.db -format burp > scope.json       # Burp project options with the hosts in scope
azhaq export -db h1.db -format html > report.html      # one self-contained page
```

The OpenAPI export starts from the description the target serves, unchanged, and adds the routes it does not list with the method each script call uses, its query names and the fields of its body, HTML forms (a GET form's fields as query parameters, a POST form's as a form-encoded or multipart body, file inputs binary), pages linked with a query string as GETs taking those names, and `x-azhaq` on each operation saying where it came from and how its GET answered. Other formats: `urls`, `hosts` (names that resolve), `names` (every name), `graphml`, `secrets`, `jsonl` (everything).

## Access control: comparing sessions

`azhaq roles` maps the same target once per session, then asks every endpoint any session reached with every other session, fills path parameters with identifiers the sessions' own answers held (each role's own objects first), and compares the answers by status, length, body and nested JSON fields. A 4xx, or an error answered with 200, is a refusal.

```
$ azhaq roles -role anon -role "alice=Authorization: Bearer $TA" -role "bob=Authorization: Bearer $TB" \
    -id 'alice:book_title=aliceBook' -- -url http://localhost:5000/
  401 → 200:79 → 200:79  http://localhost:5000/books/v1/aliceBook  [bob reads alice's object] from …/books/v1/{book_title} · sensitive: secret
  200:1.1k ×3  http://localhost:5000/users/v1/_debug  [anyone reads sensitive fields: password]
  401 → 200:95 → 200:94  http://localhost:5000/me  [signed-in only]
```

That is VAmPI: bob reads alice's book and its secret, and anyone reads every user's password. Roles are anonymous, carry headers (`-role 'user=Cookie: sid=…'`), get them from a command run when they are needed (`-role-cmd 'alice=./token.sh alice'`, for tokens that live minutes), or sign in with Chrome on a login page (`-login URL -role-login 'alice=alice@x.test:PASSWORD'`). A session that looks dead is named, with what the site said (`Signature expired`), and roles exits 3, also when every session died together; an expired JSON Web Token is said before anything is sent. The verdicts, worst first: anyone reads sensitive fields (passwords, secrets, keys, card numbers, a token several sessions share), a role reads another role's object, an object every signed-in role reads alike, roles read the same sensitive fields, the same answer for a session that never found the URL, signed-in only, only one role reads it, some roles refused, different fields per role, an object anyone reads, status differs. Whose object it is comes from the answers (an identifier only that role's list holds) or from `-id ROLE:NAME=VALUE`. `-all` also lists endpoints that answer everyone alike or with each role's own data; `-json` gives each row with every role's answer and nothing but the summary on stderr. The replay sends GETs only, never to state-changing names, within `-replay-max` requests. Each role's run gets a database of its own, `ROLE.db` in `-dir` (default `azhaq-roles-<time>`), to read with `query` and `show` afterwards; `roles` sets their `-db` itself, so the run options after `--` leave it out, as they leave out the session flags (`-header`, `-cookie`, `-login`).

Signing in opens the page in Chrome, fills the user name and password the way typing would, submits, and keeps the cookies and a JSON Web Token the page stores in `localStorage` or `sessionStorage`. Logins that need more (one-time codes, SSO) take `-header` or `-cookie`. A run with a session never requests a URL that looks like a logout.

## A bug bounty program

`-scope` takes a program's scope and makes it the run's: wildcards are enumerated as domains, hosts and URLs probed as given, out-of-scope entries excluded, and no request goes to a host outside it, not even a redirect target. Without any scope, a redirect is followed only within the site (the same registrable domain or address): a redirect to a third party is recorded with its `Location`, and its page is never reported as the target's. Targets you give that the scope excludes are skipped and listed. It reads HackerOne's scope CSV, a Burp project options file, plain lines (`*.example.com`, `app.example.org:8443`, `10.0.0.0/24`, `!excluded.example.com`), or the current scope of any public program on HackerOne, Bugcrowd, Intigriti or YesWeHack, from [bounty-targets-data](https://github.com/arkadiyt/bounty-targets-data). Every command that sends requests to targets (`run`, `plan`, `probe`, `crawl`, `ports`, `dirs`, `params`, `shots`, and the runs inside `roles` and `watch`, after `--`) takes `-scope`, `-allow` and `-deny`. Given with targets of your own (`probe -l hosts.txt -scope hackerone -program x`), the scope filters them; it adds the program's own targets only when you give none.

```
azhaq scope -scope bugcrowd -program tesla                       # what a run would take, exclude and skip
azhaq plan  -scope bugcrowd -program tesla -max-requests 5000    # what it would ask whom, and the cap
azhaq run   -scope bugcrowd -program tesla -db tesla.db -rate 5 -max-requests 5000
```

Budgets: `-rate 10` paces requests to targets, `-max-requests 5000` stops a run after that many (port connects count too), `-timeout 20m` stops it after that long, and `-daily-requests 20000 -program NAME` spreads a day's allowance over the runs in a workspace. Work a limit stops is not lost: `azhaq resume -db FILE` continues where it stopped, and so it does after Ctrl-C or a crash. A run keeps the answers it got in its workspace until it is complete, so a resumed run does not ask again: Juice Shop capped at 50 requests and resumed until done sent 211 requests in all, one uninterrupted run 205. A port scan the budget cut short scans that address again.

## Watching a target

Every run into the same `-db` adds to the workspace. `azhaq watch` runs again and again and reports what a person watching cares about: new names that resolve, new web services, new URLs, ports that opened or closed, pages whose status or title changed, API listings that grew or shrank (`/users/v1: 5 items → 6 items`), and what disappeared, ignoring query values that change on every request. It posts to Slack, Discord, Telegram or any JSON webhook, and stays quiet when nothing changed.

```
azhaq watch -db acme.db -notify https://hooks.slack.com/services/… -- -scope acme-scope.csv    # once, from cron
azhaq watch -db acme.db -every 24h -notify "https://api.telegram.org/bot…/sendMessage?chat_id=…" -- -domain acme.com
azhaq new   -db acme.db -since 72h        # what the newest run still sees that was first seen lately
azhaq diff  -db acme.db                   # the full difference between the last two runs
```

## In a pipeline

Each step of the usual chain has a command that reads targets from flags, a file or stdin, prints each result as it is found, and writes JSON with the field names of the tool it stands in for (`-json`), so existing `jq` filters keep working:

```
azhaq subs -d example.com -silent | azhaq dns -silent | azhaq probe -json      # subfinder | dnsx | httpx
azhaq subs -d example.com -w words.txt -permute -live                          # + puredns bruteforce, alterx | dnsx
azhaq crawl  -u https://app.example.com/ -json                                 # katana + jsluice
azhaq urls   -d example.com -silent                                            # gau
azhaq ports  -host scanme.nmap.org -p top-1000 -json                           # naabu (connect scan)
azhaq dirs   -u https://app.example.com/ -w common.txt -e php,bak              # ffuf -ac
azhaq params -u https://app.example.com/search -w burp-parameter-names.txt     # arjun (GET)
azhaq asn    -a AS64500                                                        # asnmap
azhaq shots  -l hosts.txt -dir screenshots                                     # gowitness
```

`probe` writes httpx's fields with httpx's meanings: `host` is the name, `host_ip` the address the request connected to, `a` and `aaaa` the addresses the name resolved to, `status_code` the first answer (a 302 stays 302). Where a redirect stays in the scope (without one, in the site) it is followed, and `final_url` and `final_status_code` say where it ended; the title and technologies are the final page's. Every target given ends as a service, a failure or a skip in the summary. `subs -json` gives each name with the `source` and all the `sources` that gave it (`dns-brute` and `permute` for names `-w` and `-permute` found by resolving guesses). subdomain.center pads its answer with about 500 random names per call: a name only it gave is kept when it resolves (not to a wildcard). Keyless sources asked by default: anubis, certspotter, crt.sh, crtname, hackertarget, hudsonrock, rapiddns, scanmalware, shodanct, subdomain.center, thc; a source that fails while others answer is listed in the summary and does not make the exit code 3 (`-fail-on-errors` does). `-db FILE` keeps any of them in a workspace for `query`, `show` and `export`.

What other tools found joins a workspace with `azhaq ingest`: subfinder, dnsx, httpx, katana, naabu, nuclei and gau JSON lines, an ffuf JSON report or `-json` lines, Azhaq's own export, or plain lists of URLs, hosts and addresses. An answer httpx, katana or ffuf got to a GET is taken in as Azhaq's own probe records one, so it is a web service for `export -format targets`, `burp` and `html`, and an answer for the map and `openapi`; a request katana sent with another method, or saw a script send (`-xhr`), says what the route takes, with its body's fields; the forms katana read (`-fx`) are the page's.

```
subfinder -d example.com -json | azhaq ingest -in - -db example.db
```

## For assistants: MCP

```
azhaq mcp -scope hackerone -program security -max-requests 20000 -rate 5
claude mcp add azhaq -- azhaq mcp -allow example.com -max-requests 5000
```

`azhaq mcp` serves the Model Context Protocol over stdio. Its tools run Azhaq itself and return the same summary and rows (`azhaq_scope`, `azhaq_plan`, `azhaq_map`, `azhaq_resume`, `azhaq_subdomains`, `azhaq_probe`, `azhaq_ports`, `azhaq_query`, `azhaq_show`, `azhaq_roles`, `azhaq_export`, `azhaq_diff`, `azhaq_workspaces`). The scope, the request budget for all calls together and the pace are fixed when the server starts; no tool argument can widen them, an argument the tool's schema does not take (an unknown name, a string where a list goes) is refused, and results are bounded (at most 1,000 rows; an export comes in pages of about 16 KB, each a whole document: an OpenAPI description with some of the paths, whole lines) so one call does not fill a context. A map stopped by the budget, a timeout or a cancel continues with `azhaq_resume`. [docs/MCP.md](docs/MCP.md) (`azhaq docs mcp`).

## More options

| Option | Effect |
| --- | --- |
| `-browser` | also load pages in Chrome: the requests their scripts send and the links and forms of the rendered page |
| `-login URL -login-user U -login-pass P` | sign in with Chrome first (password also from `$AZHAQ_LOGIN_PASS`) |
| `-cookie N=V`, `-header 'K: V'` | reuse a session you already have; add headers |
| `-screenshots DIR` | a screenshot of each web service, look-alikes grouped in the HTML report (Chrome on the machine; `AZHAQ_CHROME` to point at one) |
| `-asn AS64500`, `-cidr 192.0.2.0/24` | start from networks: announced prefixes, address ranges, their reverse DNS names and web services |
| `-list FILE` | targets one per line (`-` for stdin): URLs, hosts, `host:port`, addresses |
| `-passive` | third-party sources and DNS only; nothing is sent to the targets |
| `-probe`, `-web-ports 80,443,8080` | only fetch the targets themselves; ports to try on each name |
| `-sources`, `-exclude-sources`, `-all-sources`, `-providers FILE` | subdomain sources and API keys (subfinder's `provider-config.yaml` format) |
| `-resolvers FILE`, `-dns-rate N` | DNS resolvers and their pace |
| `-dns-brute FILE`, `-permute` | active: names from a wordlist, variations of found names (need a scope) |
| `-dirs FILE`, `-params FILE`, `-ports SPEC`, `-graphql` | active: paths from a wordlist, query parameters, TCP ports, GraphQL introspection (need a scope) |
| `-all-gets` | also request found URLs that look state-changing |
| `-depth N`, `-max-items N`, `-parallel N`, `-host-parallel N`, `-delay D` | expansion and concurrency |
| `-v` | a line for every finished task |

Workers: a run started with `-serve ADDR` lends its tasks to `azhaq worker -server URL` processes on other machines, which send back what they found (each worker keeps its own HTTP cache, so a few requests are repeated). The catalog, engine, store and types are public Go packages for running Azhaq in-process and adding collectors; the API may change before 1.0.

## Collectors

| Collector | Collects |
| --- | --- |
| `azhaq-http` | status, redirect chain, title, technologies, favicon hash, length, words, lines, time, the address connected to, headers, cookie names, JSON field names; flags catch-all answers |
| `azhaq-crawl` | same-origin links (not a directory listing's sort links), forms (with script-driven ones, their encoding and file inputs), links inside JSON answers, links written in Markdown that the page renders in the browser |
| `azhaq-js` | the requests scripts make (method, path, query names, body fields, worked out from literals, template literals and assigned variables, and through a helper that takes the URL), with the script, line and code each was found in, other routes and links in scripts, chunks and source maps, joined constants, GraphQL operation names, credentials |
| `azhaq-openapi` | OpenAPI 3 and Swagger 2 documents (JSON, YAML, embedded in Swagger UI), each operation's parameters by location, body fields, security; a Swagger UI page's document even when its URL is built at run time; asks the parameterless GETs |
| `azhaq-graphql` | GraphQL endpoints; with `-graphql`, the schema by introspection |
| `azhaq-paths` | the built-in paths: robots.txt, sitemaps, API description locations, … |
| `azhaq-dns` | A/AAAA, CNAME chains, the CDN or WAF in front, MX/TXT/NS; dead and wildcard names marked and never probed |
| `azhaq-tls` | certificates and their names |
| `azhaq-subdomains` | names from passive sources (certificate transparency, archives, DNS datasets; 50+ with keys), with the sources of each name and each source's count or error |
| `azhaq-urls` | historical URLs from the Wayback Machine, Common Crawl, OTX, urlscan and Arquivo, junk left out |
| `azhaq-dns-brute`, `azhaq-permute`, `azhaq-dirs`, `azhaq-params`, `azhaq-ports` | the active techniques above |
| `azhaq-asn`, `azhaq-prefix`, `azhaq-ptr` | networks, their addresses and reverse DNS names |
| `azhaq-render`, `azhaq-shots` | Chrome: rendered pages and their requests; screenshots |
| `azhaq-search` | Shodan, FOFA and Netlas, with keys |
| `azhaq-rdap` | registration data and nameservers |
| `azhaq-cloud` | domains, hosts and URLs from a local cloud inventory |

Sources Azhaq does not query itself can be plugged in as external programs: [docs/CONNECTOR.md](docs/CONNECTOR.md).

## Benchmark

`go run ./bench` runs Azhaq and the tools it replaces on the same targets: Juice Shop, VAmPI and crAPI in Docker, ginandjuice.shop, apps the bench serves itself, and the live names of hackerone.com, tesla.com and vulnweb.com. Latest run (2026-10-27, v0.6.3; the Wayback Machine and Common Crawl refuse the bench machine, and its security software removes naabu, so the port comparison runs on GitHub's network; the archive row is from the v0.6.2 run, as OTX answered 504 on this one):

| Job | Replaces | Azhaq | Reference |
| --- | --- | --- | --- |
| Live subdomains, 3 domains, no keys | subfinder + dnsx | 555, in 37 s | 527, in 93 s |
| DNS brute force, 5,000 words | dnsx | 3 in 54 s | 3 in 69 s |
| Wildcard zone, 3 real names of 50 | dnsx | 3 found, 0 fake | 50 without `-wd` |
| Probing 576 live hosts | httpx | 410 answered; status, title and technologies agree on 399 of 402 shared (redirects out of the site compared by their own status: Azhaq does not report a third party's page as the host's); 107 s | 403 answered, 146 s |
| Server routes Juice Shop's frontend calls (77) | katana + jsluice | 70 | 1 |
| VAmPI's API paths (12), ginandjuice's script-only routes (3), crAPI's routes (40) | katana + jsluice | 12, 3, 32 | 1, 2, 0 |
| With Chrome: Juice Shop, crAPI | katana `-headless` | 70/77 in 13 s, 32/40 in 17 s | 6/77 in 7 s, 0/40 in 44 s |
| Historical URLs, 3 domains (Wayback and Common Crawl unreachable for both) | gau | 7,104, including 2,335 of gau's 2,340 | 2,340 |
| Paths, 4,750 words on 3 apps | ffuf `-ac` | 35 hits, 4 false positives, 49 s | 36 hits, 4 false positives, 53 s |
| Parameters, 5 pages | arjun | 5, including arjun's 2 | 2 |
| Screenshots, 4 front pages | gowitness | 4 | 3 |
| Credentials in a script | jsluice | 12, including jsluice's 4 | 4 |
| Reverse DNS of a /25 | dnsx `-ptr` | 36 of 36 | 36 |
| Access matrix, anonymous, member, owner (signed in by Chrome) | manual | 6/6 rows right, no logout sent | |
| A run capped at 100 requests and resumed; killed and resumed; with two workers | – | the same 180 URLs as one run each time; 207 requests over the capped run and its resumes, one run 202 | |
| Memory, Juice Shop | katana | 97 MB | 59 MB |

The Juice Shop truth is the 77 routes its server defines that its frontend calls (`bench/truth/juice_routes.py`, from the container's own code), not strings found by searching the bundle. Azhaq loses on parameter discovery time (several times arjun's), memory (above katana's), and one path of ffuf's 36.

[bench/README.md](bench/README.md) has what is measured, every table and the caveats.

## Documentation

- [Output](docs/OUTPUT.md): what every command prints, the summary, exit codes
- [MCP](docs/MCP.md): serving Azhaq to assistants
- [Architecture](docs/ARCHITECTURE.md): data model, scheduling, identity rules, limitations
- [Connector protocol](docs/CONNECTOR.md): feeding external data into the graph

## License

[MIT](LICENSE). Dependencies are MIT, BSD, Apache or Unlicense licensed, and CI checks it. Most subdomain sources are [subfinder](https://github.com/projectdiscovery/subfinder)'s (MIT, ProjectDiscovery), run in-process; technology fingerprints come from [wappalyzergo](https://github.com/projectdiscovery/wappalyzergo), whose passive matcher is included in `internal/wappalyzer`, and CDN ranges from [cdncheck](https://github.com/projectdiscovery/cdncheck) (both MIT, ProjectDiscovery).
