# Azhaq

Azhaq is one Go binary for reconnaissance. It stands in for the chain of subfinder, dnsx, httpx, katana, ffuf, gau, arjun, naabu, gowitness and notify, with their flags and JSON field names, and adds what that chain does not do: it maps the routes an app's JavaScript calls, compares what each of your accounts may read and write, holds every request to a scope and a budget, and records what it sent. Everything lands in one SQLite workspace you can query, export and diff.

**Coming from one of those tools?** [docs/MIGRATING.md](docs/MIGRATING.md) puts its flags next to azhaq's, says what differs on purpose and gives three command lines for each (also `azhaq docs migrating`).

| If you use | Run | Also |
| --- | --- | --- |
| subfinder | `azhaq subs` | names checked in DNS with `-live`, takeover candidates |
| dnsx | `azhaq dns` | wildcard answers left out per zone |
| httpx | `azhaq probe` | takeover candidates, `catchall` pages |
| katana + jsluice | `azhaq crawl` | the routes scripts call, with methods and body names |
| ffuf | `azhaq fuzz`, `azhaq dirs` | scope, budget and ledger on every request |
| gau | `azhaq urls` | a fifth archive (arquivo.pt), failures said |
| arjun | `azhaq params` | a control against pages that answer any name |
| naabu, nmap (service versions, UDP) | `azhaq ports` | UDP without root, products and versions |
| gowitness | `azhaq shots` | Chrome held to the scope and the budget |
| notify | `azhaq notify` | a lost message is exit 3 |

What it adds:

- **Routes other crawlers miss.** On OWASP Juice Shop it finds 70 of the 77 routes the server defines that its frontend calls, with methods and body fields, and names the line of the script that calls each. katana with its jsluice parser (`-jc -jsl`) lists 1; grepping the scripts it fetched for quoted paths gives 37, as bare strings.
- **Access control with evidence.** `azhaq roles` signs in as each of your accounts, reuses each session against the others, and reports `[bob reads alice's object]` with why the object is alice's. `-replay-writes` extends this to writes: it replays each account's own writes (from a saved HAR, or empty-body probes of the routes it found) with the other sessions.
- **Where to look first, with reasons.** `azhaq hunt` ranks the mapped routes, hosts and files: each row has its score, the reasons for it (`object-id`, `cross-role`, `secret`, `exposed-file`, …) and the command to run next.
- **The API routes a deploy added.** `azhaq watch` compares the routes scripts call from one run to the next: a new route with its methods and body names, a method or a name added to a known route, a route gone, each tied to the script that calls it.
- **Proof of what was sent.** Every request and connection a run with a workspace sends to a target goes in a hash-chained ledger next to it (`azhaq ledger -verify`). A kill file stops all sending.
- **A finding as a submission.** `azhaq report` writes each cross-role finding `roles` listed as a Markdown report: steps with curl, the evidence, the control, impact and remediation.
- **Safe to hand to an assistant.** `azhaq mcp` locks the scope, the request budget and the pace when it starts; no tool argument can widen them.
- **Takeover candidates flagged.** A CNAME to a cloud name that no longer exists, a domain nobody holds, or a hosting service's page for an unclaimed name is listed with its evidence. Even a plain `subs -live` flags them.
- **Nothing partial passes as complete.** What failed, what was left alone and which limit stopped a run is in the summary, and the exit code says it: `3` finished with failures, `4` stopped by a limit.

Numbers for each job, against the tool it replaces, are in the [benchmark](#benchmark).

## At a glance

| You want | Run | In place of |
| --- | --- | --- |
| One web app or API mapped: pages, the routes its JavaScript calls, API descriptions, forms | `azhaq run -url https://app/ -db app.db` | katana + jsluice, reading bundles by hand |
| Who may read or write what across accounts: IDOR, BOLA | `azhaq roles -role anon -role 'alice=Authorization: Bearer …' -role 'bob=…' -- -url https://app/` | Autorize, diffing Burp histories |
| A program's attack surface, inside its scope | `azhaq run -scope hackerone -program NAME -db prog.db` | a script around the tools below |
| Subdomains that resolve | `azhaq subs -d example.com -live` | subfinder \| dnsx |
| Web services probed | `azhaq probe -l hosts.txt -json` | httpx |
| Paths, parameters, ports, archived URLs | `azhaq dirs`, `params`, `ports`, `urls` | ffuf -ac, arjun, naabu, gau |
| UDP ports, without root | `azhaq ports -host HOST -p none -pu top` | |
| DNS records of a list of names (A, AAAA, CNAME, MX, NS, TXT, SRV, SOA, CAA, PTR, AXFR), reverse DNS of a range | `azhaq dns -l names.txt -mx -txt -json`, `azhaq dns -l 192.0.2.0/24 -ptr` | dnsx |
| Subdomains by DNS brute force | `azhaq dns -d example.com -w words.txt` | dnsx -d -w |
| A wordlist in any part of a request: path, header, body | `azhaq fuzz -u https://app/FUZZ -w words.txt` | ffuf |
| Where to start in a big map | `azhaq hunt -db app.db` | reading the map by eye |
| A finding written up to submit | `azhaq report -dir DIR` | a report template filled by hand |
| What a run sent, provably | `azhaq ledger -verify app.db.ledger.jsonl` | |
| What changed since the last run, including the API routes a deploy added | `azhaq watch -db prog.db -- RUN FLAGS` | cron and diff |
| Text from a pipe or a file sent to Slack, Discord, Telegram, Teams, Google Chat, Pushover, Gotify, e-mail or any URL | `azhaq subs -d example.com \| azhaq notify -bulk` | notify |
| An assistant doing the recon | `azhaq mcp -allow example.com -max-requests 5000` | |
| What a run would send, before it sends anything | `azhaq plan` with the run's flags | |

## Install

Download a binary for Linux, macOS or Windows from the [releases](https://github.com/trannghiach/azhaq/releases), or:

```
curl -fsSL https://raw.githubusercontent.com/trannghiach/azhaq/main/scripts/install.sh | sh
go install github.com/trannghiach/azhaq/cmd/azhaq@latest      # Go 1.26 or newer
docker run --rm -v "$PWD:/work" -u "$(id -u)" ghcr.io/trannghiach/azhaq run -domain example.com -passive
```

`scripts/install.sh` installs the latest release for Linux or macOS (amd64 or arm64) into `$HOME/.local/bin`. It downloads the archive and `checksums.txt` and checks the archive's sha256 against it. When `cosign` is found, it also checks the sigstore signature of `checksums.txt` against this repository's release workflow. Nothing is written to the install directory when the checksum does not match, or when cosign is found and the signature check fails. Without cosign, it installs after the checksum check, says the signature was not verified and prints the command that verifies it. To refuse that, run `sh install.sh --require-signature` (or `sh install.sh -s`) or set `AZHAQ_REQUIRE_SIGNATURE=1`: the script then stops before downloading anything when cosign is missing, and stops when the signature does not verify (`curl -fsSL URL | sh -s -- --require-signature`). `-v` picks a release and `-d` a directory: `sh install.sh -v v0.8.1 -d /usr/local/bin`, or from the pipe, `curl -fsSL URL | sh -s -- -v v0.8.1 -d DIR`. `COSIGN=/path/to/cosign` names the cosign to use; the script stops if it is not an executable. It needs curl or wget, tar, gzip, sha256sum or shasum, and cosign (optional, required with `sh install.sh -s`), plus the usual awk, sed, head, mktemp, uname, cp, chmod and mkdir; it names every missing tool before it downloads anything.

<details><summary>Verify a download</summary>

The checksums file is signed with [sigstore](https://www.sigstore.dev/) by the release workflow:

```
cosign verify-blob --bundle checksums.txt.sigstore.json checksums.txt \
  --certificate-identity-regexp '^https://github\.com/trannghiach/azhaq/\.github/workflows/release\.yml@refs/tags/v' --certificate-oidc-issuer https://token.actions.githubusercontent.com
sha256sum --ignore-missing -c checksums.txt
```

</details>

`azhaq help` lists the commands, `azhaq help COMMAND` shows one with examples, and `azhaq docs` prints an overview and the documentation offline. `azhaq help -json` describes every flag for a program to read. Start-up work is kept small: the CDN ranges are read the first time an address is checked.

## Quick start

Only scan systems you are allowed to test.

**Map an app.**

```
$ azhaq run -url http://localhost:3000/ -db juice.db
  URL http://localhost:3000/rest/2fa/verify  target  hint  api  POST  [called]
      POST  body tmpToken totpToken
  URL http://localhost:3000/b2b/v2/orders  target  hint  api  POST  [described]
      POST  body cid orderLines orderLinesData
  URL http://localhost:3000/api/Users  target  visited  auth  POST  status=401 title=UnauthorizedError: No Authorization header was found
  URL http://localhost:3000/#/administration  target  hint  client-route  guard=canActivate  [linked]
  …
azhaq run: 190 map rows (119 URLs, 71 api, 43 client routes, 11 auth, 8 forbidden, 1 websocket) · 154 requests · 5.6 s · db juice.db
  next: azhaq query -db juice.db -role auth,forbidden   (what needs a session)
  next: azhaq export -db juice.db -format openapi > api.json   (for Burp, Postman, ZAP)
```

**Compare two accounts.**

```
$ azhaq roles -role anon -role "alice=Authorization: Bearer $TA" -role "bob=Authorization: Bearer $TB" -- -url http://localhost:5000/
  401 → 200:79 → 200:79  http://localhost:5000/books/v1/aliceBook  [bob reads alice's object] · sensitive: secret
  200:1.1k → 200:1.1k → 200:1.1k  http://localhost:5000/users/v1/_debug  [anyone reads sensitive fields: password]
```

Each column is one role's answer as `status:bytes`, in the order the roles were given (`-` for a role never asked).

No headers to copy and no crawl: give each account's browsing as it was saved, one file per account (a HAR from the browser, Caido or Burp, or Burp's "Save items" XML). Each account's GETs are the pages it reached, its latest Authorization and Cookie headers its session, and an anonymous role is added.

```
$ azhaq roles -har alice=alice.har -har bob=bob.har
$ azhaq roles -burp alice=alice.xml -burp bob=bob.xml -replay-writes put,patch
```

**Map a program inside its scope and a budget.**

```
$ azhaq plan -scope bugcrowd -program tesla -max-requests 5000      # what it would ask, sends nothing
$ azhaq run  -scope bugcrowd -program tesla -max-requests 5000 -rate 5 -db tesla.db
$ azhaq resume -db tesla.db                                          # after the budget, Ctrl-C or a crash
```

More, task by task: [docs/RECIPES.md](docs/RECIPES.md).

## Reading the output

```
URL http://localhost:3000/rest/2fa/verify  target  hint  api  POST  [called]
│   │                                      │       │     │    │     └ how it is known, when the server did not answer it (below)
│   │                                      │       │     │    └ methods its callers use
│   │                                      │       │     └ kind: app, auth (401), forbidden (403), api, page, script, asset, sourcemap
│   │                                      │       └ coverage (below)
│   │                                      └ scope: target, or fanout (found on the way)
│   └ the URL; a template like /api/Users/{id} stands for many
└ what the row is: URL, Hostname, Domain, IPAddress, …
```

| Coverage | Meaning |
| --- | --- |
| `visited` | Requested; it answered as a page of its own. |
| `catchall` | Requested; it answered with the page every unknown path gets (an app's shell). |
| `error` | Requested; no answer. |
| `gone` | Requested; 404 or 410. |
| `hint` | Known from a script, a description, an archive or a link, not proven by a GET. |
| `skipped` | Not requested: a GET there would change something. Listed as "left alone". |
| `capped` | Not requested: a limit ran out. `azhaq resume` continues. |

A row no request answered ends with how it is known, the strongest of its sources: `[browser]` (Chrome, loading a page, sent it), `[described]` (an API description lists it), `[called]` (a script calls it), `[linked]` (a page links to it, a form submits to it, or a script names it), `[archived]` (only an archive holds it), `[guessed]` (only a wordlist found it, and the answer was a 404 or the any-path page) or `[given]` (you named it, and nothing answers or names it). A string a script only joins more path to (`"/rest/user/" + id`) is no route; `crawl -rejected` lists it. `-evidence` in `query` selects by it; [docs/CONCEPTS.md](docs/CONCEPTS.md#evidence-how-azhaq-knows-a-url) has the levels.

Every command prints results on stdout, and a summary on stderr: what failed and whether a retry may help, what was left alone, the limit that stopped it. `-json` makes both JSON. Exit codes: `0` complete, `1` error, `2` usage (nothing sent), `3` finished with failures, `4` stopped by a limit or the kill file. [docs/CONCEPTS.md](docs/CONCEPTS.md) explains every term; [docs/OUTPUT.md](docs/OUTPUT.md) every field.

## What Azhaq sends

| What | How | When |
| --- | --- | --- |
| Pages, scripts, API descriptions (at the root and under each API base), archived URL templates | GET | every run |
| 32 built-in path checks per web service (`robots.txt`, sitemaps, API descriptions, `.git/HEAD`, `backup`, `admin`, …) | GET | every run; `-no-paths` turns them off |
| Path and parameter guesses, ports, GraphQL introspection | GET (`params -X` sends names in a POST, JSON or XML body, on request), a TCP connect and one `HEAD /` (a `GET /` on a web port whose head names no product; on 5432, 6379 and 27017–27019, that database's own first request), POST | `-dirs`, `-params`, `-ports`, `-graphql`, held to the targets given or to `-allow`/`-scope` |
| UDP ports | one datagram per port, a protocol's harmless request (a DNS `. NS`, an SNMP GET of `sysDescr.0` with community `public`, …; on a port with no known protocol a DNS query, an SNMP get, memcached's version, then an empty datagram), and the next way its protocol has when none came back | `-udp`, `-pu`, `run -ports-udp`, held to the targets given or to `-allow`/`-scope` |
| A wordlist in a request | the method and body you give it, with the wordlist's words in them | `azhaq fuzz`, held to the host of `-u` or to `-allow`/`-scope` |
| Chrome | GET, HEAD and CORS preflights, and, while signing in, every method the page sends (its sign-in request, and whatever its own scripts send meanwhile, such as a socket's polling POSTs; all in the ledger); a page's own writes are refused and mapped, unless `-browser-writes`; every download is refused and listed, and a page read for its requests is loaded without its images, fonts and media | `-browser`, `-login`, `shots` |
| Other roles' writes | POST, PUT, PATCH, DELETE | `roles -replay-writes`, held to the `-url` hosts or to `-allow`/`-scope` |

The map (`run`, `crawl`) lists, and does not request, URLs whose names say a GET would change something (`/logout`, `/createdb`, `?phpids=on`). A wordlist sweep (`dirs`, `-dirs`, `fuzz`) asks every word, `/logout` included, as ffuf does; with a session, `dirs` holds those words back and `-all-gets` asks them. A URL that carries a scanner's payload in its path or query (`<script>`, `../../etc/passwd`, `union select`), as archives often keep them, or a scanner's own test file, never enters the map. No request to a target goes to a host outside the scope, Chrome's included; without a scope, they stay on the site. Chrome saves nothing to disk: a download a page starts is refused and listed. Third-party sources (subdomain lists, archives, RDAP) are asked about your domains; `-passive` sends nothing to the targets. `-rate` paces it, `-max-requests` caps it, and `azhaq plan` prints it before anything is sent.

**Path checks stop at their answer.** The checks that guess where an API description sits (`openapi.json`, `swagger.json`, `api-docs`, `v3/api-docs`, …, and the same names again under each API base the run found, such as `/rest/` or `/v3/`) are asked one at a time, likeliest first. They stop at the first answer that is an OpenAPI or Swagger document with paths, or the Swagger UI or ReDoc page that loads one. Once an origin has served a description, here or through `azhaq-openapi`, its other locations are not asked, and the summary counts them: `note: path checks: 28 skipped (an API description was already found)`. Every other check (`robots.txt`, `login`, `admin`, `graphql`, `.git/HEAD`, …) is still asked. A Swagger UI whose script holds the document (Juice Shop's `/api-docs/`) is read from the script, and the names next to it are not guessed. A page that is byte for byte what the site root answers for a made-up path (a single-page app's shell) is the catch-all answer of a directory whose own baseline was not asked, so that baseline is not requested; a directory with answers of its own is still asked.

**Screenshots.** `shots` (and `run -screenshots`) take a picture of each web service with a Chrome on the machine. A URL with a path or query is kept; `-u 192.0.2.0/28`, `-p small|medium|large|8000-8010,3000`, `-no-http`, `-no-https`, `-nmap FILE` (an `nmap -oX` file) and `-nessus FILE` say which services; `-shot-size`, `-shot-fullpage`, `-shot-wait`, `-shot-timeout`, `-shot-format jpeg`, `-shot-quality`, `-shot-js`, `-shot-codes`, `-chrome`, `-chrome-proxy`, `-chrome-profile` and `-H` shape them. Each page's row has its response headers, TLS session, the technologies of the rendered page, console messages and network log. At a set `-rate` a page's time runs from when it last moved, so a slow pace gives whole pictures, not blank ones; a picture taken before the page's images, styles and scripts loaded is marked `partial` and the run exits 3. Look-alike pages are grouped by a perceptual hash in `export -format html`, a single file whose pictures are embedded.

**Screenshot gallery.** `azhaq gallery -db shots.db` (or `-workspace DIR` for a directory of workspaces) serves a local page, `http://127.0.0.1:7180/`, to go through thousands of pictures: a grid with each page's URL, title, status and technologies, filters (status, technology, host, title, partial, look-alike group), one tile for each group of look-alikes, search of URL, title and kept page text (`title:login tech:nginx body:"sign in"`), and a page per shot with its picture, headers, cookies, TLS, network log, console and the `azhaq show` command. It is embedded in the binary, works offline, reads only the workspace and sends nothing to any target; the same data is a JSON API under `/api/` ([docs/OUTPUT.md](docs/OUTPUT.md#gallery)).

**Screenshots and the budget.** A page's images, scripts and styles each count against `-max-requests`. When too few are left, Chrome is refused them and no image is saved; `shots` and `run -screenshots` say it: `note: screenshot of http://127.0.0.1:3001/ not taken: the page needs about 26 requests and 8 were left (raise -max-requests)`. The figure is how many requests the page made when it was cut short. A run starts one Chrome and opens up to 6 tabs in it at once, as gowitness runs 6 threads (`-tabs N` changes it).

## Proving what was sent

Every run with a workspace writes `DB.ledger.jsonl` next to it: one JSON line for each request or connection sent to a target (HTTP; Chrome's requests, each once it has left, and its WebSocket handshakes with their path; TCP connects and TLS handshakes; UDP datagrams) with its time, URL or `ip:port`, host, the scope rule that allowed it (`-allow`, `-scope`; empty when the run has no rules) and the collector. Each line carries the hash of the one before, so an edited, removed or reordered line is caught, and a run that ends writes a seal line, so lines cut from the end are caught too: the summary names the seal (`sealed 3f9c…`), and `-verify` prints the last one. DNS queries and the third-party sources of `subs` and `urls` (and the RDAP registry) are not targets and are not listed. Runs into the same workspace, and `azhaq resume`, append to the same file.

```
azhaq ledger -verify app.db.ledger.jsonl    # exit 0 intact and sealed; exit 3 naming the first bad line, or the lines after the last seal
azhaq ledger -summary app.db.ledger.jsonl   # counts by kind, host, method, scope rule; first and last time
azhaq ledger -csv app.db.ledger.jsonl       # for a client report or a blue team's deconfliction
```

`-ledger FILE` writes it elsewhere, `-ledger off` not at all. A drop-in command without `-db` uses a temporary workspace and writes a ledger only with `-ledger FILE`.

`-kill-file PATH` (default `DB.stop`) is the kill switch. Create the file and, within a tenth of a second, nothing more is sent, not even a request that was already waiting for `-rate` (Chrome's included). The run exits 4 with `stopped` naming the kill switch. Remove the file and `azhaq resume -db DB` continues. A drop-in command without `-db` has no default kill file. `azhaq roles` keeps one ledger, `roles.ledger.jsonl`, and one stop file, `roles.stop`, in its `-dir`; `roles.stop` stops the runs of the roles (`roles` exits 4), and the replay that follows does not look for it.

## A workspace

```
azhaq query  -db juice.db -role api -method POST -fields key,body -json   # what the app's writes take
azhaq show   -db juice.db http://localhost:3000/rest/2fa/verify           # everything about one URL, and the line that calls it
azhaq hunt   -db juice.db                                                  # where to look first
azhaq export -db juice.db -format openapi > api.json                      # Burp, Postman, ZAP
azhaq export -db h1.db -format targets | nuclei -l -                      # web services
azhaq export -db h1.db -format burp > scope.json                          # the run's scope for Burp
azhaq watch  -db h1.db -every 24h -notify https://hooks.slack.com/… -- -scope hackerone -program acme
```

Runs into the same workspace add to it; `diff` and `watch` say what changed. `ingest` takes in what subfinder, dnsx, httpx, katana, naabu, nuclei, gau and ffuf found.

`watch` also says what changed in an app's API surface, tied to the script that calls each route. A frontend deploy that adds a route adds attack surface, and the first report is the one that pays:

```
~ 4 API routes
    + POST /api/v2/export {format, userId}  (main.js)
    ~ /api/orders/{id}: +DELETE  (main.js)
    ~ PUT /api/profile: +role  (main.js)
    - /api/legacy/report  (main.js)
```

`+` is a new route with its methods and the names it sends. `~ /route: +DELETE` is a method added to a known route; `~ PUT /route: +role` a name its call now sends. `-` is a route the previous run's scripts or API description named and no source names now. Routes are compared where a script or an API description names them: one only a crawl or a guess finds is not reported new, and one found only by guessing or in an archive is never reported gone. Placeholder names (`{id}` or `{orderId}`), identifiers, ordering and case are not changes, so the same app mapped twice reports no route change. The first run of a workspace lists none. The same text goes to Slack, Discord and Telegram, and the JSON of `-json`, `-notify-cmd` and generic hooks has a `routes` field ([docs/OUTPUT.md](docs/OUTPUT.md#watch)).

## Notifications

`watch -notify` takes a webhook URL, and `azhaq notify` sends any text the way [notify](https://github.com/projectdiscovery/notify) does, with its flags and its `provider-config.yaml`:

```
azhaq subs -d example.com -live | azhaq notify -bulk -pc ~/.config/notify/provider-config.yaml
azhaq watch -db h1.db -every 24h -notify-config provider-config.yaml -- -scope hackerone -program acme
```

A webhook URL is a secret. Azhaq never prints it: an error from a hook names the host and what went wrong, not the path or query, and not a token a server echoes back. So that it need not stand on the command line, where `ps` shows it to every user, `-notify @FILE` reads URLs from a file (one a line) and `AZHAQ_NOTIFY` holds them too (comma-separated); a provider config keeps its tokens in the file, and a word that starts with `$` in it is replaced by that environment variable.

A 429 or a 5xx is tried again (three tries, `Retry-After` honoured); a message longer than a service takes is sent in parts, not cut. A delivery that did not arrive is named in the summary and the exit code is 3: `azhaq notify` and `azhaq watch` do not exit 0 over a lost message. [docs/OUTPUT.md](docs/OUTPUT.md#notify) lists the providers and what each one sends.

## Where to look first

A map of thousands of routes does not say where to start. `azhaq hunt -db app.db` ranks it. It reads the workspace and sends nothing. One row per route template (`/rest/basket/6` and `/rest/basket/7` are one row), each with its score, the reasons for it and the command to run next:

```
$ azhaq hunt -db app.db
  1   57  http://app/api/orders/{id}  object-id: {id} in the path; path-data: "orders" in /api/orders/{id}, named, not requested; unauth-write: DELETE: nothing that names it asks for credentials (not tried)  → next: azhaq roles -role anon -role 'user=Authorization: Bearer …' -- -url http://app/
  2   33  http://app/api/v2/export  object-id: identifier parameter userId; unauth-write: POST: nothing that names it asks for credentials (not tried); input: takes format, userId  → next: azhaq roles -role anon -role 'user=Authorization: Bearer …' -- -url http://app/
$ azhaq roles -json -role anon -role 'user=Authorization: Bearer …' -- -url https://app/ > roles.jsonl
$ azhaq hunt -db app.db -roles roles.jsonl -limit 10
```

The score is the sum of a row's signals, each counted once. What raises a row: a role reading or writing another role's object (from `-roles`, with the evidence and its confidence quoted; the heaviest weights, 95 to 110, scaled by confidence); a name another party may take over; a credential in a script (the file is named) or a source map; a backup, key or database file, a directory listing; admin, debug, config and internal paths; API descriptions and GraphQL endpoints; an object identifier in the path or an `id` parameter; parameters that take a URL, a file, a command, a redirect or a query; a write method no description asks credentials for; a file upload form; a GET that looks state-changing; a server error. First seen within `-since` (default 7 days) adds a little when the workspace holds older URLs too, and a row with only that never ranks. Static assets, scripts, catch-all pages and pages that are gone never rank. Ties go to the target before fan-out, then to the row with more distinct signals, then by key. `-limit` (default 25) keeps the best rows.

The `next` command is a real invocation: `azhaq roles show -dir DIR URL` for a cross-role row (DIR is the `-dir` of the roles run), `azhaq roles …` for an identifier, `azhaq params -u URL -w WORDLIST` for a page that takes input, `azhaq show -db FILE URL` for the rest. [docs/OUTPUT.md](docs/OUTPUT.md#hunt) lists the signals.

## Access control

`azhaq roles` maps the target once per role, then asks every endpoint any role reached with every other role's session, fills `{id}` routes with each role's own objects, and compares the answers. A role is anonymous, carries headers you give it, gets them from a command (`-role-cmd`, for tokens that live minutes), or signs in with Chrome (`-role-login`). A session that dies mid-run is caught and quoted (`the site said "Signature expired"`), and a canary (an endpoint only a live session reads) renews it during the replay. Each cross-read is scored `proved`, `likely` or `guess`, with the reason. A route that answers a made-up identifier like a real one is listed as `answers any identifier`, not as a finding. `azhaq roles show -dir DIR URL` prints the answers side by side, a field-level diff, and a curl per role with its session held in a shell variable. With `-replay-writes post,put,patch` and `-har alice=alice.har`, alice's writes are asked with bob's session too, and the routes the map found are filled with each role's own identifiers (including routes that only take a write, such as `PUT /users/v1/{username}/email`) and sent with an empty body, the owner's first. A cross-role write is reported only when it is proven: the owner's object is read as the owner before and after, and `[bob writes alice's object]` is claimed only when that object changed the way the write asks, or was deleted. A write answered 2xx that left the owner's object unchanged (an app that writes the caller's own object whatever the path says) is not a finding, and a POST to a collection is never called writing another role's object. [docs/OUTPUT.md](docs/OUTPUT.md#roles) lists the verdicts and fields.

`azhaq report -dir DIR` writes up what `roles` found as one Markdown report per finding, ready to paste into HackerOne or Bugcrowd, or into a red team's client report. It reads the evidence the roles run kept in `DIR/roles.db` and sends nothing.

```
$ azhaq report -dir azhaq-roles-20261028-101500
azhaq report: 3 reports in azhaq-roles-20261028-101500/reports
  …/01-proved-get-books-v1-book-title.md  [proved] Broken object level authorization: bob reads alice's book via GET /books/v1/{book_title}
  …/02-proved-get-books-v1-book-title.md  [proved] Broken object level authorization: alice reads bob's book via GET /books/v1/{book_title}
  …/03-unrated-get-users-v1-debug.md  [unrated] Excessive data exposure: anyone reads password via GET /users/v1/_debug
```

Without `-url`, it writes a report for each listed row whose verdict is `reads another role's object`, `writes another role's object`, `anyone writes another role's object` or `anyone reads sensitive fields`, ordered by confidence (`proved`, `likely`, `guess`, then rows that carry none). With `-url URL` (and `-method M` for a write row) it writes that one report to standard output. `-format md|json` picks the form, `-o PATH` a file or a directory, `-redact` also masks hosts (`<host>`) and identifiers (`<id-1>`). Each report has a title naming the bug class, a two-sentence summary, a severity that is labelled a guess and says why, numbered steps with the curl commands from the evidence (the sessions as `$ALICE_TOKEN`, `$BOB_TOKEN`), the evidence (the owner's answer, the reader's, and the control: what a made-up identifier returned), the row's `owner_by` quoted as the reason the object is the owner's, impact and remediation by class, and notes. A report never says what the evidence does not hold: a row with no control, a body that was not kept or no `owner_by` says so under "Missing from the evidence store". Read a redacted report once before sharing it: an identifier no kept body names in an identifier field is not masked. [docs/OUTPUT.md](docs/OUTPUT.md#report) has the flags and the JSON fields.

## In a pipeline

```
azhaq subs -d example.com -silent | azhaq dns -silent | azhaq probe -json      # subfinder | dnsx | httpx
azhaq dns    -d example.com -w subdomains.txt -resp                            # dnsx -d -w (brute force)
azhaq dns    -l names.txt -mx -txt -json -r 1.1.1.1,tcp:9.9.9.9 -rl 50 -t 20   # dnsx -mx -txt -j -r ... -rl -t
azhaq dns    -l 192.0.2.0/24 -ptr -resp                                         # dnsx -ptr (reverse names of a range)
azhaq crawl  -u https://app.example.com/ -d 3 -jsonl                            # katana + jsluice (katana's flags and lines)
azhaq urls   -d example.com -silent                                            # gau (the host alone; -subs adds its subdomains)
azhaq urls   example.com -subs -mc 200 -blacklist png,jpg,css -fp | httpx      # gau --subs --mc 200 --blacklist … --fp
azhaq ports  -host scanme.nmap.org -p top-1000 -json                           # naabu (connect scan)
azhaq ports  10.0.0.0/16 -p 22,80,443 -wn -oA scan                                # a range, nmap XML and greppable files
azhaq ports  -host 192.0.2.7 -p none -pu top -json                             # the common UDP ports, no root
azhaq dirs   -u https://app.example.com/ -e php,bak                          # ffuf -ac, with SecLists' common.txt built in (-w FILE for your own)
azhaq fuzz   -u https://app.example.com/FUZZ -w common.txt -e .php,.bak -recursion   # ffuf
azhaq fuzz   -u https://10.0.0.5/ -H 'Host: FUZZ.example.com' -w subdomains.txt -fs 4242   # ffuf, virtual hosts
azhaq params -u https://app.example.com/search                                 # arjun (6,500 built-in names)
```

Each reads targets from flags, a file or stdin (`fuzz` takes one URL with its keywords in it, `-u`), prints results as found, and with `-json` uses the field names of the tool it stands in for. `dirs` and `params` have ffuf's and arjun's defaults (40 guesses in flight, 5 groups of names in flight, no pace); `-rate N` holds them to N requests a second. `dirs` takes ffuf's matchers and filters (`-ms -mw -ml -mr`, `-fc -fs -fw -fl -fr`), counts sizes, words and lines as ffuf does, starts from the path of the URL given (`-u https://h/api/` sweeps `/api/WORD`), and carries SecLists' `common.txt` (MIT, 4,750 words) for when `-w` is left out. `probe` follows no redirect unless given `-fr`, as httpx: a row's status, title, length and content type are one answer's. It takes httpx's matchers and filters (`-mc -fc -ms -fs -mr -fe -mdc …`), ports (`-p 80,8000-8100`), paths (`-path`), certificate data (`-tls-grab`), hashes (`-hash`), `-jarm`, raw output (`-sr`, `-irr`) and its CSV and Markdown forms; a target with no answer is a row with `failed: true`. `-x`, `-body` and `-rr` send the methods, body or request you give and can change data on the target; the summary says so.

**`fuzz`** puts words from a wordlist into a request, anywhere in it: the path, a query value, a header (`Host: FUZZ.example.com` for virtual hosts), the method, a JSON or form body. It takes ffuf's flags and counts as ffuf does (words are spaces plus one, lines newlines plus one, the same match and filter rules, the same calibration), so a command line moved from ffuf gives the same results:

- input: `-w FILE[:KEYWORD]` (repeatable, `-w a.txt,b.txt`, `-` for stdin), `-mode clusterbomb|pitchfork|sniper` (`§…§` marks the places), `-e`, `-ic`, `-D` (dirsearch `%EXT%`), `-enc 'FUZZ:urlencode b64encode'` (all of ffuf's encoders, in process), `-input-cmd`/`-input-num`/`-input-shell`, `-request FILE` with `-request-proto` (a raw request as Burp saves it; `-u`, `-X`, `-d`, `-H`, `-b` replace parts of it);
- request: `-u -X -d` (`-data`, `-data-ascii`, `-data-binary`), `-H`, `-b` (`-cookie`), `-r`, `-timeout`, `-x` (an http, https, socks5 or socks5h proxy), `-replay-proxy` (each match sent once more through a proxy such as Burp), `-ignore-body`, `-raw`, `-sni`, `-http2`, `-cc`/`-ck`; servers back to TLS 1.0 are reached; a body compressed with gzip, deflate or brotli is decoded, so `-fs` counts the decoded bytes even when `-H 'Accept-Encoding: gzip, deflate, br'` is given;
- matchers and filters: `-mc -ms -mw -ml -mr -mt` and `-fc -fs -fw -fl -fr -ft` (`-mt '>1000'`, `-ft '<100'`: milliseconds to the first byte), `-mmode`, `-fmode`;
- calibration: `-ac` (off by default, as in ffuf), `-ack`, `-acs basic|advanced|NAME`, `-acc STRING`, `-ach`;
- recursion: `-recursion`, `-recursion-depth`, `-recursion-strategy default|greedy`, `-maxtime-job`;
- pace and stops: `-t`, `-rate`, `-p 0.1` or `-p 0.1-2.0`, `-maxtime`, `-sf`, `-sa`, `-se` (and `-se-after N`);
- reports: `-o FILE` with `-of json|ejson|csv|ecsv|html|md|all`, `-od DIR` (the raw request and answer of each match), `-or`; `-json` prints ffuf's fields on stdout;
- `-preflight FILE` and `-postflight FILE` (raw request files sent before and after each request; `-preflight-var 'TOKEN:name="csrf" value="([^"]+)"'` or `-preflight-var-auto 'TOKEN:csrf'` read a value from the answer, and `TOKEN` in the request stands for it; `-preflight-mode`, `-preflight-error`). They carry your `-H` and `-b`, and each goes through the scope, the budget, the pace and the ledger. A value read from an answer can never change the scheme, host or port of a request: ffuf's `-preflight-anyhost` does not exist here;
- `-config FILE`, else `~/.config/ffuf/ffufrc` or `~/.ffufrc`: ffuf's TOML settings, read as flags in front of the command line's own;
- `-control FILE`: steer a run that goes (`echo 'rate 2' >> FILE`, `pause`, `resume`, `fs 4242`, `afs 100`, `fs none`, `show`, `savejson out.json`, `queueshow`, `queuedel N`, `queueskip`, `stop`), in place of ffuf's console. With stderr on a terminal and no `-s`, `-silent` or `-json`, a status line is printed over itself each second.

It differs from ffuf in these ways:

- Auto-calibration is off unless `-ac` is given (`-acs`, `-acc` and `-ach` imply it), as in ffuf, so a command line moved from ffuf gives ffuf's matches. It needs the keyword `FUZZ`, or the one `-ack` names, in the request; without it a note says nothing was calibrated. Calibration requests are paced by `-rate` and counted by `-max-requests`; ffuf's are not.
- The default matcher is `-mc 200-299,301,302,307,401,403,405,500`, unless `-ms`, `-mw`, `-ml`, `-mr` or `-mt` is given alone, as in ffuf.
- With several wordlists, `-mode pitchfork` runs as long as the longest list and the shorter ones start over (4 users and 3 passwords make 4 requests, as in ffuf 2.3).
- Every request goes through the run's budget and pace (`-max-requests`, `-rate`) and the ledger, and stops at the kill file. The host in `-u` is the scope unless `-allow`, `-deny` or `-scope` say otherwise; when the keyword starts the host (`FUZZ.example.com`) the scope is its domain. A request to a host outside the scope is not sent, and the summary counts it. The copies `-replay-proxy` sends go to the proxy you named: they are not requests to the target, so they are not in the ledger, the budget or the pace, and the summary says how many were sent.
- Five unanswered requests in a row stop the run: the target is down (exit 3, the origin is listed under "did not answer"). `-se` makes it twice `-t` failures of any kind, as ffuf's; `-se-after N` names the number. `-sf`, `-sa` and `-maxtime-job` say what they did in the summary (exit 4 for the first two, a note for the last).
- `-timeout` is seconds per request, as in ffuf. `-o` writes ffuf's report, in the order the inputs were asked; `-o NAME.txt` without `-of` writes what stdout shows, as before. `-db FILE` keeps the matches in a workspace as ffuf results are, for `query`, `show` and `export`.
- Not in `fuzz`: ffuf's scrapers (`-scraperfile`, `-scrapers`), `-search` and its history files (`-db` and `azhaq show` keep the matches), `-audit-log` (the hash-chained `-ledger` is the record of requests).

**`ports`** takes what naabu takes: names, addresses, `host:port` (that port only, unless `-p` is given), URLs, CIDR ranges (IPv4, and IPv6 down to /104) and AS numbers, several to a flag separated by commas, or on stdin or as arguments. A range is not expanded in memory and has no size cap; `-wn` scans only the addresses that accept or refuse a connect to 80 or 443, `-sn` lists them and scans nothing. `-p`, `-tp 100|1000|full` and `-pf FILE` add ports; `-ep LIST|FILE` takes ports out; `-p -` is every port; `-p u:53` is a UDP port. The ports of a host are asked in a random order, the likeliest (nmap's top 100, then its top 1000) first (`-order asc` for numbers, `-seed N` to repeat an order). A scan is paced by `-rate` (default 1500 connects a second; this machine's loopback is not paced unless given), `-T0` to `-T5` set rate, connect timeout and retries as nmap's templates do (an explicit flag wins), `-connect-timeout` is the wait for one connect (a bare number is milliseconds; `-timeout` is how long the whole run may take), `-retries N` asks the ports that did not answer N more times, `-c` is how many connects are in flight. Output is `host:port`, `-json`, `-csv`, nmap XML (`-oX`), greppable (`-oG`) or all three (`-oA BASE`). `-detect none` connects and closes, as naabu does without `-sV`. A CDN or WAF address is asked ports 80, 443, 8080 and 8443 only, and the row says so (`cdn`); `-cdn-full` scans it in full.

**`ports -udp`** also asks the common UDP ports (53, 67, 69, 111, 123, 137, 161, 500, 514, 520, 623, 1194, 1434, 1900, 3478, 4500, 5060, 5351, 5353, 5683, 10001, 11211, 27015, 47808, 51820); `-pu LIST` asks a list instead (`-pu 1-1024`, `-pu top`, `-pu top,5354`: names and numbers combine, in `-p` too), and `-p none` leaves the TCP ports out. In `azhaq run` it is `azhaq run -ports-udp SPEC`. No privileges are needed: each port gets one datagram on a connected socket, and the kernel tells an ICMP port unreachable from silence. A reply makes the port `open`, with the service, product, version and banner it gives; an ICMP port unreachable makes it `closed`; nothing, after every way asked, makes it `open|filtered`. The request is the harmless one of the protocol the port usually carries, and, on a port with no known protocol, a DNS query, an SNMP get with community `public`, memcached's version, then an empty datagram (DNS, SNMP and memcached are what move to odd ports: 5354, 8053, 10161); nothing logs in, guesses a credential or changes state. Every datagram counts against `-max-requests`, is paced and goes in the ledger as kind `udp`. A CDN or WAF address is not asked. Each open TCP port also gets `product` and `version` next to `service`, from what it says first or answers (a greeting such as SSH, FTP, SMTP, POP3, IMAP, MySQL or MariaDB, Telnet, IRC, NNTP, RTSP, SIP or VNC; an HTTP `Server` or `X-Powered-By` header, the body or title of `GET /`; and, for a port that waits to be asked, the answer to one harmless request of Redis, PostgreSQL, MongoDB, MQTT, AMQP, memcached, LDAP, SMB, DNS over TCP, Kafka, ZooKeeper, SQL Server, Oracle TNS, Cassandra, Kerberos, RDP, X11, SOCKS5, STOMP and XMPP, on any port, never with a credential). A web page that names no product gets its `<title>` in `title` (and its `<meta name="generator">` as the product). An SSH, FTP or mail port that sent no greeting is connected to once more after the scan, as sshd drops greetings when many connects arrive at once. A port that accepts a connection and closes it without a word is `tcpwrapped`. How many requests one open port can cost is in [docs/OUTPUT.md](docs/OUTPUT.md#ports-udp-products-and-versions). [docs/OUTPUT.md](docs/OUTPUT.md#ports-udp-products-and-versions) lists them.

**`subs` remembers names.** Passive sources answer differently each run (subdomain.center returns a random sample of its names on each call). Azhaq keeps every name it kept for a domain in `names/DOMAIN.json` under `$AZHAQ_DATA_DIR`, else `$XDG_DATA_HOME/azhaq`, else `~/.local/share/azhaq`, and asks this file as a source called `history` in the next run: with `-live` a stored name counts only if it resolves now (not to a wildcard), so stale names drop out and a name a source missed this time comes back; without `-live` no DNS lookup is made, and a stored name that no source gave this run is listed with `"unverified": true`. `-no-history` neither reads nor writes the file. `subs` ends with `coverage: the independent sources hold about 1609 names; this run has 1400 of them (87%) — an estimate of what the sources know, not of every name that exists; the other 47 of the 1447 names came from the name history, from guesses checked in DNS or as CNAME targets, which the estimate leaves out`; [docs/OUTPUT.md](docs/OUTPUT.md#drop-in-commands) says how it is counted.

**`subs` and subfinder's flags.** `-d` takes a comma list, a URL, a name with a trailing dot or `*.`; an IP address given as a domain is left out with a note. `-m`, `-f`, `-match-regex` and `-filter-regex` filter the names, `-cs` and `-oI` print subfinder's text forms, `-oD DIR` writes a file per domain, `-o` appends, `-ls` (with `-json`) lists the sources with their key requirement, `-recursive` runs only the sources that handle subdomains of subdomains, `-stats` prints each source's requests, names and errors, `-version` prints the version. A source that answers 429 is asked again after its `Retry-After`; `-source-rate N`, `-source-rates hackertarget=10/m,…`, `-max-results`, `-max-time`, `-max-body` and `-proxy URL` do what `subfinder -rl`, `subfinder -rls`, `subfinder -mr`, `subfinder -max-time`, `subfinder -rsr` and `subfinder -proxy` do. A source's key may also come from `$SOURCE_API_KEY` or `$VAR` in the provider file. `-sources` with a name that is no source says so (`azhaq subs -ls`).

**`subs -live` and its time.** subdomain.center answers a random 500 names per call, most of them made up. Without a key it is asked again only while its last round gave a name that resolves and no other source had; every round's new names are looked up before the next round is asked and no name is looked up twice. With `-dns-rate` the guesses may cost at most half what the real names reported cost (and not less than 1,000): On tesla.com, `subs -live -dns-rate 10` (two resolvers) took 161 s and listed 555 live names; `subfinder | dnsx -a -cname -rl 10` on the same resolvers took 211 s and listed 513. At the default pace it took 25 to 29 s against 56 to 63 s. Without `-live` nothing is looked up: the guesses are listed with `"unverified": true`, and the summary counts them. A name that is only a CNAME is a live name, as `dnsx -a -cname` lists it. Answers too big for 512 bytes (a long CNAME chain) arrive with EDNS0, or over TCP when a server truncates them.

## For assistants: MCP

```
claude mcp add azhaq -- azhaq mcp -allow example.com -max-requests 5000 -rate 5
```

The tools run Azhaq itself and return its summary and rows. The scope, the budget for all calls together and the pace are fixed at start; an argument the schema does not take is refused; results are bounded, and exports come in pages that each parse alone. Without `-allow` or `-scope` the server does not start, unless `-unlocked` says so. [docs/MCP.md](docs/MCP.md).

## Benchmark

`go run ./bench` runs Azhaq and the tools it replaces on the same targets: Juice Shop and VAmPI in Docker, the services lab (fifteen daemons), a DNS lab, servers and a zone the bench serves itself, and, at 5 requests per second, ginandjuice.shop, testphp.vulnweb.com and demo.testfire.net; passive lookups only on hackerone.com, tesla.com and vulnweb.com. It prints the numbers, losses included.

Every comparison runs **twice**, as a reviewer runs it: with the default flags of both tools, and politely (`-rate 5` for HTTP, `-dns-rate 10` with dnsx `-rl 10` and the same two resolvers, `-rate 100` for ports, the reference at the same rate). `go run ./bench -profile default|polite|both` picks. A row is a win only when Azhaq has at least the reference tool's results, counting only results that something other than Azhaq confirms (a server's own log, a second resolver, `ss`, the app's source), in at most 1.05 times its time (the median of three runs below 20 s, one run above). The record keeps the old shares and ratios too.

<!-- bench:begin -->
Latest run (2026-10-30, v0.10.0, commit dbfe31c; profile: both; 183 of 192 checks pass). **Default** is the default flags of both tools; **polite** is `-rate 5` (HTTP; `probe -rl`, as httpx counts), `-dns-rate 10` (DNS; `dns -rl`, as dnsx counts) and `-rate 100` (ports), with the reference tool at the same rate. A result counts only when something other than azhaq confirms it, and a row is a win only when azhaq has at least the reference's results in at most 1.05 times its time. The record, with every check and the commands, is `bench/history/*.json`.

| Job | Replaces | Profile | Azhaq | Reference |
| --- | --- | --- | --- | --- |
| Live subdomains, 3 domains, no keys (names that resolve at a third resolver) | subfinder + dnsx | default | 630 live in 103 s | 514 live in 139 s (1 only it found) |
| Historical URLs, vulnweb.com | gau | default | 62, including 58 of gau's 64, in 19 s | 64 in 3.8 s |
| DNS brute force, 5000 words, the DNS lab | dnsx | default | 9 confirmed in 0.1 s | 9 in 1.1 s |
| Wildcard zone, 3 real names of 50 | dnsx | default | 3 found, 0 fake | 50 without `-wd` |
| Record types (9) of 32 names on a zone the bench serves | dnsx | default | 12 answers right in 0.0 s, 290 queries | 12 in 0.9 s, 523 queries |
| Probing 107 hosts (the local apps and 100 local servers) | httpx | default | 107 answered, 107 confirmed; status, title and tech agree on 106 of 107 shared; 1.1 s | 107 answered, 107 confirmed; 1.8 s |
| Known routes of juice-shop, the whole map (`azhaq run`) | katana `-jc -jsl` | default | 70/77 in 5.3 s | 1/77 in 14 s |
| Known routes of juice-shop, the crawler alone (`azhaq crawl`, katana's depth) | katana `-jc -jsl` | default | 53/77 in 4.6 s | 1/77 in 14 s |
| Known routes of vampi, the whole map (`azhaq run`) | katana `-jc -jsl` | default | 12/12 in 0.5 s | 1/12 in 11 s |
| Known routes of vampi, the crawler alone (`azhaq crawl`, katana's depth) | katana `-jc -jsl` | default | 1/12 in 0.3 s | 1/12 in 11 s |
| Known routes of ginandjuice.shop, the whole map (`azhaq run`) | katana `-jc -jsl` | default | 3/3 in 16 s | 2/3 in 22 s |
| Known routes of ginandjuice.shop, the crawler alone (`azhaq crawl`, katana's depth) | katana `-jc -jsl` | default | 2/3 in 11 s | 2/3 in 23 s |
| Paths, 4750 words, Juice Shop and VAmPI | ffuf `-ac` | default | 22 hits, 2 false positives, 21 s | 22 hits, 2 false positives, 21 s |
| Fuzzing, 4750 words, Juice Shop and VAmPI, 4 runs | ffuf | default | 44 hits (40 confirmed), 42 s; JSON report equal on 2 of 2 | 44 hits (40 confirmed), 42 s |
| Parameters, 8 planted, 7 pages | arjun | default | 8 right, 0 wrong, 1.2 s | 8 right, 0 wrong, 3.4 s |
| Open ports, scanme.nmap.org top-1000 | `naabu -scan-type c` | default | 3 confirmed in 4.4 s | 3 confirmed in 8.9 s |
| Open ports, 127.0.0.1 1-65535 | `naabu -scan-type c` | default | 64 confirmed in 12 s | 64 confirmed in 133 s |
| Open ports, 127.0.0.0/28 (the bench's own listeners) | `naabu -scan-type c` | default | 4 confirmed in 0.1 s | 4 confirmed in 2.9 s |
| Services named right on 15 lab ports | nmap `-sV` | default | 15, 13 with a product, 9.1 s | 10, 10 with a product, 142 s |
| Screenshots, 8 targets (not blank) | gowitness | default | 8 in 5.6 s | 6 in 64 s |
| Notifications, 6 messages to 2 providers, as the stub received them | notify | default | 6 in 5.0 s | 6 in 5.0 s |
| Live subdomains, 2 domains, no keys (names that resolve at a third resolver) | subfinder + dnsx | polite | 24 live in 115 s | 19 live in 176 s (0 only it found) |
| Historical URLs, vulnweb.com | gau | polite | 62, including 58 of gau's 64, in 19 s | 64 in 4.0 s |
| DNS brute force, 310 words, the DNS lab | dnsx | polite | 9 confirmed in 29 s | 9 in 31 s |
| Record types (9) of 32 names on a zone the bench serves | dnsx | polite | 12 answers right in 3.0 s, 290 queries | 12 in 3.9 s, 523 queries |
| Probing 107 hosts (the local apps and 100 local servers) | httpx | polite | 107 answered, 107 confirmed; status, title and tech agree on 106 of 107 shared; 21 s | 107 answered, 107 confirmed; 22 s |
| Known routes of juice-shop, the crawler alone (`azhaq crawl`, katana's depth) | katana `-jc -jsl` | polite | 53/77 in 21 s | 1/77 in 17 s |
| Known routes of vampi, the crawler alone (`azhaq crawl`, katana's depth) | katana `-jc -jsl` | polite | 1/12 in 0.4 s | 1/12 in 11 s |
| Known routes of ginandjuice.shop, the crawler alone (`azhaq crawl`, katana's depth) | katana `-jc -jsl` | polite | 2/3 in 11 s | 2/3 in 22 s |
| Paths, 257 words, Juice Shop and VAmPI | ffuf `-ac` | polite | 13 hits, 0 false positives, 104 s | 13 hits, 0 false positives, 103 s |
| Fuzzing, 257 words, Juice Shop and VAmPI, 2 runs | ffuf | polite | 13 hits (13 confirmed), 105 s | 13 hits (13 confirmed), 103 s |
| Parameters, 8 planted, 3 pages | arjun | polite | 8 right, 0 wrong, 37 s | 8 right, 0 wrong, 44 s |
| Open ports, scanme.nmap.org top-1000 | `naabu -scan-type c` | polite | 3 confirmed in 11 s | 3 confirmed in 63 s |
| Open ports, 127.0.0.1 top-1000 | `naabu -scan-type c` | polite | 8 confirmed in 12 s | 8 confirmed in 32 s |
| Open ports, 127.0.0.0/28 (the bench's own listeners) | `naabu -scan-type c` | polite | 4 confirmed in 0.9 s | 4 confirmed in 5.0 s |
| Services named right on 15 lab ports | nmap `-sV` | polite | 15, 13 with a product, 9.1 s | 10, 10 with a product, 142 s |
| Screenshots, 4 targets (not blank) (gowitness has no rate option and ran at full speed: the times are not compared) | gowitness | polite | 4 in 13 s | 4 in 4.2 s |
| Notifications, 6 messages to 2 providers, as the stub received them | notify | polite | 6 in 1.0 s | 6 in 1.0 s |
<!-- bench:end -->

The Juice Shop truth is the 77 routes its server defines that its frontend calls (`bench/truth/juice_routes.py`, from the container's own code), not strings found by searching the bundle. Each app has two route rows: the whole map (`azhaq run`, which also reads API descriptions and asks common API paths) and the crawler alone (`azhaq crawl` at katana's depth, links and scripts only). VAmPI's routes are in its OpenAPI document, which a crawler never reaches, so only the map finds them. katana runs as `katana -u URL -d 3 -jc -jsl -silent -nc -timeout 10 -c 10`.

The table above is written from the newest record in `bench/history` by `go run ./bench -readme`, so its numbers cannot drift from a run. The reference commands are pinned in `bench/tools.go` and listed in [bench/README.md](bench/README.md), which also has what is measured, the checks, and the caveats (the polite path and fuzz sweeps send a short list, not 4,750 words, because at 5 requests per second that is 16 minutes a tool and app).

## Documentation

Offline too: `azhaq docs TOPIC`.

- [Recipes](docs/RECIPES.md): how do I map an app, log in, find IDOR, test writes, map a program, resume, watch, export, read GraphQL, hand it to an assistant, start from a map, write a finding up, prove what was sent
- [Migrating](docs/MIGRATING.md): from subfinder, dnsx, httpx, katana, ffuf, gau, arjun, naabu, nmap, gowitness or notify: their flags next to azhaq's
- [Concepts](docs/CONCEPTS.md): what a row says, coverage, evidence, kinds, exit codes, roles verdicts, what Azhaq sends
- [Troubleshooting](docs/TROUBLESHOOTING.md): why is my URL `hint`, the map looks thin, exit 3, exit 4, the kill file, Chrome
- [Output](docs/OUTPUT.md): every field of every command, the summary
- [Architecture](docs/ARCHITECTURE.md): every collector, every run option, how the engine works, limitations
- [MCP](docs/MCP.md) and the [connector protocol](docs/CONNECTOR.md)

## License

[MIT](LICENSE). Dependencies are MIT, BSD, Apache or Unlicense licensed, and CI checks it. Most subdomain sources are [subfinder](https://github.com/projectdiscovery/subfinder)'s (MIT, ProjectDiscovery), run in-process; technology fingerprints come from [wappalyzergo](https://github.com/projectdiscovery/wappalyzergo), whose passive matcher is included in `internal/wappalyzer`, and CDN ranges from [cdncheck](https://github.com/projectdiscovery/cdncheck) (both MIT, ProjectDiscovery).
