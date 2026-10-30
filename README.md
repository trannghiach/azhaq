# Azhaq

Azhaq maps what an application or a bug bounty program exposes, and who may read and write it. It is one Go binary: subdomains, probing, crawling, the routes an app's JavaScript calls, API descriptions, GraphQL schemas, ports, archives, and a map of who may read and write what across your accounts. Everything lands in one SQLite workspace you can query, export and diff.

- **Routes other crawlers miss.** On OWASP Juice Shop it finds 70 of the 77 routes the server defines that its frontend calls, with methods and body fields, and names the line of the script that calls each. katana with its jsluice parser (`-jc -jsl`) lists 1; grepping the scripts it fetched for quoted paths gives 37, as bare strings.
- **Access control with evidence.** `azhaq roles` signs in as each of your accounts, reuses each session against the others, and reports `[bob reads alice's object]` with why the object is alice's. `-replay-writes` extends this to writes: it replays each account's own writes (from a saved HAR, or empty-body probes of the routes it found) with the other sessions.
- **Where to look first, with reasons.** `azhaq hunt` ranks the mapped routes, hosts and files: each row has its score, the reasons for it (`object-id`, `cross-role`, `secret`, `exposed-file`, …) and the command to run next.
- **The API routes a deploy added.** `azhaq watch` compares the routes scripts call from one run to the next: a new route with its methods and body names, a method or a name added to a known route, a route gone, each tied to the script that calls it.
- **Proof of what was sent.** Every request and connection a run with a workspace sends to a target goes in a hash-chained ledger next to it (`azhaq ledger -verify`). A kill file stops all sending.
- **A finding as a submission.** `azhaq report` writes each cross-role finding `roles` listed as a Markdown report: steps with curl, the evidence, the control, impact and remediation.
- **Safe to hand to an assistant.** `azhaq mcp` locks the scope, the request budget and the pace when it starts; no tool argument can widen them.
- **Takeover candidates flagged.** A CNAME to a cloud name that no longer exists, a domain nobody holds, or a hosting service's page for an unclaimed name is listed with its evidence. Even a plain `subs -live` flags them.
- **The usual chain, at parity or faster.** `subs`, `probe`, `ports`, `dirs`, `params` and `urls` stand in for subfinder, httpx, naabu, ffuf, arjun and gau, with their JSON field names.

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
| Subdomains by DNS brute force | `azhaq dns -d example.com -w words.txt` | dnsx -d -w |
| A wordlist in any part of a request: path, header, body | `azhaq fuzz -u https://app/FUZZ -w words.txt` | ffuf |
| Where to start in a big map | `azhaq hunt -db app.db` | reading the map by eye |
| A finding written up to submit | `azhaq report -dir DIR` | a report template filled by hand |
| What a run sent, provably | `azhaq ledger -verify app.db.ledger.jsonl` | |
| What changed since the last run, including the API routes a deploy added | `azhaq watch -db prog.db -- RUN FLAGS` | cron and diff |
| An assistant doing the recon | `azhaq mcp -allow example.com -max-requests 5000` | |
| What a run would send, before it sends anything | `azhaq plan` with the run's flags | |

## Install

Download a binary for Linux, macOS or Windows from the [releases](https://github.com/trannghiach/azhaq/releases), or:

```
curl -fsSL https://raw.githubusercontent.com/trannghiach/azhaq/main/scripts/install.sh | sh
go install github.com/trannghiach/azhaq/cmd/azhaq@latest      # Go 1.26 or newer
docker run --rm -v "$PWD:/work" -u "$(id -u)" ghcr.io/trannghiach/azhaq run -domain example.com -passive
```

`scripts/install.sh` installs the latest release for Linux or macOS (amd64 or arm64) into `$HOME/.local/bin`. It downloads the archive and `checksums.txt` and checks the archive's sha256 against it. When `cosign` is found, it also checks the sigstore signature of `checksums.txt` against this repository's release workflow. Nothing is written to the install directory when the checksum does not match, or when cosign is found and the signature check fails. Without cosign, it installs after the checksum check, says the signature was not verified and prints the command that verifies it. `-v` picks a release and `-d` a directory: `sh install.sh -v v0.8.1 -d /usr/local/bin`, or from the pipe, `curl -fsSL URL | sh -s -- -v v0.8.1 -d DIR`. `COSIGN=/path/to/cosign` names the cosign to use; the script stops if it is not an executable. It needs curl or wget, tar, and sha256sum or shasum.

<details><summary>Verify a download</summary>

The checksums file is signed with [sigstore](https://www.sigstore.dev/) by the release workflow:

```
cosign verify-blob --bundle checksums.txt.sigstore.json checksums.txt \
  --certificate-identity-regexp '^https://github\.com/trannghiach/azhaq/\.github/workflows/release\.yml@refs/tags/v' --certificate-oidc-issuer https://token.actions.githubusercontent.com
sha256sum --ignore-missing -c checksums.txt
```

</details>

`azhaq help` lists the commands, `azhaq help COMMAND` shows one with examples, and `azhaq docs` prints the documentation offline. `azhaq help -json` describes every flag for a program to read. Start-up work is kept small: the CDN ranges are read the first time an address is checked, and `azhaq version` runs in about 16 MB.

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
azhaq run: 182 map rows (113 URLs, 71 api, 43 client routes, 11 auth, 7 forbidden, 1 websocket) · 148 requests · 5.4 s · db juice.db
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

A row no request answered ends with how it is known, the strongest of its sources: `[described]` (an API description lists it), `[called]` (a script calls it, or Chrome saw the request), `[linked]` (a page links to it, a form submits to it, or a script names it), `[archived]` (only an archive holds it) or `[guessed]` (only a wordlist found it, and the answer was a 404 or the any-path page). `-evidence` in `query` selects by it; [docs/CONCEPTS.md](docs/CONCEPTS.md#evidence-how-azhaq-knows-a-url) has the levels.

Every command prints results on stdout, and a summary on stderr: what failed and whether a retry may help, what was left alone, the limit that stopped it. `-json` makes both JSON. Exit codes: `0` complete, `1` error, `2` usage (nothing sent), `3` finished with failures, `4` stopped by a limit or the kill file. [docs/CONCEPTS.md](docs/CONCEPTS.md) explains every term; [docs/OUTPUT.md](docs/OUTPUT.md) every field.

## What Azhaq sends

| What | How | When |
| --- | --- | --- |
| Pages, scripts, API descriptions (at the root and under each API base), archived URL templates | GET | every run |
| 32 built-in path checks per web service (`robots.txt`, sitemaps, API descriptions, `.git/HEAD`, `backup`, `admin`, …) | GET | every run; `-no-paths` turns them off |
| Path and parameter guesses, ports, GraphQL introspection | GET, a TCP connect and one `HEAD /` (a `GET /` on a web port whose head names no product; on 5432, 6379 and 27017–27019, that database's own first request), POST | `-dirs`, `-params`, `-ports`, `-graphql`, held to the targets given or to `-allow`/`-scope` |
| UDP ports | one datagram per port, a protocol's harmless request (a DNS `. NS`, an SNMP GET of `sysDescr.0` with community `public`, …; a DNS query on a port with no known protocol), a second one when none came back (an empty datagram on a port with no known protocol) | `-udp`, `-pu`, `run -ports-udp`, held to the targets given or to `-allow`/`-scope` |
| A wordlist in a request | the method and body you give it, with the wordlist's words in them | `azhaq fuzz`, held to the host of `-u` or to `-allow`/`-scope` |
| Chrome | GET, HEAD and CORS preflights, and the sign-in form; a page's own writes are refused and mapped, unless `-browser-writes`; every download is refused and listed, and a page read for its requests is loaded without its images, fonts and media | `-browser`, `-login`, `shots` |
| Other roles' writes | POST, PUT, PATCH, DELETE | `roles -replay-writes`, held to the `-url` hosts or to `-allow`/`-scope` |

URLs whose names say a GET would change something (`/logout`, `/createdb`, `?phpids=on`) are listed, not requested. A URL that carries a scanner's payload in its path or query (`<script>`, `../../etc/passwd`, `union select`), as archives often keep them, or a scanner's own test file, never enters the map. No request to a target goes to a host outside the scope, Chrome's included; without a scope, they stay on the site. Chrome saves nothing to disk: a download a page starts is refused and listed. Third-party sources (subdomain lists, archives, RDAP) are asked about your domains; `-passive` sends nothing to the targets. `-rate` paces it, `-max-requests` caps it, and `azhaq plan` prints it before anything is sent.

**Path checks stop at their answer.** The checks that guess where an API description sits (`openapi.json`, `swagger.json`, `api-docs`, `v3/api-docs`, …, and the same names again under each API base the run found, such as `/rest/` or `/v3/`) are asked one at a time, likeliest first. They stop at the first answer that is an OpenAPI or Swagger document with paths, or the Swagger UI or ReDoc page that loads one. Once an origin has served a description, here or through `azhaq-openapi`, its other locations are not asked, and the summary counts them: `note: path checks: 28 skipped (an API description was already found)`. Every other check (`robots.txt`, `login`, `admin`, `graphql`, `.git/HEAD`, …) is still asked. A Swagger UI whose script holds the document (Juice Shop's `/api-docs/`) is read from the script, and the names next to it are not guessed. A page that is byte for byte what the site root answers for a made-up path (a single-page app's shell) is the catch-all answer of a directory whose own baseline was not asked, so that baseline is not requested; a directory with answers of its own is still asked. On Juice Shop this is 148 requests for the same 70 of 77 routes.

**Screenshots and the budget.** A page's images, scripts and styles each count against `-max-requests`. When too few are left, Chrome is refused them and no image is saved; `shots` and `run -screenshots` say it: `note: screenshot of http://127.0.0.1:3001/ not taken: the page needs about 26 requests and 8 were left (raise -max-requests)`. The figure is how many requests the page made when it was cut short. A run starts one Chrome and opens up to 4 tabs in it at once (`-tabs N` changes it).

## Proving what was sent

Every run with a workspace writes `DB.ledger.jsonl` next to it: one JSON line for each request or connection sent to a target (HTTP; Chrome's requests, each once it has left, and its WebSocket handshakes with their path; TCP connects and TLS handshakes; UDP datagrams) with its time, URL or `ip:port`, host, the scope rule that allowed it (`-allow`, `-scope`; empty when the run has no rules) and the collector. Each line carries the hash of the one before, so an edited, removed or reordered line is caught, and a run that ends writes a seal line, so lines cut from the end are caught too: the summary names the seal (`sealed 3f9c…`), and `-verify` prints the last one. DNS queries and the third-party sources of `subs` and `urls` (and the RDAP registry) are not targets and are not listed. Runs into the same workspace, and `azhaq resume`, append to the same file.

```
azhaq ledger -verify app.db.ledger.jsonl    # exit 0 intact and sealed; exit 3 naming the first bad line, or the lines after the last seal
azhaq ledger -summary app.db.ledger.jsonl   # counts by kind, host, method, scope rule; first and last time
azhaq ledger -csv app.db.ledger.jsonl       # for a client report or a blue team's deconfliction
```

`-ledger FILE` writes it elsewhere, `-ledger off` not at all. A drop-in command without `-db` uses a temporary workspace and writes a ledger only with `-ledger FILE`.

`-kill-file PATH` (default `DB.stop`) is the kill switch. Create the file and, within half a second, nothing more is sent. The run exits 4 with `stopped` naming the kill switch. Remove the file and `azhaq resume -db DB` continues. A drop-in command without `-db` has no default kill file. `azhaq roles` keeps one ledger, `roles.ledger.jsonl`, and one stop file, `roles.stop`, in its `-dir`; `roles.stop` stops the runs of the roles (`roles` exits 4), and the replay that follows does not look for it.

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
azhaq crawl  -u https://app.example.com/ -json                                 # katana + jsluice
azhaq urls   -d example.com -silent                                            # gau
azhaq ports  -host scanme.nmap.org -p top-1000 -json                           # naabu (connect scan)
azhaq ports  -host 192.0.2.7 -p none -pu top -json                             # the common UDP ports, no root
azhaq dirs   -u https://app.example.com/ -w common.txt -e php,bak              # ffuf -ac
azhaq fuzz   -u https://app.example.com/FUZZ -w common.txt -e .php,.bak -recursion   # ffuf
azhaq fuzz   -u https://10.0.0.5/ -H 'Host: FUZZ.example.com' -w subdomains.txt -fs 4242   # ffuf, virtual hosts
azhaq params -u https://app.example.com/search -w burp-parameter-names.txt     # arjun
```

Each reads targets from flags, a file or stdin (`fuzz` takes one URL with its keywords in it, `-u`), prints results as found, and with `-json` uses the field names of the tool it stands in for. `dirs` and `params` run as fast as ffuf and arjun (40 guesses in flight, no pace); `-rate N` holds them to N requests a second. `probe`'s `status_code` is the first answer, as httpx's; `final_url` says where an in-scope redirect ended.

**`fuzz`** puts words from a wordlist into a request, anywhere in it: the path, a query value, a header (`Host: FUZZ.example.com` for virtual hosts), the method, a JSON or form body. It takes ffuf's flags and counts as ffuf does (words are spaces plus one, lines newlines plus one, the same match and filter rules, the same calibration), so a command line moved from ffuf gives the same results:

- input: `-w FILE[:KEYWORD]` (repeatable, `-w a.txt,b.txt`, `-` for stdin), `-mode clusterbomb|pitchfork|sniper` (`§…§` marks the places), `-e`, `-ic`, `-D` (dirsearch `%EXT%`), `-enc 'FUZZ:urlencode b64encode'` (all of ffuf's encoders, in process), `-input-cmd`/`-input-num`/`-input-shell`, `-request FILE` with `-request-proto` (a raw request as Burp saves it; `-u`, `-X`, `-d`, `-H`, `-b` replace parts of it);
- request: `-u -X -d` (`-data`, `-data-ascii`, `-data-binary`), `-H`, `-b` (`-cookie`), `-r`, `-timeout`, `-x` (an http, https, socks5 or socks5h proxy), `-replay-proxy` (each match sent once more through a proxy such as Burp), `-ignore-body`, `-raw`, `-sni`, `-http2`, `-cc`/`-ck`; servers back to TLS 1.0 are reached; a body compressed with gzip, deflate or brotli is decoded, so `-fs` counts the decoded bytes even when `-H 'Accept-Encoding: gzip, deflate, br'` is given;
- matchers and filters: `-mc -ms -mw -ml -mr -mt` and `-fc -fs -fw -fl -fr -ft` (`-mt '>1000'`, `-ft '<100'`: milliseconds to the first byte), `-mmode`, `-fmode`;
- calibration: `-ac` (`-ac=false` off), `-ack`, `-acs basic|advanced|NAME`, `-acc STRING`, `-ach`;
- recursion: `-recursion`, `-recursion-depth`, `-recursion-strategy default|greedy`, `-maxtime-job`;
- pace and stops: `-t`, `-rate`, `-p 0.1` or `-p 0.1-2.0`, `-maxtime`, `-sf`, `-sa`, `-se` (and `-se-after N`);
- reports: `-o FILE` with `-of json|ejson|csv|ecsv|html|md|all`, `-od DIR` (the raw request and answer of each match), `-or`; `-json` prints ffuf's fields on stdout;
- `-config FILE`, else `~/.config/ffuf/ffufrc` or `~/.ffufrc`: ffuf's TOML settings, read as flags in front of the command line's own;
- `-control FILE`: steer a run that goes (`echo 'rate 2' >> FILE`, `pause`, `resume`, `fs 4242`, `afs 100`, `fs none`, `show`, `savejson out.json`, `queueshow`, `queuedel N`, `queueskip`, `stop`), in place of ffuf's console. With stderr on a terminal and no `-s`, `-silent` or `-json`, a status line is printed over itself each second.

It differs from ffuf in these ways:

- Auto-calibration is on (`-ac=false` is ffuf's default), except when `-fc`, `-fs`, `-fw`, `-fl`, `-fr` or `-ft` is given: a command line moved from ffuf that has its own filters has calibrated by hand, and the summary says calibration is off (`-ac` turns it on). It needs the keyword `FUZZ`, or the one `-ack` names, in the request; without it a note says nothing was calibrated. Calibration requests are paced by `-rate` and counted by `-max-requests`; ffuf's are not.
- The default matcher is `-mc 200-299,301,302,307,401,403,405,500`, unless `-ms`, `-mw`, `-ml`, `-mr` or `-mt` is given alone, as in ffuf.
- With several wordlists, `-mode pitchfork` runs as long as the longest list and the shorter ones start over (4 users and 3 passwords make 4 requests, as in ffuf 2.3).
- Every request goes through the run's budget and pace (`-max-requests`, `-rate`) and the ledger, and stops at the kill file. The host in `-u` is the scope unless `-allow`, `-deny` or `-scope` say otherwise; when the keyword starts the host (`FUZZ.example.com`) the scope is its domain. A request to a host outside the scope is not sent, and the summary counts it. The copies `-replay-proxy` sends go to the proxy you named: they are not requests to the target, so they are not in the ledger, the budget or the pace, and the summary says how many were sent.
- Five unanswered requests in a row stop the run: the target is down (exit 3, the origin is listed under "did not answer"). `-se` makes it twice `-t` failures of any kind, as ffuf's; `-se-after N` names the number. `-sf`, `-sa` and `-maxtime-job` say what they did in the summary (exit 4 for the first two, a note for the last).
- `-timeout` is seconds per request, as in ffuf. `-o` writes ffuf's report, in the order the inputs were asked; `-o NAME.txt` without `-of` writes what stdout shows, as before. `-db FILE` keeps the matches in a workspace as ffuf results are, for `query`, `show` and `export`.
- Not in `fuzz`: ffuf's scrapers (`-scraperfile`, `-scrapers`), `-search` and its history files (`-db` and `azhaq show` keep the matches), `-audit-log` (the hash-chained `-ledger` is the record of requests), `-preflight` and `-postflight`.

**`ports -udp`** also asks the common UDP ports (53, 67, 69, 123, 137, 161, 500, 514, 520, 623, 1194, 1900, 3478, 4500, 5353, 5683, 11211, 27015, 47808, 51820); `-pu LIST` asks a list instead (`-pu 1-1024`, `-pu top`, `-pu top,5354`: names and numbers combine, in `-p` too), and `-p none` leaves the TCP ports out. In `run` it is `-ports-udp SPEC`. No privileges are needed: each port gets one datagram on a connected socket, and the kernel tells an ICMP port unreachable from silence. A reply makes the port `open`, with the service, product, version and banner it gives; an ICMP port unreachable makes it `closed`; nothing, twice, makes it `open|filtered`. The request is the harmless one of the protocol the port usually carries, and a DNS query on a port with no known protocol (DNS is what moves to odd ports: 5354, 8053), then an empty datagram; nothing logs in, guesses a credential or changes state. Every datagram counts against `-max-requests`, is paced and goes in the ledger as kind `udp`. A CDN or WAF address is not asked. Each open TCP port also gets `product` and `version` next to `service`, from what it says first or answers (an SSH, FTP, SMTP, POP3 or IMAP greeting, a MySQL or MariaDB handshake, an HTTP `Server` or `X-Powered-By` header, the body of `GET /`, PostgreSQL, Redis and MongoDB's first answer). A web page that names no product gets its `<title>` in `title` (and its `<meta name="generator">` as the product). An SSH, FTP or mail port that sent no greeting is connected to once more after the scan, as sshd drops greetings when many connects arrive at once. [docs/OUTPUT.md](docs/OUTPUT.md#ports-udp-products-and-versions) lists them.

**`subs` remembers names.** Passive sources answer differently each run (subdomain.center returns a random 500 of about 6,300 tesla.com names per call). Azhaq keeps every name it kept for a domain in `names/DOMAIN.json` under `$AZHAQ_DATA_DIR`, else `$XDG_DATA_HOME/azhaq`, else `~/.local/share/azhaq`, and asks this file as a source called `history` in the next run: a stored name counts only if it resolves now (not to a wildcard), so stale names drop out and a name a source missed this time comes back. `-no-history` neither reads nor writes the file. `subs` ends with `coverage: the independent sources hold about 1609 names; this run has 1400 of them (87%) — an estimate of what the sources know, not of every name that exists; the other 47 of the 1447 names came from the name history, from guesses checked in DNS or as CNAME targets, which the estimate leaves out`; [docs/OUTPUT.md](docs/OUTPUT.md#drop-in-commands) says how it is counted.

## For assistants: MCP

```
claude mcp add azhaq -- azhaq mcp -allow example.com -max-requests 5000 -rate 5
```

The tools run Azhaq itself and return its summary and rows. The scope, the budget for all calls together and the pace are fixed at start; an argument the schema does not take is refused; results are bounded, and exports come in pages that each parse alone. Without `-allow` or `-scope` the server does not start, unless `-unlocked` says so. [docs/MCP.md](docs/MCP.md).

## Benchmark

`go run ./bench` runs Azhaq and the tools it replaces on the same targets: Juice Shop, VAmPI and crAPI in Docker, ginandjuice.shop, apps the bench serves itself, and the live names of hackerone.com, tesla.com and vulnweb.com. It prints the numbers, losses included. The subdomain comparison is on **live** names — the ones that resolve — not the raw count: most of what a passive collector returns does not resolve (stale certificate logs, wildcard noise), so a bigger raw number is not a better result. Latest run (2026-10-30, v0.9.0; the map, access-control, resume and drop-in checks pass, the port comparison runs on GitHub's network because this machine's security software removes naabu):

| Job | Replaces | Azhaq | Reference |
| --- | --- | --- | --- |
| Live subdomains, 3 domains, no keys | subfinder + dnsx | 561 live, in 116 s (fewer raw names; the dead majority is dropped — `subs -live` shows the split) | 457 live, in 93 s |
| DNS brute force, 5,000 words | dnsx | 3 in 18 s | 3 in 69 s |
| Wildcard zone, 3 real names of 50 | dnsx | 3 found, 0 fake | 50 without `-wd` |
| Probing 575 live hosts | httpx | 409 answered; status, title and technologies agree on 399 of 401 shared (redirects out of the site compared by their own status); 107 s | 402 answered, 138 s |
| Server routes Juice Shop's frontend calls (77) | katana `-jc -jsl` + jsluice | 70, with methods and body fields | 1 (37 by grepping the scripts katana fetched for quoted paths) |
| VAmPI's API paths (12), ginandjuice's script-only routes (3), crAPI's routes (40) | katana + jsluice | 12, 3, 32 | 1, 2, 0 |
| With Chrome: Juice Shop, crAPI | katana `-headless` | 70/77 in 12 s, 32/40 in 17 s | 6/77 in 6 s, 0/40 in 44 s |
| Historical URLs, 3 domains (Wayback and Common Crawl unreachable for both) | gau | 7,115, including 2,346 of gau's 2,354 | 2,354 |
| Paths, 4,750 words on Juice Shop and VAmPI | ffuf `-ac` | 22 hits, 2 false positives, 32 s | 22 hits, 2 false positives, 38 s |
| Parameters, 5 pages | arjun | 5, including arjun's 2 | 2 |
| Screenshots, 4 front pages | gowitness | 4 in 11 s | 3 in 34 s |
| Credentials in a script | jsluice | 12, including jsluice's 4 | 4 |
| Reverse DNS of a /25 | dnsx `-ptr` | 36 | 35, all among Azhaq's |
| Access matrix, anonymous, member, owner (signed in by Chrome) | manual | 6/6 rows right, no logout sent | |
| A run capped at 100 requests and resumed; killed and resumed; with two workers | – | each maps everything one run maps; 153 requests over the capped run and its resume, one run 148 | |
| Memory, Juice Shop | katana `-jc -jsl` | 87 MB | 1.4 GB |

The Juice Shop truth is the 77 routes its server defines that its frontend calls (`bench/truth/juice_routes.py`, from the container's own code), not strings found by searching the bundle. The reference commands are pinned in `bench/tools.go` and listed in [bench/README.md](bench/README.md); katana runs as `katana -u URL -d 3 -jc -jsl -silent -nc -timeout 10 -c 10`. Parameter discovery, 6,453 names: on the local apps Azhaq is faster (1.9 s against arjun's 3.6 s for three pages; arjun also reports a `callback` VAmPI ignores); on ginandjuice.shop, both at 20 requests per second, Azhaq loses on time (74 s a page against 21–24 s), as it halves its groups for a site that refuses long query strings, but finds `category`, `searchTerm` and `search` where arjun finds nothing. On memory it loses to katana without `-jsl` (60 MB). Passive subdomains took longer than subfinder this run (116 s against 93 s): Azhaq asks subdomain.center several times for its random samples and checks the names only such sources give with DNS, which is where its 104 more live names come from.

[bench/README.md](bench/README.md) has what is measured and the caveats.

## Documentation

Offline too: `azhaq docs TOPIC`.

- [Recipes](docs/RECIPES.md): how do I map an app, log in, find IDOR, test writes, map a program, resume, watch, export, read GraphQL, hand it to an assistant, start from a map, write a finding up, prove what was sent
- [Concepts](docs/CONCEPTS.md): what a row says, coverage, evidence, kinds, exit codes, roles verdicts, what Azhaq sends
- [Troubleshooting](docs/TROUBLESHOOTING.md): why is my URL `hint`, the map looks thin, exit 3, exit 4, the kill file, Chrome
- [Output](docs/OUTPUT.md): every field of every command, the summary
- [Architecture](docs/ARCHITECTURE.md): every collector, every run option, how the engine works, limitations
- [MCP](docs/MCP.md) and the [connector protocol](docs/CONNECTOR.md)

## License

[MIT](LICENSE). Dependencies are MIT, BSD, Apache or Unlicense licensed, and CI checks it. Most subdomain sources are [subfinder](https://github.com/projectdiscovery/subfinder)'s (MIT, ProjectDiscovery), run in-process; technology fingerprints come from [wappalyzergo](https://github.com/projectdiscovery/wappalyzergo), whose passive matcher is included in `internal/wappalyzer`, and CDN ranges from [cdncheck](https://github.com/projectdiscovery/cdncheck) (both MIT, ProjectDiscovery).
