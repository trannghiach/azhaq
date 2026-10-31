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

The addresses `localhost:3000` and `localhost:5000` are lab containers (`docker run -p 3000:3000 bkimminich/juice-shop`, `docker run -p 5000:5000 erev0s/vampi`). `$TA` and `$TB` hold two accounts' tokens, and `alice.har` and `alice.xml` are those accounts' saved browsing. `-program` names a program in the platform's public list (`tesla` on Bugcrowd, `security` on HackerOne); `acme` in other examples stands for yours.

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

Every command prints results on stdout, and a summary on stderr: what failed and whether a retry may help, what was left alone, the limit that stopped it. `-json` makes both JSON. Exit codes: `0` complete, `1` error, `2` usage (nothing sent), `3` finished with failures, `4` stopped by a limit or the kill file. [docs/CONCEPTS.md](docs/CONCEPTS.md) explains every term; [docs/OUTPUT.md](docs/OUTPUT.md) the summary and the exit codes; each command's fields are on its page (`azhaq docs COMMAND`).

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

`run` (path checks): see [docs/commands/run.md](docs/commands/run.md).

`shots`: see [docs/commands/shots.md](docs/commands/shots.md).

`gallery`: see [docs/commands/gallery.md](docs/commands/gallery.md).

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

`juice.db` is the workspace of the first example, and `h1.db` one made by a run with `-scope hackerone -program …`. `nuclei` is a separate tool.

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

`watch`: see [docs/commands/watch.md](docs/commands/watch.md).

## Notifications

`notify`: see [docs/commands/notify.md](docs/commands/notify.md).

## Where to look first

`hunt`: see [docs/commands/hunt.md](docs/commands/hunt.md).

## Access control

`roles`: see [docs/commands/roles.md](docs/commands/roles.md); `report`: see [docs/commands/report.md](docs/commands/report.md).

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

`names.txt`, `subdomains.txt` and `common.txt` are lists of yours, one entry a line (`fuzz` has no built-in wordlist; `dirs` carries `common.txt`). Each reads targets from flags, a file or stdin (`fuzz` takes one URL with its keywords in it, `-u`), prints results as found, and with `-json` uses the field names of the tool it stands in for. `dirs` and `params` have ffuf's and arjun's defaults (40 guesses in flight, 5 groups of names in flight, no pace); `-rate N` holds them to N requests a second. `dirs` takes ffuf's matchers and filters (`-ms -mw -ml -mr`, `-fc -fs -fw -fl -fr`), counts sizes, words and lines as ffuf does, starts from the path of the URL given (`-u https://h/api/` sweeps `/api/WORD`), and carries SecLists' `common.txt` (MIT, 4,750 words) for when `-w` is left out. `probe` follows no redirect unless given `-fr`, as httpx: a row's status, title, length and content type are one answer's. It takes httpx's matchers and filters (`-mc -fc -ms -fs -mr -fe -mdc …`), ports (`-p 80,8000-8100`), paths (`-path`), certificate data (`-tls-grab`), hashes (`-hash`), `-jarm`, raw output (`-sr`, `-irr`) and its CSV and Markdown forms; a target with no answer is a row with `failed: true`. `-x`, `-body` and `-rr` send the methods, body or request you give and can change data on the target; the summary says so.

`fuzz`: see [docs/commands/fuzz.md](docs/commands/fuzz.md).

`ports`: see [docs/commands/ports.md](docs/commands/ports.md).

`subs`: see [docs/commands/subs.md](docs/commands/subs.md).

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

- [Output](docs/OUTPUT.md): the summary and what every command prints; the fields of each command are on its page, `azhaq docs COMMAND`

- [Architecture](docs/ARCHITECTURE.md): every collector, every run option, how the engine works, limitations
- [MCP](docs/MCP.md) and the [connector protocol](docs/CONNECTOR.md)

## License

[MIT](LICENSE). Dependencies are MIT, BSD, Apache or Unlicense licensed, and CI checks it. Most subdomain sources are [subfinder](https://github.com/projectdiscovery/subfinder)'s (MIT, ProjectDiscovery), run in-process; technology fingerprints come from [wappalyzergo](https://github.com/projectdiscovery/wappalyzergo), whose passive matcher is included in `internal/wappalyzer`, and CDN ranges from [cdncheck](https://github.com/projectdiscovery/cdncheck) (both MIT, ProjectDiscovery).
