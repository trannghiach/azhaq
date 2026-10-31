# azhaq

azhaq is one Go binary for reconnaissance. It stands in for subfinder, dnsx, httpx, katana, ffuf, gau, arjun, naabu, gowitness, asnmap and notify, with their flags and JSON field names. It adds what that chain does not do. It maps the routes an app's JavaScript calls and compares what each of your accounts may read and write. It holds every request to a scope and a budget, and records what it sent. Everything lands in one SQLite workspace you can query, export and diff.

Coming from one of those tools? [docs/MIGRATING.md](docs/MIGRATING.md) puts its flags next to azhaq's, says what differs on purpose and gives three command lines for each. `azhaq docs migrating` prints it offline.

## What it replaces

| If you use | Run | Also |
| --- | --- | --- |
| subfinder | [`azhaq subs`](docs/commands/subs.md) | names checked in DNS with `-live`, takeover candidates |
| dnsx | [`azhaq dns`](docs/commands/dns.md) | wildcard answers left out per zone |
| httpx | [`azhaq probe`](docs/commands/probe.md) | takeover candidates, `catchall` pages |
| katana + jsluice | [`azhaq crawl`](docs/commands/crawl.md) | the routes scripts call, with methods and body names |
| ffuf | [`azhaq fuzz`](docs/commands/fuzz.md), [`azhaq dirs`](docs/commands/dirs.md) | scope, budget and ledger on every request |
| gau | [`azhaq urls`](docs/commands/urls.md) | a fifth archive (arquivo.pt), failures said |
| arjun | [`azhaq params`](docs/commands/params.md) | a control against pages that answer any name |
| naabu, nmap (service versions, UDP) | [`azhaq ports`](docs/commands/ports.md) | UDP without root, products and versions |
| gowitness | [`azhaq shots`](docs/commands/shots.md) | Chrome held to the scope and the budget |
| asnmap | [`azhaq asn`](docs/commands/asn.md) | AS numbers also expand to targets in `ports` and `run -asn` |
| notify | [`azhaq notify`](docs/commands/notify.md) | a lost message is exit 3 |

## What it adds

- **Routes other crawlers miss.** On OWASP Juice Shop azhaq finds 70 of the 77 routes the server defines that its frontend calls. It lists their methods and body fields, and names the script line that calls each. katana with its jsluice parser (`-jc -jsl`) lists 1. Grepping the scripts it fetched for quoted paths gives 37, as bare strings. It also saves reading bundles by hand.
- **Access control with evidence.** [`azhaq roles`](docs/commands/roles.md) signs in as each of your accounts, reuses each session against the others, and reports `[bob reads alice's object]` with why the object is alice's. It stands in for Autorize and for diffing Burp histories. `-replay-writes` extends this to writes.
- **Where to look first.** [`azhaq hunt`](docs/commands/hunt.md) ranks the mapped routes, hosts and files, each with the reasons for its score and the command to run next.
- **The API routes a deploy added.** [`azhaq watch`](docs/commands/watch.md) compares the routes scripts call from one run to the next and ties each change to the script that calls it. It stands in for cron and diff.
- **A finding as a submission.** [`azhaq report`](docs/commands/report.md) writes each cross-role finding as a Markdown report: steps with curl, evidence, control, impact and remediation, in place of a template filled by hand.
- **Takeover candidates flagged.** A CNAME to a cloud name that no longer exists, a domain nobody holds, or a hosting service's page for an unclaimed name is listed with its evidence. Even a plain `subs -live` flags them.

Numbers for each job, against the tool it replaces, are in the [benchmark](#benchmark).

## Install

Download a binary for Linux, macOS or Windows from the [releases](https://github.com/trannghiach/azhaq/releases), or:

```
curl -fsSL https://raw.githubusercontent.com/trannghiach/azhaq/main/scripts/install.sh | sh
go install github.com/trannghiach/azhaq/cmd/azhaq@latest      # Go 1.26 or newer
docker run --rm -v "$PWD:/work" -u "$(id -u)" ghcr.io/trannghiach/azhaq run -domain example.com -passive
```

`azhaq help` lists the commands, `azhaq help COMMAND` shows one with examples, and `azhaq docs` prints an overview and the documentation offline. `azhaq help -json` describes every flag for a program to read. Start-up work is kept small: the CDN ranges are read the first time an address is checked.

<details><summary>What <code>install.sh</code> does, and verifying a download</summary>

`scripts/install.sh` installs the latest release for Linux or macOS (amd64 or arm64) into `$HOME/.local/bin`.

- It downloads the archive and `checksums.txt`, and checks the archive's sha256 against it.
- When `cosign` is found, it also checks the sigstore signature of `checksums.txt` against this repository's release workflow.
- Nothing is written when the checksum does not match, or when cosign is found and the signature check fails.
- Without cosign, it installs after the checksum check, says the signature was not verified and prints the command that verifies it.
- `sh install.sh --require-signature` (or `-s`), or `AZHAQ_REQUIRE_SIGNATURE=1`, refuses that: the script stops before downloading anything when cosign is missing, and stops when the signature does not verify. From the pipe: `curl -fsSL URL | sh -s -- --require-signature`.
- `-v` picks a release and `-d` a directory: `sh install.sh -v v0.8.1 -d /usr/local/bin`, or from the pipe `curl -fsSL URL | sh -s -- -v v0.8.1 -d DIR`.
- `COSIGN=/path/to/cosign` names the cosign to use. The script stops if it is not an executable.
- It needs curl or wget, tar, gzip, sha256sum or shasum, awk, sed, head, mktemp, uname, cp, chmod and mkdir, and cosign (optional, required with `-s`). It names every missing tool before it downloads anything.

The release workflow signs the checksums file with [sigstore](https://www.sigstore.dev/). To check a download by hand:

```
cosign verify-blob --bundle checksums.txt.sigstore.json checksums.txt \
  --certificate-identity-regexp '^https://github\.com/trannghiach/azhaq/\.github/workflows/release\.yml@refs/tags/v' --certificate-oidc-issuer https://token.actions.githubusercontent.com
sha256sum --ignore-missing -c checksums.txt
```

</details>

## Quick start

Only scan systems you are allowed to test.

- `localhost:3000` and `localhost:5000` are lab containers: `docker run -p 3000:3000 bkimminich/juice-shop` and `docker run -p 5000:5000 erev0s/vampi`.
- `$TA` and `$TB` hold two accounts' tokens. `alice.har` and `alice.xml` are those accounts' saved browsing.
- `-program` names a program in the platform's public list: `tesla` on Bugcrowd, `security` on HackerOne. `acme` in other examples stands for yours.

### Map an app

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

### Compare two accounts

```
$ azhaq roles -role anon -role "alice=Authorization: Bearer $TA" -role "bob=Authorization: Bearer $TB" -- -url http://localhost:5000/
  401 → 200:79 → 200:79  http://localhost:5000/books/v1/aliceBook  [bob reads alice's object] · sensitive: secret
  200:1.1k → 200:1.1k → 200:1.1k  http://localhost:5000/users/v1/_debug  [anyone reads sensitive fields: password]
```

Each column is one role's answer as `status:bytes`, in the order the roles were given. A `-` is a role that was never asked.

Or give each account's browsing as it was saved, one file per account, with no headers to copy and no crawl: a HAR from the browser, Caido or Burp, or Burp's "Save items" XML. An anonymous role is added. The page on [`roles`](docs/commands/roles.md#history-files) says how each is used.

```
$ azhaq roles -har alice=alice.har -har bob=bob.har
$ azhaq roles -burp alice=alice.xml -burp bob=bob.xml -replay-writes put,patch
```

### Map a program inside its scope and a budget

```
$ azhaq plan -scope bugcrowd -program tesla -max-requests 5000      # what it would ask, sends nothing
$ azhaq run  -scope bugcrowd -program tesla -max-requests 5000 -rate 5 -db tesla.db   # in place of a script around the tools
$ azhaq resume -db tesla.db                                          # after the budget, Ctrl-C or a crash
```

### After a run

`juice.db` is the workspace of the first example. Runs into the same workspace add to it, and `azhaq diff` and `azhaq watch` say what changed.

```
azhaq query  -db juice.db -role api -method POST -fields key,body -json   # what the app's writes take
azhaq show   -db juice.db http://localhost:3000/rest/2fa/verify           # everything about one URL, and the line that calls it
azhaq hunt   -db juice.db                                                  # where to look first, instead of reading the map by eye
```

`azhaq export` writes the workspace for Burp, Postman, ZAP and nuclei. `azhaq watch` repeats a run into a workspace and reports what changed. More, task by task: [docs/RECIPES.md](docs/RECIPES.md).

## Reading the output

```
URL http://localhost:3000/rest/2fa/verify  target  hint  api  POST  [called]
│   │                                      │       │     │    │     └ how it is known, when the server did not answer it
│   │                                      │       │     │    └ methods its callers use
│   │                                      │       │     └ kind: app, auth (401), forbidden (403), api, page, script, …
│   │                                      │       └ coverage: what azhaq did with it
│   │                                      └ scope: target, or fanout (found on the way)
│   └ the URL; a template like /api/Users/{id} stands for many
└ what the row is: URL, Hostname, Domain, IPAddress, …
```

Coverage is one of seven states:

- `visited`: it answered as a page of its own.
- `catchall`: it answered with the page every unknown path gets.
- `error`: no answer.
- `gone`: 404 or 410.
- `hint`: known, not proven by a GET.
- `skipped`: not requested, because a GET there would change something.
- `capped`: not requested, because a limit ran out. `azhaq resume` continues.

A row that no request answered ends with how it is known, such as `[called]`. [Concepts](docs/CONCEPTS.md#evidence-how-azhaq-knows-a-url) lists the levels.

Every command prints results on stdout and a summary on stderr: what failed, what was left alone and which limit stopped it. `-json` makes both JSON. Exit codes: `0` complete, `1` error, `2` usage (nothing sent), `3` finished with failures, `4` stopped by a limit or the kill file. See [Concepts](docs/CONCEPTS.md) and [Output](docs/OUTPUT.md).

## Drop-in commands

Each reads targets from flags, a file or stdin, prints results as found, and with `-json` uses the field names of the tool it stands in for. It also keeps the tool's defaults: `dirs` and `params` have ffuf's and arjun's, and no pace unless `-rate` says so. Word lists are yours, one entry a line. `dirs` carries SecLists' `common.txt`, and `fuzz` has no built-in list. `probe -x`, `-body` and `-rr` send the methods, body or request you give and can change data on the target. The summary says so.

```
azhaq subs -d example.com -silent | azhaq dns -silent | azhaq probe -json      # subfinder | dnsx | httpx
azhaq urls   example.com -subs -mc 200 -blacklist png,jpg,css -fp | httpx      # gau --subs --mc 200 --blacklist … --fp
azhaq ports  10.0.0.0/16 -p 22,80,443 -wn -oA scan                                # a range, nmap XML and greppable files
azhaq ports  -host 192.0.2.7 -p none -pu top -json                             # the common UDP ports, no root
azhaq subs -d example.com | azhaq notify -bulk -pc provider-config.yaml        # text from a pipe to a chat, e-mail or a webhook (notify)
```

Every tool's own command lines, flag by flag, are in [docs/MIGRATING.md](docs/MIGRATING.md).

## Commands

| Command | What it does |
| --- | --- |
| [`run`](docs/commands/run.md) | Map a target into one graph. |
| [`plan`](docs/commands/plan.md) | Show what a run would send, without sending. |
| [`scope`](docs/commands/scope.md) | Read a program's scope. |
| [`roles`](docs/commands/roles.md) | Show where the answers differ between sessions. |
| [`report`](docs/commands/report.md) | Write each finding `roles` listed up to submit. |
| [`resume`](docs/commands/resume.md) | Continue a run that a limit stopped. |
| [`query`](docs/commands/query.md) | Ask a database a precise question. |
| [`show`](docs/commands/show.md) | Everything known about one URL, host or name. |
| [`hunt`](docs/commands/hunt.md) | Where to look first: routes, hosts and files, ranked. |
| [`watch`](docs/commands/watch.md) | Run again and again, and report what changed. |
| [`new`](docs/commands/new.md) | What a workspace first saw lately. |
| [`diff`](docs/commands/diff.md) | Compare two runs. |
| [`export`](docs/commands/export.md) | Write a database in another tool's format. |
| [`ingest`](docs/commands/ingest.md) | Add other tools' results to a database. |
| [`ledger`](docs/commands/ledger.md) | Check, count or export what a run sent. |
| [`gallery`](docs/commands/gallery.md) | Browse a workspace's screenshots. |
| [`asn`](docs/commands/asn.md) | The prefixes autonomous systems announce. |
| [`mcp`](docs/commands/mcp.md) | Serve azhaq to MCP clients. |
| [`worker`](docs/commands/worker.md) | Take work from a run started with `-serve`. |
| [`docs`](docs/commands/docs.md) | Print the documentation offline. |

## Safety controls

These controls hold for everything azhaq sends to a target. [Concepts](docs/CONCEPTS.md) has the rules and the exceptions.

- **Scope.** No request to a target goes to a host outside the [scope](docs/CONCEPTS.md#scope), Chrome's included. Without a scope, requests stay on the site.
- **Budget and pace.** `-max-requests` caps what a run sends, and `-rate` paces it. `azhaq resume` continues a run that a limit stopped. `azhaq plan` prints what a run would send before anything goes out.
- **Kill switch.** Create the kill file (`-kill-file`, default `DB.stop`) and nothing more is sent, within a tenth of a second.
- **Ledger.** Every request and connection of a run with a workspace is recorded in a hash-chained file that a seal closes. `azhaq ledger -verify` checks it.
- **Side effects.** The map lists, and does not request, URLs whose names say a GET would change something. Chrome refuses a page's own writes unless `-browser-writes`, and every download.
- **What is sent.** Pages, scripts, API descriptions and 32 built-in path checks are GETs. Guesses, ports, UDP and wordlists go out only when you ask. A port (`-ports`) gets a TCP connect, and one that says nothing also a `HEAD /`. [Every row](docs/CONCEPTS.md#what-azhaq-sends).
- **Passive.** `-passive` sends nothing to the targets. Third-party sources, such as subdomain lists, archives and RDAP, are asked about your domains.

## For assistants: MCP

```
claude mcp add azhaq -- azhaq mcp -allow example.com -max-requests 5000 -rate 5
```

The tools run azhaq itself and return its summary and rows. The scope, the budget for all calls together and the pace are fixed at start, and no tool argument can widen them. An argument the schema does not take is refused. Without `-allow` or `-scope` the server does not start, unless `-unlocked` says so. Results are bounded, and exports come in pages that each parse alone: see [docs/MCP.md](docs/MCP.md).

## Benchmark

`go run ./bench` runs azhaq and the tools it replaces on the same targets, and prints the numbers, losses included. [bench/README.md](bench/README.md) has what is measured, the two profiles, the bar a row must clear, and the caveats.

- **Local:** Juice Shop and VAmPI in Docker, the services lab (fifteen daemons), a DNS lab, and servers and a zone that the bench serves itself.
- **Public, at 5 requests per second:** ginandjuice.shop, testphp.vulnweb.com and demo.testfire.net.
- **Public, passive lookups only:** hackerone.com, tesla.com and vulnweb.com.

Every comparison runs twice, as a reviewer runs it: with the default flags of both tools, and politely. `go run ./bench -profile default|polite|both` picks. The record keeps the old shares and ratios too.

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

The Juice Shop truth is the 77 routes its server defines that its frontend calls (`bench/truth/juice_routes.py`, from the container's own code), not strings found by searching the bundle.

- Each app has two route rows: the whole map (`azhaq run`, which also reads API descriptions and asks common API paths) and the crawler alone (`azhaq crawl` at katana's depth: links and scripts only).
- VAmPI's routes are in its OpenAPI document, which a crawler never reaches, so only the map finds them.
- katana runs as `katana -u URL -d 3 -jc -jsl -silent -nc -timeout 10 -c 10`.

`go run ./bench -readme` writes the table above from the newest record in `bench/history`, so its numbers cannot drift from a run. The reference commands are pinned in `bench/tools.go`. The polite path and fuzz sweeps send a short list, not 4,750 words, because at 5 requests per second that is 16 minutes a tool and app.

## Documentation

`azhaq docs TOPIC` prints each page offline.

- [Commands](#commands): one page for each command, with examples, fields, edge cases and flags.
- [Recipes](docs/RECIPES.md): task by task, from mapping an app to proving what was sent.
- [Migrating](docs/MIGRATING.md): from subfinder, dnsx, httpx, katana, ffuf, gau, arjun, naabu, nmap, gowitness, asnmap or notify, flags side by side.
- [Concepts](docs/CONCEPTS.md): a row, coverage, evidence, kinds, scope, budget, the ledger, roles verdicts, what azhaq sends.
- [Troubleshooting](docs/TROUBLESHOOTING.md): a URL that is `hint`, a thin map, exit 3, exit 4, the kill file, Chrome.
- [Output](docs/OUTPUT.md): stdout and stderr, the summary, exit codes, the ledger format.
- [Architecture](docs/ARCHITECTURE.md): every collector, every run option, how the engine works, limitations.
- [MCP](docs/MCP.md) and the [connector protocol](docs/CONNECTOR.md).

## License

[MIT](LICENSE). Dependencies are MIT, BSD, Apache or Unlicense licensed, and CI checks it. The `common.txt` that `dirs` carries is SecLists' (MIT, 4,750 words). Most subdomain sources are [subfinder](https://github.com/projectdiscovery/subfinder)'s (MIT, ProjectDiscovery), run in-process. Technology fingerprints come from [wappalyzergo](https://github.com/projectdiscovery/wappalyzergo), whose passive matcher is included in `internal/wappalyzer`, and CDN ranges from [cdncheck](https://github.com/projectdiscovery/cdncheck). Both are MIT, ProjectDiscovery.
