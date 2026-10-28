# Azhaq

Azhaq maps what an application or a bug bounty program exposes, and who may read and write it. It is one Go binary: subdomains, probing, crawling, the routes an app's JavaScript calls, API descriptions, GraphQL schemas, ports, archives, and a map of who may read and write what across your accounts. Everything lands in one SQLite workspace you can query, export and diff.

- **Routes other crawlers miss.** On OWASP Juice Shop it finds 70 of the 77 routes the server defines that its frontend calls, with methods and body fields, and names the line of the script that calls each. katana with jsluice finds 1.
- **Access control with evidence.** `azhaq roles` signs in as each of your accounts, reuses each session against the others, and reports `[bob reads alice's object]` with why the object is alice's. `-replay-writes` extends this to writes: it replays each account's own writes (from a saved HAR, or empty-body probes of the routes it found) with the other sessions.
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
| What changed since the last run | `azhaq watch -db prog.db -- RUN FLAGS` | cron and diff |
| An assistant doing the recon | `azhaq mcp -allow example.com -max-requests 5000` | |
| What a run would send, before it sends anything | `azhaq plan` with the run's flags | |

## Install

Download a binary for Linux, macOS or Windows from the [releases](https://github.com/trannghiach/azhaq/releases), or:

```
go install github.com/trannghiach/azhaq/cmd/azhaq@latest      # Go 1.26 or newer
docker run --rm -v "$PWD:/work" -u "$(id -u)" ghcr.io/trannghiach/azhaq run -domain example.com -passive
```

<details><summary>Verify a download</summary>

The checksums file is signed with [sigstore](https://www.sigstore.dev/) by the release workflow:

```
cosign verify-blob --bundle checksums.txt.sigstore.json checksums.txt \
  --certificate-identity-regexp '^https://github\.com/trannghiach/azhaq/\.github/workflows/release\.yml@refs/tags/v' --certificate-oidc-issuer https://token.actions.githubusercontent.com
sha256sum --ignore-missing -c checksums.txt
```

</details>

`azhaq help` lists the commands, `azhaq help COMMAND` shows one with examples, and `azhaq docs` prints the documentation offline. `azhaq help -json` describes every flag for a program to read.

## Quick start

Only scan systems you are allowed to test.

**Map an app.**

```
$ azhaq run -url http://localhost:3000/ -db juice.db
  URL http://localhost:3000/rest/2fa/verify  target  hint  api  POST
      POST  body tmpToken totpToken
  URL http://localhost:3000/b2b/v2/orders  target  hint  api  POST
      POST  body cid orderLines orderLinesData
  URL http://localhost:3000/api/Users  target  visited  auth  POST  status=401
  URL http://localhost:3000/#/administration  target  hint  client-route  guard=canActivate
  …
azhaq run: 182 map rows (113 URLs, 71 api, 43 client routes, 11 auth, 7 forbidden, 1 websocket) · 191 requests · 4.6 s · db juice.db
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

**Map a program inside its scope and a budget.**

```
$ azhaq plan -scope bugcrowd -program tesla -max-requests 5000      # what it would ask, sends nothing
$ azhaq run  -scope bugcrowd -program tesla -max-requests 5000 -rate 5 -db tesla.db
$ azhaq resume -db tesla.db                                          # after the budget, Ctrl-C or a crash
```

More, task by task: [docs/RECIPES.md](docs/RECIPES.md).

## Reading the output

```
URL http://localhost:3000/rest/2fa/verify  target  hint  api  POST
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

Every command prints results on stdout, and a summary on stderr: what failed and whether a retry may help, what was left alone, the limit that stopped it. `-json` makes both JSON. Exit codes: `0` complete, `1` error, `2` usage (nothing sent), `3` finished with failures, `4` stopped by a limit. [docs/CONCEPTS.md](docs/CONCEPTS.md) explains every term; [docs/OUTPUT.md](docs/OUTPUT.md) every field.

## What Azhaq sends

| What | How | When |
| --- | --- | --- |
| Pages, scripts, API descriptions (at the root and under each API base), archived URL templates | GET | every run |
| 32 built-in path checks per web service (`robots.txt`, sitemaps, API descriptions, `.git/HEAD`, `backup`, `admin`, …) | GET | every run; `-no-paths` turns them off |
| Path and parameter guesses, ports, GraphQL introspection | GET, a TCP connect and one `HEAD /`, POST | `-dirs`, `-params`, `-ports`, `-graphql` (need a scope) |
| Chrome | GET, HEAD and CORS preflights, and the sign-in form; a page's own writes are refused and mapped, unless `-browser-writes`; every download is refused and listed, and a page read for its requests is loaded without its images, fonts and media | `-browser`, `-login`, `shots` |
| Other roles' writes | POST, PUT, PATCH, DELETE | `roles -replay-writes` (needs a scope) |

URLs whose names say a GET would change something (`/logout`, `/createdb`, `?phpids=on`) are listed, not requested. A URL that carries a scanner's payload in its path or query (`<script>`, `../../etc/passwd`, `union select`), as archives often keep them, or a scanner's own test file, never enters the map. No request to a target goes to a host outside the scope, Chrome's included; without a scope, they stay on the site. Chrome saves nothing to disk: a download a page starts is refused and listed. Third-party sources (subdomain lists, archives, RDAP) are asked about your domains; `-passive` sends nothing to the targets. `-rate` paces it, `-max-requests` caps it, and `azhaq plan` prints it before anything is sent.

## A workspace

```
azhaq query  -db juice.db -role api -method POST -fields key,body -json   # what the app's writes take
azhaq show   -db juice.db http://localhost:3000/rest/2fa/verify           # everything about one URL, and the line that calls it
azhaq export -db juice.db -format openapi > api.json                      # Burp, Postman, ZAP
azhaq export -db h1.db -format targets | nuclei -l -                      # web services
azhaq export -db h1.db -format burp > scope.json                          # the run's scope for Burp
azhaq watch  -db h1.db -every 24h -notify https://hooks.slack.com/… -- -scope hackerone -program acme
```

Runs into the same workspace add to it; `diff` and `watch` say what changed. `ingest` takes in what subfinder, dnsx, httpx, katana, naabu, nuclei, gau and ffuf found.

## Access control

`azhaq roles` maps the target once per role, then asks every endpoint any role reached with every other role's session, fills `{id}` routes with each role's own objects, and compares the answers. A role is anonymous, carries headers you give it, gets them from a command (`-role-cmd`, for tokens that live minutes), or signs in with Chrome (`-role-login`). A session that dies mid-run is caught and quoted (`the site said "Signature expired"`), and a canary (an endpoint only a live session reads) renews it during the replay. Each cross-read is scored `proved`, `likely` or `guess`, with the reason. A route that answers a made-up identifier like a real one is listed as `answers any identifier`, not as a finding. `azhaq roles show -dir DIR URL` prints the answers side by side, a field-level diff, and a curl per role with its session held in a shell variable. With `-replay-writes post,put,patch` and `-har alice=alice.har`, alice's writes are asked with bob's session too, and the routes the map found are filled with each role's own identifiers (including routes that only take a write, such as `PUT /users/v1/{username}/email`) and sent with an empty body, the owner's first. A cross-role write is reported only when it is proven: the owner's object is read as the owner before and after, and `[bob writes alice's object]` is claimed only when that object changed the way the write asks, or was deleted. A write answered 2xx that left the owner's object unchanged (an app that writes the caller's own object whatever the path says) is not a finding, and a POST to a collection is never called writing another role's object. [docs/OUTPUT.md](docs/OUTPUT.md#roles) lists the verdicts and fields.

## In a pipeline

```
azhaq subs -d example.com -silent | azhaq dns -silent | azhaq probe -json      # subfinder | dnsx | httpx
azhaq crawl  -u https://app.example.com/ -json                                 # katana + jsluice
azhaq urls   -d example.com -silent                                            # gau
azhaq ports  -host scanme.nmap.org -p top-1000 -json                           # naabu (connect scan)
azhaq dirs   -u https://app.example.com/ -w common.txt -e php,bak              # ffuf -ac
azhaq params -u https://app.example.com/search -w burp-parameter-names.txt     # arjun
```

Each reads targets from flags, a file or stdin, prints results as found, and with `-json` uses the field names of the tool it stands in for. `dirs` and `params` pace themselves (100 and 20 requests a second per host by default): `-rate 0` runs them as fast as ffuf and arjun. `probe`'s `status_code` is the first answer, as httpx's; `final_url` says where an in-scope redirect ended.

## For assistants: MCP

```
claude mcp add azhaq -- azhaq mcp -allow example.com -max-requests 5000 -rate 5
```

The tools run Azhaq itself and return its summary and rows. The scope, the budget for all calls together and the pace are fixed at start; an argument the schema does not take is refused; results are bounded, and exports come in pages that each parse alone. Without `-allow` or `-scope` the server does not start, unless `-unlocked` says so. [docs/MCP.md](docs/MCP.md).

## Benchmark

`go run ./bench` runs Azhaq and the tools it replaces on the same targets: Juice Shop, VAmPI and crAPI in Docker, ginandjuice.shop, apps the bench serves itself, and the live names of hackerone.com, tesla.com and vulnweb.com. It prints the numbers, losses included. Latest run (2026-10-28, v0.7.2; the map, access-control, resume and drop-in checks pass, the port comparison runs on GitHub's network because this machine's security software removes naabu):

| Job | Replaces | Azhaq | Reference |
| --- | --- | --- | --- |
| Live subdomains, 3 domains, no keys | subfinder + dnsx | 540, in 42 s | 505, in 71 s |
| DNS brute force, 5,000 words | dnsx | 3 in 52 s | 3 in 71 s |
| Wildcard zone, 3 real names of 50 | dnsx | 3 found, 0 fake | 50 without `-wd` |
| Probing 559 live hosts | httpx | 397 answered; status, title and technologies agree on 387 of 388 shared (redirects out of the site compared by their own status); 106 s | 389 answered, 144 s |
| Server routes Juice Shop's frontend calls (77) | katana + jsluice | 70 | 1 |
| VAmPI's API paths (12), ginandjuice's script-only routes (3), crAPI's routes (40) | katana + jsluice | 12, 3, 32 | 1, 2, 0 |
| With Chrome: Juice Shop, crAPI | katana `-headless` | 70/77 in 12 s, 32/40 in 17 s | 6/77 in 6 s, 0/40 in 44 s |
| Historical URLs, 3 domains (Wayback and Common Crawl unreachable for both) | gau | 7,108, including 2,341 of gau's 2,346 | 2,346 |
| Paths, 4,750 words on 3 apps | ffuf `-ac` | 35 hits, 4 false positives, 49 s | 36 hits, 4 false positives, 52 s |
| Parameters, 5 pages | arjun | 5, including arjun's 2 | 2 |
| Screenshots, 4 front pages | gowitness | 4 in 15 s | 3 in 34 s |
| Credentials in a script | jsluice | 12, including jsluice's 4 | 4 |
| Reverse DNS of a /25 | dnsx `-ptr` | 36 of 36 | 36 |
| Access matrix, anonymous, member, owner (signed in by Chrome) | manual | 6/6 rows right, no logout sent | |
| A run capped at 100 requests and resumed; killed and resumed; with two workers | – | each maps everything one run maps; 197 requests over the capped run and its resumes, one run 191 | |
| Memory, Juice Shop | katana | 93 MB | 60 MB |

The Juice Shop truth is the 77 routes its server defines that its frontend calls (`bench/truth/juice_routes.py`, from the container's own code), not strings found by searching the bundle. Azhaq loses on parameter discovery time (68 s against arjun's 26 s), memory (above katana's plain `-jc` crawl; katana `-jc -jsl` took 1.7 GB on the same app in a reviewer's test), and one path of ffuf's 36.

[bench/README.md](bench/README.md) has what is measured and the caveats.

## Documentation

Offline too: `azhaq docs TOPIC`.

- [Recipes](docs/RECIPES.md): how do I map an app, log in, find IDOR, test writes, map a program, resume, watch, export, read GraphQL, hand it to an assistant
- [Concepts](docs/CONCEPTS.md): what a row says, coverage, kinds, exit codes, roles verdicts, what Azhaq sends
- [Troubleshooting](docs/TROUBLESHOOTING.md): why is my URL `hint`, the map looks thin, exit 3, exit 4, Chrome
- [Output](docs/OUTPUT.md): every field of every command, the summary
- [Architecture](docs/ARCHITECTURE.md): every collector, every run option, how the engine works, limitations
- [MCP](docs/MCP.md) and the [connector protocol](docs/CONNECTOR.md)

## License

[MIT](LICENSE). Dependencies are MIT, BSD, Apache or Unlicense licensed, and CI checks it. Most subdomain sources are [subfinder](https://github.com/projectdiscovery/subfinder)'s (MIT, ProjectDiscovery), run in-process; technology fingerprints come from [wappalyzergo](https://github.com/projectdiscovery/wappalyzergo), whose passive matcher is included in `internal/wappalyzer`, and CDN ranges from [cdncheck](https://github.com/projectdiscovery/cdncheck) (both MIT, ProjectDiscovery).
