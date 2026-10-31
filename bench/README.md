# Benchmark

`go run ./bench` measures Azhaq against the tools it is meant to replace, on the same targets, and prints the numbers including the ones where Azhaq loses.

```
go run ./bench                          # everything, both profiles
go run ./bench -profile polite          # only the polite profile (default or both too)
go run ./bench -only fuzz,dns,services  # these sections alone
go run ./bench -domains=false           # leave out the passive domain lookups
go run ./bench -crapi                   # also OWASP crAPI (about 2 GB of images)
go run ./bench -refbin DIR -nmap SCRIPT # reference tools built elsewhere; nmap unpacked without sudo
go run ./bench -readme                  # rewrite the README's benchmark table from the newest record
```

Run it from the repository root. It needs Docker (Juice Shop and VAmPI from `bench/compose.yaml`, the services lab from `bench/services.yaml` when the services section runs), network access, a C compiler (jsluice uses cgo), Python 3 (arjun), Chrome (screenshots, `-browser`, `-login`) and linux/amd64 (the reference tools are pinned to their linux/amd64 release archives, or taken from `-refbin`). It exits non-zero if a check fails, and writes a JSON record to `bench/history/`. The bench never stops containers: `-down` takes down only its own two (`azhaq-bench`).

## Two profiles

Every comparison section runs azhaq and its reference tool with the same inputs and settings, once per profile; a check and a measured run carry the profile's name.

| | default | polite |
| --- | --- | --- |
| HTTP | the default flags of both tools | azhaq `-rate 5`; the reference at 5 (`-rl 5` httpx, katana and ffuf; arjun `--rate-limit 5`, which caps requests per second where its `-d` is a delay per thread; gowitness has no rate option and runs with its defaults, since with `-t 1` it shoots the first page and times out on the rest; notify `-rl 5`; gau one thread) |
| DNS | azhaq and dnsx defaults, the same two resolvers | azhaq `-dns-rate 10`; dnsx `-rl 10`, the same two resolvers |
| ports | the defaults, `-scan-type c` for naabu | azhaq `-rate 100`; naabu `-rate 100`; nmap `--max-rate 100` |
| path and fuzz lists | all 4,750 words of SecLists `common.txt` | about 250 words (`-polite-words`): every Nth word and twenty paths the apps serve. At 5 requests per second the whole list is 16 minutes a tool and app, which does not fit a run under 90 minutes |
| what else is smaller | everything | screenshots of four targets, parameters on three pages, domains `hackerone.com` and `vulnweb.com` (`-polite-domains`), DNS brute force with 300 words, no katana `-headless`, roles or scale |

Public test sites (ginandjuice.shop, testphp.vulnweb.com, demo.testfire.net) are always asked at 5 requests per second, in both profiles.

## The bar

Each comparison row is two checks.

- **Results**: azhaq's results are at least the reference's, counting only results that something other than azhaq confirms: a server's own log, a second resolver, `ss -ltn`, the app's own routes or planted parameters, a GET to the host itself. Not 95%.
- **Time**: azhaq's time is at most 1.05 times the reference's: the median of three runs when the first took under 20 s, one run above; for `dirs` and `fuzz` the two tools' runs alternate (azhaq, ffuf, azhaq, ffuf, …), so a target that slows down or speeds up as the bench goes on costs both the same. A run of azhaq that failed (a flag or a command a stream has not delivered) is no time to compare, and fails the check.

Every check names the exact commands, so a reviewer can run them again. The record still has the old numbers (shares of the reference's results, ratios of times).

## Reference tools

Downloaded to `bench/.work/bin` and verified against pinned SHA-256 sums (`bench/tools.go`).

| Tool | Version | Used for |
| --- | --- | --- |
| katana | 1.8.0 | crawling with JavaScript parsing and its jsluice parser (`-d 3 -jc -jsl`), and with Chrome (`-headless -system-chrome -no-sandbox`) |
| subfinder | 2.17.0 | passive subdomains, default sources, no API keys |
| dnsx | 1.3.1 | deciding which names are live, for both tools; brute force with the same words and resolvers; reverse DNS (`-ptr`) |
| alterx | 0.1.0 | permutations of the live names, resolved by dnsx |
| gau | 2.2.4 | historical URLs (`--providers wayback,otx,urlscan`) |
| ffuf | 2.3.0 | the same wordlist as Azhaq's path sweep, with auto-calibration (`-ac`), at the same rate |
| httpx | 1.12.0 | probing: `-fr -td -cdn -favicon -title -sc`, the same User-Agent and concurrency as Azhaq |
| naabu | 2.6.1 | TCP connect scan (`-s c`), top 1,000 ports |
| jsluice | commit `0ddfab1` (2024-01-10) | URLs in the scripts katana found, and secrets in the planted script; built from source with `go install` |
| arjun | 2.2.7 | query parameters (GPL-3.0; installed with pip in a virtual environment and run as a separate program) |
| gowitness | 3.2.2 | screenshots (GPL-3.0; run as a separate program) |
| nmap | 7.94 | `-sV` service and version detection on the services lab (NPSL; run as a separate program; extracted from the Ubuntu .debs with `dpkg -x`, no sudo; `-nmap` names a script that runs it) |
| notify | 1.0.7 | notifications to a local stub (built with `go install` by the bench, like jsluice; MIT) |

Wordlists come from SecLists (MIT) at a pinned commit and are checked against their SHA-256 sums: `subdomains-top1million-5000.txt` for DNS brute force, `common.txt` for paths, `burp-parameter-names.txt` for parameters.

## What is measured

- **routes**: distinct paths on the app's origin a tool reported, static assets excluded.
- **known**: routes from an independent list that a tool found. For Juice Shop the list is the 77 routes its server defines (`app.get/post/…` in the container's `build/server.js`) whose static parts its frontend bundle writes, as they are or as a prefix constant plus a suffix (`bench/truth/juice_routes.py`, `bench/truth/juice-shop-v20.3.0-routes.txt`); until v0.6 it was the 45 `/api` and `/rest` strings a search of the bundle found, which left out every route built in a template literal. For VAmPI and crAPI it is the paths of the app's own OpenAPI document. A templated path (`/users/v1/{username}`) counts when a tool found a concrete instance of it or the same template, whatever its parameters are called; its static part alone (`/users/v1`) no longer counts. For ginandjuice.shop it is three routes that appear only in page scripts or script-driven forms.
- **shell**: reported URLs whose response is the page the app returns for any path (the SPA index on Juice Shop). For Azhaq these are URLs marked `visited`; katana does not claim to have visited what it lists, so its number is how much of its output is that page.
- **live**: names that dnsx resolves (A, AAAA or CNAME), out of the union of both tools' names. Each tool is credited with the live names it found.
- **katana ∪ jsluice**: known routes that either tool found, katana crawling and jsluice reading the scripts katana listed.
- **bundle grep**: known routes among the quoted strings that start with a path (`"/rest/user/login"`) in the same scripts: what reading the bundles by hand gives, without methods, bodies or the routes built from parts.
- **probe agreement**: for hosts both Azhaq and httpx answered, the final status, the title (whitespace collapsed) and the technology list (names and versions) must all match.
- **historical URLs**: distinct URLs on the domain or its subdomains, normalized the way Azhaq stores them, static assets left out; the share of gau's list that Azhaq's `-urls` file also holds.
- **time** and **RSS**: wall time and peak resident memory of each run. Azhaq's app runs include its default domain fan-out (subdomain sources, archives, RDAP), which waits on third-party services, and technology fingerprints (about 30 MB; `-no-tech` leaves them out).

## Checks

The command fails when one of these does not hold. Rows marked "both" are measured in both profiles, each with the two checks of the bar.

- Apps (both): `crawl` against katana `-d 3 -jc -jsl` on Juice Shop, VAmPI and ginandjuice.shop, scored on the app's own routes. Default profile: Juice Shop at least 90% of its 77 known routes, VAmPI every path of its OpenAPI document, crAPI at least 30 of its 40; on every app at least as many known routes as katana ∪ jsluice, and no catch-all page reported as visited. ginandjuice.shop: the page scripts are read and the routes only they contain are found; product and blog pages fold into one template row each.
- With a browser: `-browser` finds at least the known routes katana `-headless` finds, on Juice Shop and crAPI.
- Diffs: two identical Juice Shop runs produce an empty diff; a diff between two different targets is labelled; `azhaq watch` reports no change on an unchanged app.
- Roles: on Juice Shop, anonymous against a registered user (with its token, and signed in on the login page with Chrome), `/api/Users` and `/rest/user/authentication-details` go from 401 to 200; on the multi-tenant app, anonymous, member and owner match the known access table, and no signed-in role requests the sign-out link.
- Paths (both): hits of `dirs` against `ffuf -ac`, confirmed as not the app's catch-all answer; no more false positives.
- Fuzz (both): `fuzz` against ffuf on Juice Shop and VAmPI, calibrated (`-ac`) and, by default, with `-fs`; the hits confirmed as not the catch-all answer; the JSON report equals ffuf's after `duration` is dropped.
- Parameters (both): the parameters a planted server reads (and none it does not) against arjun; ginandjuice.shop, two pages and 1,000 names at 5 requests per second, in at most 1.05 times arjun's time.
- Ports (both): open ports of scanme.nmap.org (once), of 127.0.0.1 confirmed by `ss -ltn` taken before and after, and of 127.0.0.0/28 against listeners the bench opened, against naabu `-scan-type c`.
- Services (both): the lab's fifteen daemons, each named by what it says (the lab's own list in `bench/services.yaml`), against `nmap -sV`; at least 90% named.
- Screenshots (both): image files that decode and are not one colour, against gowitness, on the five local apps and three pages the bench serves.
- Probing (both): the hosts that answer (the local apps, the services lab's web ports and 100 local servers), confirmed by a GET to the host; status, title and technologies agree on at least 95% of shared hosts; three public test sites at 5 requests per second; and every input is a row, a failure or a skip.
- Domains (both): `subs -live` against `subfinder | dnsx`, on live names a third resolver confirms, in the time of the two together; every confirmed name only the reference finds is in azhaq's list or its source is named as failed; no empty subdomain or archive result without an error or `degraded` flag.
- URLs (both): `urls` against gau on vulnweb.com, and every URL gau lists is in azhaq's list.
- DNS (both): record types (A, AAAA, CNAME, MX, NS, TXT, SRV, CAA, SOA) and `-ptr` against dnsx on a zone the bench serves, counted at the server (answers right, queries received, queries in the busiest second); brute force on the DNS lab with the same words and resolver; in the wildcard zone, the three real names and nothing else.
- DNS lab, no docker (`lab`): `ports -pu` finds the lab's UDP port, `subs -w -live` gives the names the lab answers, a wildcard subzone gives only its real name, the dangling CNAMEs are named takeover candidates.
- Notify (both): `azhaq notify` against notify, with the same input and provider config, against a stub whose log is the evidence; the same requests; no webhook token in any output when the webhook cannot be reached.
- Networks: an AS's announced prefixes match its registered routes; reverse DNS finds at least 95% of what dnsx `-ptr` finds.
- Scope: no request leaves the program's scope, also with Chrome (`-browser`, `-login`, `shots`, `crawl -browser`).
- Claims: summary, ledger and an independent count agree on every path a request takes, including `azhaq_ports` after the MCP budget is spent.
- Scale: on Juice Shop behind a counting proxy, a run capped at 100 requests per process and resumed until done, a run killed with SIGKILL and resumed, and a run shared with two workers each map the same URLs as one uninterrupted run, and no process sends more than its budget.
- OpenAPI: the export of Juice Shop, VAmPI, DVGA, ginandjuice.shop and a fixture with `/blog` and `/blog/` is a valid OpenAPI 3 document by the bench's own checker (`bench/openapi.go`: structure, unique operation ids, path parameters declared, references resolve).
- Docs: no public doc says an active option needs `-allow` or a scope, or that requests are "GETs only" without HEAD; the README's "Latest run (date, vX)" names the newest release in the changelog and is not older than the tag.
- Go tests (`go test ./bench`): rows that were one assertion each (`bench/smoke_test.go`).

## Older results

The numbers below are from v0.6.2 to v0.9.0, taken before the two profiles and the 1.05 bar; the README's table is written from the newest record.

2026-10-27, v0.6.2, Go 1.27.1, one machine: `go run ./bench -crapi` (record `bench/history/2026-10-27T045837-db9f6fa-dirty.json`, taken before the commit). The probe comparison compares a redirect out of the host's site by its own status: httpx `-fr` reports the third party's page as the host's, Azhaq records the redirect. 44 of 45 checks pass; the one failure is the port comparison, which has nothing to compare with: this machine's security software removes the naabu binary. Ports and archives are compared on GitHub's network (workflow `bench-archives`).

### Applications

Juice Shop, VAmPI and ginandjuice.shop from 2026-10-29 (v0.8.1, `go run ./bench -domains=false -brute=false -ports=false -probe=false -network=false`), katana with `-jsl`.


| App | Azhaq routes | known | shell | time | RSS | katana routes | known | shell | time | RSS |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Juice Shop | 110 | 70/77 | 0 | 5.4 s | 99 MB | 5 | 1/77 | 3 | 14.1 s | 1404 MB |
| VAmPI | 14 | 12/12 | 0 | 0.6 s | 75 MB | 1 | 1/12 | 0 | 11.1 s | 36 MB |
| ginandjuice.shop | 16 | 3/3 | 0 | 15.5 s | 99 MB | 14 | 2/3 | 0 | 18.5 s | 813 MB |
| crAPI (2026-10-27, katana without `-jsl`) | 85 | 32/40 | 0 | 4.5 s | 102 MB | 4 | 0/40 | 1 | 13.0 s | 59 MB |

| Known routes | Azhaq | katana `-jsl` | jsluice | katana ∪ jsluice | bundle grep |
| --- | --- | --- | --- | --- | --- |
| Juice Shop | 70/77 | 1/77 | 0/77 | 1/77 | 37/77 |
| VAmPI | 12/12 | 1/12 | 0/12 | 1/12 | 0/12 |
| ginandjuice.shop | 3/3 | 2/3 | 1/3 | 2/3 | 1/3 |
| crAPI (2026-10-27) | 32/40 | 0/40 | 0/40 | 0/40 | – |

| With a browser | routes | known | shell | time |
| --- | --- | --- | --- | --- |
| Juice Shop, Azhaq `-browser` | 176 | 70/77 | 0 | 12.7 s |
| Juice Shop, katana `-headless` | 30 | 6/77 | 4 | 6.9 s |
| crAPI, Azhaq `-browser` | 86 | 32/40 | 0 | 17.9 s |
| crAPI, katana `-headless` | 5 | 0/40 | 1 | 44.2 s |

Juice Shop's routes come from the calls its Angular bundle makes (`this.http.post(\`${host}/rest/2fa/verify\`, …)`); the seven Azhaq misses are parameter routes of `/api/*` resources the server defines and the frontend never asks for by id, and two middleware mounts. crAPI's frontend joins every API path from constants (`"identity/" + API.LOGIN`); the other 8 of its 40 (admin and management endpoints) appear nowhere in the frontend. Memory is the process alone, without Chrome for the browser rows. ginandjuice.shop's time includes the domain fan-out, which waits for the slowest subdomain source.

### Sessions and roles

| | endpoints listed | expected | time |
| --- | --- | --- | --- |
| Juice Shop, anonymous → user, with the user's token | 35 | `/api/Users`, `/rest/user/authentication-details` 401 → 200 | 11.7 s |
| Juice Shop, anonymous → user, signed in with `-role-login` | 37 | both, 401 → 200 | 14.9 s |
| multi-tenant app, anonymous → member → owner, `-role-login` | | 6/6 rows of the access table; no signed-in role requested the sign-out link | 7.3 s |

`azhaq roles` asks every endpoint any role reached with every other role and fills path parameters from identifiers in the answers, each role's own objects first, so the table is a full matrix. Outside the bench, on Juice Shop it reports another user's basket (`/rest/basket/14`, alice's, read by bob and admin), `/api/Addresss/3` read by admin only, and `/rest/memories` handing anyone users' password hashes; on VAmPI, a book's secret read by the other user and `/users/v1/_debug` handing anyone every password.

### Discovery

| | Azhaq | Reference | shared | Azhaq time | reference time |
| --- | --- | --- | --- | --- | --- |
| paths, 4,750 words on 3 apps (ffuf `-ac`) | 35 hits | 36 | 35 | 53.7 s | 59.3 s |
| false positives (hits that answer like a missing path) | 4 | 4 | | | |
| parameters, 5 pages, 6,453 names (arjun) | 5 | 2 | 2 | 120.1 s | 29.5 s |
| screenshots, 4 front pages (gowitness) | 4 | 3 | | 36 s | 34 s |
| secrets in the planted script (jsluice) | 12 | 4 | 4 | | |

Azhaq's parameter search is slower than arjun's: it confirms each name it finds on its own, and it sends at most 20 requests a second per host.

### Scope, watch and scale

- Scope: no request reached the host outside the program's scope (links, scripts, a redirect, a form and `robots.txt` pointed at it, with path, parameter, port and GraphQL modules on); 5 in-scope URLs mapped.
- Watch: three runs of an unchanged app, no change reported. Two identical Juice Shop runs diff empty.
- Juice Shop behind a counting proxy, 184 URLs in one run of 5.4 s:

| | URLs as one run | detail |
| --- | --- | --- |
| `-max-requests 100`, then `azhaq resume` until done | yes | 3 processes; Juice Shop received at most 100 requests from one, 211 in all against 205 for one run |
| killed with SIGKILL after 1.8 s, then `azhaq resume` | yes | |
| `-serve` with two `azhaq worker` processes | yes | the workers ran 239 tasks; 6.8 s |

### Domains

| Domain | live | Azhaq live | names | subdomains at | whole run | subfinder live | names | time | Azhaq URLs | gau URLs | gau's in Azhaq |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| hackerone.com | 14 | 14 | 607 | 10 s | 19 s | 12 | 529 | 27 s | 2,981 | 1,621 | 1,620 |
| tesla.com | 526 | 516 | 1,855 | 9 s | 19 s | 490 | 1,806 | 19 s | 3,981 | 653 | 651 |
| vulnweb.com | 7 | 7 | 532 | 17 s | 25 s | 6 | 517 | 11 s | 141 | 65 | 62 |

Azhaq's default sources: 8 per domain, all of which answered (crt.sh is read from its `/json` endpoint; the sources that were dead or refusing every request are out of the default set). Both tools lost the Wayback Machine and Common Crawl, which refuse this address; Azhaq says so in every summary.

| Networks | Azhaq | Reference | shared |
| --- | --- | --- | --- |
| AS394161, announced prefixes (RIPEstat) against registered routes (RADb) | 102 | 39 | 31 |
| 45.33.32.128/25, addresses with a reverse name (dnsx `-ptr`) | 36 | 36 | 36 |

| Probing, 551 live hosts | answered | status, title and tech agree | favicon agrees | CDN agrees | time |
| --- | --- | --- | --- | --- | --- |
| Azhaq | 406 | 396/396 | 43/50 | 48/52 | 100.5 s |
| httpx | 396 | | | | 141.7 s |

Both sent the same User-Agent (a current browser's) with 16 requests in flight. Azhaq connects to the addresses its resolver found, IPv6 first where the machine has a route, and keeps the first hop of a redirect whose target fails.

| Active DNS on vulnweb.com | Azhaq | dnsx | shared | Azhaq time | dnsx time |
| --- | --- | --- | --- | --- | --- |
| brute force, 5,000 words | 3 | 3 | 3 | 37.0 s | 72.3 s |
| permutations of live names | 0 | 0 (alterx) | 0 | | |
| wildcard zone, 50 words, 3 real | 3 found, 0 fake | 50 (no filtering) | | | |

vulnweb.com has few names, so the permutation row says little; dnsx's `-wd` filter needs the zone to be named, and without it every guess in the wildcard zone comes back.
