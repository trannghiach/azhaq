# Benchmark

`go run ./bench` measures Azhaq against the tools it is meant to replace, on the same targets, and prints the numbers including the ones where Azhaq loses.

```
go run ./bench                  # apps and domains
go run ./bench -domains=false   # apps only
go run ./bench -crapi           # also OWASP crAPI (about 2 GB of images)
go run ./bench -brute=false     # skip DNS brute force and permutations on vulnweb.com
go run ./bench -probe=false     # skip the httpx comparison on live hosts
go run ./bench -ports=false     # skip the naabu comparison (scanme.nmap.org and this machine)
go run ./bench -network=false   # skip ASN prefixes against RADb and reverse DNS against dnsx
go run ./bench -keep            # leave the docker apps running afterwards
```

Run it from the repository root. It needs Docker, network access, a C compiler (jsluice uses cgo), Python 3 (arjun), Chrome (screenshots, `-browser`, `-login`) and linux/amd64 (the reference tools are pinned to their linux/amd64 release archives). It exits non-zero if a check fails, and writes a JSON record to `bench/history/`.

`-only dirs,params` runs those sections alone (while working on one layer; the full run is for a release). The reference tools' runs are kept for the rest of the UTC day in `bench/.work/refcache` and replayed, with their times, when the same tool is run on the same target with the same arguments and input files; the report says how many were. `-fresh` runs them again.

The Wayback Machine and Common Crawl refuse the reference machine's address, and its security software removes naabu, so the archive and port scan comparisons also run on GitHub's network: push a tag `bench-*` (workflow `bench-archives`: domains, archives and ports), and its results are readable as annotations without signing in.

## Targets

| Target | How it runs | What is sent |
| --- | --- | --- |
| OWASP Juice Shop v20.3.0 | `bench/compose.yaml`, port 3101 | full run |
| VAmPI | `bench/compose.yaml`, port 5102 | full run |
| ginandjuice.shop | PortSwigger's public test site | full run |
| OWASP crAPI v1.1.6 (`-crapi`) | upstream compose with images pinned by digest (`bench/crapi-override.yaml`), port 8888 | full run |
| `bench/domains.txt` | public domains | subdomain sources, archives and DNS resolution |
| live names of hackerone.com, tesla.com, vulnweb.com | public bug bounty programs and a test zone | probing: `GET /` over HTTPS or HTTP and the favicon, from each tool, 16 requests in flight; no port scans |
| vulnweb.com | Acunetix's public test zone | DNS brute force (5,000 words) and permutations, through public resolvers |
| `wild.example.com` | a DNS server inside the bench on 127.0.0.1 | brute force against a zone where every label resolves |
| scanme.nmap.org, 127.0.0.1 | Nmap's host for scanning, this machine | TCP connect scan, top 1,000 ports |
| AS394161, 45.33.32.128/25 | an AS's announced prefixes; the /25 around scanme.nmap.org | RIPEstat and RADb queries, reverse DNS |
| a multi-tenant app, a secrets page, a counting proxy | served by the bench on 127.0.0.1 | sign-in with Chrome and three roles; planted credentials; budgets, resume and workers on Juice Shop |

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

The command fails when one of these does not hold:

- Apps: Juice Shop at least 90% of its 77 known routes, VAmPI every path of its OpenAPI document, crAPI at least 30 of its 40; on every app at least as many known routes as katana ∪ jsluice, and no catch-all page reported as visited. ginandjuice.shop: the page scripts are read and the routes only they contain are found; product and blog pages fold into one template row each.
- With a browser: `-browser` finds at least the known routes katana `-headless` finds, on Juice Shop and crAPI.
- Diffs: two identical Juice Shop runs produce an empty diff; a diff between two different targets is labelled; `azhaq watch` reports no change on an unchanged app.
- Roles: on Juice Shop, anonymous against a registered user (with its token, and signed in on the login page with Chrome), `/api/Users` and `/rest/user/authentication-details` go from 401 to 200; on the multi-tenant app, anonymous, member and owner match the known access table, and no signed-in role requests the sign-out link.
- Paths: at least 95% of ffuf `-ac`'s hits with the same wordlist and rate, and no more false positives. Parameters: at least 95% of arjun's. Ports: at least 95% of naabu's open ports. Screenshots: at least 95% of gowitness's pages. Secrets: everything jsluice finds in the planted script.
- Scope: no request leaves the program's scope.
- Drop-in commands and exports: `azhaq crawl`, `probe` and `subs` stand in for katana, httpx and subfinder | dnsx; the OpenAPI export holds VAmPI's paths and 30 of crAPI's; targets and the HTML report are written.
- Scale: on Juice Shop behind a counting proxy, a run capped at 100 requests per process and resumed until done, a run killed with SIGKILL and resumed, and a run shared with two workers each map the same URLs as one uninterrupted run, and no process sends more than its budget.
- Domains: no empty subdomain or archive result without an error or `degraded` flag, unless every source answered and found nothing; at least 95% of subfinder's live names, the subdomain results in at most twice its time; at least 95% of gau's historical URLs.
- Networks: an AS's announced prefixes match its registered routes; reverse DNS finds at least 95% of what dnsx `-ptr` finds.
- Probing: Azhaq answers at least 95% of the hosts httpx answers; status, title and technologies agree on at least 95% of them; at most twice httpx's time.
- DNS: brute force on vulnweb.com finds at least 95% of what dnsx finds with the same words and resolvers, in at most twice its time; in the wildcard zone, the three real names and nothing else.

## Latest results

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
