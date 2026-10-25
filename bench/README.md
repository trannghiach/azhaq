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
| katana | 1.8.0 | crawling with JavaScript parsing (`-d 3 -jc`), and with Chrome (`-headless -system-chrome -no-sandbox`) |
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
- **known**: routes from an independent list that a tool found. For Juice Shop the list is every `/api/*` and `/rest/*` string in the frontend bundle plus the server-rendered pages it links to (`bench/truth/`). For VAmPI and crAPI it is the paths of the app's own OpenAPI document. A templated path (`/users/v1/{username}`) counts when a tool found it as written, a concrete instance of it, or its static part (`/users/v1`). For ginandjuice.shop it is three routes that appear only in page scripts or script-driven forms.
- **shell**: reported URLs whose response is the page the app returns for any path (the SPA index on Juice Shop). For Azhaq these are URLs marked `visited`; katana does not claim to have visited what it lists, so its number is how much of its output is that page.
- **live**: names that dnsx resolves (A, AAAA or CNAME), out of the union of both tools' names. Each tool is credited with the live names it found.
- **katana ∪ jsluice**: known routes that either tool found, katana crawling and jsluice reading the scripts katana listed.
- **probe agreement**: for hosts both Azhaq and httpx answered, the final status, the title (whitespace collapsed) and the technology list (names and versions) must all match.
- **historical URLs**: distinct URLs on the domain or its subdomains, normalized the way Azhaq stores them, static assets left out; the share of gau's list that Azhaq's `-urls` file also holds.
- **time** and **RSS**: wall time and peak resident memory of each run. Azhaq's app runs include its default domain fan-out (subdomain sources, archives, RDAP), which waits on third-party services, and technology fingerprints (about 170 MB; `-no-tech` leaves them out).

## Checks

The command fails when one of these does not hold:

- Apps: Juice Shop at least 40 of its 45 known routes, VAmPI every path of its OpenAPI document, crAPI at least 30 of its 40; on every app at least as many known routes as katana ∪ jsluice, and no catch-all page reported as visited. ginandjuice.shop: the page scripts are read and the routes only they contain are found; product and blog pages fold into one template row each.
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

2026-10-25, commit `0187bde`, Go 1.27.1, one machine; record `bench/history/2026-10-25T115806-0187bde.json`. All 21 checks pass.

| App | Azhaq routes | known | shell | time | RSS | katana routes | known | shell | time | RSS |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Juice Shop | 121 | 45/45 | 0 | 7.0 s | 223 MB | 5 | 0/45 | 3 | 13.5 s | 61 MB |
| VAmPI | 14 | 12/12 | 0 | 1.5 s | 160 MB | 1 | 1/12 | 0 | 11.3 s | 34 MB |
| ginandjuice.shop | 15 | 3/3 | 0 | 31.4 s | 207 MB | 13 | 1/3 | 0 | 15.8 s | 64 MB |
| crAPI | 69 | 32/40 | 0 | 7.0 s | 210 MB | 4 | 0/40 | 1 | 13.1 s | 57 MB |

| Known routes | Azhaq | katana | jsluice | katana ∪ jsluice |
| --- | --- | --- | --- | --- |
| Juice Shop | 45/45 | 0/45 | 0/45 | 0/45 |
| VAmPI | 12/12 | 1/12 | 0/12 | 1/12 |
| ginandjuice.shop | 3/3 | 1/3 | 1/3 | 2/3 |
| crAPI | 32/40 | 0/40 | 0/40 | 0/40 |

crAPI's frontend joins every API path from constants (`"identity/" + API.LOGIN`); Azhaq resolves 32 of the 40 its OpenAPI document lists, and the other 8 (admin and management endpoints) appear nowhere in the frontend. Azhaq's memory is mostly technology fingerprints (about 170 MB; `-no-tech` brings Juice Shop to about 57 MB). Its time on ginandjuice.shop includes the domain fan-out, which waits for the slowest subdomain source; it keeps at most 2 requests in flight per host, katana ran with `-c 10`.

`azhaq roles` on Juice Shop, anonymous against a freshly registered user: 12 endpoints differ, among them `/api/Users` (every account) and `/rest/user/authentication-details`, 401 → 200.

Path sweep on Juice Shop, 33 words: Azhaq 3 hits, ffuf `-ac` 3 hits, 3 shared, no catch-all page in either.

| Domain | live | Azhaq live | names | time | subfinder live | names | time | Azhaq URLs | gau URLs | gau's in Azhaq |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| hackerone.com | 12 | 12 | 573 | 31 s | 11 | 524 | 31 s | 3,096 | 1,625 | 1,625 |
| tesla.com | 510 | 497 | 1,841 | 26 s | 487 | 1,819 | 31 s | 4,079 | 651 | 651 |
| vulnweb.com | 7 | 7 | 532 | 20 s | 6 | 518 | 31 s | 144 | 65 | 65 |

Both tools run subfinder's default keyless sources; 7 or 8 of 14 answered per domain, and Azhaq records each failure. For historical URLs both lost the Wayback Machine (it answers 429 to this address) and Common Crawl (its index refuses connections from here); gau's URLs came from OTX and urlscan, which Azhaq also asks, and Azhaq's extra URLs come mostly from arquivo.pt (capped at 10,000 rows a domain).

| Probing, 533 live hosts | answered | status, title and tech agree | favicon agrees | CDN agrees | time |
| --- | --- | --- | --- | --- | --- |
| Azhaq | 376 | 376/376 | 40/48 | 49/52 | 114.4 s |
| httpx | 376 | | | | 133.4 s |

Both sent the same User-Agent with 16 requests in flight. With its default random browser User-Agent, httpx got Akamai's "Access Denied" page on about 85 tesla.com hosts in a separate run, where Azhaq got the real page.

| Active DNS on vulnweb.com | Azhaq | dnsx | shared | Azhaq time | dnsx time |
| --- | --- | --- | --- | --- | --- |
| brute force, 5,000 words | 3 | 3 | 3 | 39.2 s | 69.1 s |
| permutations of live names | 0 | 0 (alterx) | 0 | | |
| wildcard zone, 50 words, 3 real | 3 found, 0 fake | 50 (no filtering) | | | |

vulnweb.com has few names, so the permutation row says little; dnsx's `-wd` filter needs the zone to be named, and without it every guess in the wildcard zone comes back.
