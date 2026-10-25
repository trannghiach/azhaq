# Benchmark

`go run ./bench` measures Azhaq against the tools it is meant to replace, on the same targets, and prints the numbers including the ones where Azhaq loses.

```
go run ./bench                  # apps and domains
go run ./bench -domains=false   # apps only
go run ./bench -crapi           # also OWASP crAPI (about 2 GB of images)
go run ./bench -brute=false     # skip DNS brute force and permutations on vulnweb.com
go run ./bench -probe=false     # skip the httpx comparison on live hosts
go run ./bench -keep            # leave the docker apps running afterwards
```

Run it from the repository root. It needs Docker, network access, a C compiler (jsluice uses cgo) and linux/amd64 (the reference tools are pinned to their linux/amd64 release archives). It exits non-zero if a check fails, and writes a JSON record to `bench/history/`.

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

## Reference tools

Downloaded to `bench/.work/bin` and verified against pinned SHA-256 sums (`bench/tools.go`).

| Tool | Version | Used for |
| --- | --- | --- |
| katana | 1.8.0 | crawling with JavaScript parsing (`-d 3 -jc`) |
| subfinder | 2.17.0 | passive subdomains, default sources, no API keys |
| dnsx | 1.3.1 | deciding which names are live, for both tools; brute force with the same words and resolvers |
| alterx | 0.1.0 | permutations of the live names, resolved by dnsx |
| gau | 2.2.4 | historical URLs (`--providers wayback,otx,urlscan`) |
| ffuf | 2.3.0 | the same wordlist as Azhaq's path sweep, with auto-calibration (`-ac`) |
| httpx | 1.12.0 | probing: `-fr -td -cdn -favicon -title -sc`, the same User-Agent and concurrency as Azhaq |
| jsluice | commit `0ddfab1` (2024-01-10) | URLs in the scripts katana found, built from source with `go install` (no release binaries) |
| naabu | 2.6.1 | installed; not compared until Azhaq has a port scanner |

The brute-force wordlist is SecLists' `subdomains-top1million-5000.txt` (MIT), fetched at a pinned commit and checked against its SHA-256 sum.

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

- Juice Shop: at least 40 of the 45 known routes; no catch-all page reported as visited.
- Two identical Juice Shop runs produce an empty diff; a diff between two different targets is labelled.
- VAmPI: every path of its OpenAPI document.
- ginandjuice.shop: the four page scripts are read and the routes only they contain are found; product and blog pages fold into one template row each.
- Domains: no empty subdomain or archive result without an error or `degraded` flag, unless every source answered and found nothing.
- Subdomains: across all domains, at least 95% of subfinder's live names, in at most twice its time.
- Every app: at least as many known routes as katana ∪ jsluice, and no catch-all page reported as visited; crAPI at least 30 of its 40 OpenAPI routes.
- `azhaq roles` on Juice Shop, anonymous against a user the bench registers: at least 5 endpoints differ, and `/api/Users` and `/rest/user/authentication-details` go from 401 to 200.
- Probing: Azhaq answers at least 95% of the hosts httpx answers; status, title and technologies agree on at least 95% of them; at most twice httpx's time.
- Historical URLs: at least 95% of gau's URLs, summed over the domains.
- Brute force on vulnweb.com: at least 95% of what dnsx finds with the same words and resolvers, in at most twice its time.
- Wildcard zone: the three real names and nothing else.

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
