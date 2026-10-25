# Benchmark

`go run ./bench` measures Azhaq against the tools it is meant to replace, on the same targets, and prints the numbers including the ones where Azhaq loses.

```
go run ./bench                  # apps and domains
go run ./bench -domains=false   # apps only
go run ./bench -crapi           # also OWASP crAPI (about 2 GB of images)
go run ./bench -brute=false     # skip DNS brute force and permutations on vulnweb.com
go run ./bench -keep            # leave the docker apps running afterwards
```

Run it from the repository root. It needs Docker, network access and linux/amd64 (the reference tools are pinned to their linux/amd64 release archives). It exits non-zero if a check fails, and writes a JSON record to `bench/history/`.

## Targets

| Target | How it runs | What is sent |
| --- | --- | --- |
| OWASP Juice Shop v20.3.0 | `bench/compose.yaml`, port 3101 | full run |
| VAmPI | `bench/compose.yaml`, port 5102 | full run |
| ginandjuice.shop | PortSwigger's public test site | full run |
| OWASP crAPI v1.1.6 (`-crapi`) | upstream compose with images pinned by digest (`bench/crapi-override.yaml`), port 8888 | full run |
| `bench/domains.txt` | public domains | passive only: subdomain sources, archives and DNS resolution; no HTTP or port traffic to the hosts |
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
| gau | 2.2.4 | historical URLs |
| ffuf | 2.3.0 | the same wordlist as Azhaq's path sweep, with auto-calibration (`-ac`) |
| httpx, naabu | 1.12.0, 2.6.1 | installed; not compared until Azhaq has probing parity and a port scanner |

The brute-force wordlist is SecLists' `subdomains-top1million-5000.txt` (MIT), fetched at a pinned commit and checked against its SHA-256 sum.

## What is measured

- **routes**: distinct paths on the app's origin a tool reported, static assets excluded.
- **known**: routes from an independent list that a tool found. For Juice Shop the list is every `/api/*` and `/rest/*` string in the frontend bundle plus the server-rendered pages it links to (`bench/truth/`). For VAmPI and crAPI it is the paths of the app's own OpenAPI document. A templated path (`/users/v1/{username}`) counts when a tool found it as written, a concrete instance of it, or its static part (`/users/v1`). For ginandjuice.shop it is three routes that appear only in page scripts or script-driven forms.
- **shell**: reported URLs whose response is the page the app returns for any path (the SPA index on Juice Shop). For Azhaq these are URLs marked `visited`; katana does not claim to have visited what it lists, so its number is how much of its output is that page.
- **live**: names that dnsx resolves (A, AAAA or CNAME), out of the union of both tools' names. Each tool is credited with the live names it found.
- **time** and **RSS**: wall time and peak resident memory of each run. Azhaq's app runs include its default domain fan-out (CT, archives, RDAP), which waits on third-party services.

## Checks

The command fails when one of these does not hold:

- Juice Shop: at least 40 of the 45 known routes; no catch-all page reported as visited.
- Two identical Juice Shop runs produce an empty diff; a diff between two different targets is labelled.
- VAmPI: every path of its OpenAPI document.
- ginandjuice.shop: the four page scripts are read and the routes only they contain are found; product and blog pages fold into one template row each.
- Domains: no empty subdomain or archive result without an error or `degraded` flag, unless every source answered and found nothing.
- Subdomains: across all domains, at least 95% of subfinder's live names, in at most twice its time.
- Brute force on vulnweb.com: at least 95% of what dnsx finds with the same words and resolvers, in at most twice its time.
- Wildcard zone: the three real names and nothing else.

## Latest results

2026-10-25, commit `c7db18e`, Go 1.27.1, one machine; record `bench/history/2026-10-25T101708-c7db18e.json`.

| App | Azhaq routes | known | shell | time | RSS | katana routes | known | shell | time | RSS |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Juice Shop | 120 | 45/45 | 0 | 5.7 s | 44 MB | 5 | 0/45 | 3 | 13.1 s | 60 MB |
| VAmPI | 14 | 12/12 | 0 | 0.5 s | 22 MB | 1 | 1/12 | 0 | 11.1 s | 35 MB |
| ginandjuice.shop | 14 | 3/3 | 0 | 19.8 s | 38 MB | 13 | 1/3 | 0 | 16.6 s | 61 MB |
| crAPI | 25 | 0/40 | 0 | 0.9 s | 32 MB | 3 | 0/40 | 1 | 12.9 s | 58 MB |

crAPI's frontend builds every API path at run time (`"identity/" + "api/auth/login"`), which neither tool resolves yet. ginandjuice.shop is a remote host: Azhaq keeps at most 2 requests in flight per host, while katana ran with `-c 10`; Azhaq's time also includes its domain fan-out, bounded by the slowest subdomain source.

Path sweep on Juice Shop, 33 words: Azhaq 3 hits, ffuf `-ac` 3 hits, 3 shared, no catch-all page in either.

| Domain (passive) | live | Azhaq live | names | time | subfinder live | names | time |
| --- | --- | --- | --- | --- | --- | --- | --- |
| hackerone.com | 13 | 12 | 526 | 20 s | 12 | 524 | 31 s |
| tesla.com | 509 | 490 | 1814 | 31 s | 486 | 1802 | 31 s |
| vulnweb.com | 7 | 7 | 520 | 20 s | 6 | 519 | 31 s |

Both tools run subfinder's default keyless sources; in this run 7 of 14 answered for each domain (the others were rate limited, timed out or need a key for useful results), and Azhaq reports each failure in its payload. No historical URLs came back from gau: the Wayback Machine answered 429 to this address.

| Active DNS on vulnweb.com | Azhaq | dnsx | shared | Azhaq time | dnsx time |
| --- | --- | --- | --- | --- | --- |
| brute force, 5,000 words | 3 | 3 | 3 | 36.8 s | 75.8 s |
| permutations of live names | 0 | 0 (alterx) | 0 | | |
| wildcard zone, 50 words, 3 real | 3 found, 0 fake | 50 (no filtering) | | | |

vulnweb.com has few names, so the permutation row says little; dnsx's `-wd` filter needs the zone to be named, and without it every guess in the wildcard zone comes back.
