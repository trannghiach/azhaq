# Benchmark

`go run ./bench` measures Azhaq against the tools it is meant to replace, on the same targets, and prints the numbers including the ones where Azhaq loses.

```
go run ./bench                  # apps and domains
go run ./bench -domains=false   # apps only
go run ./bench -crapi           # also OWASP crAPI (about 2 GB of images)
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
| `bench/domains.txt` | public domains | passive only: CT logs, archives and DNS resolution; no HTTP or port traffic to the hosts |

## Reference tools

Downloaded to `bench/.work/bin` and verified against pinned SHA-256 sums (`bench/tools.go`).

| Tool | Version | Used for |
| --- | --- | --- |
| katana | 1.8.0 | crawling with JavaScript parsing (`-d 3 -jc`) |
| subfinder | 2.17.0 | passive subdomains, default sources, no API keys |
| dnsx | 1.3.1 | deciding which names are live, for both tools |
| gau | 2.2.4 | historical URLs |
| ffuf | 2.3.0 | the same wordlist as Azhaq's path sweep, with auto-calibration (`-ac`) |
| httpx, naabu | 1.12.0, 2.6.1 | installed; not compared until Azhaq has probing parity and a port scanner |

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
- Domains: no empty CT or archive result without an error or `degraded` flag, unless every source answered and found nothing (vulnweb.com has no certificates in CT logs).

## Latest results

2026-10-25, commit `bef171a`, Go 1.27.1, one machine; record `bench/history/2026-10-25T071201-bef171a.json`.

| App | Azhaq routes | known | shell | time | RSS | katana routes | known | shell | time | RSS |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Juice Shop | 120 | 45/45 | 0 | 6.6 s | 43 MB | 5 | 0/45 | 3 | 13.3 s | 61 MB |
| VAmPI | 14 | 12/12 | 0 | 0.6 s | 20 MB | 1 | 1/12 | 0 | 11.1 s | 35 MB |
| ginandjuice.shop | 12 | 3/3 | 0 | 23.2 s | 32 MB | 13 | 1/3 | 0 | 17.9 s | 61 MB |
| crAPI | 25 | 0/40 | 0 | 1.0 s | 29 MB | 3 | 0/40 | 1 | 12.9 s | 57 MB |

crAPI's frontend builds every API path at run time (`"identity/" + "api/auth/login"`), which neither tool resolves yet. ginandjuice.shop is a remote host: Azhaq keeps at most 2 requests in flight per host and made about 60, while katana ran with `-c 10`.

Path sweep on Juice Shop, 33 words: Azhaq 3 hits, ffuf `-ac` 3 hits, 3 shared, no catch-all page in either.

| Domain (passive) | live | Azhaq live | names | time | subfinder live | names | time |
| --- | --- | --- | --- | --- | --- | --- | --- |
| hackerone.com | 12 | 10 | 10 | 14 s | 11 | 527 | 31 s |
| tesla.com | 503 | 54 | 145 | 8 s | 499 | 1808 | 31 s |
| vulnweb.com | 5 | 0 | 0 | 9 s | 5 | 519 | 31 s |

Subfinder queries far more sources. Azhaq asks two CT logs, and in this run crt.sh answered 502 or timed out for all three domains, so its numbers are Cert Spotter alone (marked `degraded`). In an earlier run where crt.sh answered, Azhaq found 184 of 503 live tesla.com names. No historical URLs came back from either tool: the Wayback Machine answered 429 to every request from this address and arquivo.pt failed; gau returned none as well (in a manual run its Wayback source got 429 and Common Crawl refused the connection).
