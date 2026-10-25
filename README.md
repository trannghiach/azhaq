# Azhaq

Azhaq is a reconnaissance engine written in Go. Give it a URL, a domain, an organization name or a cloud asset inventory, and it maps what is reachable from there: hosts, URLs, forms, API routes, DNS records, certificates, historical URLs and registration data. Everything goes into one SQLite graph, deduplicated across sources. Running it again shows what changed.

It maps and does not attack: no payloads, no fuzzing, no vulnerability checks.

## Why

A typical recon pipeline chains several tools (a subdomain finder, an HTTP prober, a crawler, an archive fetcher) and ends with separate lists that overlap. Azhaq does the same collection natively and keeps one graph:

- a hostname seen by CT logs, DNS, a crawl and a TLS certificate is one node, with all four observations attached;
- a second run against the same target prints a diff instead of a new dump;
- it is a single static binary with no external tools, no browser and no CGO, and it can be embedded as a Go library.

## Install

```
go install github.com/trannghiach/azhaq/cmd/azhaq@latest
```

or from a clone: `go build -o azhaq ./cmd/azhaq`. Requires Go 1.26 or newer.

## Usage

Only scan systems you are authorized to test.

```
azhaq run -url https://app.example.com/
```

Try it offline against a built-in fixture:

```
$ azhaq run -demo
...
map
  IPAddress 127.0.0.1  target  addr
  URL http://127.0.0.1:35733/  target  visited  app  status=200 title=Azhaq fixture
  URL http://127.0.0.1:35733/api/status  target  visited  api  status=200
  URL http://127.0.0.1:35733/auth  target  visited  page  status=200 title=Auth
  URL http://127.0.0.1:35733/login  target  visited  page  status=200 title=Login
entities=5 observations=10 edges=7 errors=0 degraded=0
```

Common options:

| Option | Effect |
| --- | --- |
| `-org NAME`, `-cloud FILE`, `-in seeds.jsonl` | start from an organization, a cloud inventory or a list of seeds |
| `-passive` | only third-party sources (CT, DNS, RDAP, Wayback); nothing is sent to the target |
| `-allow D` / `-deny D` | keep the run inside, or out of, a domain |
| `-cookie N=V`, `-header 'K: V'` | reuse a session you already have |
| `-paths FILE` | extra paths to probe, merged with the built-in list |
| `-depth N`, `-max-items N` | expansion limits (default 4 and 512) |
| `-delay D` | pause before each request |
| `-db FILE` | graph file to write (default: a new timestamped file per run) |
| `-json` / `-obs` | JSON summary, or the full observation log |

Other commands:

```
azhaq plan   -url URL              # show which collectors would run
azhaq export [-db FILE]            # dump the graph as JSONL
azhaq diff   -a OLD.db -b NEW.db   # compare two runs
azhaq ingest -in facts.jsonl       # load facts from another tool
azhaq bench                        # timing and memory on the fixture
```

## Collectors

| Collector | Input | Collects |
| --- | --- | --- |
| `azhaq-http` | URL, hostname | status, redirect chain, title, headers, cookie names (not values) |
| `azhaq-crawl` | URL | same-origin links, forms, parameter names |
| `azhaq-js` | URL | routes extracted from JavaScript, tagged as API or page |
| `azhaq-paths` | URL | common paths, `robots.txt`, sitemaps |
| `azhaq-dns` | hostname | A/AAAA, CNAME, MX, TXT and NS records |
| `azhaq-tls` | hostname | certificate details and SANs within the same domain |
| `azhaq-ct` | domain | hostnames from Certificate Transparency (crt.sh, Cert Spotter) |
| `azhaq-cdx` | domain | historical URLs (Wayback Machine, arquivo.pt as fallback) |
| `azhaq-rdap` | domain, organization | registration data and nameservers |
| `azhaq-cloud` | cloud inventory file | domains, hosts and URLs from a local JSON inventory |

Sources Azhaq does not query itself, such as paid search engines like Shodan, can be plugged in as external programs. See [docs/CONNECTOR.md](docs/CONNECTOR.md).

## Documentation

- [Architecture](docs/ARCHITECTURE.md): data model, scheduling, identity rules, limitations
- [Connector protocol](docs/CONNECTOR.md): feeding external data into the graph

## License

[MIT](LICENSE). Dependencies are MIT, BSD or Apache licensed.
