# Azhaq

Azhaq is a reconnaissance engine written in Go. Give it a URL, a domain, an organization name or a cloud asset inventory, and it maps what is reachable from there: hosts, URLs, forms, API routes and operations, DNS records, certificates, historical URLs and registration data. Everything goes into one SQLite graph, deduplicated across sources. Running it again shows what changed.

It maps and does not attack: no payloads, no fuzzing, no vulnerability checks.

## Why

A typical recon pipeline chains several tools (a subdomain finder, an HTTP prober, a crawler, an archive fetcher) and ends with separate lists that overlap. Azhaq does the same collection natively and keeps one graph:

- a hostname seen by CT logs, DNS, a crawl and a TLS certificate is one node, with all four observations attached;
- a second run against the same target prints a diff instead of a new dump;
- it is a single static binary with no external tools, no browser and no CGO.

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
  URL http://127.0.0.1:43905/  target  visited  app  status=200 title=Azhaq fixture
  URL http://127.0.0.1:43905/api/status  target  visited  api  status=200 via=paths
  URL http://127.0.0.1:43905/app.js  target  visited  script  status=200
  URL http://127.0.0.1:43905/auth  target  visited  page  status=200 title=Auth
  URL http://127.0.0.1:43905/login  target  visited  page  status=200 title=Login via=paths
      form GET /auth
entities=6 observations=12 edges=9 errors=0 degraded=0
```

Each URL row says whether it was `visited`, only found (`hint`), or answered with the page every unknown path gets (`catchall`, typical of single-page apps), followed by a role such as `app`, `auth` (401), `forbidden` (403), `api` or `script`. Pages that differ only by an ID are folded into one template row, for example `/catalog/product?productId={n}  (18 urls)`. Forms are listed under the page that has them. [The map](docs/ARCHITECTURE.md#the-map) has the details.

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
azhaq diff   -a OLD.db -b NEW.db   # compare two runs of the same seeds
azhaq ingest -in facts.jsonl       # load facts from another tool
azhaq bench                        # timing and memory on the fixture
```

## Collectors

| Collector | Input | Collects |
| --- | --- | --- |
| `azhaq-http` | URL, hostname | status, redirect chain, title, headers, cookie names (not values); flags catch-all answers |
| `azhaq-crawl` | URL | same-origin links, forms (including script-driven `data-action` forms), parameter names, links inside JSON responses |
| `azhaq-js` | URL | routes from each page's inline and same-origin scripts and the chunks they import, tagged as API or page |
| `azhaq-openapi` | URL | operations, methods and parameter names from OpenAPI 3 and Swagger 2 documents (JSON or YAML); never calls them |
| `azhaq-paths` | URL | common paths and API description locations, `robots.txt`, sitemaps; drops catch-all answers |
| `azhaq-dns` | hostname | A/AAAA, CNAME, MX, TXT and NS records |
| `azhaq-tls` | hostname | certificate details and SANs within the same domain |
| `azhaq-ct` | domain | hostnames from Certificate Transparency (crt.sh and Cert Spotter, merged); a failed source marks the result `degraded` |
| `azhaq-cdx` | domain | historical URLs (Wayback Machine with backoff, arquivo.pt as fallback); a refused archive marks the result `degraded` |
| `azhaq-rdap` | domain, organization | registration data and nameservers |
| `azhaq-cloud` | cloud inventory file | domains, hosts and URLs from a local JSON inventory |

Sources Azhaq does not query itself, such as paid search engines like Shodan, can be plugged in as external programs. See [docs/CONNECTOR.md](docs/CONNECTOR.md).

## Documentation

- [Architecture](docs/ARCHITECTURE.md): data model, scheduling, identity rules, limitations
- [Connector protocol](docs/CONNECTOR.md): feeding external data into the graph

## License

[MIT](LICENSE). Dependencies are MIT, BSD or Apache licensed, and CI checks it.
