# azhaq probe

Find the web services of hosts: status, title, technologies, CDN, certificate, hashes; matchers and filters; raw responses. Replaces httpx (see [Migrating](../MIGRATING.md#httpx-azhaq-probe)).

## Synopsis

```
azhaq probe -u TARGET | -l FILE | stdin  [-p PORTS] [-path P] [-fr] [-mc 200 -ms admin …] [-tls-grab -hash md5 -jarm …] [-sr] [-rate N] [-json | -csv | -md] [-silent]
```

## Examples

```
# Names from subs, live ones only, as JSON
azhaq subs -d example.com -live | azhaq probe -json

# A list, held to a program's scope, 10 requests a second
azhaq probe -l hosts.txt -scope hackerone -program security -rate 10

# Several ports, keep 200 and 401 answers that hold "admin", print title and technologies
azhaq probe -l hosts.txt -p 443,8000-8100 -mc 200,401 -ms 'admin' -title -td

# Follow redirects, read the certificate, hash the body
azhaq probe -l hosts.txt -fr -tls-grab -hash md5 -json

# Keep every response
azhaq probe -l hosts.txt -sr -srd out -irh -irr -json

# Send POST too: this can change data on the target
azhaq probe -u https://app.example.com -x GET,POST -body 'a=1'
```

## What it does

1. Takes targets from `-u`, `-l` or stdin: URLs, hosts, `host:port`, IPs, address ranges or AS numbers.
2. Asks each name at the ports `-p` names, and prints one line per web service as it answers.
3. Reads status, title, technologies, CDN, certificate and hashes from the answers. The flags choose which.
4. Keeps or drops rows with matchers (`-mc`, `-ms`, `-ml`, `-mr`) and filters (`-fc`, `-fs`, `-fl`, `-fe`).
5. Gives every target a row, a failure or a skip included.
6. Sends other methods or your own request only when you ask: `-x` adds methods, `-request` sends a request file. Both can change data on the target.

## Output

One web service per line, as it answers. `-json` prints httpx's fields, one object per line, and the summary as one JSON object on stderr. `-csv` and `-md` use httpx's columns. `-oa FILE` writes the text, JSON, CSV and Markdown forms side by side.

A target with no answer is a row with `failed: true` (`-probe` prints `[FAILED]`). See [Targets with no answer](#targets-with-no-answer).

Always present:

| Field | Meaning |
| --- | --- |
| `input` | The target as given. |
| `host` | The name. |
| `host_ip` | The address the request connected to. Through a proxy no connection to the target is seen, so it is the literal IP given, or the first address the name resolves to. |
| `time` | How long the request took, as a Go duration. |
| `timestamp`, `url`, `port`, `scheme`, `path`, `method`, `status_code`, `content_length`, `words`, `lines`, `failed` | As httpx. |

Present when there is something to say:

| Field | Meaning |
| --- | --- |
| `a`, `aaaa` | The addresses the name resolved to. |
| `cname`, `resolvers`, `title`, `webserver`, `content_type`, `location`, `tech`, `cdn`, `cdn_name`, `cdn_type`, `catchall` | As httpx. |
| `favicon`, `favicon_md5`, `favicon_path`, `favicon_url` | With `-favicon`. |
| `final_url`, `chain_status_codes` | With `-fr`. |

On request:

| Field | With | Meaning |
| --- | --- | --- |
| `tls` | `-tls-grab` | `tls_version`, `cipher`, `subject_cn`, `subject_an`, `issuer_cn`, `serial`, `not_before`, `not_after`, `expired`, `self_signed`, `mismatched`, `wildcard_certificate`, `fingerprint_hash`. |
| `hash` | `-hash` | `body_md5`, `header_md5`, … |
| `jarm_hash` | `-jarm` | The JARM fingerprint of a TLS server. |
| `body_preview` | `-bp` | The first characters of the body. |
| `extracts` | `-er`, `-ep` | What the regex finds. |
| `asn` | `-asn` | `as_number`, `as_name`, `as_country`, `as_range`, from RIPEstat. |
| `csp`, `body_fqdn`, `body_domains` | `-efqdn` | The names a page and its policy name. |
| `websocket` | `-websocket` | Set for a server that speaks it. |
| `http2` | `-http2` | Whether the server speaks HTTP/2. |
| `pipeline` | `-pipeline` | Whether the server answers pipelined requests. |
| `vhost` | `-vhost` | A virtual host. |
| `sni` | `-sni` | The TLS server name asked for. |
| `cpe` | `-cpe` | Products, as CPE. |
| `wordpress` | `-wp` | WordPress plugins and themes. |
| `knowledgebase` | `-kb` | The kind of page. |
| `header`, `raw_header` | `-irh` | The response headers. |
| `request`, `body` | `-irr` | The request and the response. `body` is also set with `-mdc` and `-fdc`, as httpx does. |
| `chain` | `-include-chain` | Each hop of a followed redirect. |
| `stored_response_path` | `-sr` | Where the response is stored. |
| `screenshot_path`, `screenshot_path_rel` | `-ss` | Where the screenshot is saved. |

## Summary and exit codes

The summary and the exit codes are the shared ones: see [the summary](../OUTPUT.md#the-summary) and [exit codes](../OUTPUT.md#exit-codes). The summary counts the targets that got no answer under `without an answer`, and says how many rows the matchers and filters left out.

## Details

### One answer's fields

- `status_code`, `content_type`, `content_length`, `title` and `webserver` are one answer's: the first, or with `-fr` the last.
- `chain_status_codes` lists the statuses of the whole chain.
- `url` of a URL input is the input as given, with its slash, query and fragment (`http://h/` and `http://h/#x` are two values); `path` stays the path asked. For a bare host it is httpx's form, the front page without a slash (`http://h`).

### Targets with no answer

- A target that got no answer, such as a name that does not resolve or a closed port, is a row with `failed: true` and an `error`.
- The summary counts it under `without an answer`.
- A bare host, IP or `host:port` is asked over both schemes, the likelier first (https on port 443 and on ports below 1024, http on 80, 8080 and above 1024). When neither answers, the row's `url` and `scheme`, the summary's `failed` target and `unreachable` entry name the scheme asked last, as httpx does, and the `error` is that try's: `127.0.0.1:9` is `http://127.0.0.1:9`, `127.0.0.1:8081` is `https://127.0.0.1:8081`.
- A plain request that is answered 400, or not answered, is asked again over TLS, as httpx does. The 400 stays when TLS does not answer.
- Every target given ends as a row, a failure or a skip.
- A target that resolved and got neither an answer nor a recorded failure is listed as failed, with `no answer and no failure recorded`.

### One row for each input line

- Each input line has its own row, whatever else was given.
- `https://h/`, `h` and `h:443` that reach one page are three rows. There is one request and the same answer. Each row's `input` is its own line.
- It is never one answer and a `no answer` for the others.
- A line given twice is one row.

### Ports of an input
- Without `-p`, a URL or `host:port` is asked once, on its own port. A bare name is asked on the web ports.
- With `-p`, the port of a `host:port` or a URL is replaced by the ports of `-p`, as in httpx. `-l 127.0.0.1:3001 -p 5002` asks `http://127.0.0.1:5002/` only, and the row's `port` is `5002`. `input` is the line as given.
- `-path` is joined onto the path of a URL input, as httpx does: `-u 'http://h/rest/products/search?q=juice#frag' -path /,/login` asks `/rest/products/search/?q=juice` and `/rest/products/search/login?q=juice`. One slash goes between the two paths, a path that already ends with the other, or starts with it, is not repeated, the URL's query is kept and the path's own query is added to it, and the fragment is never sent. A bare host has no path, so `-path` is the whole path there (`/`, `/login`).
- A port of `-p` with no scheme is asked as a bare `host:port` is, plain HTTP first above 1024. A URL with a path, a query or a user keeps its path and its scheme on the new port. A port of `-p` that is the URL's own leaves the URL as given.

### Pace
- `-rl N` counts services a second, as httpx does. A target's first request waits its turn. Its favicon, redirects and second scheme do not.
- `-rate N` paces every request instead. The default is no pace, where httpx's `-rl` is 150.
- `-t N` is the work items in flight: 16 by default, where httpx's is 50.
- `-req-timeout` is one request's time. `-timeout` stops the whole run.

### Page kinds (`-kb`)
- `-kb` (also `-fpt` and `-fep`) classifies each page with the dit model. It is read from `~/.dit/model.json`, or from `$AZHAQ_DIT_MODEL`.
- azhaq never downloads the model. Without it, the command is a usage error, exit 2, that says where to fetch it: `the page classifier's model is not at …`. Fetch the model once from the address in the message.
- The model is about 100 MB and takes a few seconds to load.

## Flags

<!-- flags:begin probe -->
**Targets and input**

| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-u` | string, repeatable |  | target: URL, host, host:port, IP, address range or AS number (repeatable, or comma-separated) |
| `-l` | string |  | file of targets (- for stdin; a glob such as 'hosts-*.txt') |
| `-p` | string |  | ports to probe on each name: 80,443,8000-8100, each led by http: or https: to ask one scheme only (http:80,https:443); an input with a port of its own (host:port, a URL) is asked on these ports instead of its own |
| `-scope` | string |  | a program's scope: a file (HackerOne CSV, bounty-targets JSON, Burp options, lines) or hackerone, bugcrowd, intigriti, yeswehack |
| `-program` | string |  | the program to take from a -scope list (handle, name or URL) |
| `-max-ips` | int | `4096` | addresses expanded from -asn and -cidr prefixes, for the whole run |
| `-no-stdin` | bool |  | do not read targets from stdin |

**What to ask**

| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-path` | string |  | path or paths to ask of every target, a list (comma-separated) or a file: joined onto the path of a URL input, as httpx does, with the URL's query kept and the path's added; a host has no path, so the path is the whole of it |
| `-x` | string |  | also send these methods to every target (GET, POST, HEAD, …; all for the common ones): requests that can change data on the target |
| `-body` | string |  | body sent with the -x methods: it can change data on the target |
| `-probe` | bool |  | print a row for every target: [SUCCESS], or [FAILED] when nothing answered |
| `-fr` | bool |  | follow redirects within the site (status, title and length are then the last answer's; the chain is in chain_status_codes) |
| `-no-follow` | bool |  | do not follow redirects: each URL is asked once and its redirect recorded with the Location (httpx's default) |
| `-no-tech` | bool |  | skip technology fingerprints (saves about 30 MB of memory) |
| `-tls-grab` | bool |  | report the certificate and the TLS version of each answer |
| `-hash` | string |  | report these body and header digests: md5,mmh3,simhash,sha1,sha256,sha512 |
| `-jarm` | bool |  | report the JARM fingerprint of TLS servers (ten handshakes a server) |

**Matchers and filters**

| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-mc` | string |  | keep rows with these status codes (200,302, spans 200-299, classes 4xx) |
| `-ms` | string |  | keep rows whose response (headers and body) holds one of these strings, comma-separated, any case |
| `-mdc` | string |  | keep rows for which this condition holds, over the -json fields: 'contains(body, "admin") && status_code == 200' |
| `-fc` | string |  | drop rows with these status codes |

**Output fields**

| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-sc` | bool |  | print the status code |
| `-title` | bool |  | print the page title |
| `-td` | bool |  | print the technologies |
| `-ip` | bool |  | print the address connected to |
| `-location` | bool |  | print the redirect location (and where a followed chain ended) |

**Raw responses**

| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-sr` | bool |  | store each response (request and response as sent) under -srd/response/HOST/SHA1.txt, with an index.txt |
| `-srd` | string |  | directory of -sr (default output) |
| `-irh` | bool |  | add the response headers to -json rows (header, raw_header) |
| `-irr` | bool |  | add the request and the response to -json rows (request, body, header, raw_header) |
| `-debug-req` | bool |  | print each request to stderr |

**Scope and safety**

| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-allow` | string, repeatable |  | a domain, host or address range the run may touch; with any -allow, nothing else is requested |
| `-deny` | string, repeatable |  | a domain, host or address range the run must not touch, even when given as a target |
| `-deny-path` | string, repeatable |  | a regular expression on a URL's path and query: a URL it matches is never requested, by any collector or Chrome, and is listed as not requested (repeatable; azhaq decides nothing by itself) |
| `-kill-file` | string |  | stop all sending, at once, when this file exists, and exit 4; azhaq resume works once it is removed (default DB.stop) |
| `-ledger` | string |  | write every request and connection to a target to this file, a chain of hashes that azhaq ledger -verify checks (default DB.ledger.jsonl next to the workspace; off: none; with a temporary database, only when given) |

**Pace and limits**

| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-rate` | float |  | requests per second to targets, over all hosts (0: no pace) |
| `-rl` | float |  | services asked per second, as httpx -rl: each target's first request waits its turn, its favicon, redirects and second scheme do not (-rate paces every request) |
| `-delay` | duration |  | time between requests to targets: a pace of one request per DELAY over all hosts (as -rate 1/DELAY) |
| `-host-parallel` | int |  | requests in flight per host (default 10, as katana) |
| `-parallel` | int |  | work items in flight (default 16) |
| `-dns-rate` | float |  | DNS queries per second per resolver (0: no pace but the queries in flight, as dnsx) |
| `-req-timeout` | duration |  | time one request may take (default 10 s to the first byte, 30 s in all); -timeout bounds the whole run |
| `-timeout` | duration |  | stop after this long and keep what was found; azhaq resume continues (0: no limit) |
| `-max-requests` | int |  | requests to targets this run may send (0: no cap); the work left over is for azhaq resume |

**Session and network**

| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-H` | string, repeatable |  | extra request header K: V |
| `-cookie` | string, repeatable |  | Cookie name=value (repeatable; sent as one Cookie header) |
| `-proxy` | string |  | send every request through this proxy (http://, https:// or socks5://) |
| `-resolvers` | string |  | DNS resolvers: a file with one per line, or a comma list; each is ADDR, ADDR:PORT or udp:, tcp:, dot:, doh:URL[:get] and then the address (default: public resolvers) |

**Output**

| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-db` | string |  | keep the graph in this database for query, show, export and diff (default: a temporary one) |
| `-json` | bool |  | JSONL output, and the summary as one JSON object on stderr |
| `-o` | string |  | also write results to this file |
| `-silent` | bool |  | results only: no progress; the summary only when something failed (a source that failed, a takeover candidate as a [takeover] line on stderr); stdout stays one result per line |
| `-v` | bool |  | print a line for every finished task, not only failures |

<details>
<summary>Flags familiar from httpx, other names and flags accepted with no effect (152)</summary>

| Flag | Type | Default | Meaning | Kind |
| --- | --- | --- | --- | --- |
| `-asn` | bool |  | print and report the autonomous system of the address (RIPEstat) | httpx's name |
| `-auto-referer` | bool |  | send each request's URL as its Referer | httpx's name |
| `-body-preview` | int |  | print the first N characters of the body | httpx's name |
| `-cdn` | bool |  | print the CDN, WAF or cloud in front | httpx's name |
| `-cname` | bool |  | print the first CNAME | httpx's name |
| `-content-length` | bool |  | print the content length | httpx's name |
| `-content-type` | bool |  | print the content type | httpx's name |
| `-cpe` | bool |  | report products by title, body and favicon, as CPE (add -favicon for the hash) | httpx's name |
| `-csp-probe` | bool |  | probe the names of each Content-Security-Policy too | httpx's name |
| `-csv` | bool |  | print CSV, as httpx | httpx's name |
| `-csv-output-encoding` | string |  | CSV encoding: utf-8 writes a byte order mark first (implies -csv) | httpx's name |
| `-custom-fingerprint-file` | string |  | wappalyzer fingerprints (JSON) to add to the built-in ones | httpx's name |
| `-debug` | bool |  | print each request and response to stderr | httpx's name |
| `-debug-resp` | bool |  | print each response to stderr | httpx's name |
| `-exclude` | string |  | leave out: cdn (ports other than 80 and 443 of CDN addresses), private-ips, a port, an address or range, or a regex | httpx's name |
| `-exclude-output-fields` | string |  | leave these fields out of -json rows, comma-separated | httpx's name |
| `-extract-fqdn` | bool |  | report the names a page and its policy name: csp, body_fqdn, body_domains | httpx's name |
| `-extract-preset` | string |  | print what a ready regex finds: url, ipv4, mail | httpx's name |
| `-extract-regex` | string, repeatable |  | print what this regex finds in the response | httpx's name |
| `-favicon` | bool |  | also hash each front page's favicon (one or two more requests per service) | httpx's name |
| `-filter-cdn` | string |  | drop rows behind these CDN providers | httpx's name |
| `-filter-condition` | string |  | drop rows for which this condition holds | httpx's name |
| `-filter-duplicates` | bool |  | drop rows that answer almost as one already printed (same status and a body within 3 bits of its simhash) | httpx's name |
| `-filter-error-page` | bool |  | drop error pages (as -fpt error) | httpx's name |
| `-filter-favicon` | string |  | drop rows with these favicon hashes (implies the favicon request) | httpx's name |
| `-filter-length` | string |  | drop rows with these content lengths | httpx's name |
| `-filter-line-count` | string |  | drop rows with these line counts | httpx's name |
| `-filter-page-type` | string |  | drop rows of these page types, comma-separated (login,captcha,parked,error…); implies -kb | httpx's name |
| `-filter-regex` | string, repeatable |  | drop rows whose response matches one of these regexes | httpx's name |
| `-filter-response-time` | string |  | drop rows by response time: '> 1' | httpx's name |
| `-filter-string` | string |  | drop rows whose response holds one of these strings | httpx's name |
| `-filter-word-count` | string |  | drop rows with these word counts | httpx's name |
| `-follow-host-redirects` | bool |  | with -fr: follow redirects to the same host only | httpx's name |
| `-http2` | bool |  | report whether the server speaks HTTP/2 (one more request each) | httpx's name |
| `-include-chain` | bool |  | add each hop of a followed redirect to -json rows (chain) | httpx's name |
| `-include-response-base64` | bool |  | like -irr, base64-encoded | httpx's name |
| `-input-mode` | string |  | input mode: burp reads the URLs of a Burp XML export given with -l | httpx's name |
| `-j` | bool |  | JSONL output (as -json) | httpx's name |
| `-knowledge-base` | bool |  | report the kind of page (login, captcha, …) in knowledgebase; needs the dit model (see TROUBLESHOOTING) | httpx's name |
| `-leave-default-ports` | bool |  | print URLs with their default port (:80, :443) | httpx's name |
| `-line-count` | bool |  | print the line count | httpx's name |
| `-list-dsl-variables` | bool |  | list the fields -json rows hold, and stop | httpx's name |
| `-markdown` | bool |  | print a Markdown table | httpx's name |
| `-match-cdn` | string |  | keep rows behind these CDN providers | httpx's name |
| `-match-favicon` | string |  | keep rows with these favicon hashes (implies the favicon request) | httpx's name |
| `-match-length` | string |  | keep rows with these content lengths | httpx's name |
| `-match-line-count` | string |  | keep rows with these line counts | httpx's name |
| `-match-regex` | string, repeatable |  | keep rows whose response matches every one of these regexes | httpx's name |
| `-match-response-time` | string |  | keep rows by response time: '< 1', '>= 500ms' | httpx's name |
| `-match-word-count` | string |  | keep rows with these word counts | httpx's name |
| `-max-host-error` | int |  | as -maxhr | httpx's name |
| `-max-redirects` | int | `10` | with -fr: redirects to follow | httpx's name |
| `-maxhr` | int |  | connects or timeouts in a row after which a host is not asked again (default 5) | httpx's name |
| `-method` | bool |  | print the request method | httpx's name |
| `-no-decode` | bool |  | hash and match the body as sent, not converted to UTF-8 | httpx's name |
| `-no-fallback` | bool |  | ask an input without a scheme over both http and https and report each that answers | httpx's name |
| `-omit-body` | bool |  | with -sr: leave the body out of the stored file | httpx's name |
| `-output-all` | string |  | write the results to FILE (text), FILE.json, FILE.csv and FILE.md | httpx's name |
| `-pipeline` | bool |  | report whether the server answers pipelined requests (ten requests each) | httpx's name |
| `-probe-all-ips` | bool |  | send the request to every address of a name, one row each | httpx's name |
| `-random-agent` | bool |  | send a browser's User-Agent picked at random for each request | httpx's name |
| `-request` | string |  | send the request in this file (request line, headers, blank line, body) to every target: it can change data on the target | httpx's name |
| `-respect-hsts` | bool |  | with -fr: go to https when a redirect's answer sent Strict-Transport-Security | httpx's name |
| `-response-size-to-read` | int |  | most bytes read of a response (default 2 MiB of a page, 16 MiB of a script) | httpx's name |
| `-response-size-to-save` | int |  | with -sr: most bytes of a response stored (0: all that was read) | httpx's name |
| `-response-time` | bool |  | print the response time | httpx's name |
| `-retries` | int |  | times to send a request again when nothing answered (each counts as a request) | httpx's name |
| `-rlm` | float |  | services asked per minute (as -rl, per minute) | httpx's name |
| `-screenshot` | bool |  | save a screenshot of each web service's front page under -srd/screenshot (Chrome on the machine); rows are printed when the run ends, with screenshot_path; implies -sr | httpx's name |
| `-sni-name` | string |  | TLS server name to ask for, whatever the host | httpx's name |
| `-store-chain` | bool |  | like -sr, with the redirect chain in the file | httpx's name |
| `-strip` | string |  | strip tags from the body preview: html or xml (the preview always has its tags stripped, as httpx) | httpx's name |
| `-target` | string, repeatable |  | target (as -u) | httpx's name |
| `-tls-probe` | bool |  | probe the names of each certificate too (implies -tls-grab) | httpx's name |
| `-vhost` | bool |  | report a virtual host (one more request each) | httpx's name |
| `-vhost-input` | bool |  | lines are vhost,ip: ask the ip with the vhost as Host | httpx's name |
| `-web-server` | bool |  | print the Server header | httpx's name |
| `-websocket` | bool |  | print websocket for a server that speaks it | httpx's name |
| `-word-count` | bool |  | print the word count | httpx's name |
| `-wordpress` | bool |  | report WordPress plugins and themes | httpx's name |
| `-bp` | int |  | print the first N characters of the body | other name |
| `-cff` | string |  | wappalyzer fingerprints (JSON) to add to the built-in ones | other name |
| `-cl` | bool |  | print the content length | other name |
| `-csvo` | string |  | CSV encoding: utf-8 writes a byte order mark first (implies -csv) | other name |
| `-ct` | bool |  | print the content type | other name |
| `-e` | string |  | leave out: cdn (ports other than 80 and 443 of CDN addresses), private-ips, a port, an address or range, or a regex | other name |
| `-efqdn` | bool |  | report the names a page and its policy name: csp, body_fqdn, body_domains | other name |
| `-eof` | string |  | leave these fields out of -json rows, comma-separated | other name |
| `-ep` | string |  | print what a ready regex finds: url, ipv4, mail | other name |
| `-er` | string, repeatable |  | print what this regex finds in the response | other name |
| `-fcdn` | string |  | drop rows behind these CDN providers | other name |
| `-fd` | bool |  | drop rows that answer almost as one already printed (same status and a body within 3 bits of its simhash) | other name |
| `-fdc` | string |  | drop rows for which this condition holds | other name |
| `-fe` | string, repeatable |  | drop rows whose response matches one of these regexes | other name |
| `-fep` | bool |  | drop error pages (as -fpt error) | other name |
| `-ffc` | string |  | drop rows with these favicon hashes (implies the favicon request) | other name |
| `-fhr` | bool |  | with -fr: follow redirects to the same host only | other name |
| `-filter-code` | string |  | drop rows with these status codes | other name |
| `-fl` | string |  | drop rows with these content lengths | other name |
| `-flc` | string |  | drop rows with these line counts | other name |
| `-follow-redirects` | bool |  | follow redirects within the site (status, title and length are then the last answer's; the chain is in chain_status_codes) | other name |
| `-fpt` | string |  | drop rows of these page types, comma-separated (login,captcha,parked,error…); implies -kb | other name |
| `-frt` | string |  | drop rows by response time: '> 1' | other name |
| `-fs` | string |  | drop rows whose response holds one of these strings | other name |
| `-fwc` | string |  | drop rows with these word counts | other name |
| `-http-proxy` | string |  | send every request through this proxy (http://, https:// or socks5://) | other name |
| `-im` | string |  | input mode: burp reads the URLs of a Burp XML export given with -l | other name |
| `-include-response` | bool |  | add the request and the response to -json rows (request, body, header, raw_header) | other name |
| `-include-response-header` | bool |  | add the response headers to -json rows (header, raw_header) | other name |
| `-irrb` | bool |  | like -irr, base64-encoded | other name |
| `-kb` | bool |  | report the kind of page (login, captcha, …) in knowledgebase; needs the dit model (see TROUBLESHOOTING) | other name |
| `-lc` | bool |  | print the line count | other name |
| `-ldp` | bool |  | print URLs with their default port (:80, :443) | other name |
| `-ldv` | bool |  | list the fields -json rows hold, and stop | other name |
| `-list-output-fields` | bool |  | list the fields -json rows hold, and stop | other name |
| `-lof` | bool |  | list the fields -json rows hold, and stop | other name |
| `-match-code` | string |  | keep rows with these status codes (200,302, spans 200-299, classes 4xx) | other name |
| `-match-condition` | string |  | keep rows for which this condition holds, over the -json fields: 'contains(body, "admin") && status_code == 200' | other name |
| `-match-string` | string |  | keep rows whose response (headers and body) holds one of these strings, comma-separated, any case | other name |
| `-maxr` | int | `10` | with -fr: redirects to follow | other name |
| `-mcdn` | string |  | keep rows behind these CDN providers | other name |
| `-md` | bool |  | print a Markdown table | other name |
| `-mfc` | string |  | keep rows with these favicon hashes (implies the favicon request) | other name |
| `-ml` | string |  | keep rows with these content lengths | other name |
| `-mlc` | string |  | keep rows with these line counts | other name |
| `-mr` | string, repeatable |  | keep rows whose response matches every one of these regexes | other name |
| `-mrt` | string |  | keep rows by response time: '< 1', '>= 500ms' | other name |
| `-mwc` | string |  | keep rows with these word counts | other name |
| `-nf` | bool |  | ask an input without a scheme over both http and https and report each that answers | other name |
| `-oa` | string |  | write the results to FILE (text), FILE.json, FILE.csv and FILE.md | other name |
| `-ob` | bool |  | with -sr: leave the body out of the stored file | other name |
| `-pa` | bool |  | send the request to every address of a name, one row each | other name |
| `-ports` | string |  | ports to probe on each name: 80,443,8000-8100, each led by http: or https: to ask one scheme only (http:80,https:443); an input with a port of its own (host:port, a URL) is asked on these ports instead of its own | other name |
| `-rate-limit` | float |  | same as -rl | other name |
| `-rhsts` | bool |  | with -fr: go to https when a redirect's answer sent Strict-Transport-Security | other name |
| `-rr` | string |  | send the request in this file (request line, headers, blank line, body) to every target: it can change data on the target | other name |
| `-rstr` | int |  | most bytes read of a response (default 2 MiB of a page, 16 MiB of a script) | other name |
| `-rsts` | int |  | with -sr: most bytes of a response stored (0: all that was read) | other name |
| `-rt` | bool |  | print the response time | other name |
| `-server` | bool |  | print the Server header | other name |
| `-sni` | string |  | TLS server name to ask for, whatever the host | other name |
| `-ss` | bool |  | save a screenshot of each web service's front page under -srd/screenshot (Chrome on the machine); rows are printed when the run ends, with screenshot_path; implies -sr | other name |
| `-status-code` | bool |  | print the status code | other name |
| `-store-response` | bool |  | store each response (request and response as sent) under -srd/response/HOST/SHA1.txt, with an index.txt | other name |
| `-store-response-dir` | string |  | directory of -sr (default output) | other name |
| `-t` | int |  | work items in flight (default 16) | other name |
| `-tech-detect` | bool |  | print the technologies | other name |
| `-vi` | bool |  | lines are vhost,ip: ask the ip with the vhost as Host | other name |
| `-wc` | bool |  | print the word count | other name |
| `-web-ports` | string |  | ports to probe on each name: 80,443,8000-8100, each led by http: or https: to ask one scheme only (http:80,https:443); an input with a port of its own (host:port, a URL) is asked on these ports instead of its own | other name |
| `-wp` | bool |  | report WordPress plugins and themes | other name |
| `-nc` | bool |  | accepted, as httpx has it: azhaq prints no color | accepted, no effect |

</details>
<!-- flags:end -->
