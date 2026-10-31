# azhaq probe

Find the web services of hosts: status, title, technologies, CDN, certificate, hashes; matchers and filters; raw responses. Replaces httpx (see [Migrating](../MIGRATING.md#httpx-azhaq-probe)).

## Synopsis

```
azhaq probe -u TARGET | -l FILE | stdin  [-p PORTS] [-path P] [-fr] [-mc 200 -ms admin …] [-tls-grab -hash md5 -jarm …] [-sr] [-rate N] [-json | -csv | -md] [-silent]
```

## Examples

```
azhaq subs -d example.com -live | azhaq probe -json
azhaq probe -l hosts.txt -scope hackerone -program security -rate 10
azhaq probe -l hosts.txt -p 443,8000-8100 -mc 200,401 -ms 'admin' -title -td
azhaq probe -l hosts.txt -fr -tls-grab -hash md5 -json   # follow redirects, certificate, body hash
azhaq probe -l hosts.txt -sr -srd out -irh -irr -json   # keep every response
azhaq probe -u https://app.example.com -x GET,POST -body 'a=1'   # sends POST: can change data on the target
```

## Output

One web service per line, as it answers; -json: httpx's fields (url, host, host_ip, port, scheme, status_code, title, tech, tls, hash, …); a target with no answer is a row with failed:true (-probe prints [FAILED])

httpx's fields. Always: `timestamp`, `url`, `input` (the target as given), `host` (the name), `host_ip` (the address the request connected to), `port`, `scheme`, `path`, `method`, `status_code`, `content_length`, `words`, `lines`, `time` (a Go duration), `failed`. When present: `a` and `aaaa` (the addresses the name resolved to), `cname`, `resolvers`, `title`, `webserver`, `content_type`, `location`, `tech`, `cdn`, `cdn_name`, `cdn_type`, `favicon`, `favicon_md5`, `favicon_path`, `favicon_url` (with `-favicon`), `final_url` and `chain_status_codes` (with `-fr`), `catchall`. On request: `tls` (`-tls-grab`: `tls_version`, `cipher`, `subject_cn`, `subject_an`, `issuer_cn`, `serial`, `not_before`, `not_after`, `expired`, `self_signed`, `mismatched`, `wildcard_certificate`, `fingerprint_hash`), `hash` (`-hash`: `body_md5`, `header_md5`, …), `jarm_hash`, `body_preview` (`-bp`), `extracts` (`-er`, `-ep`), `asn` (`-asn`: `as_number`, `as_name`, `as_country`, `as_range`, from RIPEstat), `csp`, `body_fqdn`, `body_domains` (`-efqdn`), `websocket`, `http2`, `pipeline`, `vhost`, `sni`, `cpe` (`-cpe`), `wordpress` (`-wp`), `knowledgebase` (`-kb`), `header`, `raw_header` (`-irh`), `request`, `body` (`-irr`; also with `-mdc` and `-fdc`, as httpx), `chain` (`-include-chain`), `stored_response_path` (`-sr`), `screenshot_path` and `screenshot_path_rel` (`-ss`). `status_code`, `content_type`, `content_length`, `title` and `webserver` are one answer's: the first, or with `-fr` the last, and `chain_status_codes` lists the statuses of the chain. A target that got no answer (a name that does not resolve, a closed port) is a row with `failed: true` and an `error`, and the summary counts it under `without an answer`; every target given ends as a row, a failure or a skip, and one that resolved and got neither is listed as failed, `no answer and no failure recorded`. Each input line has its own row, whatever else was given: `https://h/`, `h` and `h:443` that reach one page are three rows (one request, the same answer, each row's `input` its own line), never one answer and a `no answer` for the others; a line given twice is one row. Matchers and filters leave rows out and the summary says how many. `-csv` and `-md` use httpx's columns; `-oa FILE` writes the text, JSON, CSV and Markdown forms side by side.

## Summary and exit codes

The summary and the exit codes are the shared ones: see [OUTPUT.md](../OUTPUT.md#exit-codes).

## Flags

<!-- flags:begin probe -->
| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-H` | string, repeatable |  | extra request header K: V |
| `-allow` | string, repeatable |  | a domain, host or address range the run may touch; with any -allow, nothing else is requested |
| `-asn` | bool |  | print and report the autonomous system of the address (RIPEstat) |
| `-auto-referer` | bool |  | send each request's URL as its Referer |
| `-body` | string |  | body sent with the -x methods: it can change data on the target |
| `-body-preview` | int |  | print the first N characters of the body |
| `-bp` | int |  | print the first N characters of the body |
| `-cdn` | bool |  | print the CDN, WAF or cloud in front |
| `-cff` | string |  | wappalyzer fingerprints (JSON) to add to the built-in ones |
| `-cl` | bool |  | print the content length |
| `-cname` | bool |  | print the first CNAME |
| `-content-length` | bool |  | print the content length |
| `-content-type` | bool |  | print the content type |
| `-cookie` | string, repeatable |  | Cookie name=value (repeatable; sent as one Cookie header) |
| `-cpe` | bool |  | report products by title, body and favicon, as CPE (add -favicon for the hash) |
| `-csp-probe` | bool |  | probe the names of each Content-Security-Policy too |
| `-csv` | bool |  | print CSV, as httpx |
| `-csv-output-encoding` | string |  | CSV encoding: utf-8 writes a byte order mark first (implies -csv) |
| `-csvo` | string |  | CSV encoding: utf-8 writes a byte order mark first (implies -csv) |
| `-ct` | bool |  | print the content type |
| `-custom-fingerprint-file` | string |  | wappalyzer fingerprints (JSON) to add to the built-in ones |
| `-db` | string |  | keep the graph in this database for query, show, export and diff (default: a temporary one) |
| `-debug` | bool |  | print each request and response to stderr |
| `-debug-req` | bool |  | print each request to stderr |
| `-debug-resp` | bool |  | print each response to stderr |
| `-delay` | duration |  | time between requests to targets: a pace of one request per DELAY over all hosts (as -rate 1/DELAY) |
| `-deny` | string, repeatable |  | a domain, host or address range the run must not touch, even when given as a target |
| `-dns-rate` | float |  | DNS queries per second per resolver (0: no pace but the queries in flight, as dnsx) |
| `-e` | string |  | leave out: cdn (ports other than 80 and 443 of CDN addresses), private-ips, a port, an address or range, or a regex |
| `-efqdn` | bool |  | report the names a page and its policy name: csp, body_fqdn, body_domains |
| `-eof` | string |  | leave these fields out of -json rows, comma-separated |
| `-ep` | string |  | print what a ready regex finds: url, ipv4, mail |
| `-er` | string, repeatable |  | print what this regex finds in the response |
| `-exclude` | string |  | leave out: cdn (ports other than 80 and 443 of CDN addresses), private-ips, a port, an address or range, or a regex |
| `-exclude-output-fields` | string |  | leave these fields out of -json rows, comma-separated |
| `-extract-fqdn` | bool |  | report the names a page and its policy name: csp, body_fqdn, body_domains |
| `-extract-preset` | string |  | print what a ready regex finds: url, ipv4, mail |
| `-extract-regex` | string, repeatable |  | print what this regex finds in the response |
| `-favicon` | bool |  | also hash each front page's favicon (one or two more requests per service) |
| `-fc` | string |  | drop rows with these status codes |
| `-fcdn` | string |  | drop rows behind these CDN providers |
| `-fd` | bool |  | drop rows that answer almost as one already printed (same status and a body within 3 bits of its simhash) |
| `-fdc` | string |  | drop rows for which this condition holds |
| `-fe` | string, repeatable |  | drop rows whose response matches one of these regexes |
| `-fep` | bool |  | drop error pages (as -fpt error) |
| `-ffc` | string |  | drop rows with these favicon hashes (implies the favicon request) |
| `-fhr` | bool |  | with -fr: follow redirects to the same host only |
| `-filter-cdn` | string |  | drop rows behind these CDN providers |
| `-filter-code` | string |  | drop rows with these status codes |
| `-filter-condition` | string |  | drop rows for which this condition holds |
| `-filter-duplicates` | bool |  | drop rows that answer almost as one already printed (same status and a body within 3 bits of its simhash) |
| `-filter-error-page` | bool |  | drop error pages (as -fpt error) |
| `-filter-favicon` | string |  | drop rows with these favicon hashes (implies the favicon request) |
| `-filter-length` | string |  | drop rows with these content lengths |
| `-filter-line-count` | string |  | drop rows with these line counts |
| `-filter-page-type` | string |  | drop rows of these page types, comma-separated (login,captcha,parked,error…); implies -kb |
| `-filter-regex` | string, repeatable |  | drop rows whose response matches one of these regexes |
| `-filter-response-time` | string |  | drop rows by response time: '> 1' |
| `-filter-string` | string |  | drop rows whose response holds one of these strings |
| `-filter-word-count` | string |  | drop rows with these word counts |
| `-fl` | string |  | drop rows with these content lengths |
| `-flc` | string |  | drop rows with these line counts |
| `-follow-host-redirects` | bool |  | with -fr: follow redirects to the same host only |
| `-follow-redirects` | bool |  | follow redirects within the site (status, title and length are then the last answer's; the chain is in chain_status_codes) |
| `-fpt` | string |  | drop rows of these page types, comma-separated (login,captcha,parked,error…); implies -kb |
| `-fr` | bool |  | follow redirects within the site (status, title and length are then the last answer's; the chain is in chain_status_codes) |
| `-frt` | string |  | drop rows by response time: '> 1' |
| `-fs` | string |  | drop rows whose response holds one of these strings |
| `-fwc` | string |  | drop rows with these word counts |
| `-hash` | string |  | report these body and header digests: md5,mmh3,simhash,sha1,sha256,sha512 |
| `-host-parallel` | int |  | requests in flight per host (default 10, as katana) |
| `-http-proxy` | string |  | send every request through this proxy (http://, https:// or socks5://) |
| `-http2` | bool |  | report whether the server speaks HTTP/2 (one more request each) |
| `-im` | string |  | input mode: burp reads the URLs of a Burp XML export given with -l |
| `-include-chain` | bool |  | add each hop of a followed redirect to -json rows (chain) |
| `-include-response` | bool |  | add the request and the response to -json rows (request, body, header, raw_header) |
| `-include-response-base64` | bool |  | like -irr, base64-encoded |
| `-include-response-header` | bool |  | add the response headers to -json rows (header, raw_header) |
| `-input-mode` | string |  | input mode: burp reads the URLs of a Burp XML export given with -l |
| `-ip` | bool |  | print the address connected to |
| `-irh` | bool |  | add the response headers to -json rows (header, raw_header) |
| `-irr` | bool |  | add the request and the response to -json rows (request, body, header, raw_header) |
| `-irrb` | bool |  | like -irr, base64-encoded |
| `-j` | bool |  | JSONL output (as -json) |
| `-jarm` | bool |  | report the JARM fingerprint of TLS servers (ten handshakes a server) |
| `-json` | bool |  | JSONL output, and the summary as one JSON object on stderr |
| `-kb` | bool |  | report the kind of page (login, captcha, …) in knowledgebase; needs the dit model (see TROUBLESHOOTING) |
| `-kill-file` | string |  | stop all sending, at once, when this file exists, and exit 4; azhaq resume works once it is removed (default DB.stop) |
| `-knowledge-base` | bool |  | report the kind of page (login, captcha, …) in knowledgebase; needs the dit model (see TROUBLESHOOTING) |
| `-l` | string |  | file of targets (- for stdin; a glob such as 'hosts-*.txt') |
| `-lc` | bool |  | print the line count |
| `-ldp` | bool |  | print URLs with their default port (:80, :443) |
| `-ldv` | bool |  | list the fields -json rows hold, and stop |
| `-leave-default-ports` | bool |  | print URLs with their default port (:80, :443) |
| `-ledger` | string |  | write every request and connection to a target to this file, a chain of hashes that azhaq ledger -verify checks (default DB.ledger.jsonl next to the workspace; off: none; with a temporary database, only when given) |
| `-line-count` | bool |  | print the line count |
| `-list-dsl-variables` | bool |  | list the fields -json rows hold, and stop |
| `-list-output-fields` | bool |  | list the fields -json rows hold, and stop |
| `-location` | bool |  | print the redirect location (and where a followed chain ended) |
| `-lof` | bool |  | list the fields -json rows hold, and stop |
| `-markdown` | bool |  | print a Markdown table |
| `-match-cdn` | string |  | keep rows behind these CDN providers |
| `-match-code` | string |  | keep rows with these status codes (200,302, spans 200-299, classes 4xx) |
| `-match-condition` | string |  | keep rows for which this condition holds, over the -json fields: 'contains(body, "admin") && status_code == 200' |
| `-match-favicon` | string |  | keep rows with these favicon hashes (implies the favicon request) |
| `-match-length` | string |  | keep rows with these content lengths |
| `-match-line-count` | string |  | keep rows with these line counts |
| `-match-regex` | string, repeatable |  | keep rows whose response matches every one of these regexes |
| `-match-response-time` | string |  | keep rows by response time: '< 1', '>= 500ms' |
| `-match-string` | string |  | keep rows whose response (headers and body) holds one of these strings, comma-separated, any case |
| `-match-word-count` | string |  | keep rows with these word counts |
| `-max-host-error` | int |  | as -maxhr |
| `-max-ips` | int | `4096` | addresses expanded from -asn and -cidr prefixes, for the whole run |
| `-max-redirects` | int | `10` | with -fr: redirects to follow |
| `-max-requests` | int |  | requests to targets this run may send (0: no cap); the work left over is for azhaq resume |
| `-maxhr` | int |  | connects or timeouts in a row after which a host is not asked again (default 5) |
| `-maxr` | int | `10` | with -fr: redirects to follow |
| `-mc` | string |  | keep rows with these status codes (200,302, spans 200-299, classes 4xx) |
| `-mcdn` | string |  | keep rows behind these CDN providers |
| `-md` | bool |  | print a Markdown table |
| `-mdc` | string |  | keep rows for which this condition holds, over the -json fields: 'contains(body, "admin") && status_code == 200' |
| `-method` | bool |  | print the request method |
| `-mfc` | string |  | keep rows with these favicon hashes (implies the favicon request) |
| `-ml` | string |  | keep rows with these content lengths |
| `-mlc` | string |  | keep rows with these line counts |
| `-mr` | string, repeatable |  | keep rows whose response matches every one of these regexes |
| `-mrt` | string |  | keep rows by response time: '< 1', '>= 500ms' |
| `-ms` | string |  | keep rows whose response (headers and body) holds one of these strings, comma-separated, any case |
| `-mwc` | string |  | keep rows with these word counts |
| `-nc` | bool |  | accepted, as httpx has it: azhaq prints no color |
| `-nf` | bool |  | ask an input without a scheme over both http and https and report each that answers |
| `-no-decode` | bool |  | hash and match the body as sent, not converted to UTF-8 |
| `-no-fallback` | bool |  | ask an input without a scheme over both http and https and report each that answers |
| `-no-follow` | bool |  | do not follow redirects: each URL is asked once and its redirect recorded with the Location (httpx's default) |
| `-no-stdin` | bool |  | do not read targets from stdin |
| `-no-tech` | bool |  | skip technology fingerprints (saves about 30 MB of memory) |
| `-o` | string |  | also write results to this file |
| `-oa` | string |  | write the results to FILE (text), FILE.json, FILE.csv and FILE.md |
| `-ob` | bool |  | with -sr: leave the body out of the stored file |
| `-omit-body` | bool |  | with -sr: leave the body out of the stored file |
| `-output-all` | string |  | write the results to FILE (text), FILE.json, FILE.csv and FILE.md |
| `-p` | string |  | ports to probe on each name: 80,443,8000-8100, each led by http: or https: to ask one scheme only (http:80,https:443) |
| `-pa` | bool |  | send the request to every address of a name, one row each |
| `-parallel` | int |  | work items in flight (default 16) |
| `-path` | string |  | path or paths to ask of every target in place of its own: a list, comma-separated, or a file |
| `-pipeline` | bool |  | report whether the server answers pipelined requests (ten requests each) |
| `-ports` | string |  | ports to probe on each name: 80,443,8000-8100, each led by http: or https: to ask one scheme only (http:80,https:443) |
| `-probe` | bool |  | print a row for every target: [SUCCESS], or [FAILED] when nothing answered |
| `-probe-all-ips` | bool |  | send the request to every address of a name, one row each |
| `-program` | string |  | the program to take from a -scope list (handle, name or URL) |
| `-proxy` | string |  | send every request through this proxy (http://, https:// or socks5://) |
| `-random-agent` | bool |  | send a browser's User-Agent picked at random for each request |
| `-rate` | float |  | requests per second to targets, over all hosts (0: no pace) |
| `-rate-limit` | float |  | same as -rl |
| `-req-timeout` | duration |  | time one request may take (default 10 s to the first byte, 30 s in all); -timeout bounds the whole run |
| `-request` | string |  | send the request in this file (request line, headers, blank line, body) to every target: it can change data on the target |
| `-resolvers` | string |  | DNS resolvers: a file with one per line, or a comma list; each is ADDR, ADDR:PORT or udp:, tcp:, dot:, doh:URL[:get] and then the address (default: public resolvers) |
| `-respect-hsts` | bool |  | with -fr: go to https when a redirect's answer sent Strict-Transport-Security |
| `-response-size-to-read` | int |  | most bytes read of a response (default 2 MiB of a page, 16 MiB of a script) |
| `-response-size-to-save` | int |  | with -sr: most bytes of a response stored (0: all that was read) |
| `-response-time` | bool |  | print the response time |
| `-retries` | int |  | times to send a request again when nothing answered (each counts as a request) |
| `-rhsts` | bool |  | with -fr: go to https when a redirect's answer sent Strict-Transport-Security |
| `-rl` | float |  | services asked per second, as httpx -rl: each target's first request waits its turn, its favicon, redirects and second scheme do not (-rate paces every request) |
| `-rlm` | float |  | services asked per minute (as -rl, per minute) |
| `-rr` | string |  | send the request in this file (request line, headers, blank line, body) to every target: it can change data on the target |
| `-rstr` | int |  | most bytes read of a response (default 2 MiB of a page, 16 MiB of a script) |
| `-rsts` | int |  | with -sr: most bytes of a response stored (0: all that was read) |
| `-rt` | bool |  | print the response time |
| `-sc` | bool |  | print the status code |
| `-scope` | string |  | a program's scope: a file (HackerOne CSV, bounty-targets JSON, Burp options, lines) or hackerone, bugcrowd, intigriti, yeswehack |
| `-screenshot` | bool |  | save a screenshot of each web service's front page under -srd/screenshot (Chrome on the machine); rows are printed when the run ends, with screenshot_path; implies -sr |
| `-server` | bool |  | print the Server header |
| `-silent` | bool |  | results only: no progress; the summary only when something failed (a source that failed, a takeover candidate as a [takeover] line on stderr); stdout stays one result per line |
| `-sni` | string |  | TLS server name to ask for, whatever the host |
| `-sni-name` | string |  | TLS server name to ask for, whatever the host |
| `-sr` | bool |  | store each response (request and response as sent) under -srd/response/HOST/SHA1.txt, with an index.txt |
| `-srd` | string |  | directory of -sr (default output) |
| `-ss` | bool |  | save a screenshot of each web service's front page under -srd/screenshot (Chrome on the machine); rows are printed when the run ends, with screenshot_path; implies -sr |
| `-status-code` | bool |  | print the status code |
| `-store-chain` | bool |  | like -sr, with the redirect chain in the file |
| `-store-response` | bool |  | store each response (request and response as sent) under -srd/response/HOST/SHA1.txt, with an index.txt |
| `-store-response-dir` | string |  | directory of -sr (default output) |
| `-strip` | string |  | strip tags from the body preview: html or xml (the preview always has its tags stripped, as httpx) |
| `-t` | int |  | work items in flight (default 16) |
| `-target` | string, repeatable |  | target (as -u) |
| `-td` | bool |  | print the technologies |
| `-tech-detect` | bool |  | print the technologies |
| `-timeout` | duration |  | stop after this long and keep what was found; azhaq resume continues (0: no limit) |
| `-title` | bool |  | print the page title |
| `-tls-grab` | bool |  | report the certificate and the TLS version of each answer |
| `-tls-probe` | bool |  | probe the names of each certificate too (implies -tls-grab) |
| `-u` | string, repeatable |  | target: URL, host, host:port, IP, address range or AS number (repeatable, or comma-separated) |
| `-v` | bool |  | print a line for every finished task, not only failures |
| `-vhost` | bool |  | report a virtual host (one more request each) |
| `-vhost-input` | bool |  | lines are vhost,ip: ask the ip with the vhost as Host |
| `-vi` | bool |  | lines are vhost,ip: ask the ip with the vhost as Host |
| `-wc` | bool |  | print the word count |
| `-web-ports` | string |  | ports to probe on each name: 80,443,8000-8100, each led by http: or https: to ask one scheme only (http:80,https:443) |
| `-web-server` | bool |  | print the Server header |
| `-websocket` | bool |  | print websocket for a server that speaks it |
| `-word-count` | bool |  | print the word count |
| `-wordpress` | bool |  | report WordPress plugins and themes |
| `-wp` | bool |  | report WordPress plugins and themes |
| `-x` | string |  | also send these methods to every target (GET, POST, HEAD, …; all for the common ones): requests that can change data on the target |
<!-- flags:end -->
