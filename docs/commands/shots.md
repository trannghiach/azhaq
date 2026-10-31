# azhaq shots

A screenshot of each web service, look-alikes grouped (needs Chrome). Replaces gowitness (see [Migrating](../MIGRATING.md#gowitness-azhaq-shots)).

## Synopsis

```
azhaq shots -u TARGET | -l FILE | -nmap FILE | -nessus FILE | stdin  [-p PORTS] [-dir DIR] [-shot-size WxH] [-shot-fullpage] [-shot-format jpeg] [-rate N] [-json]
```

## Examples

```
azhaq shots -l services.txt -dir shots
azhaq shots -u http://127.0.0.1:3001/rest/products/search   # a path and query are kept
azhaq shots -u 192.0.2.0/28 -p small -rate 5   # a range, ports 80 and 443
azhaq shots -nmap scan.xml -shot-format jpeg -shot-fullpage
```

## Output

URL and picture file per line; -json: one object per page with {"url","file","title","final_url","phash","response_code","headers","tls","technologies","console","network"}, and {"partial":true} when the page was not fully loaded (exit 3), or drew without assets of hosts outside the scope ("blocked", "blocked_hosts": a note, and the exit code does not change, the scope is yours); text: partial (3 off-scope assets blocked: cdn.example.com)

## Summary and exit codes

The summary and the exit codes are the shared ones: see [OUTPUT.md](../OUTPUT.md#exit-codes).

## Flags

<!-- flags:begin shots -->
| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-H` | string, repeatable |  | extra request header K: V |
| `-allow` | string, repeatable |  | a domain, host or address range the run may touch; with any -allow, nothing else is requested |
| `-browser-writes` | bool |  | let pages in Chrome send their writes (POST, PUT, DELETE…, beacons, forms posted on load) as a user's browser would: they change data on the target; by default Chrome sends only GET, HEAD and OPTIONS outside signing in, and maps the writes it does not send |
| `-chrome` | string |  | the Chrome or Chromium to run (default $AZHAQ_CHROME, else the first found) |
| `-chrome-profile` | string |  | a Chrome user data directory to use and keep: sessions it holds go with the pages (default: a temporary one) |
| `-chrome-proxy` | string |  | send Chrome's own connections through this http or socks5 proxy (default: -proxy, else the environment's); a plain http:// request reaches an http proxy as a proxy request, a page over TLS as a CONNECT tunnel |
| `-cidr` | string, repeatable |  | seed an address range such as 192.0.2.0/24 |
| `-cookie` | string, repeatable |  | Cookie name=value (repeatable; sent as one Cookie header) |
| `-csv` | string |  | also write one row per page to this CSV file (url, final_url, response_code, title, technologies, file, phash, partial) |
| `-db` | string |  | keep the graph in this database for query, show, export and diff (default: a temporary one) |
| `-deny` | string, repeatable |  | a domain, host or address range the run must not touch, even when given as a target |
| `-dir` | string | `screenshots` | directory for the picture files |
| `-hostnames` | bool |  | with -nmap or -nessus: the host's name instead of its address, when the file has one |
| `-json` | bool |  | JSONL output, and the summary as one JSON object on stderr |
| `-kill-file` | string |  | stop all sending, at once, when this file exists, and exit 4; azhaq resume works once it is removed (default DB.stop) |
| `-l` | string |  | file of targets (- for stdin) |
| `-ledger` | string |  | write every request and connection to a target to this file, a chain of hashes that azhaq ledger -verify checks (default DB.ledger.jsonl next to the workspace; off: none; with a temporary database, only when given) |
| `-max-ips` | int | `4096` | addresses expanded from -asn and -cidr prefixes, for the whole run |
| `-max-requests` | int |  | requests to targets this run may send (0: no cap); the work left over is for azhaq resume |
| `-nessus` | string, repeatable |  | a Nessus file (.nessus): the web services it found |
| `-nmap` | string, repeatable |  | an nmap XML file (-oX): the web services it found |
| `-no-http` | bool |  | try names and addresses over https only |
| `-no-https` | bool |  | try names and addresses over http only |
| `-no-tech` | bool |  | skip technology fingerprints (saves about 30 MB of memory) |
| `-o` | string |  | also write results to this file |
| `-open-only` | bool | `true` | with -nmap: only ports found open |
| `-p` | string |  | web ports to try on each host, comma-separated: numbers, ranges, small (80, 443), medium or large (default: 443, then 80) |
| `-program` | string |  | the program to take from a -scope list (handle, name or URL) |
| `-proxy` | string |  | send requests to targets through this proxy (http://, https:// or socks5://); Chrome too (default: $HTTP_PROXY, $HTTPS_PROXY) |
| `-random` | bool |  | take the targets in random order |
| `-rate` | float |  | requests per second to targets, over all hosts (0: no pace) |
| `-scope` | string |  | a program's scope: a file (HackerOne CSV, bounty-targets JSON, Burp options, lines) or hackerone, bugcrowd, intigriti, yeswehack |
| `-service` | string |  | with -nmap or -nessus: the service names to take, comma-separated, or all (default: http ones; www, http and https for Nessus) |
| `-shot-codes` | string |  | take only pages that answer with these statuses, comma-separated (default: any); the others are listed as skipped |
| `-shot-format` | string | `png` | screenshot format: png or jpeg |
| `-shot-fullpage` | bool |  | screenshot the whole page, not only the first screen (up to 16384 pixels tall) |
| `-shot-html` | bool |  | keep each page's rendered HTML beside its screenshot |
| `-shot-js` | string |  | a file of JavaScript to run on each page before its screenshot (it runs on the target's page) |
| `-shot-quality` | int | `80` | jpeg quality, 1 to 100 |
| `-shot-size` | string | `1440x900` | screenshot size in pixels, WIDTHxHEIGHT |
| `-shot-timeout` | duration | `30s` | time a page gets: with -rate, how long it may go without a request let go or an answer, not in all |
| `-shot-wait` | duration | `1.5s` | wait after a page's load event for scripts that draw after it, before the screenshot (0: none) |
| `-silent` | bool |  | results only: no progress; the summary only when something failed (a source that failed, a takeover candidate as a [takeover] line on stderr); stdout stays one result per line |
| `-tabs` | int | `6` | Chrome tabs open at once for screenshots and -browser (gowitness -t) |
| `-timeout` | duration |  | stop after this long and keep what was found; azhaq resume continues (0: no limit) |
| `-u` | string, repeatable |  | target: URL (its path and query are kept), host, host:port, IP or address range such as 192.0.2.0/24 |
| `-unsafe-ports` | bool | `true` | let Chrome open the ports it refuses by default (6000, 6666, 10080 and others); -unsafe-ports=false keeps its refusal |
| `-v` | bool |  | print a line for every finished task, not only failures |
<!-- flags:end -->
