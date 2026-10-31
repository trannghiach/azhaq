# azhaq shots

A screenshot of each web service, look-alikes grouped (needs Chrome). Replaces gowitness (see [Migrating](../MIGRATING.md#gowitness-azhaq-shots)).

## Synopsis

```
azhaq shots -u TARGET | -l FILE | -nmap FILE | -nessus FILE | stdin  [-p PORTS] [-dir DIR] [-shot-size WxH] [-shot-fullpage] [-shot-format jpeg] [-rate N] [-json]
```

## Examples

```
# A list of services into a directory
azhaq shots -l services.txt -dir shots

# One page: its path and query are kept
azhaq shots -u http://127.0.0.1:3001/rest/products/search

# A range, ports 80 and 443, 5 requests a second
azhaq shots -u 192.0.2.0/28 -p small -rate 5

# The services of an nmap scan, as full-page JPEGs
azhaq shots -nmap scan.xml -shot-format jpeg -shot-fullpage
```

## What it does

`shots` (and `run -screenshots`) takes a picture of each web service with a Chrome on the machine.

1. Takes the services from `-u`, `-l`, `-nmap`, `-nessus` or stdin. A URL with a path or query keeps them.
2. Starts one Chrome and opens up to 6 tabs in it at once, as gowitness runs 6 threads. `-tabs N` changes that.
3. Loads each page and saves a picture of it. Chrome is held to the scope.
4. Records what Chrome saw: response headers, TLS session, the technologies of the rendered page, console messages and the network log.
5. Marks a page `partial` when it was not fully loaded, and the run exits 3.
6. Groups look-alike pages by a perceptual hash in `export -format html`, one file with the pictures embedded.

What shapes it:

- Which services: `-u 192.0.2.0/28`, `-p small|medium|large|8000-8010,3000`, `-no-http`, `-no-https`, `-nmap FILE` (an `nmap -oX` file) and `-nessus FILE`.
- How they are shot: `-shot-size`, `-shot-fullpage`, `-shot-wait`, `-shot-timeout`, `-shot-format jpeg`, `-shot-quality`, `-shot-js`, `-shot-codes`, `-chrome`, `-chrome-proxy`, `-chrome-profile` and `-H`.

## Output

Plain: one line per page, with its URL and picture file. `-json`: one object per page. `-csv FILE` writes the scalar columns.

| Field | Meaning |
| --- | --- |
| `url`, `final_url` | The URL asked, and where it ended. |
| `file` | The picture: `.png` or `.jpg`. |
| `file_name`, `file_path` | The picture's name, and its absolute path. |
| `format` | `png` or `jpeg`. |
| `title` | The page's title. |
| `bytes` | The picture's size in bytes. |
| `probed_at` | When the page was probed. |
| `phash`, `perception_hash` | A perceptual hash of the picture. See [Details](#perceptual-hash). |
| `response_code`, `response_reason`, `protocol` | What Chrome saw. |
| `content_length` | The document's bytes on the wire. |
| `headers` | `[{"key","value"}]`. |
| `tls` | `protocol`, `key_exchange`, `cipher`, `subject_name`, `san_list`, `issuer`, `valid_from`, `valid_to`, `server_signature_algorithm`, `encrypted_client_hello`. |
| `technologies` | `[{"value"}]`, fingerprinted on the rendered page and its headers. |
| `console` | `[{"type","value"}]`: `console.*` calls and uncaught errors, up to 200. |
| `network` | Every request the page made, up to 2000. `network_more` counts the rest. See [Details](#network-log). |
| `html_file` | The rendered HTML, with `-shot-html`. |
| `partial`, `unloaded`, `resources`, `note` | Set when the page was not fully loaded. See [Partial pages](#partial-pages). |
| `partial`, `blocked`, `blocked_hosts`, `note` | Set when the picture was drawn without assets of hosts outside the scope. See [Partial pages](#partial-pages). |

All of it is read from events Chrome already sends. It costs no request.

## Summary and exit codes

The summary and the exit codes are the shared ones: see [the summary](../OUTPUT.md#the-summary) and [exit codes](../OUTPUT.md#exit-codes). Two cases are specific to `shots`:

- A page whose own in-scope assets did not load is `partial`, and the run exits 3.
- A page that is partial only because assets of hosts outside the scope were blocked is marked and noted. The run still exits 0, because the scope is yours.

## Details

### Perceptual hash

- `phash` is also `perception_hash`: `p:` and 16 hex digits of a DCT perceptual hash.
- Pages 10 bits or fewer apart look alike.

### Network log

- `network` entries have `request_type`, `method`, `status_code`, `url`, `remote_ip`, `mime_type`, `time_ms`, `bytes` and `error`.
- Past 2000, `network_more` counts the rest.

### Partial pages

A page that was not fully loaded when the picture was taken has these fields, and the run exits 3:

- `partial`.
- `unloaded`: its images, styles, scripts, fonts and media that did not load, or failed.
- `resources`: how many it asked for.
- `note`.

### Pages that need hosts outside the scope

- Chrome is held to the scope. What a page loads from a host outside it, such as a CDN's styles, fonts and scripts, is never asked for. The picture is drawn without it.
- The page then has `partial`, `blocked` (how many of its requests were refused), `blocked_hosts` and a `note` that says how to allow them.
- To allow them, use `-allow cdn.jsdelivr.net`. When no scope was named, add `-allow` for the page's own host too, since any `-allow` replaces the default scope.
- This does not change the exit code: see [Summary and exit codes](#summary-and-exit-codes).
- The text line of such a row ends `partial (3 off-scope assets blocked: cdn.jsdelivr.net)`. The gallery tags it the same way, with `partial_why` in its API.
- The refused URLs are also in the summary's skipped list, once each.
- Nothing outside the scope is loaded by default.

### Chrome, ports and file names
- `AZHAQ_CHROME` names the browser. In a container where Chrome cannot start its sandbox, `AZHAQ_CHROME_NO_SANDBOX=1` runs it without one. Do that only where you accept that the pages it loads are untrusted.
- Chrome refuses some ports, such as 6000, 6666 and 10080, with `net::ERR_UNSAFE_PORT`. `-unsafe-ports` allows them by default.
- A URL you give is shot as given, one file for each page, named like `http_host_port_path_hash.png`; with a scheme it is one target and one row (where Chrome ended is in `final_url`), and only a bare name or `host:port` is tried on both schemes. The URLs a run finds itself are shot only when they are front pages.
- A page that calls `alert()` on load has its dialog accepted and is shot. Nothing waits for a click.

### Pace

At a set `-rate`, a page's time runs from when it last moved. A slow pace gives whole pictures, not blank ones.

### Screenshots and the budget

- A page's images, scripts and styles each count against `-max-requests`.
- When too few are left, Chrome is refused them and no image is saved. `shots` and `run -screenshots` say it:

```
note: screenshot of http://127.0.0.1:3001/ not taken: the page needs about 26 requests and 8 were left (raise -max-requests)
```

- The figure is how many requests the page made when it was cut short.
- When the budget was spent before the page loaded, the note says so: `screenshot of http://127.0.0.1:3001/ not taken: the budget was spent before the page loaded (raise -max-requests)`.

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
