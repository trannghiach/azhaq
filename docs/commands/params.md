# azhaq params

Query parameters pages read, from a list (GET; -X POST, JSON or XML send bodies). Replaces arjun (see [Migrating](../MIGRATING.md#arjun-azhaq-params)).

## Synopsis

```
azhaq params -u URL | -l FILE | -i FILE | stdin  [-w small|medium|large|FILE] [-X GET|POST|JSON|XML] [-t N] [-c N] [-d SECONDS] [-stable] [-T SECONDS] [-include DATA] [-casing STYLE] [-passive] [-rate N] [-oJ FILE] [-oT FILE] [-oB HOST:PORT] [-json]
```

## Examples

```
azhaq params -u https://app.example.com/search
azhaq params -u https://app.example.com/search -w burp-parameter-names.txt -rate 5 -oJ params.json
azhaq params -i burp-export.xml -allow app.example.com -X POST    # bodies may change data
```

## Output

URL and parameter names per line; -json: {"url","method","params","why"} (why: status, size, headers, location, lines, reflected or named for each name; values: the value a name needed, for debug and the like). -oJ writes arjun's file, {"URL": {"params","method","headers"}}; -oT one request per line, URL?name=1234&…. A page that rate-limits (429, 418, 503) or leaves requests unanswered fails with exit 3 and a note; a page left alone says why.

`url`, `method` (`GET`, or `POST`, `JSON`, `XML` when names were sent in a body), `params`, and `why` (what changed in the answer for each name: `status`, `size`, `headers` (the set of header names), `location` (the redirect target), `lines`, `reflected` (its value came back more often than random names' values do) or `named` (the page printed the name)); `values` holds the value a name needed (`{"debug":"true"}`) when it only answered to that one; `writes` is the number of body requests sent. A page that answers names it does not read (most names of a group, or nearly every name tried alone, change its answer, and so do as many random names made like them) is listed in the summary's `notes`; the names of that group are dropped and the search stops there, names found in earlier groups stay. A page that rate-limits (429, 418, 503), or leaves requests unanswered, fails with exit 3 (`failed`, retryable) and a note; a page left alone (it changes by itself, is not text, is past `-params-per-host`) has a note too. With `-oJ FILE` the command writes arjun's file, `{"URL": {"params": [...], "method": "GET", "headers": {...}}}`; with `-oT FILE` one request per line, `URL?name=1234&other=5678` (a body method: the URL, a tab and the body).

## Summary and exit codes

The summary and the exit codes are the shared ones: see [OUTPUT.md](../OUTPUT.md#exit-codes).

## Flags

<!-- flags:begin params -->
| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-H` | string, repeatable |  | extra request header K: V |
| `-T` | float | `15` | seconds to wait for each request; one that times out is asked again with 5 s more, up to 20 s (arjun -T) |
| `-X` | string | `GET` | how names are sent: GET (query), POST (form body), JSON or XML. A body sends requests that may change data on the target, and needs -allow or -scope, or a single page |
| `-all-gets` | bool |  | also request found URLs that look like a GET would change something (logout, delete, reset, save…); by default they are listed, not requested |
| `-allow` | string, repeatable |  | a domain, host or address range the run may touch; with any -allow, nothing else is requested |
| `-c` | int |  | names per request at most (0: 500, and about 7.6 KB in a query; fewer where the server refuses a long query) |
| `-casing` | string |  | write the names in one style: snake (like_this), camel (likeThis) or lower (likethis) |
| `-cookie` | string, repeatable |  | Cookie name=value (repeatable; sent as one Cookie header) |
| `-d` | float |  | seconds to wait before each request, one at a time (arjun -d) |
| `-db` | string |  | keep the graph in this database for query, show, export and diff (default: a temporary one) |
| `-deny` | string, repeatable |  | a domain, host or address range the run must not touch, even when given as a target |
| `-i` | string |  | import pages: a file of URLs, a Burp Suite XML export (HTML, JSON and XML items) or a raw HTTP request (GET or POST) |
| `-include` | string |  | sent with every request: a query (a=1&b=2) for GET; for a body a form, a JSON object, or XML, or a template with $arjun$ where the names go |
| `-json` | bool |  | JSONL output, and the summary as one JSON object on stderr |
| `-kill-file` | string |  | stop all sending, at once, when this file exists, and exit 4; azhaq resume works once it is removed (default DB.stop) |
| `-l` | string |  | file of page URLs (- for stdin) |
| `-ledger` | string |  | write every request and connection to a target to this file, a chain of hashes that azhaq ledger -verify checks (default DB.ledger.jsonl next to the workspace; off: none; with a temporary database, only when given) |
| `-max-requests` | int |  | requests to targets this run may send (0: no cap); the work left over is for azhaq resume |
| `-o` | string |  | also write results to this file |
| `-oB` | string |  | send each page with the names found through this proxy, HOST:PORT (Burp), after the search |
| `-oJ` | string |  | write results to this file as JSON: {"URL": {"params": [...], "method": "GET", "headers": {...}}} |
| `-oT` | string |  | write results to this file as text, one request per line: URL?name=1234&other=5678 |
| `-passive` | bool |  | also try the query names the archives (Wayback Machine, Common Crawl, OTX) hold for the pages' domains |
| `-program` | string |  | the program to take from a -scope list (handle, name or URL) |
| `-proxy` | string |  | send requests to targets through this proxy (http://, https:// or socks5://); Chrome too (default: $HTTP_PROXY, $HTTPS_PROXY) |
| `-rate` | float |  | parameter requests per second per host (0: no limit, as arjun) |
| `-scope` | string |  | a program's scope: a file (HackerOne CSV, bounty-targets JSON, Burp options, lines) or hackerone, bugcrowd, intigriti, yeswehack |
| `-silent` | bool |  | results only: no progress; the summary only when something failed (a source that failed, a takeover candidate as a [takeover] line on stderr); stdout stays one result per line |
| `-stable` | bool |  | one request at a time, 3 to 9 s apart, and 30 s wait after a refused connection (arjun --stable) |
| `-t` | int | `5` | requests in flight per page (arjun -t) |
| `-timeout` | duration |  | stop after this long and keep what was found; azhaq resume continues (0: no limit) |
| `-u` | string, repeatable |  | page URL |
| `-urls-timeout` | duration | `3m0s` | time each archive source gets per domain (the Wayback Machine's answer for a large domain takes several minutes) |
| `-v` | bool |  | print a line for every finished task, not only failures |
| `-w` | string | `large` | parameter names: a file, one per line, or small (1,000 names), medium (3,000) or large (6,500, the default) |
<!-- flags:end -->
