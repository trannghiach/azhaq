# azhaq params

Finds the query parameters a page reads, by trying names from a list. Names go in the query by default; `-X POST`, `-X JSON` and `-X XML` send them in a body. Replaces arjun (see [Migrating](../MIGRATING.md#arjun-azhaq-params)).

## Synopsis

```
azhaq params -u URL | -l FILE | -i FILE | stdin  [-w small|medium|large|FILE] [-X GET|POST|JSON|XML] [-t N] [-c N] [-d SECONDS] [-stable] [-T SECONDS] [-include DATA] [-casing STYLE] [-passive] [-rate N] [-oJ FILE] [-oT FILE] [-oB HOST:PORT] [-json]
```

## Examples

```
# one page, the built-in list of names
azhaq params -u https://app.example.com/search

# your own wordlist, 5 requests a second, arjun's JSON file
azhaq params -u https://app.example.com/search -w burp-parameter-names.txt -rate 5 -oJ params.json

# pages from a Burp export, names sent in a body (bodies may change data)
azhaq params -i burp-export.xml -allow app.example.com -X POST
```

## What it does

1. Takes pages from `-u`, `-l`, `-i` or stdin.
2. Asks each page with random names first, to get a reference answer and the page's own noise.
3. Sends the names of the list in groups and compares each answer with that reference.
4. Narrows a group that changed the answer down to the names that did it, and prints them with `why`.
5. When the page refuses a request without its input (400 or 422), asks the names not found again with the names found so far in every request, against a new reference taken the same way, and repeats while a pass finds more (at most 3 passes). A page that reports its required fields one at a time says nothing about the second until the first is given. A page that answers without input is not asked again.

A body method sends requests that may change data on the target.

## Output

Plain output is the URL and the parameter names, one line per page. With `-json` you get one object per page.

| Field | Meaning |
| --- | --- |
| `url` | The page. |
| `method` | `GET`, or `POST`, `JSON` or `XML` when the names were sent in a body. |
| `params` | The names found. |
| `why` | What changed in the answer for each name. The values are below. |
| `values` | The value a name needed, such as `{"debug":"true"}`, when it answered only to that one. |
| `writes` | The number of body requests sent. |

What `why` says for a name:

| Value | The answer changed in |
| --- | --- |
| `status` | its status |
| `size` | its size |
| `headers` | the set of header names |
| `location` | the redirect target |
| `lines` | its line count |
| `body` | its body, on a page that gave the same body three times in a row |
| `reflected` | the name's value came back more often than random names' values do |
| `named` | the page printed the name |

A name found in step 5 has its reason followed by what was present, such as `status, once username was present`. Its requests are counted in `requests` like the others.

Two files can be written as well:

- `-oJ FILE` writes arjun's file: `{"URL": {"params": [...], "method": "GET", "headers": {...}}}`.
- `-oT FILE` writes one request per line: `URL?name=1234&other=5678`. For a body method the line is the URL, a tab and the body.

## Summary and exit codes

The summary and the exit codes are the shared ones: see [the summary](../OUTPUT.md#the-summary) and [exit codes](../OUTPUT.md#exit-codes). These cases are specific to `params`.

- A page that rate-limits (429, 418, 503) or leaves requests unanswered fails with exit 3. The failure is listed as `failed` and retryable, with a note.
- A page not searched has a note that says why: it changes by itself, is not text, is past `-params-per-host`, or a `-deny-path` rule matches its address.
- A page that answers names it does not read is listed in the summary's `notes`: see Details.

## Details

### Pages that answer names they do not read
- A page answers names it does not read when most names of a group, or nearly every name tried alone, change its answer. As many random names made like them change it too.
- The names of that group are dropped and the search stops there. Names found in earlier groups stay.
- The summary's `notes` list the page.

## Flags

<!-- flags:begin params -->
| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-H` | string, repeatable |  | extra request header K: V |
| `-T` | float | `15` | seconds to wait for each request; one that times out is asked again with 5 s more, up to 20 s (arjun -T) |
| `-X` | string | `GET` | how names are sent: GET (query), POST (form body), JSON or XML. A body sends requests that may change data on the target, and needs -allow or -scope, or a single page |
| `-allow` | string, repeatable |  | a domain, host or address range the run may touch; with any -allow, nothing else is requested |
| `-c` | int |  | names per request at most (0: 500, and about 7.6 KB in a query; fewer where the server refuses a long query) |
| `-casing` | string |  | write the names in one style: snake (like_this), camel (likeThis) or lower (likethis) |
| `-cookie` | string, repeatable |  | Cookie name=value (repeatable; sent as one Cookie header) |
| `-d` | float |  | seconds to wait before each request, one at a time (arjun -d) |
| `-db` | string |  | keep the graph in this database for query, show, export and diff (default: a temporary one) |
| `-deny` | string, repeatable |  | a domain, host or address range the run must not touch, even when given as a target |
| `-deny-path` | string, repeatable |  | a regular expression on a URL's path and query: a URL it matches is never requested, by any collector or Chrome, and is listed as not requested (repeatable; azhaq decides nothing by itself) |
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
