# azhaq urls

Lists the URLs that web archives hold for a domain: the Wayback Machine, Common Crawl, OTX, urlscan.io and Arquivo. Replaces gau (see [Migrating](../MIGRATING.md#gau-azhaq-urls)).

## Synopsis

```
azhaq urls -d DOMAIN | -dL FILE | DOMAIN… | stdin  [-subs] [-providers wayback,otx,…] [-mc/-fc/-mt/-ft LIST] [-from/-to YYYYMM] [-blacklist EXT,…] [-fp] [-raw] [-proxy URL] [-retries N] [-urls-threads N] [-o FILE] [-json]
```

## Examples

```
# every URL the archives hold for a domain
azhaq urls -d example.com

# with subdomains, from two archives, without static files, one URL per host and path
azhaq urls example.com -subs -providers wayback,commoncrawl -blacklist png,jpg,css,js -fp | httpx

# only 200 answers of type text/html captured since 2024, with no pause between requests
azhaq urls -d example.com -mc 200 -mt text/html -from 2024 -urls-pause 0
```

## What it does

1. Takes domains from `-d`, `-dL`, arguments or stdin.
2. Asks each archive for the URLs of the domain. `-providers` chooses the archives, and `-subs` adds the subdomains. Without `-subs`, `www.DOMAIN` counts as the domain itself, as the Wayback Machine's index files it.
3. Reads pages from each archive, and asks again when an archive answers 429 or 503.
4. Applies your filters, and prints each URL once unless you give `-raw`.

## Output

By default URLs are printed as each archive page arrives, unsorted, when stdout is not a terminal. On a terminal, or with `-sort`, they are sorted and printed at the end. `-raw` prints every row the archives gave, as they gave it. `-o` appends to the file. With `-json` you get one object per URL.

| Field | Meaning |
| --- | --- |
| `url` | The archived URL. |
| `source` | The archive that gave it first: `wayback`, `commoncrawl`, `otx`, `urlscan` or `arquivo`. |

The summary lists one row for each archive:

| Field | Meaning |
| --- | --- |
| `count` | URLs the archive gave. |
| `pages` | Pages read from it. |
| `seconds` | Time spent on it. |
| `requests` | Requests sent, retries included. |
| `retried`, `waited_seconds` | Requests asked again after a 429 or 503, and the seconds waited: see Details. |
| `error` | Why the archive failed, in words: see Details. |
| `capped` | Set when the archive stopped at `-urls-pages` with more to read. |
| `unfiltered`, `unfiltered_by` | What the archive keeps none of, and the filter that could not apply: see Details. |

## Summary and exit codes

The summary and the exit codes are the shared ones: see [the summary](../OUTPUT.md#the-summary) and [exit codes](../OUTPUT.md#exit-codes). These points are specific to `urls`.

- The summary has a `sources` block with a row for each archive. It reads as the one of `subs` ([The sources block](subs.md#the-sources-block)), with `urls` where `subs` has `names`.
- The summary's top-level `requests` is what reached the targets, as in every command. `urls` sends none, so it is 0. The archives are third parties: their requests, retries included, are `requests` in each archive row and in the `sources` block, and a note adds them up.
- It has `junk`, the URLs left out and why: see [Junk](#junk).

## Details

### Retries
- A 429 or 503 is asked again after its `Retry-After`, or after 2, 5, 10, 20, then 30 s.
- It is asked again for as long as the archive's `-urls-timeout` and the run's `-timeout` allow.
- The summary row counts them in `retried` and `waited_seconds`.

### Errors
- `error` says why the archive failed. It reads like these:
  - `failed after 4 tries, 429 Too Many Requests`
  - `failed after 4 tries, dial tcp …: connection refused`
  - `…, Retry-After 2m0s; the 2m0s to wait is more than the 45s left (-urls-timeout or -timeout)`

### Junk
`urls` counts the URLs on the domains that it left out as junk, by reason. Each URL is counted once.

- `"scanner payload"`: for example 3.
- `"scanner probe"`: a scanner's own file or tag, a NUL byte (`%00`) in the path or query, or a query that is only punctuation or a dot and an extension (`?.`, `?.tst`, `?.bak`).
- `"directory listing sort link"`.
- `"script placeholder (NaN, undefined, null)"`.
- `"dot segment"`.
- `"malformed link (wildcard, quote, bracket, ellipsis)"`: the ellipsis is `…` or a `...` that ends the path or is a segment of its own.
- `"link cut at the end of its sentence"`: a path or query that ends in `.`, `,`, `;`, `'` or an unmatched `)` or `]`.

Every source's URLs go through these rules, OTX's too.

`counts` has the total as `dropped as junk`, and a note says it: `7 URLs dropped as junk (…; -raw keeps them)`. `-raw` prints them and drops none.

### Filters an archive cannot apply
- `unfiltered` lists what an archive keeps none of: `status`, `type` or `date`.
- When you give a filter it cannot apply, `unfiltered_by` names the filter, such as `-mc` or `-ft`.
- The archive is asked all the same and its URLs are kept, as gau keeps them, with no status on the row.
- The notes say the same in words: `otx has no status of its captures: its 13 URLs are not filtered by -mc`.

## Flags

<!-- flags:begin urls -->
| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-archive` | string, repeatable |  | ask NAME's archive at this address instead of its own, as NAME=URL (a mirror or a test server; repeatable) |
| `-blacklist` | string |  | leave out URLs whose path ends in these extensions, comma-separated (png,jpg,svg) |
| `-config` | string |  | a gau config file (default: ~/.gau.toml when it exists): threads, retries, subdomains, parameters, providers, blacklist, proxy, [urlscan] apikey and host, otx, and the [filters] table; flags win |
| `-d` | string, repeatable |  | domain (repeatable; domains may also be given as arguments, as gau takes them) |
| `-dL` | string |  | file of domains (- for stdin) |
| `-db` | string |  | keep the graph in this database for query, show, export and diff (default: a temporary one) |
| `-fail-on-capped` | bool |  | exit 4 when an archive stopped at its page cap with more to read |
| `-fail-on-errors` | bool |  | exit 3 on every failure: also fan-out (a source for the domain of a URL) and a source that failed while others answered |
| `-fc` | string |  | leave out URLs the archive recorded with these HTTP status codes, comma-separated; the archives that keep no status (OTX, urlscan.io) are asked all the same and their URLs kept, with a note |
| `-fp` | bool |  | keep one URL for each host and path, dropping the variants that differ by parameters |
| `-from` | string |  | only captures from this time on: YYYY, YYYYMM, YYYYMMDD or YYYYMMDDhhmmss; OTX, which dates no capture, is asked all the same and its URLs kept, with a note |
| `-ft` | string |  | leave out URLs the archive recorded with these MIME types, comma-separated; the archives that keep no type (OTX, urlscan.io) are asked all the same and their URLs kept, with a note |
| `-json` | bool |  | JSONL output, and the summary as one JSON object on stderr |
| `-mc` | string |  | keep only URLs the archive recorded with these HTTP status codes, comma-separated (200,301); the archives that keep no status (OTX, urlscan.io) are asked all the same and their URLs kept, as gau keeps them, with a note |
| `-mt` | string |  | keep only URLs the archive recorded with these MIME types, comma-separated (text/html); the archives that keep no type (OTX, urlscan.io) are asked all the same and their URLs kept, with a note |
| `-o` | string |  | also write results to this file, appending to it as gau does |
| `-provider-config` | string |  | API keys per source, YAML (default ~/.config/azhaq/providers.yaml, else subfinder's provider-config.yaml) |
| `-providers` | string |  | the archives to ask, comma-separated: wayback, commoncrawl, otx, urlscan, arquivo (default: all five). A value that names a file, or has a / in it, is the API-key file, as -providers meant before; -provider-config says that without doubt |
| `-proxy` | string |  | send the archive requests through this proxy: http://HOST:PORT, https:// or socks5:// |
| `-raw` | bool |  | print the archived URLs exactly as the archives gave them: no normalising, junk filter or deduplication |
| `-retries` | int |  | times an archive request is asked again after a 429, 503 or network error, after its Retry-After (seconds or a date, however long) or 2, 5, 10, 20, then 30 s; 0 makes the first refusal final (default: a 429 or 503 is asked again until the archive's time, -urls-timeout, or the run's is spent, a network error 3 times; a wait longer than the time left ends the request at once, with the reason) |
| `-silent` | bool |  | results only: no progress; the summary only when something failed (a source that failed, a takeover candidate as a [takeover] line on stderr); stdout stays one result per line |
| `-sort` | bool |  | print once every archive has answered, sorted (the default on a terminal) |
| `-stream` | bool |  | print each URL as it arrives, unsorted (the default when stdout is not a terminal) |
| `-subs` | bool |  | also the subdomains of each domain: the archives are asked for *.DOMAIN (default: the name given, as gau does without --subs; azhaq run keeps the broader default) |
| `-threads` | int |  | same as -urls-threads |
| `-timeout` | duration |  | stop after this long and keep what was found; azhaq resume continues (0: no limit) |
| `-to` | string |  | only captures up to this time, in the same form |
| `-urls-max` | int | `500000` | URLs kept for each domain (0: no cap); the summary counts the ones past it |
| `-urls-pages` | int | `50` | pages read from each archive for a domain (0: no cap); an archive that stops at the cap says so in the summary |
| `-urls-pause` | duration |  | pause between the requests of one archive (default: 1 s for the Wayback Machine and Common Crawl, 0.5 s for OTX, 2 s for urlscan.io; 0 for none) |
| `-urls-threads` | int |  | domains asked at once (default 16) |
| `-urls-timeout` | duration | `3m0s` | time each archive source gets per domain (the Wayback Machine's answer for a large domain takes several minutes) |
| `-v` | bool |  | print a line for every finished task, not only failures |
| `-version` | bool |  | print the version |
<!-- flags:end -->
