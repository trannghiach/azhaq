# azhaq dirs

Sweeps a wordlist of paths and reports those that answer unlike a path that cannot exist. SecLists' `common.txt` is built in. A URL with a path is swept from that path. Replaces `ffuf -ac` (see [Migrating](../MIGRATING.md#ffuf-azhaq-fuzz-and-azhaq-dirs)).

## Synopsis

```
azhaq dirs -u URL | -l FILE | stdin  [-w WORDLIST] [-e EXT] [-depth N] [-mc/-ms/-mw/-ml/-mr LIST] [-fc/-fs/-fw/-fl/-fr LIST] [-rate N] [-json]
```

## Examples

```
# sweep a site with the built-in wordlist
azhaq dirs -u https://app.example.com/

# sweep below /api/, try two extensions, hide one size, send 20 requests a second
azhaq dirs -u https://app.example.com/api/ -w common.txt -e php,bak -fs 4242 -rate 20

# several services from a file, as JSON
azhaq dirs -l services.txt -json
```

## What it does

1. Takes each service from `-u`, `-l` or stdin. A URL with a path is swept from that path.
2. Asks every word of the wordlist, with each `-e` extension if you give any. An empty line is a word too: it asks the base URL itself, as in ffuf, and is counted like the rest.
3. Calibrates on paths that cannot exist, as ffuf's `-ac` does, unless you give a filter (`-fc`, `-fs`, `-fw`, `-fl` or `-fr`). Then the filters are yours: no guess is sent, and every answer they do not remove and a matcher keeps is listed, catch-all answers included. The summary says so in a note.
4. Applies the matchers and filters to the answers and prints the paths that pass.

Nothing else is sent: no front page is asked first, so with a filter given a sweep of N words is N requests, and `-max-requests N` is enough. The calibration guesses (or, with a filter, the first two words) double as the check that the service answers: if none of them gets an answer, the sweep stops there, the service is listed under `unreachable`, and the exit is 3.

The request is ffuf's, so a ffuf command line carries over: [Details](#details) lists what it sends.

## Output

Plain output is one URL per line with its status, size, words and lines. With `-json` you get one object per URL. The sizes, words and lines are counted as ffuf counts them, so a `-fs` or `-fl` value carries over. `-mc` defaults to ffuf's `200-299,301,302,307,401,403,405,500`.

| Field | Meaning |
| --- | --- |
| `url` | The URL that answered. |
| `status` | The HTTP status. |
| `length` | The size of the whole body, as ffuf counts it, up to 64 MB. |
| `words` | The number of spaces in the whole body, plus one. |
| `lines` | The number of newlines in the whole body, plus one. |
| `redirectlocation` | Where a redirect points. |

## Summary and exit codes

The summary and the exit codes are the shared ones: see [the summary](../OUTPUT.md#the-summary) and [exit codes](../OUTPUT.md#exit-codes). Two cases end with exit 3.

- **Cut-off answers.** An answer cut off before its body ended, by a server going down or a dropped connection, is asked once more. It is never counted as a hit. The summary says how many paths still got no whole answer: `12 paths got no whole answer, after one retry: they were not judged`.
- **429 answers.** A sweep whose guesses were answered 429 says so the same way: `6 of 6 guesses were answered 429 …`. A 429 is outside the default `-mc`, so those paths were not judged.

`fuzz` asks a cut-off answer once more too, then counts it as an error.

## Details

### What a match is
- `length` is the whole body, as ffuf counts it, up to 64 MB.
- `words` is the number of spaces plus one, and `lines` the number of newlines plus one. Both count the whole body.
- The matchers `-ms -mw -ml -mr` and the filters `-fc -fs -fw -fl -fr` read these numbers.
- With `-mr` they read the response headers and the first MB of the body.

### The request
- The request is ffuf's, with no `Accept` header. An app that picks its answer by that header, such as Express's redirect body, answers with the same size as to ffuf.
- It sends `Accept-Encoding: gzip` and decodes the answer before counting.
- A `-H` of yours wins over these headers.
- The `User-Agent` is a current Chrome's, not `Fuzz Faster U Fool`. Sizes do not change with it unless the app answers by it. `-H 'User-Agent: …'` sends another.

### Which words are asked
- A sweep asks every word, `/logout` and `/delete` included, as ffuf does.
- No word is held back, with a session or without one: what a GET does on the server cannot be known from its name. A word whose URL a `-deny-path` rule matches is not sent and is listed under `skipped` with the rule.
- With a session, the run checks it as it goes. A word that ended the session is noticed: a `-login` run signs in again, a `-cookie` or `-H` run stops with a failure and exit 3. The words sent since the last good check are counted in the note, not repeated: [Sessions](../CONCEPTS.md#sessions).
- `-u https://h/api/` asks `https://h/api/WORD`. A query or fragment on the URL is dropped, and a note says so.

### Pace
- `-rate` paces every request, the calibration guesses included; ffuf sends its calibration unpaced. With a filter given there are no guesses. Calibration asks 4 guesses for each directory, and one more for each extension. At a low rate a sweep takes about (guesses ÷ rate) seconds longer than ffuf's, and stays within your rate.

## Flags

<!-- flags:begin dirs -->
**Targets and input**

| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-u` | string, repeatable |  | web service, such as https://app.example.com/ |
| `-l` | string |  | file of services (- for stdin) |
| `-scope` | string |  | a program's scope: a file (HackerOne CSV, bounty-targets JSON, Burp options, lines) or hackerone, bugcrowd, intigriti, yeswehack |
| `-program` | string |  | the program to take from a -scope list (handle, name or URL) |

**What to ask**

| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-w` | string |  | wordlist (default: SecLists' common.txt, built in: 4750 words) |
| `-e` | string |  | also try each word with these extensions, comma-separated (php,bak) |
| `-depth` | int | `1` | directory levels to sweep; 2 also sweeps directories found |

**Matchers and filters**

| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-mc` | string |  | report only these statuses (comma-separated, ranges, or all; default ffuf's: 200-299,301,302,307,401,403,405,500) |
| `-fc` | string |  | hide these statuses |
| `-fs` | string |  | hide these response sizes |

**Scope and safety**

| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-allow` | string, repeatable |  | a domain, host or address range the run may touch; with any -allow, nothing else is requested |
| `-deny` | string, repeatable |  | a domain, host or address range the run must not touch, even when given as a target |
| `-deny-path` | string, repeatable |  | a regular expression on a URL's path and query: a URL it matches is never requested, by any collector or Chrome, and is listed as not requested (repeatable; azhaq decides nothing by itself) |
| `-kill-file` | string |  | stop all sending, at once, when this file exists, and exit 4; azhaq resume works once it is removed (default DB.stop) |
| `-ledger` | string |  | write every request, connection and DNS query the run sends (to targets, third-party sources and resolvers) to this file, a chain of hashes that azhaq ledger -verify checks (default DB.ledger.jsonl next to the workspace; off: none; with a temporary database, only when given) |

**Pace and limits**

| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-rate` | float |  | path guesses per second per host (0: no limit but -t, as ffuf) |
| `-t` | int | `40` | path guesses in flight per service (as ffuf) |
| `-max-requests` | int |  | requests to targets this run may send (0: no cap); the work left over is for azhaq resume |
| `-timeout` | duration |  | stop after this long and keep what was found; azhaq resume continues (0: no limit) |

**Session and network**

| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-H` | string, repeatable |  | extra request header K: V |
| `-cookie` | string, repeatable |  | Cookie name=value (repeatable; sent as one Cookie header) |

**Output**

| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-db` | string |  | keep the graph in this database for query, show, export and diff (default: a temporary one) |
| `-json` | bool |  | JSONL output, and the summary as one JSON object on stderr |
| `-o` | string |  | also write results to this file |
| `-silent` | bool |  | results only: no progress; the summary only when something failed (a source that failed, a takeover candidate as a [takeover] line on stderr); stdout stays one result per line |
| `-v` | bool |  | print a line for every finished task, not only failures |

<details>
<summary>Flags familiar from ffuf (7)</summary>

| Flag | Type | Default | Meaning | Kind |
| --- | --- | --- | --- | --- |
| `-fl` | string |  | hide these line counts | ffuf's name |
| `-fr` | string |  | hide answers whose headers or body match this regular expression | ffuf's name |
| `-fw` | string |  | hide these word counts | ffuf's name |
| `-ml` | string |  | report only these line counts | ffuf's name |
| `-mr` | string |  | report only answers whose headers or body match this regular expression | ffuf's name |
| `-ms` | string |  | report only these response sizes (values and ranges, 100-200) | ffuf's name |
| `-mw` | string |  | report only these word counts | ffuf's name |

</details>
<!-- flags:end -->
