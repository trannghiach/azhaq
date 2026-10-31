# azhaq dirs

Paths from a wordlist (SecLists' common.txt built in) that answer unlike a path that cannot exist; a URL with a path is swept from that path. Replaces ffuf -ac (see [Migrating](../MIGRATING.md#ffuf-azhaq-fuzz-and-azhaq-dirs)).

## Synopsis

```
azhaq dirs -u URL | -l FILE | stdin  [-w WORDLIST] [-e EXT] [-depth N] [-mc/-ms/-mw/-ml/-mr LIST] [-fc/-fs/-fw/-fl/-fr LIST] [-rate N] [-json]
```

## Examples

```
azhaq dirs -u https://app.example.com/
azhaq dirs -u https://app.example.com/api/ -w common.txt -e php,bak -fs 4242 -rate 20
```

## Output

One URL per line with status, size, words and lines; -json: {"url","status","length","words","lines","redirectlocation"}. Sizes, words and lines are counted as ffuf counts them, so a -fs or -fl value carries over. The calibration is on (it is ffuf's -ac); -mc defaults to ffuf's 200-299,301,302,307,401,403,405,500.

## Summary and exit codes

The summary and the exit codes are the shared ones: see [OUTPUT.md](../OUTPUT.md#exit-codes).

## Flags

<!-- flags:begin dirs -->
| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-H` | string, repeatable |  | extra request header K: V |
| `-all-gets` | bool |  | also request found URLs that look like a GET would change something (logout, delete, reset, save…); by default they are listed, not requested |
| `-allow` | string, repeatable |  | a domain, host or address range the run may touch; with any -allow, nothing else is requested |
| `-cookie` | string, repeatable |  | Cookie name=value (repeatable; sent as one Cookie header) |
| `-db` | string |  | keep the graph in this database for query, show, export and diff (default: a temporary one) |
| `-deny` | string, repeatable |  | a domain, host or address range the run must not touch, even when given as a target |
| `-depth` | int | `1` | directory levels to sweep; 2 also sweeps directories found |
| `-e` | string |  | also try each word with these extensions, comma-separated (php,bak) |
| `-fc` | string |  | hide these statuses |
| `-fl` | string |  | hide these line counts |
| `-fr` | string |  | hide answers whose headers or body match this regular expression |
| `-fs` | string |  | hide these response sizes |
| `-fw` | string |  | hide these word counts |
| `-json` | bool |  | JSONL output, and the summary as one JSON object on stderr |
| `-kill-file` | string |  | stop all sending, at once, when this file exists, and exit 4; azhaq resume works once it is removed (default DB.stop) |
| `-l` | string |  | file of services (- for stdin) |
| `-ledger` | string |  | write every request and connection to a target to this file, a chain of hashes that azhaq ledger -verify checks (default DB.ledger.jsonl next to the workspace; off: none; with a temporary database, only when given) |
| `-max-requests` | int |  | requests to targets this run may send (0: no cap); the work left over is for azhaq resume |
| `-mc` | string |  | report only these statuses (comma-separated, ranges, or all; default ffuf's: 200-299,301,302,307,401,403,405,500) |
| `-ml` | string |  | report only these line counts |
| `-mr` | string |  | report only answers whose headers or body match this regular expression |
| `-ms` | string |  | report only these response sizes (values and ranges, 100-200) |
| `-mw` | string |  | report only these word counts |
| `-o` | string |  | also write results to this file |
| `-program` | string |  | the program to take from a -scope list (handle, name or URL) |
| `-rate` | float |  | path guesses per second per host (0: no limit but -t, as ffuf) |
| `-scope` | string |  | a program's scope: a file (HackerOne CSV, bounty-targets JSON, Burp options, lines) or hackerone, bugcrowd, intigriti, yeswehack |
| `-silent` | bool |  | results only: no progress; the summary only when something failed (a source that failed, a takeover candidate as a [takeover] line on stderr); stdout stays one result per line |
| `-t` | int | `40` | path guesses in flight per service (as ffuf) |
| `-timeout` | duration |  | stop after this long and keep what was found; azhaq resume continues (0: no limit) |
| `-u` | string, repeatable |  | web service, such as https://app.example.com/ |
| `-v` | bool |  | print a line for every finished task, not only failures |
| `-w` | string |  | wordlist (default: SecLists' common.txt, built in: 4750 words) |
<!-- flags:end -->
