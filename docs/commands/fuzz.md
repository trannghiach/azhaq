# azhaq fuzz

Puts words from wordlists into a request, anywhere in it: the path, a query value, a header (virtual hosts), the method, a JSON or form body. Filters, auto-calibration and recursion are ffuf's. Replaces ffuf (see [Migrating](../MIGRATING.md#ffuf-azhaq-fuzz-and-azhaq-dirs)).

## Synopsis

```
azhaq fuzz -u URL | -request FILE  -w FILE[:KEYWORD] [-w …] [-mode clusterbomb|pitchfork|sniper] [-X METHOD] [-d DATA] [-H 'Name: value'] [-mc/-ms/-mw/-ml/-mr/-mt] [-fc/-fs/-fw/-fl/-fr/-ft] [-ac] [-recursion] [-e .php,.bak] [-enc 'FUZZ:urlencode'] [-x PROXY] [-replay-proxy PROXY] [-t N] [-rate N] [-p SECONDS] [-o FILE -of json|ejson|csv|ecsv|html|md|all] [-od DIR] [-json] [-db FILE]
```

## Examples

```
# paths and extensions, two directory levels, auto-calibrated
azhaq fuzz -u https://app.example.com/FUZZ -w common.txt -e .php,.bak -recursion -recursion-depth 2 -ac

# a JSON login: two wordlists read in step, match answers that say "welcome"
azhaq fuzz -u https://app.example.com/login -X POST -H 'Content-Type: application/json' -d '{"user":"USER","password":"PASS"}' -w users.txt:USER -w pass.txt:PASS -mode pitchfork -mr 'welcome'

# virtual hosts of an address, hiding one answer size, matches kept in a workspace
azhaq fuzz -u https://10.0.0.5/ -H 'Host: FUZZ.example.com' -w subdomains.txt -fs 4242 -json -db vhosts.db

# a request saved from Burp, sent through Burp again, with a report file
azhaq fuzz -request login.req -request-proto https -w pass.txt:PASS -mc all -fc 401 -o report.json -x http://127.0.0.1:8080

# one wordlist in each marked place in turn
azhaq fuzz -u 'https://app.example.com/api/§v1§/users/§1§' -w ids.txt -mode sniper
```

## What it does

1. Takes the request from `-u` or from a raw request file (`-request FILE`), with a keyword in it. The keyword is `FUZZ`, or the one you give in `-w FILE:KEYWORD`.
2. Reads the wordlists and combines them by `-mode`.
3. Sends one request for each combination. The scope, the budget, the pace and the ledger apply to each.
4. Counts each answer as ffuf does and applies the matchers, filters and calibration.
5. Prints one line for each match. `-o FILE` also writes ffuf's report.

A word is asked whatever it says, `/logout` included. A request to a host outside the scope is not sent.

## Output

A match is one line: the input and `[Status, Size, Words, Lines, Duration]`. `-v` adds the URL, `-s` prints the inputs only, and several keywords print one block each. With `-input-cmd` the position is shown, not the command's output. With `-json` you get one object per match, with ffuf's fields. `-o FILE` writes a report: see [Reports](#reports).

| Field | Meaning |
| --- | --- |
| `input` | An object keyed by keyword, the values in base64 as ffuf prints them. `FFUFHASH` is ffuf's name for the request. |
| `position` | The number of the input in the run. |
| `status`, `length`, `words`, `lines` | The answer's status, size, words and lines, counted as ffuf counts them. |
| `content-type`, `redirectlocation`, `url` | The answer's content type, its redirect target and the URL asked. |
| `duration` | Nanoseconds to the first byte. |
| `scraper` | Always `{}`. |
| `resultfile` | The `-od` file of the match. |
| `host` | The host and port asked. |

One line looks like this:

```
{"input":{"FFUFHASH":"YzdjOGEz","FUZZ":"YWRtaW4="},"position":12,"status":200,"length":483,"words":51,"lines":7,"content-type":"text/plain","redirectlocation":"","url":"…","duration":7596361,"scraper":{},"resultfile":"","host":"127.0.0.1:3001"}
```

## Summary and exit codes

The summary and the exit codes are the shared ones: see [the summary](../OUTPUT.md#the-summary) and [exit codes](../OUTPUT.md#exit-codes). With `-json` the summary is one JSON line on stderr. These cases are specific to `fuzz`:

- Five unanswered requests in a row stop the run, because the target is down. The exit code is 3 and the origin is listed under "did not answer".
- With `-se` the run stops after twice `-t` failures of any kind in a row, as in ffuf. `-se-after N` names that number.
- `-sf`, `-sa` and `-maxtime-job` say what they did in the summary. The first two end with exit 4, the last adds a note.
- A report that cannot be written is a `failed` entry, not a silent loss. The exit code is 3. The place is tested before the first request.
- A note counts the preflight and postflight requests sent: they are in the request total. One that failed is a `failed` entry, `preflight/postflight failed: …`, and the exit code is 3.
- With calibration on, a note says what it filtered: `auto-calibration filtered out answers with size 1234`.
- The summary also counts the requests the scope held back and the copies `-replay-proxy` sent: see [Scope, budget and pace](#scope-budget-and-pace).

## Details

### Reports
`-o FILE -of FORMAT` writes ffuf's report files, in the order the inputs were asked. They are written when the run ends, also when it is stopped by `-maxtime`, the budget or Ctrl-C.

| `-of` | File |
| --- | --- |
| `json` (the default for any name but the suffixes below) | `{"commandline","time","results":[…],"config":{…}}` |
| `ejson` | the same without `config`, `input` values in base64 |
| `csv`, `ecsv` | a header of the keywords, then the columns below; `ecsv` has the input values in base64 |
| `html`, `md` | ffuf's page and table |
| `all` | one file of each of the six, named FILE.json, FILE.ejson, FILE.html, FILE.md, FILE.csv, FILE.ecsv |

- In `json`, `results` are the `-json` lines above, with `input` values as plain text.
- `config` holds ffuf's keys for the run: `url`, `method`, `headers`, `matchers` with the filters calibration added, `inputproviders`, …
- The columns of `csv` and `ecsv` are `url,redirectlocation,position,status_code,content_length,content_words,content_lines,content_type,duration,resultfile,Ffufhash`. `duration` is as Go prints it (`1.2ms`).
- A name ending `.csv`, `.ecsv`, `.html`, `.md` or `.ejson` takes that format without `-of`.
- A name ending `.txt` and no `-of` gets the text of stdout, as before.
- `-or` writes no file for a run with no matches, and the summary says so.
- `-od DIR` writes each match's request and answer as one file, named by the md5 of its text. It is shown as `| RES |` in the text output and as `resultfile` in the reports.
- `-db FILE` keeps the matches in a workspace as ffuf results are, for `query`, `show` and `export`.

### ffuf's flags, by job
`fuzz` takes ffuf's flags and counts as ffuf does. Words are spaces plus one, lines newlines plus one, with the same match and filter rules and the same calibration. A command line moved from ffuf gives the same results.

- **Input**
  - `-w FILE[:KEYWORD]` is repeatable. `-w a.txt,b.txt` takes two lists, and `-` reads stdin.
  - `-mode clusterbomb|pitchfork|sniper` combines the lists. `§…§` marks the places.
  - `-e` adds extensions, `-ic` ignores comments, and `-D` reads dirsearch lists, where `%EXT%` stands for each extension.
  - `-enc 'FUZZ:urlencode b64encode'` encodes a keyword. All of ffuf's encoders are available, run in process.
  - `-input-cmd`, `-input-num` and `-input-shell` take the words from a command.
  - `-request FILE` reads a raw request as Burp saves it, and `-request-proto` gives its protocol. `-u`, `-X`, `-d`, `-H` and `-b` replace parts of it.
- **Request**
  - `-u`, `-X`, `-d` (also `-data`, `-data-ascii`, `-data-binary`), `-H`, `-b` (also `-cookie`), `-r` and `-timeout`.
  - `-timeout` is seconds per request, as in ffuf.
  - `-x` sends every request through an http, https, socks5 or socks5h proxy.
  - `-replay-proxy` sends each match once more through a proxy such as Burp.
  - `-ignore-body`, `-raw`, `-sni`, `-http2`, `-cc` and `-ck`.
  - Servers back to TLS 1.0 are reached.
  - A body compressed with gzip, deflate or brotli is decoded. So `-fs` counts the decoded bytes, even when `-H 'Accept-Encoding: gzip, deflate, br'` is given.
- **Matchers and filters**
  - `-mc -ms -mw -ml -mr -mt` match, and `-fc -fs -fw -fl -fr -ft` filter.
  - `-mt '>1000'` and `-ft '<100'` compare the milliseconds to the first byte.
  - `-mmode` and `-fmode` combine them.
- **Calibration**: `-ac`, `-ack`, `-acs basic|advanced|NAME`, `-acc STRING` and `-ach`. See [Calibration](#calibration).
- **Recursion**: `-recursion`, `-recursion-depth`, `-recursion-strategy default|greedy` and `-maxtime-job`.
- **Pace and stops**: `-t`, `-rate`, `-p 0.1` or `-p 0.1-2.0`, `-maxtime`, `-sf`, `-sa` and `-se` with `-se-after N`.
- **Reports**: `-o FILE` with `-of json|ejson|csv|ecsv|html|md|all`, `-od DIR` and `-or`. `-json` prints ffuf's fields on stdout.
- **Settings**: `-config FILE`, else `~/.config/ffuf/ffufrc` or `~/.ffufrc`. They are ffuf's TOML settings, read as flags in front of the command line's own.

### Preflight and postflight
- `-preflight FILE` and `-postflight FILE` name raw request files, sent before and after each request.
- `-preflight-var 'TOKEN:name="csrf" value="([^"]+)"'` or `-preflight-var-auto 'TOKEN:csrf'` reads a value from the answer. `TOKEN` in the request stands for it.
- `-preflight-mode` and `-preflight-error` set when they run and what a failed one does.
- They carry your `-H` and `-b`. Each goes through the scope, the budget, the pace and the ledger.
- A value read from an answer can never change the scheme, host or port of a request. ffuf's `-preflight-anyhost` does not exist here.

### Steering a run
- `-control FILE` steers a run that goes, in place of ffuf's console. A line added to the file is a command: `echo 'rate 2' >> FILE`.
- The commands are `rate 2`, `pause`, `resume`, `fs 4242`, `afs 100`, `fs none`, `show`, `savejson out.json`, `queueshow`, `queuedel N`, `queueskip` and `stop`.
- With stderr on a terminal and no `-s`, `-silent` or `-json`, a status line is printed over itself each second.

### Calibration
- Calibration is off unless `-ac` is given. `-acs`, `-acc` and `-ach` imply it, as in ffuf, so the matches are ffuf's for the same flags.
- It needs the keyword `FUZZ`, or the one `-ack` names, in the request. Without it a note says nothing was calibrated.
- `-rate` paces its guesses like any request, and `-max-requests` counts them. ffuf's are unpaced and not counted.
- The default strategy asks 6 guesses: `admin…`, `.htaccess…` and a random name, each at two lengths. At `-rate 5` they take about a second.
- At `-rate 5` a sweep takes about (guesses ÷ 5) seconds longer than ffuf's, and stays within your rate.

### Matching and wordlists
- The default matcher is `-mc 200-299,301,302,307,401,403,405,500`, unless `-ms`, `-mw`, `-ml`, `-mr` or `-mt` is given alone, as in ffuf.
- An empty line of a wordlist is a word: `FUZZ` is replaced by nothing, so a wordlist that starts with a blank line asks the base URL (as in ffuf).
- With several wordlists, `-mode pitchfork` runs as long as the longest list. The shorter ones start over. 4 users and 3 passwords make 4 requests, as in ffuf 2.3.

### Stopping and resuming
- A run stopped by `-max-requests`, `-maxtime`, the kill file or Ctrl-C keeps in its `-db` the exact inputs it asked. `azhaq resume -db FILE` asks only the others, so no input goes out twice, and its summary counts only what it newly did. Workers answer out of order, so the inputs asked are not always the first N.
- The `-start N` in the summary's command is the first input not asked in a row. Run by hand, it may repeat inputs past it; `azhaq resume` does not.

### What goes out
- The request carries the headers ffuf sends: no `Accept`, `Accept-Encoding: gzip`, and yours from `-H`. So a size matches ffuf's for the same server.
- The `User-Agent` is a Chrome's unless `-H` gives one.
- A header that names a host, such as `Host`, is held to the scope too: see [Concepts](../CONCEPTS.md).

### Scope, budget and pace
- The host in `-u` is the scope unless `-allow`, `-deny` or `-scope` say otherwise. When the keyword starts the host, as in `FUZZ.example.com`, the scope is its domain.
- A request to a host outside the scope is not sent, and the summary counts it.
- Every request goes through the run's budget and pace (`-max-requests`, `-rate`) and the ledger, and stops at the kill file.
- `-x` and `-replay-proxy` need their scheme, as in `http://127.0.0.1:8080`. The environment's `HTTP_PROXY` is not read, because Go sends loopback traffic through a proxy only when it is named.
- The copies `-replay-proxy` sends go to the proxy you named. They are not requests to the target, so they are not in the ledger, the budget or the pace. The summary says how many were sent.

### Not in `fuzz`
- ffuf's scrapers: `-scraperfile` and `-scrapers`.
- `-search` and its history files. `-db` and `azhaq show` keep the matches.
- `-audit-log`. The hash-chained `-ledger` is the record of requests.

## Flags

<!-- flags:begin fuzz -->
| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-D` | bool |  | dirsearch wordlists: %EXT% in a line stands for each -e extension |
| `-H` | string, repeatable |  | header "Name: value"; the keyword may stand in name and value, Host included (repeatable). A header that names a host (Host, X-Forwarded-Host, X-Host, X-Original-Host) joins the target when no -allow, -deny or -scope is given; with one, the host must be in the scope |
| `-V` | bool |  | print the version |
| `-X` | string |  | HTTP method (default GET, POST with -d); the keyword may stand in it |
| `-ac` | bool |  | calibrate the filters on names that cannot exist, as ffuf does (off by default, as in ffuf; -acs, -acc and -ach turn it on too) |
| `-acc` | string, repeatable |  | a name to calibrate with instead of the random ones |
| `-ach` | bool |  | calibrate for each host and directory of the path (with a Host header or a keyword in the host) |
| `-ack` | string | `FUZZ` | the keyword calibration replaces |
| `-acs` | string, repeatable |  | calibration strategy: basic, advanced (adds the names as directories), or a file ~/.config/ffuf/autocalibration/NAME.json (repeatable or comma list) |
| `-allow` | string, repeatable |  | a domain, host or address range the run may touch (repeatable); default: the host of -u |
| `-b` | string, repeatable |  | cookie data "NAME=VALUE; NAME2=VALUE2" |
| `-c` | bool |  | colour the status of each result in the text output |
| `-cc` | string |  | client certificate file for TLS; -ck names its key |
| `-ck` | string |  | client key file for TLS |
| `-config` | string |  | read these settings from an ffuf configuration file (default: ~/.config/ffuf/ffufrc, else ~/.ffufrc); flags override it |
| `-control` | string |  | steer the run from this file: lines added to it are commands (rate N, pause, resume, stop, fc\|fs\|fw\|fl\|fr\|ft VALUE, afc… to add, none to remove, show, savejson FILE, queueshow, queuedel N, queueskip) |
| `-cookie` | string, repeatable |  | ffuf's alias of -b |
| `-d` | string |  | request body; the keyword may stand in it |
| `-data` | string |  | ffuf's alias of -d |
| `-data-ascii` | string |  | ffuf's alias of -d |
| `-data-binary` | string |  | ffuf's alias of -d |
| `-db` | string |  | keep the matches in this database for query, show, export and diff (none by default) |
| `-debug-log` | string |  | write each failed request and its error to this file |
| `-deny` | string, repeatable |  | a domain, host or address range the run must not touch |
| `-e` | string |  | extensions added to each FUZZ word, comma-separated: .php,.bak |
| `-enc` | string, repeatable |  | encoders for a keyword: 'FUZZ:urlencode b64encode' (repeatable); one of b64decode, b64encode, hexdecode, hexencode, jsonescape, jsonunescape, lower, md5, sha1, sha224, sha256, sha384, sha512, unicodedecode, unicodeencodeall, upper, urldecode, urlencode, urlencodeall, utf16, utf16be, xmlescape, xmlunescape or a .tmpl file with #PAYLOAD# |
| `-fc` | string |  | filter out these statuses |
| `-fl` | string |  | filter out these line counts |
| `-fmode` | string | `or` | filters: an answer is dropped by any (or) or by all (and) of them |
| `-fr` | string |  | filter out answers matching this regexp |
| `-fs` | string |  | filter out these response sizes |
| `-ft` | string |  | filter out answers by milliseconds to the first byte: >MS or <MS |
| `-fw` | string |  | filter out these word counts |
| `-http2` | bool |  | use HTTP/2 where the server offers it |
| `-ic` | bool |  | ignore comments in wordlists |
| `-ignore-body` | bool |  | do not read the answer's body: size is the Content-Length, words and lines 0 |
| `-input-cmd` | string, repeatable |  | a command whose output is the input, COMMAND[:KEYWORD], run for each number up to -input-num with FFUF_NUM set |
| `-input-num` | int | `100` | how many inputs an -input-cmd gives |
| `-input-shell` | string | `/bin/sh` | the shell that runs an -input-cmd |
| `-json` | bool |  | JSONL output, and the summary as one JSON object on stderr |
| `-kill-file` | string |  | stop all sending, at once, when this file exists, and exit 4; azhaq resume works once it is removed (default DB.stop) |
| `-ledger` | string |  | write every request and connection to a target to this file, a chain of hashes that azhaq ledger -verify checks (default DB.ledger.jsonl next to the workspace; off: none; with a temporary database, only when given) |
| `-max-requests` | int |  | requests this run may send (0: no cap) |
| `-maxtime` | seconds |  | stop after this many seconds and say so (0: no limit) |
| `-maxtime-job` | seconds |  | give up a job (the first one, or a directory found by -recursion) after this many seconds and go on with the next (0: no limit) |
| `-mc` | string |  | match these statuses, comma-separated values and ranges, or all (default 200-299,301,302,307,401,403,405,500, unless another matcher is given) |
| `-ml` | string |  | match these line counts (values and ranges) |
| `-mmode` | string | `or` | matchers: an answer must match any (or) or all (and) of them |
| `-mode` | string | `clusterbomb` | how several wordlists combine: clusterbomb (every combination), pitchfork (line by line) or sniper (one wordlist in each §marked§ place of the request in turn) |
| `-mr` | string |  | match answers (headers and body) with this regexp; the keyword stands for its input |
| `-ms` | string |  | match these response sizes (values and ranges) |
| `-mt` | string |  | match answers by milliseconds to the first byte: >MS or <MS |
| `-mw` | string |  | match these word counts (values and ranges) |
| `-noninteractive` | bool |  | accepted for ffuf's command lines: no effect (there is no console; see -control) |
| `-o` | string |  | write the report to this file, in the format -of says (json by default; a name ending .txt gets what stdout shows, as before) |
| `-od` | string |  | keep the request and answer of each match as a file in this directory (its name is shown with the match) |
| `-of` | string |  | the format of -o: json, ejson, html, md, csv, ecsv, all (all writes one file for each, with the suffixes) |
| `-or` | bool |  | write no -o file when there are no matches |
| `-p` | string |  | seconds each thread waits after a request: 0.1, or a random time in a range 0.1-2.0 |
| `-postflight` | value, repeatable |  | a raw request file sent after each fuzzing request that was answered |
| `-postflight-var` | string |  | like -preflight-var, for the -postflight before it |
| `-postflight-var-auto` | string |  | like -preflight-var-auto, for the -postflight before it |
| `-preflight` | string |  | a raw request file sent before each fuzzing request (repeatable, in order); it carries -H and -b of the command, and is held to the scope, budget and pace |
| `-preflight-error` | string | `abort` | abort: a failed flight fails the request; ignore: it is noted and the request goes on without the flight's values |
| `-preflight-mode` | string | `per-request` | per-request: the preflights run before each request; per-thread: once for each thread, its values kept |
| `-preflight-var` | value, repeatable |  | a value read from the answer of the -preflight before it: NAME:regexp (the first group; the body, then the headers); NAME in later requests stands for it |
| `-preflight-var-auto` | value, repeatable |  | a value read from that answer by name: NAME:key tries a form field, meta tag, cookie and header, NAME:[form\|meta\|cookie\|header]key names one |
| `-program` | string |  | the program to take from a -scope list |
| `-r` | bool |  | follow redirects |
| `-rate` | float |  | requests per second, over all (0: no pace) |
| `-raw` | bool |  | send the path and query as written, not encoded |
| `-recursion` | bool |  | descend into directories found (the URL must end with FUZZ) |
| `-recursion-depth` | int |  | levels of recursion (0: no limit) |
| `-recursion-strategy` | string | `default` | default: directories that redirect to themselves; greedy: every match |
| `-replay-proxy` | string |  | send each match once more through this proxy (Burp, for the history); the copy is the proxy's own, not counted by -max-requests or -rate and not in the ledger |
| `-request` | string |  | read the request from this file (a raw HTTP request, as Burp saves it); -u, -X, -d, -H and -b replace what it holds |
| `-request-proto` | string | `https` | the protocol for the URL a -request file's Host header gives |
| `-s` | bool |  | ffuf's name for -silent |
| `-sa` | bool |  | stop on all of these: -sf, over 20% of answers 429, and -se |
| `-scope` | string |  | a program's scope: a file or hackerone, bugcrowd, intigriti, yeswehack |
| `-se` | bool |  | stop on spurious errors: twice -t requests in a row failing (without it, five requests in a row that got no answer stop the run) |
| `-se-after` | int |  | stop after this many requests in a row failing, in place of -se's twice -t |
| `-seal-to` | string |  | when the run ends, append the ledger's seal as one JSON line ({"time","ledger","seal","entries"}) to this file, or POST it to this URL: kept where the run's own files are not, so azhaq ledger -verify -seal can tell the ledger from one with lines removed and the rest re-chained to look intact |
| `-sf` | bool |  | stop when more than 95% of the first 50 or more answers are 403 |
| `-silent` | bool |  | print the input values only, no progress; the summary only when something failed |
| `-sni` | string |  | the server name for TLS (the keyword does not work here) |
| `-start` | int |  | skip the first N inputs: where a stopped run left off (its summary gives the command) |
| `-t` | int | `40` | requests in flight |
| `-timeout` | seconds | `10` | each request's timeout, in seconds |
| `-u` | string |  | target URL; the keyword (FUZZ) may stand anywhere in it, in the host too |
| `-v` | bool |  | print the full URL and redirect location with each result |
| `-w` | string, repeatable |  | wordlist FILE[:KEYWORD] (- for stdin; repeatable; a comma list is several; the keyword is FUZZ without one) |
| `-x` | string |  | send every request through this proxy: an http, https, socks5 or socks5h URL |
<!-- flags:end -->
