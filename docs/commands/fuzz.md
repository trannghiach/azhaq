# azhaq fuzz

Wordlists put into a request, anywhere in it: paths, query values, headers (virtual hosts), JSON or form bodies; filters, auto-calibration and recursion as ffuf has them. Replaces ffuf (see [Migrating](../MIGRATING.md#ffuf-azhaq-fuzz-and-azhaq-dirs)).

## Synopsis

```
azhaq fuzz -u URL | -request FILE  -w FILE[:KEYWORD] [-w …] [-mode clusterbomb|pitchfork|sniper] [-X METHOD] [-d DATA] [-H 'Name: value'] [-mc/-ms/-mw/-ml/-mr/-mt] [-fc/-fs/-fw/-fl/-fr/-ft] [-ac] [-recursion] [-e .php,.bak] [-enc 'FUZZ:urlencode'] [-x PROXY] [-replay-proxy PROXY] [-t N] [-rate N] [-p SECONDS] [-o FILE -of json|ejson|csv|ecsv|html|md|all] [-od DIR] [-json] [-db FILE]
```

## Examples

```
azhaq fuzz -u https://app.example.com/FUZZ -w common.txt -e .php,.bak -recursion -recursion-depth 2 -ac
azhaq fuzz -u https://app.example.com/login -X POST -H 'Content-Type: application/json' -d '{"user":"USER","password":"PASS"}' -w users.txt:USER -w pass.txt:PASS -mode pitchfork -mr 'welcome'
azhaq fuzz -u https://10.0.0.5/ -H 'Host: FUZZ.example.com' -w subdomains.txt -fs 4242 -json -db vhosts.db
azhaq fuzz -request login.req -request-proto https -w pass.txt:PASS -mc all -fc 401 -o report.json -x http://127.0.0.1:8080
azhaq fuzz -u 'https://app.example.com/api/§v1§/users/§1§' -w ids.txt -mode sniper
```

## Output

Ffuf's: one line per match, the input and [Status, Size, Words, Lines, Duration] (-v adds the URL; several keywords print one block each; -s the inputs only); -json: ffuf's fields {"input","position","status","length","words","lines","content-type","redirectlocation","url","duration","host"}, input values base64. -o writes ffuf's report (json by default, -of for the other formats; a name ending .txt gets stdout's text). Auto-calibration is off unless -ac (or -acs, -acc, -ach) is given, as in ffuf. The host of -u is the scope unless -allow, -deny or -scope say otherwise.

ffuf's: `input` (an object keyed by keyword, the values in base64 as ffuf prints them, and `FFUFHASH`, ffuf's name for the request), `position`, `status`, `length`, `words`, `lines`, `content-type`, `redirectlocation`, `url`, `duration` (nanoseconds to the first byte), `scraper` (always `{}`), `resultfile` (the `-od` file), `host`: `{"input":{"FFUFHASH":"YzdjOGEz","FUZZ":"YWRtaW4="},"position":12,"status":200,"length":483,"words":51,"lines":7,"content-type":"text/plain","redirectlocation":"","url":"…","duration":7596361,"scraper":{},"resultfile":"","host":"127.0.0.1:3001"}`. The request carries the headers ffuf sends (no `Accept`, `Accept-Encoding: gzip`, yours from `-H`; with no `-allow`, `-deny` or `-scope`, a host you name in a header joins the targets you named; with a rule, a header naming a host outside it is refused before anything is sent), so a size matches ffuf's for the same server; the `User-Agent` is a Chrome's unless `-H` gives one. A word is asked whatever it says, `/logout` included. Calibration is off unless `-ac` is given (`-acs`, `-acc` and `-ach` imply it), as in ffuf, so the matches are ffuf's for the same flags; with it the summary notes what it filtered (`auto-calibration filtered out answers with size 1234`), and `-rate` paces its guesses like any request (ffuf's are unpaced: at `-rate 5` a sweep takes about (guesses ÷ 5) seconds longer, and stays within your rate). The summary is one JSON line on stderr. Text: one line per match, the input and `[Status, Size, Words, Lines, Duration]`; `-v` adds the URL, `-s` prints the inputs only; with `-input-cmd` the position is shown, not the command's output. `-o FILE` writes the report, see below.

## Summary and exit codes

The summary and the exit codes are the shared ones: see [OUTPUT.md](../OUTPUT.md#exit-codes).

## Details

### Reports

`fuzz -o FILE -of FORMAT` writes ffuf's report files, in the order the inputs were asked, when the run ends (also when it is stopped, by `-maxtime`, the budget or Ctrl-C). A report that cannot be written is a `failed` entry in the summary (exit 3), not a silent loss; the place is tested before the first request.

| `-of` | File |
| --- | --- |
| `json` (the default for any name but the suffixes below) | `{"commandline","time","results":[…],"config":{…}}`: results as the `-json` line above, with `input` values as plain text; `config` holds ffuf's keys for the run (`url`, `method`, `headers`, `matchers` with the filters calibration added, `inputproviders`, …) |
| `ejson` | the same without `config`, `input` values in base64 |
| `csv`, `ecsv` | a header of the keywords, then `url,redirectlocation,position,status_code,content_length,content_words,content_lines,content_type,duration,resultfile,Ffufhash`; `ecsv` has the input values in base64; `duration` as Go prints it (`1.2ms`) |
| `html`, `md` | ffuf's page and table |
| `all` | one file of each of the six, named FILE.json, FILE.ejson, FILE.html, FILE.md, FILE.csv, FILE.ecsv |

A name ending `.csv`, `.ecsv`, `.html`, `.md` or `.ejson` takes that format without `-of`; a name ending `.txt` and no `-of` gets the text of stdout. `-or` writes no file for a run with no matches (the summary says so). `-od DIR` writes each match's request and answer as one file named by the md5 of its text, shown as `| RES |` in the text output and `resultfile` in the reports.

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
