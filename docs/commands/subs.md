# azhaq subs

Subdomains from passive sources. Replaces subfinder (see [Migrating](../MIGRATING.md#subfinder-azhaq-subs)).

## Synopsis

```
azhaq subs -d DOMAIN | -dL FILE | stdin  [-live] [-json] [-silent] [-o FILE] [-db FILE] [-m GLOB | -f GLOB | -match-regex RE | -filter-regex RE] [-source-rate N] [-ls]
```

## Examples

```
azhaq subs -d example.com
azhaq subs -d example.com -live -json -db example.db
azhaq subs -d example.com,example.org -live -dns-rate 10 -source-rate 2 -m '*.dev.example.com'
azhaq subs -ls -json
```

## Output

One name per line, as subfinder prints it (-cs: host,[sources]; -live -oI: host,ip,source); -json: {"host","input","source","sources"} like subfinder, with "unverified":true on a name that only subdomain.center guessed or only the name history held, which was not looked up in DNS (without -live), and with -live dnsx's a, aaaa, cname. The domain given is not printed, as subfinder keeps only the names below it. The summary's counts add up: from sources, less the domain itself and did not resolve, plus CNAME targets and guesses found, is the names printed.

`host`, `input` (the domain), `source` (the first source that gave the name), `sources` (all of them; `dns-brute` or `permute` for a name found by `-w` or `-permute`; `history` for a name an earlier run kept, below; `cname` for a live name DNS met as another name's CNAME target); `unverified: true` on a name that only subdomain.center guessed or only the name history held (no source gave it this run) and that no DNS lookup checked (without `-live`; below); `wildcard_certificate: true` on a name a certificate gave as `*.name`; with `-live`, dnsx's `a` and `aaaa` (the addresses; a name that is only a CNAME has none), `cname` (the chain) and `cdn` (the CDN or WAF in front), and with `-oI` an `ip`. A name that is a takeover candidate has `takeover` (`service`, `target`, `evidence`, `strength`) on its row (with `-live`: the candidates are found by DNS), and every candidate is in the summary (`takeover`). With `-cs` the text form is `host,[source,source]`, with `-live -oI` `host,ip,source`; `-oD DIR` also writes `DIR/DOMAIN.txt` (`.json` with `-json`) for each domain.

## Summary and exit codes

The summary and the exit codes are the shared ones: see [OUTPUT.md](../OUTPUT.md#exit-codes).

## Details

**`subs`: sources, names kept, coverage.** `subs` counts the sources it asked, in the summary's `counts`:

| Count | Meaning |
| --- | --- |
| `sources asked` | Passive sources that ran for the domains given. Skipped ones, such as a keyed source with no key, are not counted, and neither is `history`. |
| `sources answered` | Those that returned without an error. |
| `sources failed` | Failures of sources in the default set, or named with `-sources`. |
| `off-by-default failed` | Failures of sources that ran only because of `-all-sources`. |

`sources asked` is `sources answered` plus `sources failed` plus `off-by-default failed`. The summary has `degraded` when `sources failed` is above 0. A source whose answer was an error with a 200 status (hackertarget's `API count exceeded`, a JSON `{"error": …}`, a challenge page) and that gave no names is a failed source, and its `error` holds the server's words: `api.hackertarget.com answered 200 with an error, not names: API count exceeded - Increase Quota with Membership`; one that gave names first keeps them and says so in `partial`. The per-source status in the workspace (`azhaq show`, the `sources` payload of an `azhaq-subdomains` observation) has, for each source, `count`, `seconds`, `calls`, `requests` (sent, retries included), `error`, `skipped` (why it did not run), `partial` (what it says about its own answer: Cert Spotter without a key reads the first page only), `rate_limited` with `retried_429`, `waited_seconds`, `retry_after_seconds` and `gave_up_429` (a source that answered 429 is asked again after its `Retry-After`, up to three times and 30 s each; one that asks for longer, or keeps refusing, is not waited for), `rounds` (for subdomain.center: per call, the names it gave, how many were new, how many were looked up, how many resolved and no other source had, and the seconds that took), and from `-live` runs `kept`, `dropped_unresolved`, `unverified`, `checked_seconds` (for the sources whose names are checked) and `"default": false` on a source that ran only because of `-all-sources`.

The counts also say what became of the names, so a reader can add them up:

| Count | Meaning |
| --- | --- |
| `from sources` | The names every source gave for the domains, with the name history and subdomain.center's guesses, before any check. |
| `the domain itself` | The domain given, when a source returned it: `subs` lists subdomains, as subfinder does, so it is not printed (`run`'s map has it as the target it is). |
| `did not resolve` | Names dropped because DNS says they do not exist: guesses and history names that did not resolve, and with `-live` every other name that did not. |
| `collected` | With `-live`: `from sources` less the domain itself and the guesses that did not resolve. |
| `resolved from sources` | With `-live`: the names from sources that resolved and were printed. |
| `CNAME only` | With `-live`: printed names that are a CNAME and have no address of their own (`dnsx -a -cname` lists those too, dangling or not). |
| `found as CNAME targets`, `found by guessing` | Live names no source gave: another name's CNAME target in scope, and the names of `-w` and `-permute`. |
| `unverified` | Printed names no DNS lookup checked (without `-live`) and that no source gave this run: names only subdomain.center guessed and names only the name history held. |
| `not checked` | With `-live`: names the resolvers failed on, left out (the run says so and `azhaq resume` checks them). |
| `left out by -m/-f` | Names a `-m`, `-f`, `-match-regex` or `-filter-regex` removed. |
| `listed under another domain` | A name under two of the domains given, printed once. |
| `cut by -max-names` | Names past `-max-names` (default 200,000), left out; the run ends with exit 3. |

`from sources` less `the domain itself`, `did not resolve`, `not checked`, `left out by -m/-f`, `listed under another domain` and `cut by -max-names`, plus `found as CNAME targets` and `found by guessing`, is the number of results. The run prints it as a note: `count: 2638 from the sources − 2096 did not resolve − 1 not checked + 10 found as CNAME targets = 551 printed`.

Azhaq keeps every name it kept for a domain in `names/DOMAIN.json` under `$AZHAQ_DATA_DIR`, else `$XDG_DATA_HOME/azhaq`, else `~/.local/share/azhaq`: the first and last time seen (`first_seen`, `last_seen`) and the sources that gave it (`sources`), at most 200,000 names per domain (the ones unseen the longest go first). The next run asks this file as a source called `history`: with `-live` a stored name counts only if it resolves now (not to a wildcard), so stale names drop out and a name a source missed this time comes back; without `-live` no DNS lookup is made, and a stored name that no source gave this run is listed with `"unverified": true` (its `source` is `history`). A stored name a source gave again is not flagged: its `source` is that source, and `history` comes last in `sources`. Every name a run kept is stored, so flagging them all would flag nearly every name after the first run. `-no-history` neither reads nor writes the file. A file that cannot be written is a note, `name history not saved: …`.

`subs` ends with a note such as

```
coverage: the independent sources hold about 1609 names; this run has 1400 of them (87%) — an estimate of what the sources know, not of every name that exists; the other 47 of the 1447 names came from the name history, from guesses checked in DNS or as CNAME targets, which the estimate leaves out
```

It is a Chao1 estimate over how many independent sources gave each name: S + f1²/(2·f2), with f1 names given by one source and f2 by two (with f2 = 0: S + f1(f1−1)/2). Independent means every source except the ones that pad their answer (subdomain.center) and `history`; a name only those gave is in the output but not in the count. It needs two independent sources that gave names, and counts the names printed (with `-live`, the live ones). It estimates what the sources know, not every name that exists. The `azhaq-subdomains` payload has `"coverage": {"observed", "estimated", "share"}`; the row of a sampled source (subdomain.center) in `sources` has `"population_estimate"`, a Schnabel estimate of how many names one call draws from, when its rounds repeated names.

## Flags

<!-- flags:begin subs -->
| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-all-sources` | bool |  | also run slower subdomain sources outside the default set |
| `-cs` | bool |  | text output: host,[source,source] (subfinder -cs) |
| `-d` | string, repeatable |  | domain (repeatable; a comma list, a URL or a name with a trailing dot is cleaned, as subfinder does) |
| `-dL` | string |  | file of domains (- for stdin) |
| `-db` | string |  | keep the graph in this database for query, show, export and diff (default: a temporary one) |
| `-dns-rate` | float |  | DNS queries per second per resolver (0: no pace but the queries in flight, as dnsx) |
| `-ei` | bool |  | accepted for subfinder's sake: an IP address given as a domain is always left out with a note |
| `-exclude-sources` | string |  | subdomain sources never to run, comma-separated |
| `-f` | string, repeatable |  | leave out names matching these (comma list or file), as subfinder -f |
| `-fail-on-errors` | bool |  | exit 3 on every failure: also fan-out (a source for the domain of a URL) and a source that failed while others answered |
| `-filter-regex` | string, repeatable |  | leave out names matching this regular expression |
| `-json` | bool |  | JSONL output, and the summary as one JSON object on stderr |
| `-live` | bool |  | only names that resolve (wildcard answers left out); without it nothing is looked up, and the names only subdomain.center guessed or only the name history held are listed unverified |
| `-ls` | bool |  | list the sources and exit: name, then * if a key is required and ~ if one improves the answer; with -json one object each (name, default, recursive, keyRequirement) |
| `-m` | string, repeatable |  | only names matching these (comma list or file; * matches anything), as subfinder -m |
| `-match-regex` | string, repeatable |  | only names matching this regular expression |
| `-max-body` | int |  | largest response body read from a subdomain source, in bytes (default 33554432), as subfinder -rsr |
| `-max-names` | int |  | most names kept per domain, and looked up with -live (default 200000) |
| `-max-results` | int |  | most names one paging subdomain source gives (0: no cap), as subfinder -mr |
| `-max-time` | duration |  | wait this long for all subdomain sources of a domain, then go on with what they gave (0: -source-timeout and a short grace bound the wait), as subfinder -max-time |
| `-nW` | bool |  | same as -live (subfinder's name) |
| `-no-history` | bool |  | do not read or write the name history (names earlier runs found, kept under $AZHAQ_DATA_DIR, else ~/.local/share/azhaq; with -live each is checked by DNS in the run) |
| `-o` | string |  | also write results to this file |
| `-oD` | string |  | write one file per domain into this directory (NAME.txt, NAME.json with -json), as well as stdout |
| `-oI` | bool |  | text output: host,ip,source, with -live (subfinder -oI); -json rows get an ip field |
| `-oJ` | bool |  | same as -json (subfinder's name) |
| `-permute` | bool |  | also resolve variations of the names found (api → api-dev, api2, dev.api), like alterx \| dnsx (active DNS) |
| `-providers` | string |  | API keys per source, YAML (default ~/.config/azhaq/providers.yaml, else subfinder's provider-config.yaml) |
| `-proxy` | string |  | send every subdomain source request through this proxy URL, as subfinder -proxy (else HTTP_PROXY and HTTPS_PROXY) |
| `-recursive` | bool |  | only sources that look for subdomains of subdomains, as subfinder -recursive (see -ls) |
| `-resolvers` | string |  | DNS resolvers: a file with one per line, or a comma list; each is ADDR, ADDR:PORT or udp:, tcp:, dot:, doh:URL[:get] and then the address (default: public resolvers) |
| `-silent` | bool |  | results only: no progress; the summary only when something failed (a source that failed, a takeover candidate as a [takeover] line on stderr); stdout stays one result per line |
| `-source-rate` | float |  | requests per second to each subdomain source, as subfinder -rl (0: each source's own pace); a source's lower own pace stays |
| `-source-rates` | string |  | pace single subdomain sources, as subfinder -rls: name=N/unit, comma-separated, unit s, m or h (hackertarget=10/m,crtsh=1/s) |
| `-source-timeout` | duration | `30s` | give each subdomain source this long, 30s as subfinder does; a slower one (crt.sh) is abandoned, listed as failed, and the names the others gave are kept; -source-timeout 60s or more waits for crt.sh on a large domain (not -timeout, the run's bound) |
| `-sources` | string |  | subdomain sources to run, comma-separated (default: the default set; none: no source, for a DNS-only run) |
| `-stats` | bool |  | after the run, one note per source: requests, names, errors and seconds, as subfinder -stats |
| `-t` | int |  | work items in flight (default 16) |
| `-timeout` | duration |  | stop after this long and keep what was found; azhaq resume continues (0: no limit) |
| `-v` | bool |  | print a line for every finished task, not only failures |
| `-version` | bool |  | print the version and exit |
| `-w` | string |  | also resolve WORD.domain for each word in this file, like puredns bruteforce (active DNS; the names found are live) |
<!-- flags:end -->
