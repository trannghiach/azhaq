# azhaq subs

Lists the subdomains of a domain from passive sources. Replaces subfinder (see [Migrating](../MIGRATING.md#subfinder-azhaq-subs)).

## Synopsis

```
azhaq subs -d DOMAIN | -dL FILE | stdin  [-live] [-json] [-silent] [-o FILE] [-db FILE] [-m GLOB | -f GLOB | -match-regex RE | -filter-regex RE] [-source-rate N] [-ls]
```

## Examples

```
# every subdomain the passive sources know
azhaq subs -d example.com

# only names that resolve, as JSON, kept in a workspace
azhaq subs -d example.com -live -json -db example.db

# two domains, live names under dev only, DNS at 10 queries a second, sources at 2 a second
azhaq subs -d example.com,example.org -live -dns-rate 10 -source-rate 2 -m '*.dev.example.com'

# list the sources and the key each wants, as JSON
azhaq subs -ls -json
```

## What it does

1. Takes domains from `-d`, `-dL` or stdin. `-d` takes a comma list, a URL, or a name with a trailing dot or `*.`. An IP address given as a domain is left out, with a note.
2. Asks each passive source for names below the domain. The name history of earlier runs is read as one more source.
3. With `-live`, looks the names up in DNS and keeps those that resolve, with wildcard answers left out. Without `-live` nothing is looked up.
4. With `-w WORDS` or `-permute`, also resolves guesses. That is active DNS, and the names found are live.
5. Prints each name once, then the summary with its counts and a coverage estimate.

## Output

Plain output is one name per line, as subfinder prints it. The domain you give is not printed, because subfinder keeps only the names below it. `-o` appends to a file. With `-json` you get one object per name, with subfinder's fields and azhaq's. The summary's counts add up to the names printed: see [What became of the names](#what-became-of-the-names).

| Flag | Each line is |
| --- | --- |
| `-cs` | `host,[source,source]` |
| `-live -oI` | `host,ip,source` |
| `-oD DIR` | also writes `DIR/DOMAIN.txt` for each domain, `.json` with `-json` |

| Field | Meaning |
| --- | --- |
| `host` | The name. |
| `input` | The domain you gave. |
| `source` | The first source that gave the name. |
| `sources` | Every source that gave it, with the special values below. |
| `unverified` | `true` on a name no DNS lookup checked, without `-live`: one only subdomain.center guessed, or one only the name history held. |
| `wildcard_certificate` | `true` on a name a certificate gave as `*.name`. |
| `a`, `aaaa` | With `-live`, the addresses, also those the name's CNAME chain ends in. |
| `cname` | With `-live`, the chain. |
| `cdn` | With `-live`, the CDN or WAF in front. |
| `ip` | With `-live -oI`. |
| `takeover` | `service`, `target`, `evidence` and `strength`, on a live name that is a takeover candidate (a page that names an unclaimed service). A CNAME to what is gone is no live name and has no row: see below. |

`sources` holds the names of the sources, and these values:

- `dns-brute` or `permute` for a name found by `-w` or `-permute`.
- `history` for a name an earlier run kept: see [Name history](#name-history).
- `cname` for a live name DNS met as another name's CNAME target.

Every takeover candidate is also in the summary, under `takeover`, with `host`, `service`, `target`, `evidence` and `strength`. With `-live`, a name whose CNAME chain ends without an address (a CNAME to a deleted service or domain) is not live: it is not printed and is not in `results`. It is counted as `CNAME without an address`, and the summary's `takeover` list and the `[takeover] …` line on stderr carry it. A CNAME whose target resolves, such as a CDN's name, is live.

## Summary and exit codes

The summary and the exit codes are the shared ones: see [the summary](../OUTPUT.md#the-summary) and [exit codes](../OUTPUT.md#exit-codes). These points are specific to `subs`. The counts themselves are in [Details](#details).

- The summary has `degraded` when `sources failed` is above 0.
- Names past `-max-names` are left out, and the run ends with exit 3.
- With `-live`, names the resolvers failed on are left out as `not checked`. The run says so, and `azhaq resume` checks them.
- A source that answered 200 with an error and gave no names is a failed source: see [Failed sources](#failed-sources).
- `subs` ends with a `coverage:` note: see [Coverage estimate](#coverage-estimate).

## Details

### Sources in the summary
`counts` says how many sources were asked:

| Count | Meaning |
| --- | --- |
| `sources asked` | Passive sources that ran for the domains given. Not counted: skipped sources, such as a keyed one with no key, and `history`. |
| `sources answered` | Sources that returned without an error. |
| `sources failed` | Failures of sources in the default set, or named with `-sources`. |
| `off-by-default failed` | Failures of sources that ran only because of `-all-sources`. |

`sources asked` is `sources answered` plus `sources failed` plus `off-by-default failed`.

### The sources block
- `asked`, `answered`, `failed` and `off_by_default_failed` count each source once for each domain, as `counts` does.
- `failed` counts sources in the default set, or named with `-sources`. `off_by_default_failed` counts sources that ran only because of `-all-sources`.
- `asked` is `answered` plus `failed` plus `off_by_default_failed`. A source skipped for want of a key is not asked.
- `names` is what each source gave, before any DNS check or filter. For `urls` the field is `urls`: see [urls](urls.md#summary-and-exit-codes).
- `requests` is what each source was sent, retries included, summed over the domains. The summary's top-level `requests` leaves them out: they go to third parties, not to targets.
- `seconds` is how long each source took, the longest over the domains. The slowest source set the run's time. crt.sh is asked in its public PostgreSQL first, as subfinder does, and in its JSON API only when the database fails or has no names; a note says which happened, as in `crt.sh database: connection refused; asked the JSON API`. The database query is limited to 10000 rows, as subfinder's is; when exactly 10000 come back the rest is asked without the limit, then from the JSON API, and the note says which path gave the names. A note names it when it held the run: `crtsh took 30 s, the next slowest source 3 s, so it held the run`.
- `failed_sources` has each failed source's reason, such as `"wayback": "web.archive.org answered 429"`. With several domains, each reason starts with its domain.
- `dns` asks resolvers, not sources, and has no such block.

The text summary ends with the same, and says why the exit code is what it is:

```
23 of 33 sources answered, 10 failed (listed above); exit 0 because other sources answered for the same domain (-fail-on-errors makes it 3)
```

### Degraded
- True when `sources failed` ([Sources in the summary](#sources-in-the-summary)) is above 0. A source the run relies on did not answer, so the names may be incomplete.
- The text summary says it on its first line: `DEGRADED: 7 of 38 sources failed`.
- It does not change the exit code. A failure the other sources made up for is listed as `partial`, and the exit stays 0. With `-fail-on-errors` it is 3.
- Failures of sources that ran only because of `-all-sources` never set it on their own.

### Failed sources
- A source whose answer was an error with a 200 status is a failed source when it gave no names. Examples are hackertarget's `API count exceeded`, a JSON `{"error": …}` and a challenge page.
- Its `error` holds the server's words: `api.hackertarget.com answered 200 with an error, not names: API count exceeded - Increase Quota with Membership`.
- A source that gave names first keeps them and says so in `partial`.

### What became of the names
The counts also say what became of the names, so a reader can add them up:

| Count | Meaning |
| --- | --- |
| `from sources` | The names every source gave for the domains, with the name history and subdomain.center's guesses, before any check. |
| `the domain itself` | The domain given, when a source returned it. It is not printed. |
| `did not resolve` | Names DNS says do not exist: guesses and history names that did not resolve, and with `-live` every other name that did not. A guess that only a wildcard answered is one of them. |
| `collected` | With `-live`: `from sources` less the domain itself and the guesses that did not resolve. |
| `resolved from sources` | With `-live`: names from sources that resolved and were printed. |
| `CNAME without an address` | With `-live`: names whose CNAME chain ends without an address, left out as not live. The takeover candidates among them are in `takeover`. |
| `found as CNAME targets`, `found by guessing` | Live names no source gave: another name's CNAME target in scope, and the names of `-w` and `-permute`. |
| `asked by guessing` | The names `-w` and `-permute` asked that no source gave. `found by guessing` is what is left of them after `did not resolve` and `left out by -m/-f`. |
| `unverified` | Printed names no DNS lookup checked, without `-live`: names only subdomain.center guessed, and names only the name history held, which no source gave this run. |
| `not checked` | With `-live`: names the resolvers failed on, left out. The run says so and `azhaq resume` checks them. |
| `left out by -m/-f` | Names a `-m`, `-f`, `-match-regex` or `-filter-regex` removed. |
| `listed under another domain` | A name under two of the domains given, printed once. |
| `cut by -max-names` | Names past `-max-names` (default 200,000), left out. The run ends with exit 3. |

- `subs` lists subdomains, as subfinder does, so it does not print the domain itself. `run`'s map has it as the target it is.
- `dnsx -a -cname` lists a name whose CNAME leads nowhere too. `subs -live` does not print it: it is no live name, and it is counted as `CNAME without an address`.

The number of results is `from sources`, less some counts and plus others:

- Less: `the domain itself`, `did not resolve`, `CNAME without an address`, `not checked`, `left out by -m/-f`, `listed under another domain` and `cut by -max-names`.
- Plus: `found as CNAME targets` and `asked by guessing` (the guesses that did not resolve are in `did not resolve`).

The run prints the sum as a note:

```
count: 2638 from the sources − 2093 did not resolve − 3 CNAME without an address − 1 not checked + 10 found as CNAME targets = 551 printed
```

With `-w`, the guesses are in it: `count: 0 from the sources + 14 asked by guessing − 2 did not resolve = 12 printed`.

### Per-source status
The workspace keeps a status for each source, shown by `azhaq show` and held in the `sources` payload of an `azhaq-subdomains` observation:

| Field | Meaning |
| --- | --- |
| `count` | Names the source gave. |
| `seconds` | Time the source took. |
| `calls` | Calls made to it. |
| `requests` | Requests sent, retries included. |
| `error` | The failure, in the server's words. |
| `skipped` | Why it did not run. |
| `partial` | What the source says about its own answer. Cert Spotter without a key reads the first page only. |
| `rate_limited` | Set with `retried_429`, `waited_seconds`, `retry_after_seconds` and `gave_up_429` when the source answered 429. |
| `rounds` | For subdomain.center, per call: names given, how many were new, looked up, and resolved with no other source having them, and the seconds. |
| `kept`, `dropped_unresolved`, `unverified`, `checked_seconds` | From `-live` runs, for the sources whose names are checked. |
| `"default": false` | The source ran only because of `-all-sources`. |

A source that answered 429 is asked again after its `Retry-After`, up to three times and 30 s each. One that asks for longer, or keeps refusing, is not waited for.

### Name history
Passive sources answer differently each run. subdomain.center, for one, returns a random sample of its names on each call. So `subs` keeps what it found.

- Azhaq keeps every name it kept for a domain in `names/DOMAIN.json`. The directory is `$AZHAQ_DATA_DIR`, else `$XDG_DATA_HOME/azhaq`, else `~/.local/share/azhaq`.
- Each name has its first and last time seen (`first_seen`, `last_seen`) and the sources that gave it (`sources`).
- At most 200,000 names are kept per domain. The ones unseen the longest go first.
- The next run asks this file as a source called `history`.
- With `-live`, a stored name counts only if it resolves now, and not to a wildcard. Stale names drop out, and a name a source missed this time comes back.
- Without `-live` no DNS lookup is made. A stored name that no source gave this run is listed with `"unverified": true`, and its `source` is `history`.
- A stored name that a source gave again is not flagged: its `source` is that source, and `history` comes last in `sources`. Every name a run kept is stored, so flagging them all would flag nearly every name after the first run.
- `-no-history` neither reads nor writes the file. A file that cannot be written is a note: `name history not saved: …`.

### Coverage estimate
`subs` ends with a note such as:

```
coverage: the independent sources hold about 1609 names; this run has 1400 of them (87%) — an estimate of what the sources know, not of every name that exists; the other 47 of the 1447 names came from the name history, from guesses checked in DNS or as CNAME targets, which the estimate leaves out
```

- It is a Chao1 estimate over how many independent sources gave each name: S + f1²/(2·f2). Here f1 is the number of names given by one source, and f2 the number given by two. With f2 = 0 it is S + f1(f1−1)/2.
- Independent means every source except the ones that pad their answer (subdomain.center) and `history`. A name only those gave is in the output but not in the count.
- It needs two independent sources that gave names.
- It counts the names printed. With `-live`, those are the live ones.
- It estimates what the sources know, not every name that exists.
- The `azhaq-subdomains` payload has `"coverage": {"observed", "estimated", "share"}`.
- The row of a sampled source (subdomain.center) in `sources` has `"population_estimate"`, a Schnabel estimate of how many names one call draws from. It is there when its rounds repeated names.

### Flags that follow subfinder
- [Migrating](../MIGRATING.md#subfinder-azhaq-subs) maps subfinder's flags to azhaq's, including the rates, `-max-results`, `-max-time`, `-max-body` and `-proxy`.
- `-m`, `-f`, `-match-regex` and `-filter-regex` filter the names.
- `-ls` lists the sources with their key requirement. With `-json` it prints one object for each.
- `-recursive` runs only the sources that handle subdomains of subdomains.
- `-stats` prints each source's requests, names and errors. `-version` prints the version.
- A source's key may also come from `$SOURCE_API_KEY`, or `$VAR` in the provider file.
- `-sources` with a name that is no source says so. `azhaq subs -ls` lists the real ones.

### `-live` and its time
- subdomain.center answers a random 500 names per call, most of them made up.
- Without a key it is asked again only while its last round gave a name that resolves and no other source had.
- Every round's new names are looked up before the next round is asked, and no name is looked up twice.
- With `-dns-rate` the guesses may cost at most half what the real names reported cost, and not less than 1,000.
- A live name has an address, directly or through its CNAME chain. A chain that ends without one is a takeover candidate, not a live name.
- Answers too big for 512 bytes, such as a long CNAME chain, arrive with EDNS0, or over TCP when a server truncates them.
- Without `-live` nothing is looked up. The guesses are listed with `"unverified": true`, and the summary counts them.

On tesla.com, `subs -live -dns-rate 10` with two resolvers took 161 s and listed 555 live names. `subfinder | dnsx -a -cname -rl 10` on the same resolvers took 211 s and listed 513. At the default pace it took 25 to 29 s against 56 to 63 s.

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
