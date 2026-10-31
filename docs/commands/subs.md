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

## Summary and exit codes

The summary and the exit codes are the shared ones: see [OUTPUT.md](../OUTPUT.md#exit-codes).

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
