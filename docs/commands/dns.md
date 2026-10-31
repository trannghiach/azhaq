# azhaq dns

Resolves names for any record type and leaves out wildcard answers. Replaces dnsx (see [Migrating](../MIGRATING.md#dnsx-azhaq-dns)).

## Synopsis

```
azhaq dns -d NAME | -l FILE | stdin  [-a -aaaa -cname -ns -txt -srv -ptr -mx -soa -caa -any -axfr -all] [-resp] [-json] [-w WORDS] [-r RESOLVERS]
```

## Examples

```
# the A records of every subdomain found, as JSON
azhaq subs -d example.com | azhaq dns -a -json

# MX and TXT records of a list, every record printed, two resolvers
azhaq dns -l names.txt -mx -txt -resp -r 1.1.1.1,tcp:9.9.9.9

# reverse lookups of a range
azhaq dns -l 192.0.2.0/24 -ptr -resp

# guess names under a domain from a wordlist, 50 names a second, 100 at once
azhaq dns -d example.com -w words.txt -rl 50 -t 100

# ask the name servers of a domain for its whole zone
azhaq dns -d example.com -axfr -allow example.com
```

## What it does

1. Takes names from `-d`, `-l` or stdin.
2. Asks resolvers for the record types you choose. A is the default.
3. Leaves out a name that only resolves through a wildcard zone.
4. Prints the names that have a record of the types asked.

`dns` sends DNS queries and nothing else. `-axfr` connects to the name servers of the name, `-trace` asks the root servers, and `-asn` asks Team Cymru's DNS service.

## Output

Plain output is one name per line: the names that have a record of the types asked. With `-json` you get one object per name a resolver answered, with the fields below. A field with no value is left out. `-db FILE` keeps the names that have records in a workspace.

What the text forms print:

| Flag | Each line is |
| --- | --- |
| `-resp` | `NAME [TYPE] [VALUE]`, one per record |
| `-resp-only` | the values, each exactly as the resolver sent it: a TXT value or a target name keeps its capitals, as in `-json` |
| `-rcode` | `NAME [NXDOMAIN]`, with the code of the answer |
| `-cdn`, `-asn` | the name, then ` [cdn-name]` or ` [AS number, name, country]` |
| `-ot '{{host}} {{a}}'` | a template over the `-json` fields; `{{ip}}` is `a` and `aaaa` together |

The `-json` fields are dnsx's, in its order:

| Field | Meaning |
| --- | --- |
| `host` | The name asked. |
| `ttl` | The TTL of the first record that has one. |
| `resolver` | The resolvers that answered. |
| `a`, `aaaa` | The addresses. |
| `cname` | The targets, with no final dot. |
| `mx`, `ptr` | The record values. |
| `soa` | `name`, `ns`, `mailbox`, `serial`, `refresh`, `retry`, `expire`, `minttl`. |
| `ns` | The name servers. |
| `txt` | The strings of a record, joined. |
| `srv` | The targets. |
| `caa` | The values. |
| `all` | Every record as text. `-omit-raw` drops it. |
| `raw` | The raw answer, with `-raw`. |
| `has_internal_ips`, `internal_ips` | An answer in a private, loopback, link-local, documentation or multicast range. |
| `status_code` | `NOERROR`, `NXDOMAIN`, `SERVFAIL`, `REFUSED`, … |
| `status_code_raw` | The code as a number. Left out for 0. |
| `takeover` | Not a dnsx field: a name whose CNAME points at what is gone. |
| `trace`, `axfr` | `{host, chain: [rows]}`, with `-trace` and `-axfr`. |
| `timestamp` | The time of the query. |
| `hosts_file` | With `-hf`. |
| `cdn`, `cdn-name`, `cdn-type` | With `-cdn`. `cdn` is true for a CDN. |
| `asn` | With `-asn`: `as-number`, `as-name`, `as-country`, `as-range`. |
| `query-time` | The duration of the query. |

## Summary and exit codes

The summary and the exit codes are the shared ones: see [OUTPUT.md](../OUTPUT.md#exit-codes). The summary counts:

| Count | Meaning |
| --- | --- |
| `asked` | Names asked. |
| `did not resolve` | Names with no record of the types asked. |
| `no answer` | Names no resolver answered. |
| `other codes` | Names answered, but not with a code `-rcode` lists. |
| `servfail from every resolver` | The name's own DNS is broken. This is not a failure. |
| `left out` | Inputs not asked about: see Details. |
| `not asked` | Names left when a run stops. |
| `wildcard answers left out` | Names that resolved only through a wildcard zone. |

The summary also lists failures per kind of error, and takeover candidates: a CNAME to a name that no longer exists.

## Details

### Which names get a row
- `-json` gives a row for every name a resolver answered, one that does not exist too: `status_code` is `NXDOMAIN` and there are no records.
- With a type flag (`-a`, `-mx`, …), only the names that have a record of that type get a row.
- With `-rcode`, only the names whose answer has that code get a row.

### Types
- `-all` asks every type but AXFR. AXFR is asked with `-axfr` only, because it connects to the name servers.
- An address gets PTR only.

### Wildcards
- A name that only resolves through a wildcard zone is left out of `a`, `aaaa` and `cname`.
- `-no-wildcard` keeps it.

### Words and inputs left out
- With `-d DOMAIN -w WORDS` it resolves `WORD.DOMAIN` for each word, as `dnsx -d -w` does.
- `left out` counts inputs that were not asked about:
  - an address or range without `-ptr`
  - a word that makes no name
  - a name outside the scope

## Flags

<!-- flags:begin dns -->
| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-a` | bool |  | ask A records and print the names that have one (the default) |
| `-aaaa` | bool |  | ask AAAA records and print the names that have one |
| `-all` | bool |  | ask every type but AXFR and print the records (-resp); an address gets only PTR |
| `-allow` | string, repeatable |  | a domain, host or address range the run may touch; with any -allow, nothing else is requested |
| `-any` | bool |  | ask ANY records and print the names that have one |
| `-asn` | bool |  | add the autonomous system of each address (as-number, as-name, as-country, as-range), asked of Team Cymru's DNS service |
| `-auto-wildcard` | bool |  | accepted: wildcard answers are always left out, unless -no-wildcard |
| `-aw` | bool |  | same as -auto-wildcard |
| `-axfr` | bool |  | ask each name server of the name, and the -resolvers you gave, for the whole zone over TCP (active; the name servers must be in scope: -allow, -scope) |
| `-caa` | bool |  | ask CAA records and print the names that have one |
| `-cdn` | bool |  | name the CDN, WAF or cloud in front of each name (cdn, cdn-name, cdn-type) |
| `-cname` | bool |  | ask CNAME records and print the names that have one |
| `-d` | string, repeatable |  | name to resolve, or with -w the domain to guess under (repeatable; a file, a comma list or - for stdin; FUZZ in it takes the words) |
| `-db` | string |  | keep the names that have records in this database for query, show and export (default: nothing is kept) |
| `-debug` | bool |  | same as -raw |
| `-deny` | string, repeatable |  | a domain, host or address range the run must not touch, even when given as a target |
| `-disable-update-check` | bool |  | same as -duc |
| `-dns-rate` | float |  | DNS queries per second per resolver (0: no pace but the queries in flight, as dnsx) |
| `-duc` | bool |  | accepted: azhaq checks for no updates |
| `-e` | string, repeatable |  | types not to ask with -all, comma-separated |
| `-hc` | bool |  | same as -health-check |
| `-health-check` | bool |  | ask each resolver a known name, print how it answered and how long it took, and exit |
| `-hf` | bool |  | same as -hostsfile |
| `-hostsfile` | bool |  | answer from the system hosts file before asking resolvers |
| `-j` | bool |  | same as -json |
| `-json` | bool |  | JSONL output, and the summary as one JSON object on stderr |
| `-l` | string, repeatable |  | names: a file, a comma list or - for stdin; a CIDR range or an AS number (AS13335) is expanded to addresses |
| `-maxtime` | float |  | stop the run after this many seconds (0: no limit); the summary says where to go on |
| `-mx` | bool |  | ask MX records and print the names that have one |
| `-nc` | bool |  | accepted: output has no colour |
| `-no-wildcard` | bool |  | print names even when they only resolve because their zone has a wildcard |
| `-ns` | bool |  | ask NS records and print the names that have one |
| `-o` | string |  | also write results to this file |
| `-omit-raw` | bool |  | leave the records as text (all) out of -json |
| `-or` | bool |  | same as -omit-raw |
| `-ot` | string |  | same as -output-template |
| `-output-template` | string |  | print each name as this template; {{host}}, {{a}}, {{ip}} and the other -json fields, lists joined by commas |
| `-program` | string |  | the program to take from a -scope list (handle, name or URL) |
| `-proxy` | string |  | send DNS through this socks5 proxy (socks5://host:port), over TCP |
| `-ptr` | bool |  | ask PTR records and print the names that have one |
| `-r` | string |  | same as -resolvers |
| `-rate-limit` | int |  | same as -rl |
| `-raw` | bool |  | print the raw DNS answers, as dig does |
| `-rc` | string |  | same as -rcode |
| `-rcode` | string |  | print NAME [RCODE] for names whose answer has one of these codes, comma-separated (noerror, nxdomain, servfail, refused, or a number); a name with no records is shown |
| `-re` | bool |  | same as -resp |
| `-recon` | bool |  | same as -all |
| `-resolvers` | string |  | DNS resolvers: a file with one per line, or a comma list; each is ADDR, ADDR:PORT or udp:, tcp:, dot:, doh:URL[:get] and then the address (default: public resolvers) |
| `-resp` | bool |  | print each record as: NAME [TYPE] [VALUE] |
| `-resp-only` | bool |  | print the values of the records only |
| `-response-type-filter` | string |  | print names with no record of these types, comma-separated (a, cname, ...) |
| `-retry` | int |  | attempts per question on other resolvers (default 3; 1 asks once) |
| `-rl` | int |  | names asked per second, over all resolvers; each name's types are asked together (0: no limit); see also -dns-rate |
| `-ro` | bool |  | same as -resp-only |
| `-rtf` | string |  | same as -response-type-filter |
| `-scope` | string |  | a program's scope: a file (HackerOne CSV, bounty-targets JSON, Burp options, lines) or hackerone, bugcrowd, intigriti, yeswehack |
| `-silent` | bool |  | results only: no progress; the summary only when something failed (a source that failed, a takeover candidate as a [takeover] line on stderr); stdout stays one result per line |
| `-soa` | bool |  | ask SOA records and print the names that have one |
| `-srv` | bool |  | ask SRV records and print the names that have one |
| `-start` | int |  | skip this many names at the start of the input, in order after de-duplication |
| `-stats` | bool |  | print progress on stderr every 5 seconds |
| `-stream` | bool |  | names come from stdin as they are written and are not de-duplicated |
| `-t` | int | `100` | names resolved at once |
| `-threads` | int | `100` | same as -t |
| `-timeout` | duration | `3s` | wait this long for each DNS answer (not the run's time, as in azhaq run: see -maxtime) |
| `-trace` | bool |  | follow the delegations from the root servers to the answer (the roots are asked, so use it on names you may ask) |
| `-trace-max-recursion` | int | `32` | most steps of -trace |
| `-txt` | bool |  | ask TXT records and print the names that have one |
| `-v` | bool |  | print each name that got no records, with its status, on stderr |
| `-w` | string, repeatable |  | words to guess: a file, a comma list or -; with -d DOMAIN resolves WORD.DOMAIN for each (wildcard answers left out) |
| `-wd` | string |  | same as -wildcard-domain |
| `-wildcard-domain` | string |  | also probe this zone for a wildcard (a zone the registrable domain does not reach, such as corp.internal) |
| `-wildcard-threshold` | int |  | accepted and not needed: each parent zone is probed for a wildcard |
| `-wt` | int |  | same as -wildcard-threshold |
<!-- flags:end -->
