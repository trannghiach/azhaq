# azhaq ports

Open TCP ports (connect scan, no root), named by what they answer on any port, with products and versions; ranges, CIDR and AS numbers without a cap; -udp asks the common UDP ports. Replaces naabu (see [Migrating](../MIGRATING.md#naabu-azhaq-ports)).

## Synopsis

```
azhaq ports -host HOST[,HOST…] | -l FILE | stdin | TARGET…  [-p LIST | -tp 100|1000|full | -pf FILE] [-ep LIST] [-udp | -pu LIST] [-rate N] [-T0..5] [-connect-timeout MS] [-retries N] [-c N] [-sn | -wn] [-cdn-full] [-csv | -json] [-oX F] [-oG F] [-oA BASE]
```

## Examples

```
azhaq ports -host scanme.nmap.org -p top-1000 -json
azhaq ports 10.0.0.0/16 -p 22,80,443 -rate 2000 -wn
azhaq ports -host 127.0.0.1 -p none -pu 1-1024 -json
azhaq ports -l hosts.txt -tp 1000 -ep 25,3306 -T2 -oA scan
```

## Output

Host:port per open port (host:port/udp for UDP); -json: {"host","ip","port","protocol","tls","cdn","cdn-name","timestamp" (UTC),"service","product","version","title","banner","state" (UDP)}; -csv: the same fields as columns; -oX nmap XML, -oG greppable, -oA all three. Targets: a name, an address, host:port (that port only, unless -p is given), a URL, a CIDR range (IPv4 or IPv6 down to /104), AS64500 (the prefixes RIPEstat lists), several to a flag separated by commas. -timeout is how long the whole run may take; the wait for one connect is -connect-timeout.

## Summary and exit codes

The summary and the exit codes are the shared ones: see [OUTPUT.md](../OUTPUT.md#exit-codes).

## Flags

<!-- flags:begin ports -->
| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-Pn` | bool |  | accepted: addresses are scanned without asking whether they are up, which is the default |
| `-T` | int | `-1` | timing template, 0 (paranoid) to 5 (insane); sets -rate, -connect-timeout and -retries where they are not given; 3 is the default |
| `-allow` | string, repeatable |  | a domain, host or address range the run may touch; with any -allow, nothing else is requested |
| `-c` | int |  | same as -workers |
| `-cdn` | bool |  | accepted: a CDN address is marked in the output, always |
| `-cdn-full` | bool |  | scan CDN and WAF addresses in full, not only ports 80, 443, 8080 and 8443 |
| `-connect-timeout` | string |  | wait this long for one port to accept or refuse a connect: 1500, 1500ms or 2s (default 1.5s; -timeout is the run's limit) |
| `-cp` | string |  | send this to each open TCP port before reading what it says (\r and \n are CR and LF) |
| `-csv` | bool |  | CSV output, a header line first |
| `-db` | string |  | keep the graph in this database for query, show, export and diff (default: a temporary one) |
| `-deny` | string, repeatable |  | a domain, host or address range the run must not touch, even when given as a target |
| `-detect` | string | `all` | what is asked of an open port: all (its banner, then HTTP and TLS, then one request of each protocol that waits to be asked, each on its own connection, several at once while the scan has workers free: at most 24 connects after the first), banner (what it says on the one connection) or none (connect and close, as naabu without -sV) |
| `-dns-rate` | float |  | DNS queries per second per resolver (0: no pace but the queries in flight, as dnsx) |
| `-ef` | string |  | file of hosts, addresses and ranges not to scan |
| `-eh` | string |  | hosts, addresses or ranges not to scan, comma-separated (same as -deny) |
| `-eof` | string |  | leave these fields out of -json, -csv and -oA's JSON, comma-separated |
| `-ep` | string |  | ports not to scan: a list or a file |
| `-host` | string, repeatable |  | hosts, addresses, CIDR ranges, AS numbers or host:port, comma-separated and repeatable |
| `-iv` | string |  | the address families of a name to scan: 4 or 6 (default both) |
| `-j` | bool |  | same as -json |
| `-json` | bool |  | JSONL output, and the summary as one JSON object on stderr |
| `-kill-file` | string |  | stop all sending, at once, when this file exists, and exit 4; azhaq resume works once it is removed (default DB.stop) |
| `-l` | string |  | file of targets (- for stdin) |
| `-ledger` | string |  | write every request and connection to a target to this file, a chain of hashes that azhaq ledger -verify checks (default DB.ledger.jsonl next to the workspace; off: none; with a temporary database, only when given) |
| `-lof` | bool |  | list the fields of -json and -csv, and stop |
| `-max-requests` | int |  | requests to targets this run may send (0: no cap); the work left over is for azhaq resume |
| `-max-retries` | int | `-1` | same as -retries |
| `-min-rate` | float |  | connects per second at least: raises -rate to this when lower |
| `-nc` | bool |  | accepted: no colours are printed |
| `-no-stdin` | bool |  | do not read targets from stdin when none is given |
| `-o` | string |  | also write results to this file |
| `-oA` | string |  | write JSON lines, XML and greppable output to BASE.json, BASE.xml and BASE.gnmap |
| `-oG` | string |  | write nmap greppable output to this file (- for stdout) |
| `-oX` | string |  | write nmap XML to this file (- for stdout) |
| `-order` | string | `random` | the order a host's ports are asked in: random (the likeliest ports first, each tier shuffled) or asc |
| `-p` | string | `top-100` | ports: top-100, top-1000, full, - (all), none, or a list of ports, ranges and these names, such as 22,80,8000-8100 or top-100,8888; u:53 is a UDP port |
| `-pf` | string |  | file of ports, one spec a line (added to -p) |
| `-program` | string |  | the program to take from a -scope list (handle, name or URL) |
| `-proxy` | string |  | connect to TCP ports through this SOCKS5 proxy (host:port); a port is then asked its banner only, and UDP is not sent |
| `-proxy-auth` | string |  | user:password for -proxy |
| `-pts` | int |  | stop asking a host after this many open ports: it answers every port (default: no limit) |
| `-pu` | string |  | UDP ports to ask: top, full or a list of ports, ranges and these names, such as 53,123,1-1024 or top,5354 (implies -udp) |
| `-r` | string |  | same as -resolvers |
| `-rate` | float |  | port connection attempts per second (0: 1500, as naabu's connect scan, and 127.0.0.1 unpaced) |
| `-resolvers` | string |  | DNS resolvers: a list such as 1.1.1.1,8.8.8.8:53 or a file, one a line (default: public resolvers) |
| `-retries` | int | `-1` | more passes over the ports that neither accepted nor refused: n passes over all of them, 0 none (default: one, when few did not answer) |
| `-sa` | bool |  | scan every address of a name, not the first two of each family |
| `-scope` | string |  | a program's scope: a file (HackerOne CSV, bounty-targets JSON, Burp options, lines) or hackerone, bugcrowd, intigriti, yeswehack |
| `-seed` | int |  | make the random port order repeat (default: a new one each run) |
| `-silent` | bool |  | results only: no progress; the summary only when something failed (a source that failed, a takeover candidate as a [takeover] line on stderr); stdout stays one result per line |
| `-sn` | bool |  | list the addresses that are up (a connect to 80 or 443 is accepted or refused) and scan nothing |
| `-source-ip` | string |  | connect from this local address |
| `-timeout` | duration |  | stop after this long and keep what was found; azhaq resume continues (0: no limit) |
| `-tp` | string |  | the most common TCP ports: 100, 1000 or full (added to -p) |
| `-udp` | bool |  | also ask the common UDP ports (25: dns, ntp, snmp, ssdp, mdns, ...) |
| `-unnamed` | int |  | after this many open ports of an address that no protocol probe could name, ask its other silent ports their banner only (0: 6, a guard against hosts that accept every connect; -1: no limit) |
| `-v` | bool |  | print a line for every finished task, not only failures |
| `-wn` | bool |  | scan only the addresses that are up (by -sn's test); the default scans every address |
| `-workers` | int |  | connects in flight at once, over all hosts (default: as many as the rate allows, up to 20000) |
<!-- flags:end -->
