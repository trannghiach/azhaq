# Moving to azhaq from another tool

If you know subfinder, dnsx, httpx, katana, ffuf, gau, arjun, naabu, nmap, gowitness, asnmap or notify, you can start with the command lines you have. Each azhaq command that stands in for one takes that tool's flags where they make sense. With `-json` it prints that tool's field names.

This page lists, tool by tool:

- the spelling of the flags people use
- what is different on purpose
- what azhaq adds

| You use | Run | Section |
| --- | --- | --- |
| subfinder | `azhaq subs` | [subfinder](#subfinder-azhaq-subs) |
| dnsx | `azhaq dns` | [dnsx](#dnsx-azhaq-dns) |
| httpx | `azhaq probe` | [httpx](#httpx-azhaq-probe) |
| katana (with jsluice) | `azhaq crawl` | [katana](#katana-azhaq-crawl) |
| ffuf | `azhaq fuzz` (any part of a request), `azhaq dirs` (paths, calibrated) | [ffuf](#ffuf-azhaq-fuzz-and-azhaq-dirs) |
| gau | `azhaq urls` | [gau](#gau-azhaq-urls) |
| arjun | `azhaq params` | [arjun](#arjun-azhaq-params) |
| naabu | `azhaq ports` | [naabu](#naabu-azhaq-ports) |
| nmap `-sV` and `-sU` | `azhaq ports` | [nmap](#nmap--sv-and--su-azhaq-ports) |
| asnmap | `azhaq asn` | [asnmap](#asnmap-azhaq-asn) |
| gowitness | `azhaq shots` | [gowitness](#gowitness-azhaq-shots) |
| notify | `azhaq notify` | [notify](#notify-azhaq-notify) |

## What is the same for every command

- **Flags.** A flag may have one dash or two: `-silent` or `--silent`. A flag a command does not have stops it with exit 2 before anything is sent, and the error names the closest flags. `azhaq help COMMAND` lists azhaq's own flags by task; `azhaq help COMMAND all` (or `-h all`) adds the names kept for the other tools' command lines, the other names of a flag and the rarely needed ones, all of which work. `azhaq help -json` lists every flag for a program, marking those `-h` leaves out.
- **Output.** Results go to stdout, one per line, as the tool prints them. A summary goes to stderr: what failed, what was not requested, and which limit stopped the run. With `-json` the results are JSON lines and the summary is one JSON object. See [OUTPUT.md](OUTPUT.md).
- **Exit codes.** `0` complete, `1` error, `2` usage, `3` finished with failures, `4` stopped by a limit or the kill file. They are the same for every command. The tools above exit 0 after most of these, so a script that checks `$?` sees more than it did. See [OUTPUT.md](OUTPUT.md#exit-codes).
- **Scope and limits.** Nothing is sent to a host outside the scope. See [Concepts](CONCEPTS.md). The flags differ by command:
  - `probe`, `crawl`, `ports`, `dirs`, `fuzz`, `params` and `shots` take `-allow`, `-deny`, `-scope`, `-max-requests`, `-kill-file`, `-ledger` and `-rate`. `-scope` takes a program's scope. Except `ports`, they also take `-deny-path REGEX`, which keeps paths out: it is where the out-of-scope regexes of katana and feroxbuster (its dont-scan list) go when a URL must never be requested. azhaq decides nothing about a path by itself, so it has no default rule.
  - `dns` takes the three scope flags.
  - `subs`, `urls`, `asn` and `notify` send nothing to a target, so they have none of these.
- **Workspace.** `-db FILE` keeps what a command found in a workspace. `query`, `show`, `export`, `diff`, `watch` and `resume` then work on it. Without `-db` the command uses a temporary workspace.
- **Pipes.** The output of one command feeds the next: `azhaq subs -d example.com -silent | azhaq dns -silent | azhaq probe -json`.
- **Examples.** `example.com`, `app.example.com` and `192.0.2.x` stand for targets of yours. Files such as `hosts.txt` or `names.txt` stand for lists of yours, one entry a line. A line that needs a config, a key, a lab or another file says so next to it.
- **Tables.** Each table has the other tool's flag on the left and azhaq's on the right. A flag with no azhaq column is one azhaq does not have, and the note says what to do instead. Flags are written for the tool's current release. azhaq's `-json` field names follow the tool's, except katana's: see the katana section.

## subfinder: `azhaq subs`

<!-- azhaq: subs -->

Behaviour, fields and edge cases: [`azhaq subs`](commands/subs.md).

| subfinder | azhaq | Note |
| --- | --- | --- |
| `-d example.com` | `-d example.com` | Takes a comma list, a URL or a name with a trailing dot, as subfinder does. `-d` may also repeat. |
| `-dL FILE` | `-dL FILE` | `-dL -` reads stdin, and so does a pipe with no `-d`. |
| `-s a,b` | `-sources a,b` | The sources to run. |
| `-es a,b` | `-exclude-sources a,b` | |
| `-all` | `-all-sources` | Also runs the slower sources outside the default set. |
| `-nW` | `-live` (or `-nW`) | Only names that resolve; wildcard answers are left out. `subfinder -nW` does the job of subfinder piped to dnsx. |
| `-r 1.1.1.1,8.8.8.8` | `-resolvers 1.1.1.1,8.8.8.8` | A file or a comma list. Prefixes: `udp:`, `tcp:`, `dot:` and `doh:`. |
| `-pc FILE` | `-providers FILE` | API keys per source. Without it azhaq reads `~/.config/azhaq/providers.yaml`, else subfinder's `provider-config.yaml`. |
| `-timeout 30` | `-source-timeout 30s` | How long each source gets: 30 s by default, as in subfinder. azhaq's `-timeout` is the whole run's, and `azhaq resume` continues it. |
| `-oJ`, `-json` | `-json` (or `-oJ`) | `{"host","input","source","sources"}`, plus `unverified` and `wildcard_certificate` when they apply. |
| `-o FILE` | `-o FILE` | |
| `-silent`, `-v` | `-silent`, `-v` | |
| `-rl N`, `-rls a=N/s` | `-source-rate N`, `-source-rates a=N/s` | Requests a second to each source, or to single ones. A source's own lower pace stays. |
| `-max-time`, `-mr`, `-rsr`, `-proxy` | `-max-time`, `-max-results`, `-max-body`, `-proxy` | |
| `-t` | `-t` | Work items in flight. |
| `-ls`, `-oD DIR`, `-cs`, `-oI`, `-recursive`, `-stats` | `-ls`, `-oD DIR`, `-cs`, `-oI`, `-recursive`, `-stats` | `-oI` needs `-live`. |
| `-m`, `-f` | `-m`, `-f`, `-match-regex`, `-filter-regex` | |
| `-ei` | `-ei` | Accepted. An IP address given as a domain is always left out, with a note. |

### What differs on purpose

<!-- azhaq: subs -->

- A name appears once, however many sources gave it. `source` is the first source and `sources` lists all of them.
- crt.sh is asked as subfinder asks it: its public PostgreSQL (`host=crt.sh user=guest dbname=certwatch`, port 5432) first, then the JSON API when the database fails or has no names. azhaq adds subfinder's `LIMIT 10000` to the query too, which keeps it fast, and when exactly 10000 rows come back it asks again without the limit (then the JSON API) for the rest, so it lists at least what subfinder lists, and a note says which path gave the names. A SOCKS5 `-proxy` carries the database connection too. An HTTP proxy cannot, so crt.sh is then asked in the JSON API only, and a note says so.
- Sources outside the default set stay out. `-all-sources` runs them.
- A source that needs a key and has none is listed as `needs a key`, not skipped without a word.
- A run in which every source failed is `degraded` and exits 3, not 0 with an empty list. The summary names each source that failed.
- azhaq keeps the names it found for a domain and checks them again in the next run. `-no-history` turns this off. See [Name history](commands/subs.md#name-history).
- With `-live`, a name that no longer resolves drops out.
- Without `-live`, a stored name that no source gave this run is listed with `"unverified": true`. So are subdomain.center's guesses.

### Examples

<!-- azhaq: subs -->

```
azhaq subs -d example.com -silent
azhaq subs -dL domains.txt -live -json -o names.jsonl
azhaq subs -d example.com -live -source-rate 2 -dns-rate 5 -resolvers 1.1.1.1,8.8.8.8
```

### What azhaq adds

<!-- azhaq: subs -->

- `-live` checks names against the zone's wildcard, per parent zone, with CNAME targets.
- `-w WORDS` also resolves `WORD.domain` for each word. `-permute` resolves variations of what was found.
- A takeover candidate is listed with its evidence. It is a CNAME to a name that no longer exists, an unclaimed domain, or a hosting service's "no such site" page.
- The summary says what each source gave. It also says how much of what the independent sources know this run holds, in the `coverage:` line: see [Coverage estimate](commands/subs.md#coverage-estimate).
- `-db` keeps the names for `query` and `diff`.

## dnsx: `azhaq dns`

<!-- azhaq: dns -->

Behaviour, fields and edge cases: [`azhaq dns`](commands/dns.md).

| dnsx | azhaq | Note |
| --- | --- | --- |
| `-l FILE` | `-l FILE` | A file, a comma list or `-`. A CIDR range or an AS number is expanded to its addresses. |
| `-d example.com` | `-d example.com` | With `-w`, the domain to guess under. `-d FUZZ.example.com -w FILE` puts the words where `FUZZ` is. |
| `-w FILE` | `-w FILE` | |
| `-a -aaaa -cname -ns -txt -srv -ptr -mx -soa -caa -any -axfr` | the same | `-a` is the default. |
| `-recon` | `-all` (or `-recon`) | Every type but AXFR. `-e TYPES` leaves some out. |
| `-resp`, `-resp-only` | `-resp`, `-resp-only` | `NAME [TYPE] [VALUE]`. |
| `-rc noerror,nxdomain` | `-rcode noerror,nxdomain` | `-rc` is accepted too. |
| `-j` | `-json` (or `-j`) | dnsx's field names. |
| `-o FILE` | `-o FILE` | |
| `-r 1.1.1.1,tcp:9.9.9.9` | `-resolvers 1.1.1.1,tcp:9.9.9.9` (or `-r`) | Prefixes: `udp:`, `tcp:`, `dot:` and `doh:`. |
| `-rl 50` | `-rl 50` | Names asked per second over all resolvers. |
| `-t 100` | `-t 100` | Names resolved at once. The default is 100 in both. |
| `-retry 2` | `-retry 3` | Attempts per question. azhaq's default is 3. |
| `-timeout 3s` | `-timeout 3s` | The wait for one DNS answer, as in dnsx. The run's own bound is `-maxtime`. |
| `-wd zone`, `-auto-wildcard` | `-wildcard-domain zone` (or `-wd`), `-auto-wildcard` (or `-aw`) | See the wildcard point below. |
| `-trace` | `-trace` | Follows the delegations from the root servers. |
| `-asn`, `-cdn` | `-asn`, `-cdn` | |
| `-hf`, `-hc` | `-hostsfile`, `-health-check` | |
| `-stream`, `-stats` | `-stream`, `-stats` | |
| `-proxy socks5://…` | `-proxy socks5://…` | |

### What differs on purpose

<!-- azhaq: dns -->

- **Wildcards.** Wildcard answers are always left out, per parent zone, with no domain to give. `-no-wildcard` prints them. `-aw` is accepted and changes nothing. dnsx prints wildcard answers unless it is given `-wd` or `-aw`.
- **`-timeout`.** It is the wait for one answer, as in dnsx. In the other azhaq commands it is how long the run may take. Here the run's bound is `-maxtime SECONDS`.
- **`-rl` and `-dns-rate`.** `-rl` counts names, as dnsx's does. `-dns-rate N` is a second pace: N queries a second to each resolver. With 6 resolvers that is up to 6 times N.
- **Pace, as observed.** With dnsx 1.x, `-rl` did not hold back the queries of `-d` with `-w` in one test run: 20 names at `-rl 1` took 0.46 s, and 40 at `-rl 10` took 0.64 s. azhaq's `-dns-rate` paced them: 20 names at 1 a second took 19 s. That is what was measured, not a statement about every dnsx version or input.
- **A polite run.** Give both `-rl 5` and `-t 5`. Add a `-resolvers` list of one address if you want 5 queries a second in all.
- **`-retry` and failures.** `-retry` is 3 where dnsx's is 2. A name that no resolver answers is a failure in the summary, and the exit code is 3.

### Examples

<!-- azhaq: dns -->

```
azhaq dns -l names.txt -mx -txt -json -r 1.1.1.1,tcp:9.9.9.9 -rl 50 -t 20
azhaq dns -d example.com -w subdomains.txt -resp
azhaq dns -l 192.0.2.0/24 -ptr -resp
```

### What azhaq adds

<!-- azhaq: dns -->

- A dangling CNAME is listed with the service it points at: a takeover candidate.
- `-all` and `-resp` print records in dnsx's form.
- `-axfr` asks only name servers in scope, the zone's first and then the `-r` resolvers, as dnsx does. When no server transfers the zone it is a failure (exit 3); dnsx prints the row with an empty `axfr` and exits 0.
- `-db` keeps the answers for `query` and `export`.
- `-maxtime` stops a long run, and the summary says where to go on.

## httpx: `azhaq probe`

<!-- azhaq: probe -->

Behaviour, fields and edge cases: [`azhaq probe`](commands/probe.md).

| httpx | azhaq | Note |
| --- | --- | --- |
| `-u TARGET`, `-l FILE` | `-u TARGET`, `-l FILE` | Or stdin. |
| `-p 80,8000-8100` | `-p 80,8000-8100` | `http:80` or `https:443` asks one scheme. A `host:port` or a URL is asked on these ports instead of its own, as in httpx. |
| `-path /a,/b` | `-path /a,/b` | A list or a file. As in httpx, a path is joined onto the path of a URL input (`http://h/api?q=1` with `-path /login` asks `/api/login?q=1`): one slash between them, the URL's query kept and the path's added, the fragment never sent. A host has no path, so the path is the whole of it. |
| `-sc -cl -ct -title -td -server -ip -cname -location -method` | the same | What a row prints. `-web-server` and `-tech-detect` are accepted. |
| `-asn -cdn -favicon -jarm -hash md5,mmh3` | the same | |
| `-tls-grab -tls-probe -csp-probe` | the same | |
| `-mc -fc -ml -fl -mlc -flc -mwc -fwc -mr -fe -ms -fs -mrt -frt` | the same | httpx's matchers and filters. `-ms` and `-fs` take strings. `-fe` filters by regex. |
| `-mdc`, `-fdc` | `-mdc`, `-fdc` | DSL conditions over the `-json` fields. |
| `-fr`, `-maxr`, `-fhr` | `-fr`, `-maxr`, `-fhr` | Follow redirects, how many, same host only. |
| `-x GET,POST`, `-body`, `-rr FILE` | the same | They send what you give. They can change data on the target, and the summary says so. |
| `-H`, `-random-agent` | `-H`, `-random-agent` | |
| `-http-proxy URL`, `-proxy URL` | `-http-proxy URL`, `-proxy URL` | |
| `-sr -srd DIR`, `-irr`, `-irh` | the same | Store responses; add them to the JSON. |
| `-ss` | `-ss` | A screenshot of each front page, with Chrome on the machine. |
| `-j`, `-json`, `-csv`, `-md` | the same | |
| `-o FILE`, `-oa FILE` | the same | |
| `-rl 150` | `-rl 150` | Services a second, as httpx counts them. See the pace point below. |
| `-t 50` | `-t 50` | Work items in flight. The default is 16; httpx's is 50. |
| `-timeout 10` | `-req-timeout 10s` | One request's time. azhaq's `-timeout` stops the whole run. |
| `-retries N`, `-maxhr N` | the same | |
| `-silent`, `-nc`, `-v` | the same | |

### What differs on purpose

<!-- azhaq: probe -->

- `probe` follows no redirect unless given `-fr`, as httpx does. A row's status, title and length are one answer's. `run` and `crawl` follow redirects inside the site.
- **Pace.** `-rl` counts services a second, as httpx does. A target's first request waits its turn. Its favicon, redirects and second scheme do not. `-rate N` paces every request instead. The default is no pace; httpx's is 150.
- A target with no answer is a row with `failed: true`, and `-probe` prints `[FAILED]` for it. The summary counts them.
- A name that resolves only because its zone has a wildcard is probed, not dropped, so a list of real hosts is not thinned.
- `-p` replaces the port of an input, as httpx does: `-l 127.0.0.1:3001 -p 5002` asks port 5002 only, and `input` stays the line as given. A URL with a path keeps its path and its own scheme on the new port, where httpx asks both schemes. Without `-p`, an input asks its own port.
- A bare `host:port` is asked over plain HTTP first on 8080 and on ports above 1024. It is asked over TLS when the plain request is answered 400.
- Every request goes through the scope, the budget, the pace and the ledger. A redirect to another site is recorded and not requested, even with `-fr`.

### Examples

<!-- azhaq: probe -->

```
azhaq probe -l hosts.txt -json
azhaq probe -l hosts.txt -p 80,443,8000-8100 -mc 200,401 -title -td -sc
azhaq probe -l hosts.txt -fr -tls-grab -hash md5 -sr -srd out -json
```

### What azhaq adds

<!-- azhaq: probe -->

- A page that answers like an unknown path is marked `catchall`.
- A CNAME or a page that names an unclaimed service is a takeover candidate.
- `-db` keeps every row for `query`, `show` and `export -format targets`.
- `-rate` and `-max-requests` hold the run to a request budget, and `azhaq resume` continues it.

## katana: `azhaq crawl`

<!-- azhaq: crawl -->

Behaviour, fields and edge cases: [`azhaq crawl`](commands/crawl.md).

| katana | azhaq | Note |
| --- | --- | --- |
| `-u URL`, `-list FILE` | `-u URL`, `-l FILE` | Or stdin. |
| `-d 3` | `-d 3` | Link levels below the start URL. 3 is the default in both. |
| `-jc`, `-jsl` | `-jc`, `-jsl` | Accepted. Scripts are always read: routes, calls with their methods and body names, router tables, source maps, API descriptions. |
| `-kb`, `-td`, `-duc` | the same | Accepted and always on. Forms and technologies are always read. |
| `-headless` | `-browser` | Pages are also loaded in Chrome. `-interact` clicks the buttons and menus. |
| `-fs rdn` | `-fs rdn` | The hosts a crawl follows: `rdn`, `fqdn`, `dn` or a regex. See below for the default. |
| `-ns` | `-ns` | Follow links to any host, still held to `-allow` and `-deny`. |
| `-cs`, `-cos` | `-cs`, `-cos` | Regexes of the URLs to follow or never follow. `-deny-path REGEX` goes further: a URL it matches is never requested, by any collector or Chrome. |
| `-do` | `-do` | Also list the URLs found and left out of scope. They are never requested. |
| `-f url,path,rdn`, `-sf`, `-sfd` | the same | Fields; one file per field. azhaq adds `method`: `-ot '{{method}} {{url}}'` prints the methods a route is called with. |
| `-em`, `-ef`, `-mr`, `-fr` | the same | Extension filters and regex filters on the printed URLs. |
| `-ndef` | `-ndef` | |
| `-jsonl`, `-j` | `-jsonl`, `-j` | katana's `{"request","response"}` lines. |
| (none) | `-json` | Not katana's: `{"url","coverage","role","status","methods","params","forms","tech"}`. |
| `-o FILE`, `-silent`, `-nc`, `-v` | the same | |
| `-sr -srd DIR`, `-ob` | the same | |
| `-kf robotstxt,sitemapxml` | `-kf robotstxt,sitemapxml` | |
| `-iqp`, `-pc` | `-iqp`, `-path-climb` (or `-pc`) | `-iqp` keeps one URL for each path, whatever its query values. `-path-climb` adds the parent directories of each link. |
| `-rl 150`, `-rlm`, `-hrl`, `-hrlm`, `-rd` | the same | |
| `-c 10`, `-p 10` | `-c 10`, `-p 16` | Requests in flight per host; work items in flight. |
| `-timeout 10` | `-request-timeout 10s` | One request's time. azhaq's `-timeout` stops the run. |
| `-ct 1h` | `-ct 1h` | Stop after this long and keep what was found. |
| `-retry N`, `-mdp N`, `-mrs N` | the same | |
| `-H`, `-proxy`, `-r` | `-H`, `-proxy`, `-r` | |
| `-H 'Cookie: a=b'` | `-cookie a=b`, `-cookie-jar` | `-cookie-jar` carries the cookies a target sets onto the requests that follow. |

### What differs on purpose

<!-- azhaq: crawl -->

- **Hosts followed.** Without `-fs`, a crawl of a name follows its registrable domain and subdomains, as `rdn` does. A crawl of an address stays on that address and port. Redirects are followed inside the site, not to any host.
- **Every URL found is asked.** Like katana and Burp's crawler, `crawl` requests every GET URL it finds in scope, `/logout` and `/delete?id=1` included: azhaq cannot know what a GET does on the server, so no name keeps a URL out. Writes go only with their flags. `-deny-path REGEX` keeps paths out of every request. With a session, a request that ends it is noticed and the session is renewed or the run stops: [Sessions](CONCEPTS.md#sessions).
- A URL with a scanner's payload in it never enters the map.
- Chrome sends only GET, HEAD and OPTIONS unless you give `-browser-writes`.
- A page with many query variants, such as `/item?id=N`, is asked for every URL, as katana does. `-per-template N` limits it, and the rest are listed.
- `crawl` asks only what a crawler asks. `-sweep` adds the 32 built-in path checks and the source map next to each script, as `run` does. The checks cover `robots.txt`, sitemaps, API descriptions, `.git/HEAD`, `admin` and more.
- **Time at a low `-rate`.** The number of requests sets the time. On Juice Shop at `-rate 5`, azhaq sends 91 requests in 21 s. katana `-jc -jsl -d 3 -rl 5` sends about 80 in 17 s.
- The extra azhaq requests are the API routes katana does not find, such as `/rest/…` and `/api/…`: about 60 more endpoints. They also include one check per directory that tells a real answer from the page the app gives every unknown path.
- Unpaced, azhaq is faster: 8.5 s against 14.3 s.
- Routes a script calls with POST are listed, as katana lists them, but a GET of one may answer 404 or 405. `-json` has their `methods`. `-ot '{{method}} {{url}}'` prints them in plain output.
- `-json` is azhaq's, not katana's. The map keeps how each URL is known: `called`, `described`, `linked`, `archived` or `guessed`. `azhaq show -db FILE URL` prints the line of the script that names it.

### Examples

<!-- azhaq: crawl -->

```
azhaq crawl -u https://app.example.com/ -d 3 -silent
azhaq crawl -u https://app.example.com/ -jsonl -o crawl.jsonl
azhaq crawl -u https://app.example.com/ -fs rdn -do -f rdn,path -rl 5
```

### What azhaq adds

<!-- azhaq: crawl -->

- The routes a frontend's JavaScript calls, with methods and body names.
- GraphQL schemas.
- API descriptions, read and expanded.
- Forms with their field names.
- `-login` signs in with Chrome, and `azhaq roles` compares what each account can reach.
- `-db` keeps the map for `query`, `show`, `hunt`, `diff` and `export -format openapi|burp|html`.

## ffuf: `azhaq fuzz` and `azhaq dirs`

<!-- azhaq: fuzz dirs -->

`azhaq fuzz` takes ffuf's flags. It counts words, lines and sizes as ffuf does. It calibrates, with `-ac`, and recurses as ffuf does, so a command line moved from ffuf gives the same results. `azhaq dirs` is the short form for the common job: paths from a wordlist, calibrated, with SecLists' `common.txt` built in. Behaviour and fields: [`fuzz`](commands/fuzz.md) and [`dirs`](commands/dirs.md).

| ffuf | azhaq `fuzz` | Note |
| --- | --- | --- |
| `-u URL`, `-w FILE[:KEYWORD]` | `-u URL`, `-w FILE[:KEYWORD]` | Repeatable. `-w -` is stdin. |
| `-mode clusterbomb` | `-mode clusterbomb` | Also `pitchfork` and `sniper`. |
| `-X`, `-d`, `-H`, `-b` | `-X`, `-d`, `-H`, `-b` | `-data`, `-data-ascii`, `-data-binary` and `-cookie` too. |
| `-request FILE`, `-request-proto` | the same | A raw request as Burp saves it. |
| `-e .php,.bak`, `-D`, `-ic` | the same | |
| `-enc 'FUZZ:urlencode'` | `-enc 'FUZZ:urlencode'` | ffuf's encoders. |
| `-mc -ms -mw -ml -mr -mt` | the same | |
| `-fc -fs -fw -fl -fr -ft` | the same | |
| `-mmode`, `-fmode` | the same | |
| `-ac`, `-acc`, `-acs`, `-ack`, `-ach` | the same | Calibration is off unless `-ac` is given, as in ffuf. `-acc`, `-acs` and `-ach` imply `-ac`. |
| `-recursion`, `-recursion-depth`, `-recursion-strategy` | the same | |
| `-t 40`, `-p 0.1`, `-rate 100` | the same | |
| `-maxtime`, `-maxtime-job` | the same | |
| `-sa`, `-se`, `-sf` | the same | |
| `-x`, `-replay-proxy` | `-x`, `-replay-proxy` | |
| `-timeout 10` | `-timeout 10` | Seconds per request, as in ffuf. |
| `-o FILE -of json` | `-o FILE -of json` | Also `ejson`, `csv`, `ecsv`, `html`, `md` and `all`; `-od DIR`, `-or`. |
| `-config FILE` | `-config FILE` | ffuf's TOML. |
| `-s`, `-v`, `-c`, `-V` | the same | |
| `-input-cmd`, `-input-num`, `-input-shell` | the same | |
| `-preflight`, `-postflight` | the same | In ffuf's development version. They go with `-preflight-var` and `-preflight-mode`. |
| `-http2`, `-sni`, `-raw`, `-ignore-body` | the same | |

| ffuf `-ac` on a path | azhaq `dirs` | Note |
| --- | --- | --- |
| `-u https://h/FUZZ -w words` | `-u https://h/ -w words` | `FUZZ` is not needed. A URL with a path, as in `-u https://h/api/`, sweeps `/api/WORD`. |
| `-e .php,.bak` | `-e php,bak` | |
| `-mc -ms -mw -ml -mr`, `-fc -fs -fw -fl -fr` | the same | |
| `-t 40` | `-t 40` | |
| `-rate N` | `-rate N` | |
| `-w` left out | | SecLists' `common.txt` (MIT) is built in. |

### What differs on purpose

<!-- azhaq: fuzz dirs -->

- **Calibration.** `dirs` calibrates by default, as ffuf does with `-ac`. `fuzz` does not calibrate unless you give `-ac`, as in ffuf, so a command line moved over returns ffuf's matches.
- `dirs` switches calibration off when you give `-fc`, `-fs`, `-fw`, `-fl` or `-fr` (`dirs` has no `-ft`). A command line moved from ffuf that has its own filters is filtered by hand, and sends no calibration guesses. The summary says so.
- Either command needs the keyword `FUZZ`, or the one `-ack` names. Without it a note says nothing was calibrated.
- **Scope.** The host in `-u` is the scope, unless `-allow`, `-deny` or `-scope` say otherwise. An input that would go to another host is counted and not sent.
- A header that names a host is held to the scope too, because a front end routes by it. These are `Host`, `X-Forwarded-Host`, `X-Host` and `X-Original-Host`. With no `-allow`, `-deny` or `-scope`, a host you name in a header joins the targets you named. With a rule, a header naming a host outside it is refused before anything is sent. See [Concepts](CONCEPTS.md).
- So `-u https://10.0.0.5/ -H 'Host: app.example.com'` and `-H 'Host: FUZZ.example.com'` run as in ffuf. With `-allow 10.0.0.5`, a word that names another host is counted and not sent.
- A `Host` from a `-request` file is not typed by you. One that differs from `-u` is refused unless `-allow` names it.
- **Budget and pace.** Every request, calibration included, counts against `-max-requests` and `-rate`, goes in the ledger and stops at the kill file.
- `-rate` also paces the calibration guesses. ffuf sends its calibration unpaced, so a low-rate sweep takes longer than ffuf's and stays within your rate. This holds for `dirs` without a filter, and for `fuzz -ac`. See [dirs](commands/dirs.md).
- **Dead target.** Five unanswered requests in a row stop the run with exit 3. `-se` makes it twice `-t` failures of any kind, as in ffuf.
- **Not in `fuzz`.** ffuf's scrapers, `-search` and its history files are not there. `-db FILE` keeps the matches. There is no audit log: the hash-chained `-ledger` is the record.
- **`dirs` follows ffuf's counting and its defaults.** That is 40 guesses in flight, no pace, and the matcher `-mc 200-299,301,302,307,401,403,405,500`.
- **Headers.** `fuzz` and `dirs` send what ffuf sends: no `Accept`, `Accept-Encoding: gzip` and your `-H` headers. The `User-Agent` is a current Chrome's, not `Fuzz Faster U Fool`. A size does not depend on it unless the app answers by it, so a `-fs` taken from ffuf filters the same answers.
- **Every word is asked.** A sweep requests `/logout` and the like, as ffuf does, with a session or without one. `-deny-path REGEX` is the one way to hold a word back.

### Examples

<!-- azhaq: fuzz dirs -->

```
azhaq dirs -u https://app.example.com/ -e php,bak
azhaq fuzz -u https://app.example.com/FUZZ -w common.txt -e .php,.bak -recursion -mc 200,301
azhaq fuzz -u https://10.0.0.5/ -H 'Host: FUZZ.example.com' -w subdomains.txt -fs 4242
```

- `common.txt` and `subdomains.txt` are wordlists of yours. SecLists has both.
- `fuzz` has no built-in list and stops with exit 2 without `-w`.
- `dirs` carries SecLists' `common.txt`, so its first line needs none.

### What azhaq adds

<!-- azhaq: fuzz dirs -->

- `-db FILE` keeps the matches in the workspace.
- `azhaq fuzz` with `-maxtime` or Ctrl-C prints the command that continues it. `azhaq resume` does too, with `-db`.
- `-control FILE` steers a run that is going: `rate 2`, `pause`, `fs 4242` or `stop`.
- The hash-chained ledger, the budget and the kill file hold every request.

## gau: `azhaq urls`

<!-- azhaq: urls -->

Behaviour, fields and edge cases: [`azhaq urls`](commands/urls.md).

| gau | azhaq | Note |
| --- | --- | --- |
| `example.com` | `example.com` | Domains as arguments, or `-d`, `-dL FILE`, or stdin. |
| `--subs` | `-subs` | The default is the name given, as in gau. |
| `--providers wayback,otx` | `-providers wayback,otx` | `commoncrawl`, `urlscan` and `arquivo` too. All five by default. |
| `--mc 200`, `--fc 404`, `--mt text/html`, `--ft image/png` | `-mc 200`, `-fc 404`, `-mt text/html`, `-ft image/png` | Filters on what the archive recorded. See the OTX point below. |
| `--from 202401`, `--to 202412` | `-from 202401`, `-to 202412` | |
| `--blacklist png,jpg` | `-blacklist png,jpg` | |
| `--fp` | `-fp` | One URL for each host and path. |
| `--o FILE` | `-o FILE` | Appends, as gau does. |
| `--json` | `-json` | `{"url","source"}`. |
| `--threads 5` | `-urls-threads 5` (or `-threads`) | Domains asked at once. All five archives of a domain run together. |
| `--timeout 45` | `-urls-timeout 3m` | The time each archive gets for a domain. azhaq's `-timeout` stops the whole run. |
| `--retries 2` | `-retries 2` | |
| `--proxy URL` | `-proxy URL` | |
| `--config FILE` | `-config FILE` | gau's TOML. `~/.gau.toml` is read when it exists. |
| `--verbose`, `--version` | `-v`, `-version` | |

### What differs on purpose

<!-- azhaq: urls -->

- A fifth archive, arquivo.pt, is asked.
- gau sends one filter for each value of `-mc 200,301`, and the archive ANDs them, so it keeps nothing. azhaq sends the values as alternatives of one filter.
- gau's `--blacklist png` matches nothing, because it compares `.png` with `png`. `-blacklist` takes either spelling.
- gau's `--fp` prints nothing in version 2.2.4. azhaq's `-fp` keeps the first URL of each host and path.
- TLS certificates are checked.
- The output is de-duplicated and has no scanner payloads or trailing punctuation. `-raw` prints what the archives gave, unchanged. The benchmark in the README counts how many of gau's URLs azhaq's list holds.
- OTX gives each URL a status (`httpcode`, 0 when it has none) and urlscan.io each page a status and a type. gau 2.2.4 sends neither `--mc` nor `--fc` to them and prints every URL. azhaq judges them: `-mc 200` keeps the URLs recorded as 200 and drops one with no recorded status, `-fc 404` leaves out the 404s and keeps one with none. An archive that keeps no type or date, OTX, is asked all the same and its URLs are kept unfiltered, with a note such as `otx has no type of its captures: its 13 URLs are not filtered by -mt`.
- A 429 or a 503 is asked again after its `Retry-After`, however long, or after 2, 5, 10, 20 and 30 seconds. This lasts as long as the archive's `-urls-timeout` and the run's `-timeout` allow. A network error is asked again 3 times.
- A source that still failed is named in the summary with its tries and the server's words, and the exit code is 3. gau exits 0. An example is `wayback: failed after 4 tries, 429 Too Many Requests`.
- Each archive is asked at its own pace. The default pause between one archive's requests is 1 s for the Wayback Machine and Common Crawl, 0.5 s for OTX, 2 s for urlscan.io and none for Arquivo. `-urls-pause` changes it: [urls](commands/urls.md#flags).

### Examples

<!-- azhaq: urls -->

```
azhaq urls -d example.com -silent
azhaq urls example.com -subs -mc 200 -blacklist png,jpg,css -fp
azhaq urls -dL domains.txt -providers wayback,commoncrawl -from 2024 -json -o urls.jsonl
```

### What azhaq adds

<!-- azhaq: urls -->

- `-timeout` with `azhaq resume`.
- `-db` and `-json` summaries.
- `-fail-on-errors` and `-fail-on-capped` for CI.
- A page cap, with a note when an archive had more to read.

## arjun: `azhaq params`

<!-- azhaq: params -->

Behaviour, fields and edge cases: [`azhaq params`](commands/params.md).

| arjun | azhaq | Note |
| --- | --- | --- |
| `-u URL` | `-u URL` | Repeatable. |
| `-i FILE` | `-i FILE` (or `-l FILE`) | A file of URLs, a Burp XML export or a raw HTTP request. |
| `-m GET\|POST\|JSON\|XML` | `-X GET\|POST\|JSON\|XML` | A body sends requests that may change data on the target. |
| `-w FILE` | `-w FILE` | Also `small`, `medium` or `large`. `large`, 6,500 names, is the default. |
| `-t 5` | `-t 5` | Requests in flight per page. |
| `-d SECONDS` | `-d SECONDS` | Delay before each request, one at a time. |
| `-T 15` | `-T 15` | Seconds to wait for a request. |
| `-c 250` | `-c 250` | Names per request at most. |
| `--headers` | `-H 'K: V'` | Repeatable. `-cookie` sets cookies. |
| `--include DATA` | `-include DATA` | A query, a form, a JSON object or XML. A `$arjun$` template is accepted. |
| `--stable` | `-stable` | |
| `--passive` | `-passive` | Names the archives hold for the domain. |
| `--casing snake` | `-casing snake` | |
| `-oJ FILE` | `-oJ FILE` | `{"URL": {"params": [...], "method": "GET", "headers": {...}}}`. |
| `-oT FILE` | `-oT FILE` | |
| `-oB HOST:PORT` | `-oB HOST:PORT` | Send each page with its names through a proxy such as Burp. |
| `-q` | `-silent` | |
| `--rate-limit N` | `-rate N` | Requests per second per host. |

### What differs on purpose

<!-- azhaq: params -->

- A page that answers any name is judged against random names of the same lengths. Such a page prints the query string back or counts the names. arjun has no control request. Reflection is told apart by a random token.
- The built-in list is 6,500 names, which is `-w large`. arjun's `large` is longer. Use `-w FILE` for a list of your own. Names are sent in the order given, without duplicates.
- When a long query is refused with 414, the group of names shrinks.
- A page that rate-limits with 429, 418 or 503, or leaves requests unanswered, fails with exit 3 and a note. It is not a silent empty list.
- Every name of the list is sent, with a session or without one. A page that `-deny-path REGEX` matches is not searched, and a note says so.

### Examples

<!-- azhaq: params -->

```
azhaq params -u https://app.example.com/search
azhaq params -u https://app.example.com/search -w burp-parameter-names.txt -rate 5 -oJ params.json
azhaq params -i burp-export.xml -allow app.example.com -X POST
```

- `burp-parameter-names.txt` is SecLists' file. Without `-w`, azhaq uses its own list of 6,500 names.
- `burp-export.xml` is a Burp "Save items" file of yours.
- `-X POST` sends the names in a body, which can change data.

### What azhaq adds

<!-- azhaq: params -->

- `why` for every name: `status`, `size`, `reflected` and more.
- Pages in parallel.
- Scope, budget, ledger and the kill file.
- `-db` for `query` and `export`.

## naabu: `azhaq ports`

<!-- azhaq: ports -->

Behaviour, fields and edge cases: [`azhaq ports`](commands/ports.md).

| naabu | azhaq | Note |
| --- | --- | --- |
| `-host a,b`, `-l FILE` | `-host a,b`, `-l FILE` | Names, addresses, `host:port`, URLs, CIDR ranges and AS numbers such as `AS13335`. Also as arguments or on stdin. |
| `-p 80,443,8000-9000`, `-p -` | the same | `-p -` or `-p full` is every port. |
| `-tp 100`, `-tp 1000`, `-tp full` | the same | Also `-p top-100`. The default is the top 100. |
| `-pf FILE`, `-ep LIST` | `-pf FILE`, `-ep LIST` | Ports to add, and ports to take out. |
| `-eh`, `-ef` | `-eh`, `-ef` | Hosts not to scan. `-deny` does the same. |
| `-rate 1000` | `-rate 1000` | Connects per second. The default is 1500, as naabu's connect scan. `127.0.0.1` is not paced unless a rate is given. |
| `-c 25` | `-c 25` | Connects in flight. The default is as many as the rate allows, up to 20,000. naabu's is 25. |
| `-retries 1` | `-retries 1` | More passes over the ports that did not answer. |
| `-timeout 1000` in ms | `-connect-timeout 1000` | The wait for one connect. azhaq's `-timeout` is how long the run may take. |
| `-j`, `-json`, `-csv` | the same | naabu's fields, and `service`, `product`, `version`, `title` and `banner`. |
| `-o FILE`, `-silent`, `-v`, `-nc` | the same | |
| `-sV`, `-nmap-cli 'nmap -sV'` | `-detect all` | The default. `-detect none` connects and closes. `-detect banner` reads what the service says. |
| `-Pn`, `-sn` | `-Pn`, `-sn` | `-Pn` is the default. `-wn` scans only the addresses that are up. |
| `-sa`, `-iv 4` | `-sa`, `-iv 4` | |
| `-cdn`, `-ec` | `-cdn`, `-cdn-full` | A CDN or WAF address is asked ports 80, 443, 8080 and 8443 only, and the row says `cdn`. `-cdn-full` scans it in full. |
| `-source-ip IP`, `-proxy` | `-source-ip IP`, `-proxy` | `-proxy-auth` too. |
| `-cp DATA` | `-cp DATA` | Sent to each open port before reading. |
| `-lof`, `-eof` | `-lof`, `-eof` | |
| `-oX`, `-oG`, `-oA` | the same | nmap's XML and greppable files. azhaq has them; naabu does not. |

### What differs on purpose

<!-- azhaq: ports -->

- The scan is a connect scan, and nothing needs root. naabu's SYN scan is not here.
- The ports of a host are asked in a random order, likeliest first. `-order asc` asks them by number, and `-seed N` repeats an order.
- By default one pass is made, and one more over the ports that neither accepted nor refused. naabu's `-retries` default is 3 passes. `-retries N` changes the number.
- Open ports are named by what they answer, with products and versions. No copy of nmap's data is used: see the next section.
- By default `ports` names the service of each open port, as `nmap -sV` does. That costs a second or two on top of the connect scan. `-detect none` connects and closes, and matches naabu's time and output.
- A host that answers every port is cut with `-pts N`, which stops after N open ports.

### Examples

<!-- azhaq: ports -->

```
azhaq ports -host scanme.nmap.org -p top-1000 -json
azhaq ports 10.0.0.0/16 -p 22,80,443 -wn -rate 2000
azhaq ports -l hosts.txt -tp 1000 -ep 25,3306 -T2 -oA scan
```

### What azhaq adds

<!-- azhaq: ports -->

- UDP ports with no root: `-udp` and `-pu`.
- TLS and the certificate's names on every silent port.
- The scope, the budget and the kill file.
- A ledger of every connection.
- `-db` with `azhaq resume`.

## nmap `-sV` and `-sU`: `azhaq ports`

<!-- azhaq: ports -->

Only the part of nmap that finds open ports and names their service is covered. These are not there:

- OS detection, as in `nmap -O`.
- Scripts, as in `nmap -sC` and `nmap --script`.
- Raw-packet scans, as in `nmap -sS` and `nmap -sA`.

A connect scan is what runs, and it needs no privileges. Behaviour, fields and edge cases: [`azhaq ports`](commands/ports.md).

| nmap | azhaq | Note |
| --- | --- | --- |
| `-p 22,80,8000-9000`, `-p-` | `-p 22,80,8000-9000`, `-p -` | |
| `--top-ports 1000` | `-tp 1000` (or `-p top-1000`) | |
| `-iL FILE` | `-l FILE` | |
| `--exclude H`, `--excludefile F` | `-eh H`, `-ef F` | |
| `-sV` | `-detect all` | The default: product and version from what the port says first or answers. `nmap --version-intensity` has no equivalent. |
| `-sU`, `-p U:53` | `-udp`, `-pu 53` | `-pu top`, `-pu 1-1024` and `-pu top,5354` also work. `-p none` leaves TCP out. |
| `-Pn`, `-sn` | `-Pn`, `-sn` | |
| `-T0` to `-T5` | `-T0` to `-T5` | Set rate, connect timeout and retries. An explicit flag wins. |
| `--min-rate N`, `--max-retries N` | `-min-rate N`, `-max-retries N` | |
| `-oX FILE`, `-oG FILE`, `-oA BASE` | the same | `-oA` writes `BASE.json`, `BASE.xml` and `BASE.gnmap`. `-` is stdout. |
| `-n` | | DNS is not a step of a scan of addresses. |

### What differs on purpose

<!-- azhaq: ports -->

- **UDP needs no root.** Each port gets one harmless datagram on a connected socket. A reply is `open`, an ICMP "port unreachable" is `closed`, and silence after every request its protocol has is `open|filtered`. Nothing logs in, guesses a credential or changes state. See [UDP, products and versions](commands/ports.md#udp-products-and-versions).
- **Versions come from a few connections.** A port that speaks first is named from what it says, on the one connection. One that waits is asked HTTP and TLS, then one harmless request of each protocol that waits to be asked. [The ports page](commands/ports.md#udp-products-and-versions) lists those protocols.
- An open port costs at most 24 more connects, all counted, paced and in the ledger. nmap's `-sV` can send many more probes to one port.
- **Open ports are what is printed.** Ports that neither accepted nor refused a connect are named in the summary and in the workspace row's `filtered_ports`. An open port may hide among them.

### Examples

<!-- azhaq: ports -->

```
azhaq ports -host 192.0.2.7 -p 22,80,443,3306 -json
azhaq ports -host 192.0.2.7 -p none -pu top -oX scan.xml
azhaq ports -host 192.0.2.0/28 -tp 1000 -T4 -oA scan
```

### What azhaq adds

<!-- azhaq: ports -->

- The scope, the budget, the kill file and a ledger of every connection.
- `-oX` files that `azhaq shots -nmap` and `azhaq ingest` read.
- One JSON object per port, for a script.

## asnmap: `azhaq asn`

<!-- azhaq: asn -->

Behaviour and fields: [`azhaq asn`](commands/asn.md).

| asnmap | azhaq | Note |
| --- | --- | --- |
| `-a AS64500` | `-a AS64500` | Repeatable. azhaq also takes `as64500` and `64500`. |
| `-f FILE` | `-l FILE` | A file of AS numbers. `-l -` reads stdin, and so does a pipe with no `-a`. |
| `-json` | `-json` | `{"as_number","as_name","prefix"}`, one object for each prefix. |
| `-o FILE` | `-o FILE` | |
| `-silent`, `-v` | `-silent`, `-v` | |
| `-i`, `-d`, `-org` | | Not in azhaq. |
| `-csv`, `-v6`, `-r`, `-p`, `-config`, `-auth` | | Not in azhaq. |

### What differs on purpose

<!-- azhaq: asn -->

- `azhaq asn` takes AS numbers only. It does not look up an IP address, a domain or an organization, as `asnmap -i`, `asnmap -d` and `asnmap -org` do.
- It lists the prefixes an autonomous system announces, from RIPEstat. It needs no key.
- `-json` prints one object for each prefix. `asnmap -json` prints one object for each AS, with the prefixes in an `as_range` list, and adds `input` and `as_country`.

### Examples

<!-- azhaq: asn -->

```
azhaq asn -a AS13335
azhaq asn -l asns.txt -json
echo AS13335 | azhaq asn -silent
```

`asns.txt` is a list of yours, one AS number a line.

### What azhaq adds

<!-- azhaq: asn -->

- `azhaq ports` and `azhaq run -asn` take an AS number as a target and expand it to its prefixes.
- `-db` keeps the graph for `query`, `show`, `export` and `diff`.

## gowitness: `azhaq shots`

<!-- azhaq: shots -->

Behaviour, fields and edge cases: [`azhaq shots`](commands/shots.md).

| gowitness | azhaq | Note |
| --- | --- | --- |
| `scan single -u URL` | `shots -u URL` | The path and query are kept. |
| `scan file -f FILE` | `shots -l FILE` | Or stdin. |
| `scan cidr -c 192.0.2.0/24` | `shots -u 192.0.2.0/24` (or `-cidr`) | |
| `scan nmap -f scan.xml` | `shots -nmap scan.xml` | Every open port is tried, as in gowitness. `-open-only`, `-service`, `-service-contains`, `-p`, `-skip-port` and `-hostnames` narrow it. |
| `scan nessus -f scan.nessus` | `shots -nessus scan.nessus` | |
| `--port 8000`, `--ports-small` | `-p 8000`, `-p small` | `medium` and `large` too. |
| `--no-http`, `--no-https` | `-no-http`, `-no-https` | |
| `--random` | `-random` | |
| `--screenshot-path DIR` | `-dir DIR` | The default is `screenshots`. |
| `--screenshot-fullpage` | `-shot-fullpage` | |
| `--screenshot-format jpeg` | `-shot-format jpeg` | gowitness writes jpeg by default; azhaq writes png. |
| `--screenshot-jpeg-quality 60` | `-shot-quality 60` | |
| `--delay 3` | `-shot-wait 3s` | The default is 1.5 s here and 3 s in gowitness. |
| `--timeout 60` | `-shot-timeout 60s` | |
| `--threads 6` | `-tabs 6` | Chrome tabs in one Chrome. |
| `--javascript-file FILE` | `-shot-js FILE` | |
| `--http-code-filter 200` | `-shot-codes 200` | |
| `--chrome-path`, `--chrome-proxy` | `-chrome`, `-chrome-proxy` | |
| `--chrome-user-data-dir DIR` | `-chrome-profile DIR` | |
| `--chrome-header 'K: V'` | `-H 'K: V'` | |
| `--chrome-window-x`, `--chrome-window-y` | `-shot-size 1440x900` | The default is 1440x900 here and 1280x720 in gowitness. |
| `--write-jsonl` | `-json` | One object per page. |
| `--write-csv` | `-csv FILE` | |
| the page's HTML is in its database | `-shot-html` | The rendered HTML, kept beside the picture. |
| `report server`, `report generate` | `export -format html` | One file with the pictures embedded. |

### What differs on purpose

<!-- azhaq: shots -->

- **Chrome is held to the scope and the budget.** Every request of every page, frame and worker is checked first. A page's own writes are refused and mapped, every download is refused, and popups close. Each request counts against `-max-requests` and `-rate`. gowitness loads whatever a page asks for.
- At a set `-rate`, a page's time runs from when it last moved, so a slow pace gives whole pictures. A picture taken before the page's images and scripts loaded is marked `partial`, and the run exits 3.
- A page the budget cannot cover is not shot, and the summary says how many requests it needed.
- `-nmap` ports that nmap did not name a web service are fan-out: when they do not answer they are listed and the exit stays 0. A dead port nmap named http exits 3.
- `-nmap` tries only ports nmap found open; gowitness also tries the others unless `--open-only`. `-open-only=false` matches gowitness.
- Chrome saves nothing to disk but the picture.
- `-shot-js` runs your script on the target's page. It is yours to scope.
- There is one row for each name. Failures list a retry hint: `azhaq query -failed`.

### Examples

<!-- azhaq: shots -->

```
azhaq shots -l services.txt -dir shots
azhaq shots -u http://127.0.0.1:3001/rest/products/search -shot-format jpeg -shot-quality 60
azhaq shots -nmap scan.xml -shot-fullpage -tabs 6 -rate 5
```

- `shots` needs Chrome or Chromium on the machine.
- `services.txt` lists URLs or `host:port`, one a line.
- The second line expects a Juice Shop on port 3001: `docker run -p 3001:3000 bkimminich/juice-shop`.
- `scan.xml` is nmap's XML, which `azhaq ports -oX scan.xml` also writes.

### What azhaq adds

<!-- azhaq: shots -->

- The response headers, TLS session, technologies, console messages and network log of every page, in `-json`.
- Look-alike pages grouped by a perceptual hash in `azhaq export -format html`.
- The screenshots next to the rest of the map in one workspace, with `-db`.
- `azhaq resume` for a page the budget capped.

## notify: `azhaq notify`

<!-- azhaq: notify watch -->

Behaviour and provider keys: [`azhaq notify`](commands/notify.md).

| notify | azhaq | Note |
| --- | --- | --- |
| `-i FILE`, `-data FILE` | `-i FILE`, `-data FILE` | Or stdin. |
| `-pc FILE`, `-provider-config FILE` | `-pc FILE`, `-provider-config FILE` | Without it azhaq reads `~/.config/azhaq/notify.yaml`, else notify's `~/.config/notify/provider-config.yaml`. |
| `-p slack,discord`, `-provider` | `-p slack,discord`, `-provider` | Slack, Discord, Telegram, Teams, Google Chat, Pushover, Gotify, SMTP and a custom URL. |
| `-id recon` | `-id recon` | |
| `-bulk`, `-cl 4000` | `-bulk`, `-cl 4000` | |
| `-mf 'x {{data}}'` | `-mf 'x {{data}}'` | |
| `-rl 1`, `-d 0.5` | `-rl 1`, `-d 0.5` | |
| `-proxy URL` | `-proxy URL` | |
| `-config FILE` | `-config FILE` | |
| `-silent`, `-v`, `-nc`, `-duc` | the same | `-nc` and `-duc` are accepted and change nothing. |

### What differs on purpose

<!-- azhaq: notify watch -->

- A delivery that did not arrive is named in the summary, and the exit code is 3. notify logs it and exits 0.
- A 429 or a 5xx is tried again: three tries, with `Retry-After` honoured. A message longer than a service takes is sent in parts, not cut.
- A webhook URL is never printed. An error names the host and what went wrong, not the path or query. `-notify @FILE` and `AZHAQ_NOTIFY` keep URLs off the command line in `watch`.
- Certificates are verified, including through `-proxy`. azhaq checks for no updates.

### Examples

<!-- azhaq: notify watch -->

Every line below needs a provider config: `-pc FILE`, or `~/.config/azhaq/notify.yaml`, or notify's own file. Without one azhaq stops with exit 2 and sends nothing.

```
azhaq subs -d example.com -live | azhaq notify -bulk -pc provider-config.yaml
azhaq notify -i report.txt -p slack,discord -id recon -mf 'recon {{date}}: {{data}}' -pc provider-config.yaml
azhaq ports -host 127.0.0.1 -json | azhaq notify -p custom -rl 2 -pc provider-config.yaml
```

- `report.txt` is any text file.
- The first line sends to every entry of the config file, so all of them must be reachable.
- `-p custom` narrows the third line to a receiver of yours on port 8000.
- Put your own webhook URLs in the first two entries.
- The keys are notify's, listed for each provider in [commands/notify.md](commands/notify.md#providers).

A sample `provider-config.yaml`:

```yaml
slack:
  - id: recon
    slack_webhook_url: https://hooks.slack.com/services/T000/B000/XXXX
discord:
  - id: recon
    discord_webhook_url: https://discord.com/api/webhooks/ID/TOKEN
custom:
  - id: lab
    custom_webhook_url: http://127.0.0.1:8000/hook
    custom_method: POST
    custom_format: '{"text":{{dataJsonString}}}'
```

### What azhaq adds

<!-- azhaq: notify watch -->

`azhaq watch` runs a recon again and again and sends only what changed:

```
azhaq watch -db h1.db -every 24h -notify-config provider-config.yaml -- -scope hackerone -program acme
```

- A change is a new host or a new API route a deploy added. When nothing changed, nothing is sent.
- The message carries the change as JSON for a receiver to act on.
