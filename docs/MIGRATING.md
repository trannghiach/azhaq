# Moving to azhaq from another tool

If you know subfinder, dnsx, httpx, katana, ffuf, gau, arjun, naabu, nmap, gowitness or notify, you can start with the command lines you have. Each azhaq command that stands in for one takes that tool's flags where they make sense and prints its field names with `-json`. This page lists, tool by tool, the spelling of the flags people use, what is different on purpose, and what azhaq adds.

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
| gowitness | `azhaq shots` | [gowitness](#gowitness-azhaq-shots) |
| notify | `azhaq notify` | [notify](#notify-azhaq-notify) |

## What is the same for every command

- A flag may have one dash or two (`-silent` or `--silent`). A flag a command does not have stops it with exit 2 before anything is sent, and `azhaq help COMMAND` lists the flags it has. `azhaq help -json` lists them for a program.
- Results go to stdout, one per line, as the tool prints them. A summary goes to stderr: what failed, what was left alone, which limit stopped it. With `-json` the results are JSON lines and the summary is one JSON object.
- Exit codes are the same everywhere: `0` complete, `1` error, `2` usage, `3` finished with failures, `4` stopped by a limit or the kill file. The tools above exit 0 after most of these; a script that checks `$?` sees more than it did.
- `probe`, `crawl`, `ports`, `dirs`, `fuzz`, `params` and `shots` take `-allow`, `-deny` and `-scope` (a program's scope), `-max-requests`, `-kill-file`, `-ledger` and `-rate`; `dns` takes the three scope flags. `subs`, `urls` and `notify` send nothing to a target, so they have none of these. Nothing is sent to a host outside the scope.
- `-db FILE` keeps what a command found in a workspace, so that `query`, `show`, `export`, `diff`, `watch` and `resume` can work on it. Without it the command uses a temporary one.
- The output of one command feeds the next: `azhaq subs -d example.com -silent | azhaq dns -silent | azhaq probe -json`.

A table below has the other tool's flag on the left and azhaq's on the right. A flag with no azhaq column is one azhaq does not have, and the note says what to do instead. Flags are written for the tool's current release; azhaq's `-json` field names follow the tool's.

## subfinder: `azhaq subs`

<!-- azhaq: subs -->

| subfinder | azhaq | Note |
| --- | --- | --- |
| `-d example.com` | `-d example.com` | A comma list, a URL or a name with a trailing dot, as subfinder takes it; `-d` may also repeat. |
| `-dL FILE` | `-dL FILE` | `-dL -` reads stdin, and so does a pipe with no `-d`. |
| `-s a,b` | `-sources a,b` | The sources to run. |
| `-es a,b` | `-exclude-sources a,b` | |
| `-all` | `-all-sources` | Also the slower sources outside the default set. |
| `-nW` | `-live` (or `-nW`) | Only names that resolve; wildcard answers are left out. `subfinder -nW` is the same job as subfinder piped to dnsx. |
| `-r 1.1.1.1,8.8.8.8` | `-resolvers 1.1.1.1,8.8.8.8` | A file or a comma list; `udp:`, `tcp:`, `dot:` and `doh:` prefixes. |
| `-pc FILE` | `-providers FILE` | API keys per source. Without it azhaq reads `~/.config/azhaq/providers.yaml`, else subfinder's `provider-config.yaml`. |
| `-timeout 30` | `-source-timeout 30s` | How long each source gets. azhaq's `-timeout` is the whole run's. |
| `-oJ`, `-json` | `-json` (or `-oJ`) | `{"host","input","source","sources"}`, plus `unverified` and `wildcard_certificate` when they apply. |
| `-o FILE` | `-o FILE` | |
| `-silent`, `-v` | `-silent`, `-v` | |
| `-rl N`, `-rls a=N/s` | `-source-rate N`, `-source-rates a=N/s` | Requests a second to each source, or to single ones; a source's own lower pace stays. |
| `-max-time`, `-mr`, `-rsr`, `-proxy` | `-max-time`, `-max-results`, `-max-body`, `-proxy` | |
| `-t` | `-t` | Work items in flight. `-timeout` is the whole run's; `azhaq resume` continues it. |
| `-ls`, `-oD DIR`, `-cs`, `-oI`, `-recursive`, `-stats` | `-ls`, `-oD DIR`, `-cs`, `-oI`, `-recursive`, `-stats` | `-oI` needs `-live`. |
| `-m`, `-f` | `-m`, `-f`, `-match-regex`, `-filter-regex` | |
| `-ei` | `-ei` | Accepted; an IP address given as a domain is always left out with a note. |

What differs on purpose:

- A name appears once, however many sources gave it; `source` is the first and `sources` all of them.
- Sources the default set leaves out stay out; `-all-sources` runs them. A source that needs a key and has none is listed `needs a key`, not skipped without a word.
- A run in which every source failed is `degraded` and exits 3, not 0 with an empty list. The summary names each source that failed.
- Azhaq keeps the names it found for a domain and checks them again in the next run; with `-live` a name that no longer resolves drops out, without it a stored name is listed with `"unverified": true`, as are subdomain.center's guesses. `-no-history` turns the history off.

Three command lines:

```
azhaq subs -d example.com -silent
azhaq subs -dL domains.txt -live -json -o names.jsonl
azhaq subs -d example.com -live -source-rate 2 -dns-rate 5 -resolvers 1.1.1.1,8.8.8.8
```

On top: `-live` checks names against the zone's wildcard (per parent zone, with CNAME targets). `-w WORDS` also resolves `WORD.domain` for each word, and `-permute` resolves variations of what was found. A CNAME to a name that no longer exists, an unclaimed domain or a hosting service's "no such site" page is listed as a takeover candidate with its evidence. The summary says what each source gave, and how much of what the independent sources know this run holds (`coverage:`). `-db` keeps the names for `query` and `diff`.

## dnsx: `azhaq dns`

<!-- azhaq: dns -->

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
| `-r 1.1.1.1,tcp:9.9.9.9` | `-resolvers 1.1.1.1,tcp:9.9.9.9` (or `-r`) | `udp:`, `tcp:`, `dot:` and `doh:` prefixes. |
| `-rl 50` | `-rl 50` | Names asked per second over all resolvers. |
| `-t 100` | `-t 100` | Names resolved at once; the default is 100 in both. |
| `-retry 2` | `-retry 3` | Attempts per question; azhaq's default is 3. |
| `-timeout 3s` | `-timeout 3s` | The wait for one DNS answer, as dnsx. The run's own bound is `-maxtime`. |
| `-wd zone`, `-auto-wildcard` | `-wildcard-domain zone` (or `-wd`), `-auto-wildcard` (or `-aw`) | See the note on wildcards. |
| `-trace` | `-trace` | Follows the delegations from the root servers. |
| `-asn`, `-cdn` | `-asn`, `-cdn` | |
| `-hf`, `-hc` | `-hostsfile`, `-health-check` | |
| `-stream`, `-stats` | `-stream`, `-stats` | |
| `-proxy socks5://…` | `-proxy socks5://…` | |

What differs on purpose:

- Wildcard answers are always left out, per parent zone, with no domain to give. `-no-wildcard` prints them; `-aw` is accepted and changes nothing. dnsx prints them unless it is given `-wd` or `-aw`.
- `-timeout` is the wait for one answer, as in dnsx; in the other azhaq commands it is how long the run may take. Here the run's bound is `-maxtime SECONDS`.
- `-rl` counts names, as dnsx's does. `-dns-rate N` is a second pace, N queries a second to each resolver, so with 6 resolvers it is up to 6 times N. For a polite run give both: `-rl 5 -t 5`, and a `-resolvers` list of one address if you want 5 queries a second in all.
- `-retry` is 3 where dnsx's is 2. A name that no resolver answers is a failure in the summary and exit 3.

Three command lines:

```
azhaq dns -l names.txt -mx -txt -json -r 1.1.1.1,tcp:9.9.9.9 -rl 50 -t 20
azhaq dns -d example.com -w subdomains.txt -resp
azhaq dns -l 192.0.2.0/24 -ptr -resp
```

On top: a dangling CNAME is listed with the service it points at (a takeover candidate). `-all` and `-resp` print records in dnsx's form, and `-axfr` asks only name servers in scope. `-db` keeps the answers for `query` and `export`, and `-maxtime` stops a long run and the summary says where to go on.

## httpx: `azhaq probe`

<!-- azhaq: probe -->

| httpx | azhaq | Note |
| --- | --- | --- |
| `-u TARGET`, `-l FILE` | `-u TARGET`, `-l FILE` | Or stdin. |
| `-p 80,8000-8100` | `-p 80,8000-8100` | `http:80` or `https:443` asks one scheme. |
| `-path /a,/b` | `-path /a,/b` | A list or a file. |
| `-sc -cl -ct -title -td -server -ip -cname -location -method` | the same | What a row prints. `-web-server` and `-tech-detect` are accepted. |
| `-asn -cdn -favicon -jarm -hash md5,mmh3` | the same | |
| `-tls-grab -tls-probe -csp-probe` | the same | |
| `-mc -fc -ml -fl -mlc -flc -mwc -fwc -mr -fe -ms -fs -mrt -frt` | the same | httpx's matchers and filters. `-ms` and `-fs` take strings; `-fe` filters by regex. |
| `-mdc`, `-fdc` | `-mdc`, `-fdc` | DSL conditions over the `-json` fields. |
| `-fr`, `-maxr`, `-fhr` | `-fr`, `-maxr`, `-fhr` | Follow redirects, how many, same host only. |
| `-x GET,POST`, `-body`, `-rr FILE` | the same | They send what you give: they can change data on the target, and the summary says so. |
| `-H`, `-random-agent` | `-H`, `-random-agent` | |
| `-http-proxy URL`, `-proxy URL` | `-http-proxy URL`, `-proxy URL` | |
| `-sr -srd DIR`, `-irr`, `-irh` | the same | Store responses; add them to the JSON. |
| `-ss` | `-ss` | A screenshot of each front page (Chrome on the machine). |
| `-j`, `-json`, `-csv`, `-md` | the same | |
| `-o FILE`, `-oa FILE` | the same | |
| `-rl 150` | `-rl 150` | Services a second, as httpx counts them: a target's first request waits its turn, its favicon, redirects and second scheme do not. `-rate N` paces every request instead. The default is no pace; httpx's is 150. |
| `-t 50` | `-t 50` | Work items in flight. The default is 16; httpx's is 50. |
| `-timeout 10` | `-req-timeout 10s` | One request's time. azhaq's `-timeout` stops the whole run. |
| `-retries N`, `-maxhr N` | the same | |
| `-silent`, `-nc`, `-v` | the same | |

What differs on purpose:

- `probe` follows no redirect unless given `-fr`, as httpx does. A row's status, title and length are one answer's. `run` and `crawl` follow redirects inside the site.
- A target with no answer is a row with `failed: true`; `-probe` prints `[FAILED]` for it. The summary counts them.
- A name that resolves only because its zone has a wildcard is probed, not dropped, so a list of real hosts is not thinned.
- A bare `host:port` is asked over plain HTTP first on 8080 and on ports above 1024, and over TLS when the plain request is answered 400.
- Every request goes through the scope, the budget, the pace and the ledger. A redirect to another site is recorded and not requested, even with `-fr`.

Three command lines:

```
azhaq probe -l hosts.txt -json
azhaq probe -l hosts.txt -p 80,443,8000-8100 -mc 200,401 -title -td -sc
azhaq probe -l hosts.txt -fr -tls-grab -hash md5 -sr -srd out -json
```

On top: a page that answers like an unknown path is marked `catchall`, a CNAME or a page that names an unclaimed service is a takeover candidate, and `-db` keeps every row for `query`, `show` and `export -format targets`. `-rate` and `-max-requests` hold the run to a request budget, and `azhaq resume` continues it.

## katana: `azhaq crawl`

<!-- azhaq: crawl -->

| katana | azhaq | Note |
| --- | --- | --- |
| `-u URL`, `-list FILE` | `-u URL`, `-l FILE` | Or stdin. |
| `-d 3` | `-d 3` | Link levels below the start URL; 3 is the default in both. |
| `-jc`, `-jsl` | `-jc`, `-jsl` | Accepted. Scripts are always read: routes, calls with their methods and body names, router tables, source maps, API descriptions. |
| `-kb`, `-td`, `-duc` | the same | Accepted and always on. Forms and technologies are always read. |
| `-headless` | `-browser` | Pages are also loaded in Chrome. `-interact` clicks the buttons and menus. |
| `-fs rdn` | `-fs rdn` | The hosts a crawl follows: `rdn`, `fqdn`, `dn` or a regex. Without it a crawl of a name follows its registrable domain and subdomains (`rdn`), and a crawl of an address stays on that address and port. |
| `-ns` | `-ns` | Follow links to any host, still held to `-allow` and `-deny`. |
| `-cs`, `-cos` | `-cs`, `-cos` | Regexes of the URLs to follow or never follow. |
| `-do` | `-do` | Also list the URLs found and left out of scope (never requested). |
| `-f url,path,rdn`, `-sf`, `-sfd` | the same | Fields; one file per field. |
| `-em`, `-ef`, `-mr`, `-fr` | the same | Extension, and regex, filters on the printed URLs. |
| `-ndef` | `-ndef` | |
| `-jsonl`, `-j` | `-jsonl`, `-j` | katana's `{"request","response"}` lines. |
| (none) | `-json` | Not katana's: `{"url","coverage","role","status","methods","params","forms","tech"}`. |
| `-o FILE`, `-silent`, `-nc`, `-v` | the same | |
| `-sr -srd DIR`, `-ob` | the same | |
| `-kf robotstxt,sitemapxml` | `-kf robotstxt,sitemapxml` | |
| `-iqp`, `-pc` | `-iqp`, `-path-climb` (or `-pc`) | One URL for each path whatever its query values; the parent directories of each link. |
| `-rl 150`, `-rlm`, `-hrl`, `-hrlm`, `-rd` | the same | |
| `-c 10`, `-p 10` | `-c 10`, `-p 16` | Requests in flight per host; work items in flight. |
| `-timeout 10` | `-request-timeout 10s` | One request's time. azhaq's `-timeout` stops the run. |
| `-ct 1h` | `-ct 1h` | Stop after this long and keep what was found. |
| `-retry N`, `-mdp N`, `-mrs N` | the same | |
| `-H`, `-proxy`, `-r` | `-H`, `-proxy`, `-r` | |
| `-H 'Cookie: a=b'` | `-cookie a=b`, `-cookie-jar` | `-cookie-jar` carries the cookies a target sets onto the requests that follow. |

What differs on purpose:

- Not asked: a URL whose name says a GET would change something (`/logout`, `/delete?id=1`) is listed, not requested (`azhaq run -all-gets` asks them). A URL with a scanner's payload in it never enters the map. Chrome sends only GET, HEAD and OPTIONS unless `-browser-writes`.
- Redirects are followed inside the site, not to any host. A page with many query variants (`/item?id=N`) is asked 3 times (`-per-template`), the rest are listed.
- `crawl` asks only what a crawler asks. `-sweep` adds the 32 built-in path checks (`robots.txt`, sitemaps, API descriptions, `.git/HEAD`, `admin`, …) and the source map next to each script, as `run` does.
- At a low `-rate` the time is set by the number of requests. On Juice Shop at `-rate 5`, azhaq sends 91 requests in 21 s and katana `-jc -jsl -d 3 -rl 5` about 80 in 17 s. The extra requests are the API routes katana does not find (`/rest/…`, `/api/…`, about 60 more endpoints) and one check per directory that tells a real answer from the page the app gives every unknown path. Unpaced, azhaq is faster (8.5 s against 14.3 s).
- `-json` is azhaq's, not katana's. The map keeps how each URL is known (`called`, `described`, `linked`, `archived`, `guessed`), and `azhaq show -db FILE URL` prints the line of the script that names it.

Three command lines:

```
azhaq crawl -u https://app.example.com/ -d 3 -silent
azhaq crawl -u https://app.example.com/ -jsonl -o crawl.jsonl
azhaq crawl -u https://app.example.com/ -fs rdn -do -f rdn,path -rl 5
```

On top: the routes a frontend's JavaScript calls, with methods and body names; GraphQL schemas; API descriptions read and expanded; forms with their field names; `-login` signs in with Chrome and `azhaq roles` compares what each account can reach. `-db` keeps the map for `query`, `show`, `hunt`, `diff` and `export -format openapi|burp|html`.

## ffuf: `azhaq fuzz` and `azhaq dirs`

<!-- azhaq: fuzz dirs -->

`azhaq fuzz` takes ffuf's flags, counts words, lines and sizes as ffuf does, and calibrates (with `-ac`) and recurses as it does, so a command line moved from ffuf gives the same results. `azhaq dirs` is the short form for the common job: paths from a wordlist, calibrated, with SecLists' `common.txt` built in.

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
| `-ac`, `-acc`, `-acs`, `-ack`, `-ach` | the same | Calibration is off unless `-ac` is given, as in ffuf; `-acc`, `-acs` and `-ach` imply `-ac`. |
| `-recursion`, `-recursion-depth`, `-recursion-strategy` | the same | |
| `-t 40`, `-p 0.1`, `-rate 100` | the same | |
| `-maxtime`, `-maxtime-job` | the same | |
| `-sa`, `-se`, `-sf` | the same | |
| `-x`, `-replay-proxy` | `-x`, `-replay-proxy` | |
| `-timeout 10` | `-timeout 10` | Seconds per request, as ffuf. |
| `-o FILE -of json` | `-o FILE -of json` | Also `ejson`, `csv`, `ecsv`, `html`, `md`, `all`; `-od DIR`, `-or`. |
| `-config FILE` | `-config FILE` | ffuf's TOML. |
| `-s`, `-v`, `-c`, `-V` | the same | |
| `-input-cmd`, `-input-num`, `-input-shell` | the same | |
| `-preflight`, `-postflight` | the same | In ffuf's development version. With `-preflight-var` and `-preflight-mode`. |
| `-http2`, `-sni`, `-raw`, `-ignore-body` | the same | |

| ffuf `-ac` on a path | azhaq `dirs` | Note |
| --- | --- | --- |
| `-u https://h/FUZZ -w words` | `-u https://h/ -w words` | `FUZZ` is not needed. A URL with a path (`-u https://h/api/`) sweeps `/api/WORD`. |
| `-e .php,.bak` | `-e php,bak` | |
| `-mc -ms -mw -ml -mr`, `-fc -fs -fw -fl -fr` | the same | |
| `-t 40` | `-t 40` | |
| `-rate N` | `-rate N` | |
| `-w` left out | | SecLists' `common.txt` (MIT) is built in. |

What differs on purpose:

- **Calibration.** `dirs` calibrates by default, as ffuf with `-ac`; it is switched off when you give `-fc`, `-fs`, `-fw`, `-fl`, `-fr` or `-ft`, since a command line moved from ffuf that has its own filters calibrated by hand, and the summary says so. `fuzz` does not calibrate unless you give `-ac`, as in ffuf, so a command line moved over returns ffuf's matches. Either needs the keyword `FUZZ` (or the one `-ack` names); without it a note says nothing was calibrated.
- **Scope.** The host in `-u` is the scope, unless `-allow`, `-deny` or `-scope` say otherwise. An input that would go to another host is counted and not sent. A header that names a host (`Host`, `X-Forwarded-Host`, `X-Host`, `X-Original-Host`, in `-H` or a `-request` file) is held to the scope as the URL's host is, since a front end routes by it: one the scope leaves out stops the run with exit 2 before the first request (`-H 'Host: app.example.com'` against `-u https://10.0.0.5/` needs `-allow app.example.com`), and one that holds the keyword is checked for each word. `Host: FUZZ.example.com` is still fine: the scope is the domain.
- **Budget and pace.** Every request, calibration included, counts against `-max-requests` and `-rate`, goes in the ledger and stops at the kill file. `-rate` paces every request, the calibration guesses included; ffuf sends its calibration unpaced, so at a low rate a sweep takes about (guesses ÷ rate) seconds longer than ffuf's, and stays within your rate (`dirs`, which calibrates always, and `fuzz -ac`).
- **Dead target.** Five unanswered requests in a row stop the run with exit 3. `-se` makes it twice `-t` failures of any kind, as ffuf's.
- **Not in `fuzz`:** ffuf's scrapers, `-search` and its history files (`-db FILE` keeps the matches), and an audit log (the hash-chained `-ledger` is the record).
- **`dirs` follows ffuf's counting and its defaults**: 40 guesses in flight, no pace, and the matcher `-mc 200-299,301,302,307,401,403,405,500`.
- **Headers.** `fuzz` and `dirs` send what ffuf sends: no `Accept`, `Accept-Encoding: gzip`, your `-H`s. The `User-Agent` is a current Chrome's, not `Fuzz Faster U Fool` (a size does not depend on it unless the app answers by it), so a `-fs` taken from ffuf filters the same answers.
- **Every word is asked.** A sweep requests `/logout` and the like, as ffuf does. Only with a session (`-cookie`, `-H 'Authorization: …'`) does `dirs` hold back the words that look like they change something; `-all-gets` asks them.

Three command lines:

```
azhaq dirs -u https://app.example.com/ -e php,bak
azhaq fuzz -u https://app.example.com/FUZZ -w common.txt -e .php,.bak -recursion -mc 200,301
azhaq fuzz -u https://10.0.0.5/ -H 'Host: FUZZ.example.com' -w subdomains.txt -fs 4242
```

On top: `-db FILE` keeps the matches in the workspace; `azhaq fuzz` with `-maxtime` or Ctrl-C prints the command that continues it and `azhaq resume` does too with `-db`. `-control FILE` steers a run that is going (`rate 2`, `pause`, `fs 4242`, `stop`). The hash-chained ledger, the budget and the kill file hold every request.

## gau: `azhaq urls`

<!-- azhaq: urls -->

| gau | azhaq | Note |
| --- | --- | --- |
| `example.com` | `example.com` | Domains as arguments, or `-d`, `-dL FILE`, or stdin. |
| `--subs` | `-subs` | The default is the name given, as gau's. |
| `--providers wayback,otx` | `-providers wayback,otx` | `commoncrawl`, `urlscan` and `arquivo` too; all five by default. |
| `--mc 200`, `--fc 404`, `--mt text/html`, `--ft image/png` | `-mc 200`, `-fc 404`, `-mt text/html`, `-ft image/png` | An archive that keeps no status or type (OTX, urlscan.io) is asked all the same and its URLs are kept unfiltered, as gau keeps them; a note says so (`otx has no status of its captures: its 13 URLs are not filtered by -mc`). |
| `--from 202401`, `--to 202412` | `-from 202401`, `-to 202412` | |
| `--blacklist png,jpg` | `-blacklist png,jpg` | |
| `--fp` | `-fp` | One URL for each host and path. |
| `--o FILE` | `-o FILE` | Appends, as gau does. |
| `--json` | `-json` | `{"url","source"}`. |
| `--threads 5` | `-urls-threads 5` (or `-threads`) | Domains asked at once; all five archives of a domain run together. |
| `--timeout 45` | `-urls-timeout 3m` | The time each archive gets for a domain. azhaq's `-timeout` stops the whole run. |
| `--retries 2` | `-retries 2` | |
| `--proxy URL` | `-proxy URL` | |
| `--config FILE` | `-config FILE` | gau's TOML; `~/.gau.toml` is read when it exists. |
| `--verbose`, `--version` | `-v`, `-version` | |

What differs on purpose:

- A fifth archive, arquivo.pt, is asked.
- The output is de-duplicated and has no scanner payloads or trailing punctuation. `-raw` prints what the archives gave, unchanged. The benchmark in the README counts how many of gau's URLs azhaq's list holds.
- A 429 or a 503 is asked again after its `Retry-After` (however long) or 2, 5, 10, 20 and 30 seconds, for as long as the archive's `-urls-timeout` and the run's `-timeout` allow; a network error is asked again 3 times. A source that still failed is named in the summary with its tries and the server's words (`wayback: failed after 4 tries, 429 Too Many Requests`) and exit 3. gau exits 0.
- Each archive is asked at its own pace, at most 2 requests a second by default. `-urls-pause` changes the wait between one archive's requests.
- `-timeout` stops the whole run; the time an archive gets for a domain is `-urls-timeout`.

Three command lines:

```
azhaq urls -d example.com -silent
azhaq urls example.com -subs -mc 200 -blacklist png,jpg,css -fp
azhaq urls -dL domains.txt -providers wayback,commoncrawl -from 2024 -json -o urls.jsonl
```

On top: `-timeout` with `azhaq resume`, `-db` and `-json` summaries, `-fail-on-errors` and `-fail-on-capped` for CI, and a page cap with a note when an archive had more to read.

## arjun: `azhaq params`

<!-- azhaq: params -->

| arjun | azhaq | Note |
| --- | --- | --- |
| `-u URL` | `-u URL` | Repeatable. |
| `-i FILE` | `-i FILE` (or `-l FILE`) | A file of URLs, a Burp XML export or a raw HTTP request. |
| `-m GET\|POST\|JSON\|XML` | `-X GET\|POST\|JSON\|XML` | A body sends requests that may change data on the target. |
| `-w FILE` | `-w FILE` | Also `small`, `medium` or `large` (the default, 6,500 names). |
| `-t 5` | `-t 5` | Requests in flight per page. |
| `-d SECONDS` | `-d SECONDS` | Delay before each request, one at a time. |
| `-T 15` | `-T 15` | Seconds to wait for a request. |
| `-c 250` | `-c 250` | Names per request at most. |
| `--headers` | `-H 'K: V'` | Repeatable; `-cookie` for cookies. |
| `--include DATA` | `-include DATA` | A query, a form, a JSON object or XML; a `$arjun$` template. |
| `--stable` | `-stable` | |
| `--passive` | `-passive` | Names the archives hold for the domain. |
| `--casing snake` | `-casing snake` | |
| `-oJ FILE` | `-oJ FILE` | `{"URL": {"params": [...], "method": "GET", "headers": {...}}}`. |
| `-oT FILE` | `-oT FILE` | |
| `-oB HOST:PORT` | `-oB HOST:PORT` | Send each page with its names through a proxy such as Burp. |
| `-q` | `-silent` | |
| `--rate-limit N` | `-rate N` | Requests per second per host. |

What differs on purpose:

- A page that answers any name (one that prints the query string back, or counts the names) is judged against random names of the same lengths. arjun has no control request. Reflection is told apart by a random token.
- The built-in list is 6,500 names (`-w large`), arjun's `large` is longer. Use `-w FILE` for a list of your own; the names are sent in the order given, without duplicates.
- When a long query is refused (414), the group of names shrinks. A page that rate-limits (429, 418, 503) or leaves requests unanswered fails with exit 3 and a note, not with a silent empty list.
- A name that looks like a logout, delete or reset is left out when you give a session (`-cookie`, `-H`), unless `-all-gets` is given.

Three command lines:

```
azhaq params -u https://app.example.com/search
azhaq params -u https://app.example.com/search -w burp-parameter-names.txt -rate 5 -oJ params.json
azhaq params -i burp-export.xml -allow app.example.com -X POST
```

On top: `why` for every name (`status`, `size`, `reflected`, …); pages in parallel; scope, budget, ledger and the kill file; `-db` for `query` and `export`.

## naabu: `azhaq ports`

<!-- azhaq: ports -->

| naabu | azhaq | Note |
| --- | --- | --- |
| `-host a,b`, `-l FILE` | `-host a,b`, `-l FILE` | Names, addresses, `host:port`, URLs, CIDR ranges and AS numbers (`AS13335`); also as arguments or on stdin. |
| `-p 80,443,8000-9000`, `-p -` | the same | `-p -` or `-p full` is every port. |
| `-tp 100`, `-tp 1000`, `-tp full` | the same | Also `-p top-100`. The default is the top 100. |
| `-pf FILE`, `-ep LIST` | `-pf FILE`, `-ep LIST` | Ports to add, and to take out. |
| `-eh`, `-ef` | `-eh`, `-ef` | Hosts not to scan. `-deny` does the same. |
| `-rate 1000` | `-rate 1000` | Connects per second. The default is 1500, as naabu's connect scan; `127.0.0.1` is not paced unless a rate is given. |
| `-c 25` | `-c 25` | Connects in flight. The default is as many as the rate allows, up to 20,000; naabu's is 25. |
| `-retries 1` | `-retries 1` | More passes over the ports that did not answer. |
| `-timeout 1000` (ms) | `-connect-timeout 1000` | The wait for one connect. azhaq's `-timeout` is how long the run may take. |
| `-j`, `-json`, `-csv` | the same | naabu's fields, and `service`, `product`, `version`, `title`, `banner`. |
| `-o FILE`, `-silent`, `-v`, `-nc` | the same | |
| `-sV`, `-nmap-cli 'nmap -sV'` | `-detect all` | The default. `-detect none` connects and closes; `-detect banner` reads what the service says. |
| `-Pn`, `-sn` | `-Pn`, `-sn` | `-Pn` is the default; `-wn` scans only the addresses that are up. |
| `-sa`, `-iv 4` | `-sa`, `-iv 4` | |
| `-cdn`, `-ec` | `-cdn`, `-cdn-full` | A CDN or WAF address is asked ports 80, 443, 8080 and 8443 only, and the row says `cdn`; `-cdn-full` scans it in full. |
| `-source-ip IP`, `-proxy` | `-source-ip IP`, `-proxy` | `-proxy-auth` too. |
| `-cp DATA` | `-cp DATA` | Sent to each open port before reading. |
| `-lof`, `-eof` | `-lof`, `-eof` | |
| `-oX`, `-oG`, `-oA` | the same | nmap's XML and greppable files; azhaq has them, naabu does not. |

What differs on purpose:

- The scan is a connect scan, and nothing needs root. naabu's SYN scan is not here.
- The ports of a host are asked in a random order, likeliest first (`-order asc` for numbers, `-seed N` to repeat). By default one pass is made, and one more over the ports that neither accepted nor refused (naabu's `-retries` default is 3 passes); `-retries N` changes it.
- Open ports are named by what they answer, with products and versions; no copy of nmap's data is used (see the next section).
- A host that answers every port is cut with `-pts N` (stop after N open ports).

Three command lines:

```
azhaq ports -host scanme.nmap.org -p top-1000 -json
azhaq ports 10.0.0.0/16 -p 22,80,443 -wn -rate 2000
azhaq ports -l hosts.txt -tp 1000 -ep 25,3306 -T2 -oA scan
```

On top: UDP ports with no root (`-udp`, `-pu`), TLS and the certificate's names on every silent port, the scope, the budget and the kill file, a ledger of every connection, and `-db` with `azhaq resume`.

## nmap `-sV` and `-sU`: `azhaq ports`

<!-- azhaq: ports -->

Only the part of nmap that finds open ports and names their service is covered. There is no OS detection (`nmap -O`), no scripts (`nmap -sC`, `nmap --script`) and no raw-packet scan (`nmap -sS`, `nmap -sA`); a connect scan is what runs, and it needs no privileges.

| nmap | azhaq | Note |
| --- | --- | --- |
| `-p 22,80,8000-9000`, `-p-` | `-p 22,80,8000-9000`, `-p -` | |
| `--top-ports 1000` | `-tp 1000` (or `-p top-1000`) | |
| `-iL FILE` | `-l FILE` | |
| `--exclude H`, `--excludefile F` | `-eh H`, `-ef F` | |
| `-sV` | `-detect all` | The default: product and version from what the port says first or answers. `nmap --version-intensity` has no equivalent. |
| `-sU`, `-p U:53` | `-udp`, `-pu 53` | `-pu top`, `-pu 1-1024` and `-pu top,5354` also work; `-p none` leaves TCP out. |
| `-Pn`, `-sn` | `-Pn`, `-sn` | |
| `-T0` to `-T5` | `-T0` to `-T5` | Set rate, connect timeout and retries; an explicit flag wins. |
| `--min-rate N`, `--max-retries N` | `-min-rate N`, `-max-retries N` | |
| `-oX FILE`, `-oG FILE`, `-oA BASE` | the same | `-oA` writes `BASE.json`, `BASE.xml` and `BASE.gnmap`. `-` is stdout. |
| `-n` | | DNS is not a step of a scan of addresses. |

What differs on purpose:

- **UDP needs no root.** Each port gets one datagram on a connected socket: a reply is `open` (with the service, product and version it gives), an ICMP "port unreachable" is `closed`, and silence after every request its protocol has is `open|filtered`. The request is the harmless one of the protocol the port usually carries, and on a port with no known protocol a DNS query, an SNMP get with community `public`, memcached's version, then an empty datagram. Nothing logs in, guesses a credential or changes state.
- **Versions come from a few connections.** A port that speaks first is named from what it says, on the one connection. One that waits is asked HTTP and TLS, then one harmless request of each protocol that waits to be asked (Redis, PostgreSQL, MongoDB, MQTT, AMQP, memcached, LDAP, SMB, Kafka, and others listed in [OUTPUT.md](OUTPUT.md#ports-udp-products-and-versions)), each on a connection of its own; an open port costs at most 24 more connects, all counted, paced and in the ledger. nmap's `-sV` can send many more probes to one port.
- **Open ports are what is printed.** Ports that neither accepted nor refused a connect are named in the summary (and in the workspace row's `filtered_ports`), since an open port may hide among them.

Three command lines:

```
azhaq ports -host 192.0.2.7 -p 22,80,443,3306 -json
azhaq ports -host 192.0.2.7 -p none -pu top -oX scan.xml
azhaq ports -host 192.0.2.0/28 -tp 1000 -T4 -oA scan
```

On top: the scope, the budget, the kill file and a ledger of every connection; `-oX` files that `azhaq shots -nmap` and `azhaq ingest` read; and one JSON object per port for a script.

## gowitness: `azhaq shots`

<!-- azhaq: shots -->

| gowitness | azhaq | Note |
| --- | --- | --- |
| `scan single -u URL` | `shots -u URL` | The path and query are kept. |
| `scan file -f FILE` | `shots -l FILE` | Or stdin. |
| `scan cidr -c 192.0.2.0/24` | `shots -u 192.0.2.0/24` (or `-cidr`) | |
| `scan nmap -f scan.xml` | `shots -nmap scan.xml` | With `-open-only`, `-service`, `-hostnames`. |
| `scan nessus -f scan.nessus` | `shots -nessus scan.nessus` | |
| `--port 8000`, `--ports-small` | `-p 8000`, `-p small` | `medium` and `large` too. |
| `--no-http`, `--no-https` | `-no-http`, `-no-https` | |
| `--random` | `-random` | |
| `--screenshot-path DIR` | `-dir DIR` | The default is `screenshots`. |
| `--screenshot-fullpage` | `-shot-fullpage` | |
| `--screenshot-format jpeg` | `-shot-format jpeg` | gowitness writes jpeg by default; azhaq writes png. |
| `--screenshot-jpeg-quality 60` | `-shot-quality 60` | |
| `--delay 3` | `-shot-wait 3s` | The default is 1.5 s here, 3 in gowitness. |
| `--timeout 60` | `-shot-timeout 60s` | |
| `--threads 6` | `-tabs 6` | Chrome tabs in one Chrome. |
| `--javascript-file FILE` | `-shot-js FILE` | |
| `--http-code-filter 200` | `-shot-codes 200` | |
| `--chrome-path`, `--chrome-proxy` | `-chrome`, `-chrome-proxy` | |
| `--chrome-user-data-dir DIR` | `-chrome-profile DIR` | |
| `--chrome-header 'K: V'` | `-H 'K: V'` | |
| `--chrome-window-x`, `--chrome-window-y` | `-shot-size 1440x900` | The default is 1440x900 here, 1280x720 in gowitness. |
| `--write-jsonl` | `-json` | One object per page. |
| `--write-csv` | `-csv FILE` | |
| (the page's HTML is in its database) | `-shot-html` | The rendered HTML, kept beside the picture. |
| `report server`, `report generate` | `export -format html` | One file with the pictures embedded. |

What differs on purpose:

- Chrome is held to the scope and the budget: every request of every page, frame and worker is checked first, a page's own writes are refused and mapped, every download is refused, popups close, and each request counts against `-max-requests` and `-rate`. gowitness loads whatever a page asks for.
- At a set `-rate` a page's time runs from when it last moved, so a slow pace gives whole pictures; a picture taken before the page's images and scripts loaded is marked `partial` and the run exits 3. A page the budget cannot cover is not shot, and the summary says how many requests it needed.
- Chrome saves nothing to disk but the picture. `-shot-js` runs your script on the target's page: it is yours to scope.
- One row for each name; failures list a retry hint (`azhaq query -failed`).

Three command lines:

```
azhaq shots -l services.txt -dir shots
azhaq shots -u http://127.0.0.1:3001/rest/products/search -shot-format jpeg -shot-quality 60
azhaq shots -nmap scan.xml -shot-fullpage -tabs 6 -rate 5
```

On top: the response headers, TLS session, technologies, console messages and network log of every page in `-json`; look-alike pages grouped by a perceptual hash in `azhaq export -format html`; the screenshots next to the rest of the map in one workspace (`-db`); and `azhaq resume` for a page the budget capped.

## notify: `azhaq notify`

<!-- azhaq: notify watch -->

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

What differs on purpose:

- A delivery that did not arrive is named in the summary and the exit code is 3. notify logs it and exits 0.
- A 429 or a 5xx is tried again (three tries, `Retry-After` honoured). A message longer than a service takes is sent in parts, not cut.
- A webhook URL is never printed: an error names the host and what went wrong, not the path or query. `-notify @FILE` and `AZHAQ_NOTIFY` keep URLs off the command line in `watch`.
- Certificates are verified, including through `-proxy`. Azhaq checks for no updates.

Three command lines:

```
azhaq subs -d example.com -live | azhaq notify -bulk -pc provider-config.yaml
azhaq notify -i report.txt -p slack,discord -id recon -mf 'recon {{date}}: {{data}}'
azhaq ports -host 127.0.0.1 -json | azhaq notify -p custom -rl 2
```

On top: `azhaq watch -db h1.db -every 24h -notify-config provider-config.yaml -- -scope hackerone -program acme` runs a recon again and again and sends only what changed: a new host, a new API route a deploy added, nothing when nothing changed. Its message carries the change as JSON for a receiver to act on.
