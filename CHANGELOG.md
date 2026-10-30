# Changelog

## Unreleased

### Fixed

- `roles` sends every request through `-proxy`: the role runs, the history reads and the replay. The replay went direct (a proxy saw 93 requests of 144); `roles -proxy URL` sets it for all of them, and `params -proxy` is accepted.
- `probe` asks what it is given and nothing more, as httpx does: a URL or a `host:port` is one request. The name in it was also asked on ports 443 and 80 (two more GETs per input, a second GET to a public host whose one request timed out, and a second row that contradicted the first). A bare name is still asked over https, then http.
- A `-header` that names a host (`Host`, `X-Forwarded-Host`, `X-Host`, `X-Original-Host`) outside the scope is refused before anything is sent: `-allow 127.0.0.1 -deny secret.lab -header 'Host: secret.lab'` sent 35 requests that a front end routing by Host would serve as the denied host. The MCP server refuses those headers outright, and the ledger records the Host sent (`vhost`) when it is not the URL's.
- Write replay no longer calls a server error a refusal: when every other role's write got a 5xx (a unique key the server already held: SQLAlchemy's 500), the verdict is `the other roles' writes failed with a server error (5xx): neither refused nor accepted`.
- `ingest` reads naabu's JSON lines for an address, which carry `ip` and no `host`; they were refused as a format it does not know.
- `azhaq mcp` answers a `shutdown` request (sent by clients built on the language-server pattern) instead of `method not found`, and ends when stdin closes.

## v0.10.0

### `subs`

- `subs -live` is no slower than `subfinder | dnsx` at the same DNS rate, and lists live names it did not. subdomain.center is asked again only while a round gave a name that resolves and no other source had; each round's new names are looked up before the next round is asked, and no name is looked up twice. With `-dns-rate`, the guesses cost at most half what the real names did.
- A name that is only a CNAME is a live name with `-live`, as dnsx `-a -cname` lists it (tesla.com: 25 such names that `subs -live` left out).
- A DNS answer too big for 512 bytes (a long CNAME chain) is asked for with EDNS0 and read over TCP when truncated; before, names such as `autodiscover.tesla.com` failed with `buffer size too small`.
- A resolver whose NXDOMAIN answers a second resolver has confirmed 64 times in a row is checked on one in 16 (and every time again after one it gets wrong), so a dead name costs one query instead of two.
- A source that answers 429 is asked again after its `Retry-After` (2, 4, 8 s when it gives none), up to three times; the summary says what the waiting cost, and a source that keeps refusing is listed as having given up.
- Without `-live`, `subs` looks nothing up: a name only subdomain.center guessed, or only the name history held, is listed with `"unverified": true` and counted, and a guess is not added to the name history until a run has seen it resolve.
- The summary's counts add up: `from sources`, `did not resolve`, `unverified`, `not checked`, `CNAME only`, and a `count:` note that writes the sum.
- crt.sh is asked again after 1, 2 and 4 s and not past 12 s (it was 2, 4 and 8 s): a down crt.sh set the time of every run.
- Cert Spotter pages with `after=` when a key is given, and says it read the first page only when it is not.
- subfinder is v2.14.1-0.20261026103132-98ef8711acb9 (main), with its archive and windvane fixes.
- subfinder's input and flags: `-d` takes comma lists, URLs and trailing dots (IP addresses are left out with a note); `-m`, `-f`, `-match-regex`, `-filter-regex`; `-ls` (`-json`); `-cs`, `-oI`, `-oD`; `-o` appends; `-recursive`; `-stats`; `-version`; `-nW` and `-oJ`; `-source-rate`, `-source-rates`, `-max-results`, `-max-time`, `-max-body`, `-source-proxy`; `$SOURCE_API_KEY` and `$VAR` in provider files; `-t` is `-parallel`. An unknown name in `-sources` is said, and alone is a usage error.
- `-max-names` on `subs` (default 200,000 per domain, not 20,000); names cut are counted and the run exits 3. `wildcard_certificate` marks a name a certificate gave as `*.name`.
- Without `-live`, a domain's names are printed when its sources have answered, not when the last domain has.

### `dns`

- `dns` asks any record type: `-a -aaaa -cname -ns -txt -srv -ptr -mx -soa -caa -any`, `-all` (every type, with `-e` to leave some out) and `-axfr`, and prints dnsx's rows: `-json` has dnsx's fields (`ttl`, `resolver`, `mx`, `soa`, `all`, `status_code_raw`, `cdn-name`, ...) and leaves empty ones out; `-resp`, `-resp-only`, `-output-template`, `-omit-raw` and `-raw` are dnsx's forms.
- `dns -json` gives a row for every name a resolver answered, one that does not exist too, with its `status_code`; `-rcode` and `-response-type-filter` select by code and by missing record.
- `dns` takes a CIDR range, an AS number, a comma list and `-d`/`-w` as a file, a list or stdin, and looks addresses up with `-ptr`; there is no cap of 20,000 names and names are read as they come (`-stream`). A 100,000-name list is asked in 2 s against dnsx's 7.7 s.
- `-resolvers` (and `-r` in `dns`) takes a file or a comma list with `udp:`, `tcp:`, `dot:` and `doh:` prefixes, in every command; every question carries EDNS0 (4,096 bytes), and `dns -proxy socks5://` sends DNS through a proxy.
- `dns -t`, `-rl`, `-retry` and `-timeout` mean what they do in dnsx (names in flight, names a second over all resolvers, attempts per question, wait for one answer); `-timeout` is no longer the run's time (`-maxtime` is, and exits 4 with the `-start` to go on from). `-dns-rate` stays per resolver.
- `dns` no longer asks MX, TXT and NS for every apex name it never printed; `-w` accepts labels with an underscore (`_dmarc`) and prints hits as they come; `-o` appends; `-hf` reads the hosts file; `-trace` follows delegations from the roots; `-asn` names the autonomous system; `-no-wildcard` and `-wd` control the wildcard filter.
- `run -dns-brute` guesses labels with an underscore too (`_dmarc`, `_domainkey`); `dns -hc` asks each resolver a known name and says how it answered. `-all` does not include AXFR (`-axfr` asks it, held to the scope); `dns -r` resolvers are asked for every name, `localhost` and `.test` included, as dnsx does.
- The DNS lab answers MX, TXT, NS, SRV, CAA, SOA and AAAA, has a reverse zone for 127.0.0.0/24 and a zone transfer, truncates long UDP answers, and counts what it was asked (`-stats`).

### `probe`

- `probe -rl N` (`-rate-limit`, `-rlm` per minute) paces services as httpx does: a target's first request waits its turn, its favicon, redirects and second scheme follow at once. It was `-rate`, which paces every request: at the same setting a run took twice httpx's time (45 s against 22 s for 107 hosts at 5 a second). `-rate` still paces each request.
- A target whose name does not resolve says what DNS said (`no such host`, `the name has no address`, a special-use name such as `.invalid`) and is one row: before, a name with no record was `no answer and no failure recorded`, and a URL's name that DNS refused was listed again as a target of its own.
- `probe` follows no redirect unless given `-fr` (with `-maxr`, `-fhr`, `-rhsts`), as httpx does. A row's status, title, length and content type all come from one answer; with `-fr` they are the last answer's and the chain is in `chain_status_codes` and `final_url`. `run` keeps following.
- `probe` takes httpx's matchers and filters over the response as sent: `-mc/-fc`, `-ml/-fl`, `-mlc/-flc`, `-mwc/-fwc`, `-mfc/-ffc`, `-ms/-fs`, `-mr/-fe`, `-mcdn/-fcdn`, `-mrt/-frt`, `-mdc/-fdc`, `-fd`, `-fpt/-fep`. The summary says how many rows they left out and which conditions could not be judged.
- A target that is dropped for a wildcard answer, or that gets no answer, is a row with `failed: true` and an `error` (`-probe` prints `[FAILED]`), and the summary counts it. A name that resolves only through a wildcard is probed, not dropped.
- `probe` stores and prints responses: `-sr`, `-srd`, `-ob`, `-store-chain`, `-rstr`, `-rsts`, `-irh`, `-irr`, `-irrb`, `-include-chain`, `-debug`, `-debug-req`, `-debug-resp`, `-ss` (screenshots).
- `probe` reports `tls` (`-tls-grab`, read from the handshake the request made: no extra connection), `cname`, `resolvers`, `asn`, `hash` (`-hash`), `jarm_hash`, `body_preview`, `extracts` (`-er`, `-ep`), `favicon_md5`, `favicon_path`, `favicon_url`, `websocket`, `http2`, `pipeline`, `vhost`, `sni`, `cpe`, `wordpress`, `knowledgebase`, `csp`, `body_fqdn` and `body_domains`.
- `probe` takes httpx's input flags: `-p` ports and ranges with `http:` and `https:` (also for addresses), `-path`, `-nf`, `-pa`, `-e`, `-sni`, `-no-decode`, `-tls-probe`, `-csp-probe`, `-im burp`, `-vi`, JSON target lines, address ranges, AS numbers, comma lists, globs, `*.example.com`; its display and output flags: `-sc -cl -ct -title -td -server -ip -rt -lc -wc -location -method -cdn -cname -asn -ldp`, `-csv`, `-csvo`, `-md`, `-oa`, `-eof`, `-lof`; and its request flags: `-rlm`, `-delay`, `-retries`, `-req-timeout`, `-maxhr`, `-proxy`, `-auto-referer`, `-random-agent`, `-cff`.
- A bare `host:port` is asked over plain HTTP first on port 8080 and on ports above 1024, as httpx does, and asked again over TLS when plain HTTP is answered 400. `probe` accepts TLS 1.0 and 1.1 servers and sends no `Accept` header.
- `probe -x`, `-body` and `-rr` send the methods, body or raw request you give to the targets in scope, counted, paced and in the ledger; the summary says non-GET requests were sent. They can change data on the target.
- A page in Shift-JIS, GBK, Big5 or another declared charset has its title read in UTF-8; httpx reads only GBK, Big5 and EUC-KR.

### `crawl`

- `crawl` prints katana's JSON lines with `-jsonl`, its fields with `-f`, `-ot` and `-sf`, filters the printed URLs with `-em`, `-ef`, `-ndef`, `-mr` and `-fr`, and stores answers with `-sr`.
- A page's links are no longer cut at 64: every link is listed and asked, bounded by templates and `-max-items`.
- `crawl` follows links to the start host's subdomains with `-fs rdn|fqdn|dn|REGEX`, `-cs`, `-cos` and `-ns`, and `-do` lists the links it left out of scope; the summary counts them.
- `crawl` sends only what a crawler sends: no built-in path sweep, no favicon request and no source-map guesses; `-kf all|robotstxt|sitemapxml` asks the known files and reads every entry, `-sweep` brings the 32 paths back.
- Pages are read at every markup sink katana reads (`img`, `srcset`, `area`, `video`, `button formaction`, `object`, `hx-*`, `meta refresh`, the `Link`, `Content-Location` and `Refresh` headers) and redirect hops are listed.
- Strings in scripts and pages that katana's patterns take (`users.php`, `admin/`) are URLs when they name a page of the app; every other one is kept as a rejected candidate with its reason, listed by `-rejected` and counted in the summary. Unquoted code that the page pattern reads as a path (`a.number/t.doc` gives `a.number/t.do`) and a string a script searches for (`ua.indexOf("Trident/")`) are rejected candidates too: on Juice Shop they were five catch-all "pages" and five requests.
- GET forms are asked once with neutral values; `-submit-forms` sends POST forms (it changes data, each submission is counted and in the ledger).
- `crawl` waits and asks again on 429 and 503, retries after a timeout, carries cookies the target sets, and takes `-hrl`, `-hrlm`, `-rlm`, `-mdp`, `-mrs`, `-rd`, `-iqp`, `-pc`, `-proxy`, `-r` and `-c`, `-p`, `-rl`, `-ct`, `-dr` as katana's names; a scheme-less `:80` or `:8080` target is asked over http and `-u a,b` is split.
- `crawl -json` rows carry `tech`.
- `-browser -interact` clicks the buttons, links and menus of each page and maps the routes and requests they bring; the writes a click would send are mapped and not sent, and a click on log out or delete is not made.

### Screenshots and `gallery`

- `-tabs` is 6 by default (it was 4), as gowitness runs 6 threads: five lab apps are shot in 3.4 s against gowitness's 4.2 s; with 4 tabs the fifth page waited for a second round and the run took 5.1 s.
- A screenshot at a polite `-rate` is no longer silently blank. Four pages of 42 requests at `-rate 2` gave four pictures with no images, exit 0 and no note. A page's deadlines now run from when it last moved, not from when it started, tabs open as the pace can fund them, and the tab's icon, which no screenshot shows, is not fetched. The same run gives four complete pictures (0.000% of pixels differ from the `-rate 0` ones), at most 3 requests in any second at the server, and the summary, the ledger and the server count the same requests.
- A screenshot is taken once the page has stopped asking for what it shows: a single-page app (Juice Shop) asks for its product images only after a script's request is answered, which at `-rate 5` came after the picture was taken. A screenshot of Juice Shop at `-rate 2`, 5 and 10 is the one an unpaced run takes with `-shot-wait 5s` (0.000% of pixels differ); at the default wait the unpaced one lacks the last row of images (2.4%).
- A screenshot taken before its page's images, styles or scripts were loaded is saved with `"partial":true`, says so in a note, and the run exits 3.
- Look-alike screenshots are grouped by a DCT perceptual hash (`p:` and 16 hex digits). A login form, the nginx default page and an admin page were one group of the old 9×8 brightness hash; they are three now, and thirty copies of one portal are still one.
- `export -format html` embeds each screenshot (scaled to 560 pixels wide), so the report opens from any directory and after the screenshot folder is gone; it was `<img src="DIR/file.png">` relative to the run's `-dir`. A picture marked `partial` says so in the report.
- `shots` takes more targets: a URL with a path or query is shot (it used to give 0 results and exit 0), `-u 192.0.2.0/28`, `-p` port lists (numbers, ranges, `small`, `medium`, `large`), `-no-http`, `-no-https`, `-random`, `-nmap FILE` and `-nessus FILE`.
- `shots` and `run -screenshots` have flags for the picture and Chrome: `-shot-size`, `-shot-fullpage`, `-shot-wait`, `-shot-timeout`, `-shot-format jpeg`, `-shot-quality`, `-shot-js`, `-shot-codes`, `-shot-html`, `-chrome`, `-chrome-proxy`, `-chrome-profile`. Chrome's restricted ports (6000, 10080, …) are allowed (`-unsafe-ports=false` keeps its refusal).
- A page's row in `shots -json` has what Chrome saw: response code, headers, TLS session, the technologies of the rendered page, console messages and the network log, at no extra request. `shots -csv FILE` writes the scalar columns.
- A page's own request waits for the pace when Chrome sends it, not when it is counted, so four tabs no longer send four pages' documents together.
- `shots` and `run -screenshots` no longer fetch the favicon for the map (one request less per page), and Chrome no longer fetches `/favicon.ico` for a screenshot.
- A page that calls `alert()`, `confirm()` or `beforeunload` on load is accepted and shot in the normal time instead of timing out after 31 s with nothing.
- `azhaq gallery -db FILE` serves a workspace's screenshots to a browser on this machine: a grid of thumbnails with URL, title, status and technologies, filters (status, technology, host, title, partial, look-alike group), one tile per group of look-alikes, search of URL, title and kept page text (`title:`, `body:`, `tech:`, `header:`, `status:`, `p:`, `-term`), a page per shot (picture, headers, cookies, TLS, network, console, the `azhaq show` command) and the pages that gave no picture. It is embedded, works offline, reads the workspace read-only and sends nothing to any target (a test asserts it). 5,000 pages page and filter in under 10 ms, and `/api/` gives the same data as JSON.
- `gallery -workspace DIR` merges the workspaces of a directory in one view; a database that is not a workspace is skipped with a note, one that cannot be read is skipped and exits 3, as do pictures missing from disk.

### `ports`

- `ports -unnamed N` (`run -port-unnamed N`) sets how many open ports of an address may go unnamed before its other silent ports get their banner only; the default 6 guards against a host that accepts every connect, `-1` lifts it.
- `ports` names a service by what it answers, not by its port number. A port that says nothing and does not answer the HTTP probe is asked one harmless request of each of about 30 protocols until one answers: Redis (with `redis_version`), PostgreSQL, MongoDB (with `buildInfo`), MQTT (Mosquitto's version), AMQP (RabbitMQ's), memcached, LDAP (anonymous root DSE), SMB2, DNS over TCP, Kafka, ZooKeeper, SQL Server, Oracle TNS, Cassandra, Kerberos, RDP, X11, SOCKS5, STOMP, XMPP, RTSP, SIP, AFP, Minecraft and others. An open port costs at most 24 connects after the first, every one paced, counted and in the ledger; after six open ports of one address that nothing could name, the rest are not run down the list, and the row's `unprobed` and the summary say how many.
- Greetings are read without a request: Telnet, IRC, NNTP, RTSP, SIP, ManageSieve, VNC (protocol version in `version`), `ICY`. A greeting inside TLS (IMAPS, POP3S, SMTPS, LDAPS) is read before the HEAD. A binary answer to the HEAD is kept as a banner, a connection closed without a word is `tcpwrapped`, and a web port whose HEAD was refused (405, 501) is asked `GET /` for its title and product (Mailpit, Tomcat, etcd, Kubernetes, Docker).
- UDP: TFTP, rpcbind, the SQL Server Browser, SIP, NAT-PMP, Ubiquiti discovery and IPMI/ASF-RMCP are asked on their ports, the default list is 25 ports, and a port with no known protocol is asked DNS, then SNMP (v1; v3 engine id on 161), then memcached's version, then an empty datagram. A sysDescr names Linux, Cisco IOS, JUNOS or Windows as `product`.
- A host that refuses some UDP ports but leaves others silent may be rate-limiting its ICMP replies: up to 80 such ports are asked again one at a time at its pace, and more are left `open|filtered` and counted in `udp_limited` and the summary. Only an ICMP unreachable for the port makes it `closed`.
- `ports` scans a range or an AS number without a cap: `ports 10.0.0.0/16 -p 22,443` takes CIDR (IPv4, IPv6 down to /104) and `AS13335`, asks the addresses in blocks, and sends no reverse DNS query per address. Before, `-l` over 2,048 addresses stopped, and CIDR and ASN were refused.
- `-host a,b` takes several targets, `host:port` asks that port when `-p` is not given, bare arguments and `-no-stdin` work, `-p -` is every port, and `-tp`, `-pf`, `-ep`, `-eh`, `-ef`, `-iv`, `-sa` and `-r 1.1.1.1,8.8.8.8` are as naabu's. `-host a,b` used to scan nothing and exit 0.
- Output: `-csv`, `-oX`, `-oG`, `-oA`, `-lof`, `-eof`, and `cdn` and `cdn-name` in `-json`, whose timestamp is now UTC.
- Timing: `-connect-timeout`, `-retries` (`-max-retries`), `-c` (`-workers`), `-min-rate`, `-T0` to `-T5`, `-pts`; `-timeout` stays the run's limit, and `-timeout 500` says to use `-connect-timeout`. The default rate is 1500, and as many connects are in flight as the rate allows.
- `-cdn-full` scans a CDN or WAF address in full; the default still asks 80, 443, 8080 and 8443, and now says so in the summary.
- `-sn` lists the addresses that are up and `-wn` scans only those (a connect to 80 or 443 accepted or refused).
- Ports are asked in random order, the likeliest first; `-order asc` and `-seed N`.
- `-detect none|banner|all` sets how much an open port is asked (naabu's one connect per port with `none`); `-proxy` (SOCKS5), `-source-ip` and `-cp PAYLOAD`.
- `top-1000` has 5985 and 5986 (WinRM), not 3007 and 3013, as naabu's list.
- A name costs 2 DNS queries (A, AAAA), not 5 for an apex name; a name that does not resolve is listed in the summary.
- `run -cidr/-asn` with `-ports` scans the prefix itself and no longer stops at `-max-ips`.
- An AMQP broker on another port, which answers the HTTP probe with its version header and closes, is asked AMQP on a new connection: `RabbitMQ 3.13.7`, as nmap names it, not only `amqp 0-9-1`.

### `dirs`

- `dirs -u https://host/api/` sweeps `https://host/api/WORD`. It used to sweep nothing and print `0 paths` with exit 0 for any URL with a path. A query or fragment on the URL is dropped, and a note says so.
- `dirs` has a built-in wordlist, SecLists' `common.txt` (4,750 words, MIT): `azhaq dirs -u URL` works without `-w`, and `-dirs @common` names it for `run`.
- `dirs` takes ffuf's matchers and filters: `-ms -mw -ml -mr` and `-fc -fs -fw -fl -fr`, with the values and rules of `fuzz`, and `run` has them as `-dirs-ms` and the rest. A bad value is a usage error.
- `dirs -mc` accepts `all`, and the default is ffuf's whole `200-299` range, so a 250 is reported.
- `dirs` counts words and lines as ffuf does, over the whole body (newlines + 1): the body `a b c` and two blank lines is `Lines: 4`, where it said 1. A `-fl` value from a ffuf run carries over.
- `dirs` keeps one connection per thread. Before, about every third request opened a new one: 45,000 words left 13,500 sockets in TIME-WAIT on loopback (now 45, ffuf 40), and each new connection to an https target cost a handshake.
- `dirs` against a target that answers every guess (5,000 hits in 50,000 words) took 6.9 s against 1.5 s for the same list with no hits. Hits are now written to the workspace in batches, and the same run takes about 1.3 to 1.9 s.
- The catch-all check hides a guess whose size differs from the not-found answers only where those answers differ in size among themselves, or repeat the path they were asked for. A real page close in size to a static not-found page is no longer hidden.
- The calibration requests are paced by `-rate`, as the guesses are; they were not.
- A word with a `?` starts the query, as in ffuf (`render?url=…`, `dns-query?name=…`); it was sent as part of the path.
- A sweep whose guesses were answered 429, and one with paths that got no whole answer, say so in the summary and exit 3. Before, a rate-limited target gave 0 paths and exit 0.

### `fuzz`

- `fuzz -o FILE -of json|ejson|csv|ecsv|html|md|all` writes ffuf's report files, and `-od DIR` the raw request and answer of each match; a report that cannot be written is a failure in the summary.
- `fuzz -request FILE -request-proto` reads a raw request as Burp saves it.
- `fuzz -x` sends through an http, https or socks5 proxy; `-replay-proxy` sends each match once more through one, outside the ledger, budget and pace.
- `fuzz` decodes gzip, deflate and brotli bodies, so `-fs` counts match ffuf's when `Accept-Encoding` is given.
- `fuzz -mt` and `-ft` match and filter on milliseconds to the first byte.
- `fuzz -p`, `-maxtime-job`, `-recursion-strategy greedy`, `-sf`, `-sa`, `-se` (and `-se-after`), `-acs`, `-acc`, `-ach` and `-config` (ffuf's TOML file) work as in ffuf.
- A `fuzz` line that gives its own `-fc`, `-fs`, `-fw`, `-fl`, `-fr` or `-ft` no longer calibrates, as in ffuf; `-ac` turns it on.
- `fuzz -enc` with all of ffuf's encoders, `-input-cmd`/`-input-num`/`-input-shell`, `-mode sniper`, `-D`, `-w a,b`, `-ignore-body`, `-raw`, `-sni`, `-http2`, `-cc`/`-ck`, `-data*` and `-cookie` aliases, `-V`, `-c` colours, `-debug-log`.
- `fuzz` reaches servers that speak TLS 1.0 and 1.1.
- `fuzz -preflight`/`-postflight` with `-…-var`, `-…-var-auto`, `-preflight-mode` and `-preflight-error`: a token or session read from an answer goes into the next request; the flight requests are scoped, paced, counted and in the ledger, and a captured value can never change the host.
- `fuzz -control FILE` steers a run (rate, pause, filters, queue, save); stderr on a terminal shows one status line a second.
- `fuzz` with two long wordlists in clusterbomb no longer allocates a byte for each combination.
- `fuzz -json` and the reports carry `scraper`, `resultfile` and ffuf's `FFUFHASH` input.

### `params`

- `params` no longer says `0 pages` and exits 0 for a server that rate-limits it. A 429, 418 or 503 the page did not give before is waited out (its `Retry-After`, else 1, 2 and 4 s); if it persists the page fails, exit 3, with the names found so far kept and a note. Requests that got no answer fail the page too, and a page left alone (it changes between identical requests, is not text, HTML, JSON or XML, or is past `-params-per-host`) says why in a note.
- `params` has a built-in list: `azhaq params -u URL` needs no `-w`. `-w small|medium|large` are 1,000, 3,000 and 6,500 names, from SecLists' `burp-parameter-names.txt` (MIT) and names Azhaq's own passes found.
- `params` takes the names a page's own form fields, scripts and short replies hold first, and asks `debug`, `test`, `admin` and about 70 more with the values `1`, `true`, `yes` and `on`.
- `params` finds names by a changed header set, a changed `Location`, a changed line count, and a name the page prints back, as well as status, size and a reflected value. The `why` of each name says which.
- `params` sends 5 groups at once (`-t`), and finds the longest query a server takes (nginx's 8 KB, a 2 KB proxy) instead of failing on it; a group of 500 names or 7.6 KB is the most it sends first. Requests per page are fewer than arjun's on the same list.
- `params -X POST|JSON|XML` sends names in a form, JSON or XML body. It needs `-allow` or `-scope` to name the targets, or a single page; every request is counted in the budget, paced and in the ledger; the row and the summary say writes were sent.
- `params` takes `-i` (a Burp XML export or a raw request, with its method, body and headers), `-include`, `-casing`, `-passive`, `-c`, `-d`, `-stable`, `-T`, and writes `-oJ` (arjun's file), `-oT` (`URL?name=1234&…`) and `-oB HOST:PORT` (replay through Burp).

### `urls`

- `urls` prints each URL as its page arrives when stdout is not a terminal, so a pipe starts at once; `-sort` (and a terminal) waits and sorts. A stop by Ctrl-C or `-timeout` keeps what was found: the file is written and the summary says which archives were cut short.
- `urls` asks for the host alone by default, as gau does; `-subs` asks for `*.DOMAIN` too. `run` keeps the broader default (`-urls-subs`). otx and urlscan answer for the domain with its subdomains, and those URLs are printed too, as gau prints them (vulnweb.com: 80 URLs against gau's 70, 61 shared; gau's others are cut-off links such as `cart.php.[` and static files).
- `-mc`, `-fc`, `-mt`, `-ft`, `-from`, `-to` filter on what the archive recorded, sent in the query as gau sends them; an archive that cannot apply one (OTX; urlscan.io keeps dates only) is not asked, and the summary says so. A bad value is a usage error.
- `-blacklist EXT,…` and `-fp` leave URLs out by extension and by host and path; `-raw` prints every row as the archives gave it.
- `-providers wayback,otx,…` chooses the archives; the API-key file is `-provider-config` (a path given to `-providers` still works).
- `-proxy`, `-retries`, `-threads` (`-urls-threads`), `-urls-pages`, `-urls-pause` and `-urls-max` set the transport; an archive that stopped at its page cap is marked `capped` and noted, and `-fail-on-capped` exits 4.
- `-o` appends; domains may be arguments; `-config` and `~/.gau.toml` are read; `-version`; `-archive NAME=URL` asks a mirror.
- OTX is asked as a hostname for a name with a subdomain; Common Crawl's "no captures" answer is an empty result, not a failure.

### Notifications

- A webhook URL no longer leaks. A transport error printed the whole URL, token included; errors now name the host and the cause, and no error holds a URL's path or query or a token, even where a server echoed them back. The first 512 bytes of a failed answer are kept in the error (Slack's `channel_not_found`), with the URL's path and query and every key and header value of the provider file cut out of them.
- `watch -notify @FILE` reads webhook URLs from a file and `AZHAQ_NOTIFY` holds more, so a URL need not stand on the command line where `ps` shows it.
- `notify -v` names, on one line, the settings `config.yaml` changed; the file notify writes holds every flag at its default, and those are not listed.
- Notifications are tried again on a 429 or a 5xx, honouring `Retry-After`, and a text longer than a service takes is sent in labelled parts, not cut (Discord's cut lost the rest of a change set).
- `azhaq notify` is a drop-in for projectdiscovery/notify: its flags (`-pc`, `-p`, `-id`, `-bulk`, `-cl`, `-mf`, `-rl`, `-d`, `-proxy`, `-config`), its `provider-config.yaml` schema and its message boundaries, the same as notify's for the same input.
- Providers: Slack (webhook, threads), Discord (webhook, threads), Telegram (parse mode, threads, preview), Pushover, SMTP, Microsoft Teams (connector and workflow), Google Chat, Gotify and custom webhooks with formats and Sprig templates.
- `watch -notify-config`, `-notify-provider`, `-notify-id`, `-notify-format`, `-notify-rate`, `-notify-proxy` and `-notify-lines`; `watch` and `notify` exit 3 when a message did not arrive, where it was printed on stderr and exit 0.

### Fixed

- `-sources none` (no passive source, for a run that only resolves the names `-dns-brute` guesses) is accepted again; the check for unknown source names had made it a usage error.
- The kill file stops sending within a tenth of a second, also for requests that were already waiting for `-rate`. Before, at `-rate 2`, requests counted before the file appeared still went out for up to 2.7 s (Chrome's included). A bench check now measures this on every path.
- MCP calls that send requests run one at a time. Before, calls made at once each spent the whole budget and each kept the pace on its own.
- A request Chrome answers from its cache is neither listed in the ledger nor counted. Before, a signed-in run of a multi-page app listed every page's shared scripts and styles.
- A `-timeout` reached while requests wait for `-rate` stops the run: exit 4, and `resume` continues. Before, it failed them with exit 3. `-H 'Host: x'` now sets the Host the request goes with.
- A bad port list is a usage error, caught before anything is sent.
- The text summary of a `subs` run in which sources failed says `DEGRADED: N of M sources failed` on its first line; the exit code is unchanged, as documented.
- `probe -silent` and the other quiet commands no longer print the standard library's "Unsolicited response received on idle HTTP channel" lines on stderr.
- A screenshot directory that is a file is a usage error that names `-dir`.
- The docs no longer say an active collector needs an `-allow` scope (the targets given are its scope), and the roles recipe says a role of headers does not show behaviour that needs a cookie.

### Bench

- Every finding of the reviews that was fixed without a test now has one, in Go next to the code or, where it needs the local apps or this machine, in a `regress` section (`go run ./bench -only regress`; `$AZHAQ_REFBIN` names the reference tools). Findings still open have a skipped test that says so.

- `go run ./bench -profile default|polite|both` runs every comparison twice, with the default flags of both tools and politely (`-rate 5`, `-dns-rate 10` with dnsx `-rl 10`, ports at `-rate 100`, the reference at the same rate), and names each check and each measured run with its profile.
- Every comparison row passes only when Azhaq's results, counted only when something other than Azhaq confirms them (a server log, a second resolver, `ss`, the app's source), are at least the reference's and its time is at most 1.05 times the reference's (the median of three runs below 20 s); the old shares and ratios stay in the record.
- New comparisons: `fuzz` against ffuf (hits, matchers, filters, JSON report), `dns` record types and `-ptr` against dnsx on a zone the bench serves, `urls` against gau, `ports` service and version against `nmap -sV` on the services lab, `notify` against notify on a local stub, and `crawl` against katana; DNS brute force runs on the DNS lab and needs no public zone.
- A `lab` section checks the DNS lab without docker: the UDP port scan, `subs -w -live`, the wildcard subzone and the dangling CNAMEs.
- The MCP budget check also calls `azhaq_ports` after the budget is spent; the scope trap also covers `-browser`, `-login`, `shots` and `crawl -browser`.
- `probe` is held to rows + failed + skipped == inputs; `subs -live` to "every confirmed live name subfinder | dnsx finds is in Azhaq's list or its source is named as failed"; the docs are checked for lines that say active options need `-allow` or a scope, for "GETs only" without HEAD, and for a README benchmark label that is not the release; the OpenAPI exports of Juice Shop, VAmPI, DVGA, ginandjuice.shop and a `/blog` and `/blog/` fixture are validated by the bench's own checker; small Go tests (`bench/smoke_test.go`) hold rows that were one assertion each.
- `go run ./bench -readme` writes the README's benchmark table from the newest record. The bench no longer stops the docker apps afterwards (`-down` does), and takes reference tools from `-refbin DIR` before `bench/.work/bin`.

- A `claims` section checks every safety claim on every path a request takes, unpaced and at `-rate 10` and `-rate 2`. Each run's summary count, its ledger and an independent logging proxy (or the listeners, for TCP and UDP) must agree exactly. The paths: HTTP, Chrome, sign-in, roles, write replay, path and parameter sweeps, fuzz, ports, MCP, budgets and the kill switch.

### Docs

- `docs/MIGRATING.md` (and `azhaq docs migrating`) puts the flags of subfinder, dnsx, httpx, katana, ffuf, gau, arjun, naabu, nmap (`-sV`, `-sU`), gowitness and notify next to azhaq's, with what differs on purpose, three command lines and what azhaq adds for each.
- `azhaq docs` without a topic prints an overview: what azhaq is, six commands to start with, where to find the rest, then the list of topics.
- The README starts with what azhaq replaces and adds, links MIGRATING, and no longer carries numbers that no benchmark row measures (start-up memory, a request count for Juice Shop, per-page request counts of the parameter comparison).
- Sentences the code did not support are fixed: `-detect` says an open port costs at most 24 more connects, not 3 (help and OUTPUT.md); `-udp` says 25 ports, not about 20; `params` is not paced at 20 requests a second per host; the resume request counts and the worker overhead are no longer quoted; `probe`'s `a`, `aaaa`, `cname` and `resolvers` are listed as present when the name resolved, not always; duplicate troubleshooting entries are gone; a connector that fails ends the run with exit 3, not 1; `crawl -fs` says its default is `rdn` for a name and the origin for an address; the `ingest` summary names dnsx, nuclei and gau; the UDP and per-source timeout figures agree with the code.
- A test fails when a document names a flag its command does not have: in a command line, in a MIGRATING table, or in a sentence about a command.

## v0.9.1

Fixes from two independent reviews of v0.9.0.

### Fixed

- The request ledger and the request count now hold exactly what Chrome sent. Before, a screenshot of Juice Shop at `-rate 2` counted 51 requests, listed 36 in the ledger, and an independent proxy got 35.
  - A request that waited for the pace when the page closed was counted but never sent. It is now neither counted nor listed.
  - A request Chrome dropped and retried on a new connection was listed although it never left. A request is now listed once Chrome says it went out.
  - A WebSocket's line had only the host; it now has the handshake's path and query.

  The same run now counts 35, lists 35 and the proxy gets the same 35.

- `dirs` no longer reports an answer cut off mid-body as a hit of length 0. A server going down while it answered made five catch-all pages pass the calibration filter. A cut-off answer is now asked once more; if it is cut off again, the path is not judged and the summary says how many such paths there were. `fuzz` asks a cut-off answer once more too, then counts it as an error.
- The request ledger shows lines cut from its end. A run that ends writes a seal line, and its summary names the seal. `azhaq ledger -verify` exits 3 when lines follow the last seal: a run killed, crashed or still running, or a file whose end was removed.
- RDAP lookups are no longer in the ledger: the registry is a third-party source, like those of `subs` and `urls`.
- `run -passive` on a domain under a TLD no registry runs (`azqlab.lan`) no longer asks the archives, and ends cleanly; `subs` already skipped its sources. A name under a private suffix such as `github.io` is looked up in the sources again.

### Ports

- Port lists combine names, numbers and ranges: `-pu top,5354`, `-p top-100,8888`. A TCP list name given to `-pu`, or a UDP one to `-p`, says which to use.
- A UDP port with no known protocol is asked a DNS query first, then an empty datagram, with no extra datagrams sent. A DNS server on an odd port (5354, 8053) is now `open`, service `dns`.
- An SSH, FTP or mail port that sent no greeting gets one more connect after the scan: sshd drops greetings when many connects arrive at once. A greeting that arrives in reply to the HTTP probe is read as one.
- A web port whose answer names no product gets the page's `<title>` in a new `title` field, and its `<meta name="generator">` as product and version.

### Output

- `probe -no-follow` and `run -no-follow` ask each URL once and record the redirect. With `-web-ports 443`, a program-scoped probe stays at one request per host.
- The `subs` coverage note adds up with the names printed. It says how many names came from the history, from guesses checked in DNS or as CNAME targets, which the estimate leaves out.
- `subs` names a source that set the wall time, even without `-v`, and gives the flags that bound it or drop it.
- `subs` also says when checking guessed names in DNS took long: for example, 1,591 subdomain.center guesses for hackerone.com took 452 s at `-dns-rate 5`. The note gives the flags that pace that check or skip it.
- A run stopped by `-max-requests` says the cap holds for each run. `azhaq resume` sends up to that many more requests, or as many as its own `-max-requests` allows.
- `-o` naming a directory is a usage error that says what `-o` is for. `shots` adds that its PNG files go to `-dir`.
- An export that finds nothing says why on stderr.
- `watch` no longer notifies the first run, the baseline; it notifies changes only. `-always` sends every run, the baseline included.
- MCP: `azhaq_map` and `azhaq_plan` take `graphql`, which asks for each GraphQL endpoint's schema. `docs/MCP.md` lists what no tool starts, on purpose: writes and bodies the client chooses, wordlists, DNS brute force and UDP scans.
- Exit code 2 now says it also covers targets that all fall outside the scope given.

## v0.9.0

Two reviews of v0.8.1 ended the same way: adopt azhaq for some jobs, keep another tool for the others. This release goes after both halves:
- the jobs where reviewers kept ffuf, naabu/nmap, subfinder or gowitness;
- the work none of those tools do: deciding where to look first, noticing what a deploy added, writing the finding up, and proving what was sent.

### New

- `azhaq hunt -db FILE`: the mapped surface ranked by where to look first. Each row says why and gives the command to run next. Signals:
  - cross-role reads and writes from `roles` (`-roles FILE`);
  - exposed secrets and source maps;
  - admin, debug and internal paths;
  - backup and key files, directory listings;
  - API descriptions and GraphQL;
  - object identifiers in routes;
  - parameters that take a URL, file, command or redirect;
  - writes without credentials, file uploads, takeover candidates and what is new.

  On the five local labs, every known issue the map holds ranks in the top 20 (top 25 for DVWA).
- `watch` reports the API routes a deploy changed: a new route with its method and body fields, a method or field added, a route gone from the bundle. Each change names the script that calls the route, and notifications carry it. Two runs of an unchanged app report nothing.
- `azhaq report -dir DIR`: each finding `roles` listed, written up in Markdown or JSON, ready to submit:
  - steps to reproduce, with curl commands;
  - the owner's and the reader's answers;
  - the made-up-identifier control, and why the object is the owner's.

  `-redact` masks hosts, tokens and identifiers. A report never states what the evidence store does not hold.
- The request ledger. Every run with a workspace writes `DB.ledger.jsonl` next to it: one hash-chained line for each request or connection sent to a target (HTTP, Chrome's requests, TCP and UDP probes), with its time, target, scope rule and collector.
  - `azhaq ledger -verify` catches an edited line; `-summary` and `-csv` make it ready for a client or a blue team.
  - It matched an independent counting proxy request for request: VAmPI 41 of 41, Juice Shop 190 of 190, a path sweep 56 of 56.
- A kill switch. `-kill-file PATH` (default `DB.stop`): create the file, and within half a second nothing more is sent; exit 4, and `azhaq resume` continues once the file is gone.
- `azhaq fuzz`: ffuf's flags and counting.
  - The keyword can go in the path, query, host, headers (Host included), method or body.
  - Matchers `-mc -ms -mw -ml -mr` and filters `-fc -fs -fw -fl -fr`, auto-calibration, `-recursion`, `-e`, and clusterbomb or pitchfork over several wordlists.
  - It gave the same results as ffuf 2.3 in every comparison on the local labs. On VAmPI, common.txt took 6.6 s against ffuf's 7.3 s.
- `ports -udp` (and `run -ports-udp`): UDP inventory without root, reporting open, open|filtered or closed. It sends protocol-correct requests to 20 common UDP services. On 127.0.0.1 it agreed with `ss` on all 1,030 ports scanned.
- Open TCP ports now carry `product` and `version`, read from greetings, headers and version handshakes: OpenSSH 9.6p1, Apache httpd 2.4.25, Werkzeug, CUPS, Express, Ollama, MySQL/MariaDB, PostgreSQL, Redis, MongoDB and Elasticsearch.
- `subs` keeps a per-user history of the names it found. Later runs ask it as a source, and its names count only if they still resolve (`-no-history` to skip).
- `subs` estimates its coverage with Chao1, and gives a sampled source's population with Schnabel. A tesla.com run holds about 1,400 of the roughly 1,609 names the independent sources know.
- Every map row says how it is known: answered, described, called, linked, archived or guessed (`query -evidence`; `evidence` in exports; `x-azhaq-evidence` in OpenAPI). A GraphQL schema recovered with introspection disabled is marked partial everywhere it is shown or exported.
- `roles -har NAME=FILE` and `-burp NAME=FILE` take each account's saved browsing as the whole input. Its GETs are the pages it reached, its latest Authorization and Cookie headers its session; an anonymous role is added, and nothing is crawled without `--` run options. On VAmPI two HAR files alone gave the cross-account book reads (proved, both ways) and the debug endpoint's passwords.
- A cross-role write answered 2xx whose change no GET of the owner's object can show (VAmPI's password change) is listed as `writes another role's object: accepted; the change cannot be read back to confirm`, instead of being hidden as "changed nothing". A write is proved in the field it sets.
- The local DNS lab used by trials: `go run ./bench/labdns` serves azqlab.lan (real names, a wildcard subzone, CNAMEs to deleted cloud names) and forwards the rest.
- `dns -d DOMAIN -w FILE` brute-forces as dnsx does.
- `scripts/install.sh` installs a release after checking its sha256, and its cosign signature when cosign is present.

### Changed

- Memory: CDN and WAF ranges and the page-parsing patterns load on first use. `azhaq version` takes 16 MB (was 29). `dirs` and `params` leave technologies to `probe`: 28 MB for 200 paths (was 55).
- Fewer requests for the same map. Path checks stop once an origin has served an API description. Juice Shop takes 148 requests (was 190) with the same 70 of 77 known routes; VAmPI takes 31 (was 41).
- `subs` counts the sources asked and answered, and counts failures of off-by-default sources apart. `degraded` is set when a default source failed.
- `shots` says when the request budget left no room for a page: "the page needs about N requests". Five local apps take 4.6 s against gowitness's 34.4 s.
- The output contract (exit codes, `stopped`, `complete`, summary counts against the rows written) is tested for every case a review or hunt has found.

### Fixed

- The MCP subdomain tool is held to the server's scope. It used to ask third-party sources about any domain.
- `roles`: a request budget spent during a role's Chrome sign-in is a limit (exit 4), not an error.
- GETs that would spend a one-time token (`?token=`, `?reset_token=`), and one-word verbs such as `resetpw` and `dataerasure`, are left alone.
- `roles` lists sensitive fields the server sent masked as masked, instead of leaving them out.
- The summary says when URLs fold into templated rows ("44 map rows, 65 URLs").
- The docs no longer say active options "need a scope": the targets given are their scope.
- `dns` says how many names it asked and how many did not resolve.
- `-browser` says when Chrome found nothing the static pass had not.
- `export -format hosts` lists addresses given as targets.
- A screenshot directory that is a file is a usage error naming it.
- A `redir` parameter is recognised as a redirect target.
- A guessed name whose CNAME points at a name that no longer exists is found (`-w`, `-permute`), so its takeover check runs; with `-live` it is reported as a takeover candidate, not as a live name.
- `fuzz` stopped by the kill file, the request budget or `-maxtime` says which, and gives the command that goes on from the first input not answered (`-start N`). With `-db`, `azhaq resume -db FILE` runs it.
- `subs` asks no third-party source about a domain whose TLD has no registry (`corp.internal`, `azqlab.lan`), and says why.

## v0.8.1

### Changed

- `subs` asks subdomain.center again while its answers keep adding names. Without a key it returns a different random 500 of a domain's names per call (about 5,500 for tesla.com, about 7% of them live), so one call is a lottery: subfinder's live names that azhaq lacked on tesla.com all came from it. Six calls in a run (it allows five, then one per ~12 s) gave 42 live tesla.com hosts subfinder lacked, against 16 the other way, all of them from subfinder's own draw; checked with two resolvers (azhaq and dnsx). A key pages the whole set in one call, as before. A longer `-source-timeout` buys more rounds.
- DNS: a resolver that leaves a third of its queries unanswered is asked one turn in sixteen until it recovers. Quad9 dropped about half the queries for names under a CDN zone, each costing a two-second timeout: resolving 2,135 tesla.com names took 43 s, now 15–21 s with none failed (dnsx with the same resolvers: 24 s, 194 failed).
- `ports` does not pace this machine's loopback unless `-rate` (`-port-rate`) is given: a full scan of 127.0.0.1 took 218 s at the default 300 per second, now 3.4 s, with the same 20 open ports `ss` lists.
- Technology detection: a page that loads a library from cdnjs is no longer reported as behind Cloudflare (Wappalyzer's cdnjs → Cloudflare implication; DVNA on 127.0.0.1 was).
- Defaults at full strength, as the strongest tool for each job: parameter and path guesses are not paced (as arjun and ffuf; `-params-rate` was 20/s, `-dirs-rate` 100/s), DNS is paced only by the queries in flight (as dnsx; `-dns-rate` was 100/s per resolver), ports go at 1000/s (naabu's; was 300), 10 requests in flight per host (katana's; was 4). Set `-rate`, `-max-requests` and the per-job rates to slow a run down.
- The active options (`-ports`, `-dirs`, `-params`, `-dns-brute`, `-permute`, `-graphql`) take the targets given as their scope when no `-allow` or `-scope` names one, as the drop-in commands did; `roles -replay-writes` writes only to the `-url` hosts unless told otherwise.
- `-timeout` stopping a passive source is the run hitting its limit, not a failure: exit 4 with `azhaq resume -db FILE -timeout 0`, which asks the cut sources again (was exit 3, and resume found nothing to do).
- `subs -live` prints the live names DNS met as another name's CNAME target (tesla.com: 9 the workspace held and the output left out) and counts them in the summary; `dns` says how many names it asked and how many did not resolve.
- Benchmark: katana runs with its jsluice parser (`-jc -jsl`, its strongest static setting), and a new "bundle grep" column counts the known routes among the quoted paths in the scripts katana fetched, the by-hand baseline a reviewer measured. Juice Shop: Azhaq 70/77, katana `-jc -jsl` 1/77 (1.4 GB), bundle grep 37/77 as bare strings. The README states the reference commands.
- Benchmark: `params` runs at its defaults against arjun's on the local apps, and both at 20 requests per second on ginandjuice.shop (Azhaq alone was held to 50).
- The v0.8.0 notes said `-source-timeout` defaults to 30s; it shipped at 60s.

## v0.8.0

A raw subdomain count is a trap: most of the names a passive collector returns do not resolve (stale certificate logs, wildcard noise, numbered junk). Against a well-sourced subfinder, azhaq returns far fewer *raw* names but **more live ones** (hackerone.com: 14 live vs 12, from 42 names vs 529; tesla.com: 494 vs 480) — it was losing a comparison it actually wins, because the output did not show it. v0.8 makes the resolvable surface and its provenance visible, and fixes the reliability and speed rough edges found alongside it.

### Changed

- `subs` shows where its names came from and the live/dead split. A run prints a per-source credit line (`sources: crtname 32, rapiddns 20, anubis 15, …`), and `subs -live` reports `14 live names (42 collected, 28 did not resolve)` — so a thin-looking count is self-explaining and a raw total is read next to what it actually resolves to.
- `subs` keeps what the sources gave when a limit cuts the run. A deadline (`-timeout`) now stops waiting on slow sources a moment early and emits the names collected so far (marked `partial`/`degraded`), instead of discarding everything: `subs -all-sources -timeout 60s` returns its by-then names, never zero.
- `-source-timeout` (default 60s, v0.7.3's fixed limit) bounds each passive source apart from the run's `-timeout`, so one slow source (crt.sh) cannot starve the rest; a source past it is listed and retryable, and when others answered it is only a warning.
- `dirs` runs 40 path guesses in flight, as ffuf, so `-rate 0` matches ffuf's speed instead of running at half its threads; the default pace is still limited by `-dirs-rate`.
- `export -format openapi` marks the operations the active mapper left alone as state-changing with `x-azhaq-skipped: true` and a reason, and `export -format openapi -safe` leaves them out — so importing the description into another tool does not turn `/createdb` back into an actionable request.
- A capped run behind a sign-in prints a resume hint with the credential flags (`azhaq resume -db app.db -login-user me -login-pass …`): the session is not stored, so resume signs in again.

## v0.7.4

### Changed

- A crt.sh failure no longer makes `subs` exit 3 on its own: when the other sources returned the domain's names, a crt.sh timeout or gateway 5xx is listed (`partial`) and the exit code stays 0, like any other source. crt.sh is flaky, and a run that got its names should not fail a CI gate over it; `-fail-on-errors` still turns every source failure into exit 3.
- `-allow` and `-deny` accept a `host:port` copied from a URL's authority (`-allow 127.0.0.1:5013`): the scope is matched by host, so the port is ignored. A run whose only target was excluded by a mistyped scope already prints why; the port no longer silently leaves the target out of scope.

## v0.7.3

### Fixed

- `subs` gives a slow source the time it needs: crt.sh takes about 30 seconds for a large domain (hackerone.com, tesla.com) and the 30-second request limit cut it off before it answered, so a direct `subs -d` run reported it as a timeout and exited 3 most of the time. The limit is now 60 seconds; a source that genuinely fails or stays slow past it is still reported and still makes the exit code 3.

## v0.7.2

### New

- `-get-words exec,import` requests the URLs left alone for these words only (finer than `-all-gets`).
- `-no-paths` turns off the built-in path checks; `plan` counts them.
- `urls -json` says which source gave each URL (`source`); `run -urls-source` adds it to the url rows.
- A site with a sign-in form and no session given suggests `-login` in a `next:` line.

### Changed

- Chrome downloads nothing: a download a page starts is refused before it is saved, and listed under "left alone" (`Chrome would download it`). Before, `-browser` let the target's files land in `~/Downloads`.
- Links in `javascript:` hrefs, `on*` handlers and `data-*-url` attributes are read (DVWA's `view_source.php`, `view_help.php`).
- Routes a script builds as `this.host + "/orders"` are no longer also listed at the site's root (`/orders`); paths that are keys of an API description embedded in a script are left to the description.
- `-browser` renders pages without images, fonts, media and socket polling (half of Chrome's requests on Juice Shop); screenshots and the sign-in still load everything.
- A scanner's own test files (`acunetix_…`, `bxss.me` hosts) and random-named executables from archives never enter the map.
- `roles -replay-writes` claims a write on another role's object only when it is proven: the owner's object is read as the owner before and after, and must have changed the way the write asks (or be gone). A 2xx that changed nothing is `answered 2xx but changed nothing of the owner's`; a POST to a collection is `creates in another role's collection`; both are listed with `-all` only. Routes that only take a write (`PUT /users/v1/{username}/email`) are filled with each role's identifiers without a HAR.
- A static document (a PDF, an image) no longer tops `roles` as the same answer for a session that did not find it.
- A name is called dead only when a second resolver, of another operator, agrees.
- An origin that leaves 5 requests in a row unanswered is stopped for the run: what was left for it is `capped`, listed under "left alone" with the reason, and `azhaq resume` retries it (exit 4).
- Work is ordered by value: front pages and API paths first, other pages next, archived URLs last; archived static files (images behind query strings, media hosts) are listed and never requested.
- A directory named after a verb (`/vulnerabilities/exec/`, `/admin/user/add/`) is a section with a form, and is requested; `/exec`, `/import_paste` and a directory under an API path (`/api/jobs/run/`) are still left alone.

### Fixed

- An answer of 401 or 403 is never a catch-all: a route that exists but is gated is kept and marked `auth`/`forbidden`, not dismissed as the page an unknown path gets, and its coverage no longer flips between `visited` and `catchall` from one run to the next (which made `diff` and `watch` report phantom changes).
- `roles` whose replay was cut short by `-replay-max` reports it: exit 4, `complete:false`, and a `stopped:` line, instead of a clean exit 0 that hid an access-control comparison left unfinished.
- A path in a directory past the 24 whose unknown-path answer is asked is compared with the nearest directory above it, not the site's root: Juice Shop's `/rest/…` error page for unknown paths is no longer taken for a route.
- `params -rate 0` (`-params-rate 0`) sends without a pace, as arjun does: five lab pages and 6,453 names in 0.9 s; 0 used to mean the default 20 a second.
- MCP tools take a single string where a list of strings is expected.
- The release archives carry the recipes, concepts and troubleshooting pages and the benchmark's README.

## v0.7.1

### Fixed

- Chrome keeps the scope it started with; a later reset of the run's settings raced with the requests it was still deciding.
- The run's resolver is swapped whole: a request a finished run left behind (a source past its deadline) raced the next run's reset.
- `golang.org/x/net` v0.62.0 (GO-2026-6866, GO-2026-6860 in its HTML parser).

## v0.7.0

### Changed

- Chrome is held to the scope: every request a page, frame or worker makes is intercepted, and one to a host outside the scope (without one, outside the site) is refused before it leaves, WebSockets included; refused URLs are listed as skips (`outside the scope (Chrome)`), and Chrome's requests count against `-max-requests`. A sign-in that goes to an identity provider outside the scope says so (`add it with -allow`). This covers `-browser`, `-login`, `roles -role-login` and `shots`. Windows a page opens are closed, Chrome's requests keep to `-rate`, WebRTC sends nothing past the guard, and the local relay Chrome connects through serves Chrome alone.
- `azhaq mcp` does not start without `-allow` or `-scope`, unless `-unlocked` says so.
- `params` checks every signal against a control of random names and values: a page that echoes its query string (Juice Shop's error page) no longer reports every name in the wordlist; a page that answers names it does not read is noted and not searched.
- `roles` claims "reads another role's object" only for an identifier of that kind of object (Juice Shop's `bid` is a basket's, not a basket item's), lets the object's own answer decide (an owner or reference field that names another role clears the claim), and says why in `owner_by`.
- A crt.sh failure is never partial: it makes the exit code 3.
- A query value that switches something (`?phpids=on`, `=off`, `=enable`, …) is left alone like a state-changing name.
- An `http://` URL of a site the run was given as `https://` (from an archive, a link) is mapped as https when the http front page redirects there or serves the same page: the budget is not spent twice.
- A link's query names belong to the link's row, not to the page that holds it.
- Links and forms honour `<base href>`; an export never lists a URL left alone as state-changing as an operation.

### New

- `roles` results you can trust and replay: each cross read says how sure it is (`proved`, `likely`, `guess`) and why (`evidence`); a made-up identifier of the same shape is asked as a control, and a route that answers it like a real object is `answers any identifier`; access that works both ways is said; each session is checked on a canary during the replay and renewed (`-role-cmd`, `-role-login`), and what it answered while possibly dead is `session_suspect`; the site's `200 Access denied` page is learned as a refusal (or given with `-refusal`); `azhaq roles show -dir DIR URL` prints the kept answers side by side, a field-level diff and a curl per role with its session as a shell variable.
- Scripts on other hosts the scope allows (a CDN, `api.example.com`) are read, and the routes they call there are mapped on their own host, with the script that names them; without a scope, hosts of the same site.
- The views of an app's router (Angular, React Router, Vue Router): rows of kind `client-route` (`http://app/#/administration`), with the `guard` that protects a view (`canActivate`); never requested.
- Build manifests: Next.js `_buildManifest.js` and `_ssgManifest.js` (`/admin/users/[userId]` as `/admin/users/{userId}`), Create React App, Vite, Angular service worker and Nuxt.
- Source maps without a comment: the `SourceMap` header, or `<script>.map` guessed (at most 10 per origin, kept only when it is a source map).
- WebSocket endpoints (`new WebSocket`, socket.io) as rows of kind `websocket`, never requested as pages.
- Chrome is GET-only by default: a page's own POST, PUT, PATCH, DELETE and beacons are refused before they leave, mapped as the route's operation (`source: browser`) and listed as left alone; `-browser-writes` lets them go.
- API descriptions are looked for under each API base a run's routes reveal (`/identity/api/v2/openapi.json`, springdoc's `v3/api-docs` and `swagger-config`, springfox's `swagger-resources`), not only at the root: up to 8 bases per origin, 10 requests each.
- Map rows name the parameters worth trying first (`watch`: `returnUrl (redirect)`, `file (file)`, `cmd (command)`, `isAdmin (debug)`, …).
- Subdomain takeover candidates in the summary of `subs -live`, `dns`, `probe` and `run`: a CNAME to a name on Azure, Elastic Beanstalk or Fly.io that does not resolve, a CNAME to a domain nobody registered, or a hosting service's page for a name nobody claimed (GitHub Pages, S3, Heroku, Shopify, …), each with its evidence.
- GraphQL with introspection turned off: the root fields, their types and required arguments, read from the server's validation errors (`"recovered":"suggestions"`); no document asked can pass validation, so nothing runs. Endpoints that run queries sent with GET are marked `get_queries`.
- Docs: `azhaq docs recipes`, `concepts` and `troubleshooting`.
- `roles -replay-writes post,put,patch[,delete]` asks each role's writes with every other role's session: its own from a HAR (`-har alice=alice.har`), and the PUT and PATCH (an empty object, the owner's first; a server that replaces on PUT may clear the owner's own object) and DELETE its routes take on its objects; `[bob writes alice's object]` on Juice Shop's basket items. Opt-in, inside the scope you name; `-dry-writes` lists them without sending.
- `run -stream` prints the names, URLs, answers and open ports as they are found, before the ranked map.
- `dirs` prints and keeps each hit as it is found, so a stopped run keeps them; a drop-in run given `-db` resumes with `azhaq resume` (the workspace keeps its target list).
- Forms with an empty or `#` action submit to their page; forms carry their encoding and file inputs, and `export -format openapi` holds every form (GET forms as query parameters, POST forms as urlencoded or multipart bodies) and the pages found with a query string.
- The summary suggests `-graphql` when a GraphQL endpoint was found and not introspected.

### Fixed

- `ingest` skips and counts the lines it cannot read instead of refusing the file; katana's request-only records (headless) are read.
- Apache and nginx directory-listing sort links (`?C=N;O=D`) are no separate URLs.
- An OpenAPI description's state-changing GET (`/createdb`) is `skipped` with its word and listed as left alone, like a link's.
- Docs: the port scan's one `HEAD /` to a silent port; the drop-ins' targets are their scope; workers repeat what they share.

## v0.6.3

### Changed

- `roles` catches every signed-in session dead at once (tokens copied together expire together): when no signed-in role reads anything the anonymous role is refused, each is judged alone. It exited 0 with the access-control rows silently gone. The note quotes what the site said when the role asks again (`the site said "Signature expired. Please log in again."`).
- A JSON Web Token a role carries is read for its `exp` before anything is sent: an expired one is said at once, and the run's end says whether the session died or the site still took it (`check that it verifies token expiry`).
- A name answered SERVFAIL on every attempt, by two resolvers or more, on two passes, is dead (`result` `servfail`), not a failure: one lame delegation among 1,500 names made `subs -live` exit 3.
- MCP arguments are checked against the schema `tools/list` publishes: a wrong type, a missing field or a value outside an enum is refused with -32602, naming the argument, what it takes and what was given (`roles[0] … must be an object …, not the string "anon"`). Tool descriptions and schemas agree.
- MCP `azhaq_export` pages by unit (OpenAPI paths with the components they use, GraphQL types, SDL definitions, Burp scope entries, HTML rows, GraphML nodes, lines), so each page parses on its own; `offset` counts units.
- A route found only in scripts, by a call whose method is unknown or not GET, is `hint` when a GET answers 404, not `gone`.
- `azhaq plan` counts the queries to third-party sources (the subdomain sources, archives, RDAP, keyed engines) and bounds the requests to the targets (about 34 per web service before its links, and the cap that applies), instead of claiming to print exactly what a run sends.

### New

- `roles -role-cmd 'alice=./token.sh alice'`: a role whose headers a command prints, run before its run and again before the replay, for tokens that live minutes.
- Where each route was found: `found_in` names the script, `line:column` and the call as written (`main.js:6472:88  this.http.post(…/rest/2fa/verify…)`), in `show`, `query -json` and `run -json`.
- A method is followed through one wrapper function: `logQuery('/logger')` with `logQuery(url) { fetch(url, {method: "post"}) }` gives `POST /logger`.
- Markdown links a page's scripts render (DVNA's lessons) are read as links.
- The summary suggests `-browser` when a target page leaves its links to its scripts and the map is thin.
- `ports` asks a port that neither accepted nor refused a connect once more (when few did), waits for the greeting of a service that speaks first (a loaded sshd), and counts silent ports in `filtered` (`filtered_ports` lists up to 64) with a summary note.

### Fixed

- `ingest` of httpx, katana and ffuf output feeds `export -format targets`, `burp`, `html` and `openapi` like a run's own rows (`targets` printed nothing after an httpx ingest). katana's POST requests and forms are routes and forms; ffuf's `-json` lines are read.
- `query -fields body` holds every operation's body fields, those from an OpenAPI description too.
- JavaScript string noise left the map: `/pQ`, `/SQ`, `/juice-shop/juice-shop`, `..` paths; a version prefix alone (`/v3`) stays only when something answers there.
- `help dirs` named a `run` flag (`-dirs-threads`) for `-rate 0`; the README's roles section says where `-dir` keeps each role's database.

## v0.6.2

### Changed

- Without a scope, a redirect is followed only within the site (the same registrable domain or address). A redirect to a third party is recorded with its `Location`; its page is never reported as the target's (`probe` reported a CDN's title and technologies for a host that redirected there).
- A third-party source that fails while other sources answered for the same domain is listed with `"partial": true` and no longer makes the exit code 3; `-fail-on-errors` (now also on `subs` and `urls`) counts it.
- subdomain.center is back in the default sources, behind a check: a name only it gave is kept when it resolves, not to a wildcard. rapiddns, thc and hudsonrock join the default keyless sources.
- `query` lists every name as its own row (the map still folds names nobody resolved).
- `scope` prints text; `-json` gives the object.
- MCP: `azhaq_query` returns compact rows by default; `limit` is capped at 1,000; unknown arguments are refused (-32602); export returns its content (16 KB per call, `offset` for more) and names files right (`.html`, not `.html.html`).

### New

- MCP `azhaq_resume`: continues a workspace's run stopped by the budget, a timeout or a cancel. Summaries point at it instead of a command line.
- `ports` names services that wait to be asked: one `HEAD / HTTP/1.0` on the open connection (`http`, with the `Server` header as banner), else a TLS handshake (`tls`, `https`, and the certificate's `subject_cn` and `subject_an`). `run -ports` hands HTTP and HTTPS ports on with the right scheme. A name's IPv6 addresses that cannot be reached are said in the summary.
- `watch` and `diff` see a JSON listing grow or shrink (`/users/v1: [200] 5 items → [200] 6 items`).
- `roles` finds each role's own objects without `-id`: it learns who each role is (JWT claims, its `/me`-like answer, what a Chrome sign-in left in storage and the login's answer) and which list items are whose (an `owner`, `user`, `userId`, `email` … field), then asks the other roles for them: `[u1 reads u2's object]` on VAmPI's books and Juice Shop's baskets and users.
- `roles` says when a role's session looks dead (refused wherever a session matters) and exits 3.

### Fixed

- `roles`: a redirect to a login page is a refusal (cookie-session apps were all `status differs`); URLs found by `-paths` are compared with their real bodies (they were 0 bytes, so a users API with password hashes was missed); a flag only one role gets in list items is not a field difference; the summary counts listed rows apart from the others.
- `probe` dropped a host whose front page another target redirected to (tesla.com → www.tesla.com): it was answered from the redirect, and reported for neither. Every target now ends as a row, a failure or a skip; one that has none is listed as failed.
- `dirs` reported 1,048,576 as the length of a larger body; it reports the whole body's length, as ffuf.
- `ports` never asks a raw printing port (9100–9107) anything: it would print the request. A second name on the same address has its web and TLS ports asked again under its own name (Host header, SNI). A TLS port is handed on to the HTTP collector.
- MCP: arguments out of range are taken as their default (a huge `offset` ended the server); a failing call ends that call, not the server; `azhaq_roles` holds to the server's budget; `azhaq_resume` refuses a run started with options no tool of the server starts (`-all-gets`, `-dirs`, …).
- `roles` prints redirect targets without their query, fragment or path parameters (they can carry a role's credentials), never takes a session's id for a user's, and calls a session dead only where the anonymous visitor was asked to sign in (401, 403, a sign-in page).
- `diff -db` on a workspace with one run says so instead of printing nothing.
- MCP: no response is sent for a cancelled request; progress notifications start after a second; error texts no longer carry command-line hints; temporary target lists are removed.
- "tasks left" in a stopped run's summary is "tasks known and not done": the count can grow as a resume finds more.

## v0.6.1

### Changed

- `azhaq resume` no longer asks again what the stopped run asked: a run keeps its answers (and its path guesses) in the workspace until it is complete. Juice Shop capped at 50 requests and resumed until done: 211 requests in all, against 982 before and 205 for one run.
- `probe -json`: `status_code` is the first answer, as httpx prints it (a 302 stays 302); `final_status_code` and `final_url` say where an in-scope redirect ended.
- `-scope` given with targets of your own filters them; it adds the program's targets only when you give none.
- `query` prints every row that matches unless `-limit` is given.
- `diff` counts as removed only what answered before; names and URLs that were only heard of and not heard of again are `not_seen_again`, with the sources that failed.
- Names under a domain you gave are `live`, not `sibling`.
- A route scripts only call with POST or PUT is a `hint` when a GET answers 404 or 405, not `gone`.
- A query value that names a page (`index.jsp?content=about.htm`) is not folded into a template; `-per-template N` sets how many URLs of one template are requested.
- MCP results are sent once, as compact JSON (no `structuredContent` copy).
- subdomain.center is out of the default sources: it answers 500 random names per call.
- Catch-all and calibration paths are random names that do not name the tool.

### New

- `subs -w WORDLIST` and `subs -permute`: DNS brute force and permutations of the names found.
- `ports` scans IPv6 addresses too where they are reachable, and takes `-allow`, `-scope`, `-deny` and `-max-requests`; each connect counts against the request budget. `dirs` and `params` take `-allow` and `-all-gets`.
- `roles`: a cross-tenant test. Each role's own objects (an identifier only its answers held, or one given with `-id ROLE:NAME=VALUE`) are asked with every other role: `bob reads alice's object`. Answers are compared by nested JSON fields; sensitive fields (passwords, secrets, keys, card numbers, a token several sessions share) are named, and `anyone reads sensitive fields` is listed by default. New verdicts: `only one role reads it`, `roles read the same sensitive fields`. Rows carry `owner`, `readers`, `sensitive`.
- `query -failed`: every failed target, the list to retry; summaries name up to 100 targets per failure.
- `-dirs-rate 0` (and `dirs -rate 0`): no pace but the threads, as ffuf.
- `show HOSTNAME` lists the name's web services and the error of one that failed.
- `export -format graphql` (introspection JSON) and `-format sdl`; `-graphql` keeps the whole schema and the map lists each query, mutation and subscription with its arguments; OpenAPI exports carry the GraphQL endpoint as one POST with `x-azhaq-graphql`.
- `export -format burp` writes the run's scope as resolved when it started, excludes included.
- Script calls inline in a page with a page-relative path (`xhr.open("GET", "util/status.jsp?host=" + h)`) are read.

### Fixed

- With a session, `dirs` and `params` no longer send words that read like an action (`delete`, `reset-db`, `logout`); they are listed as skipped. Summaries no longer list as skipped a URL a guess requested.
- URLs carrying a scanner's payload kept by an archive (`/etc/passwd`, `;curl …oast.live`, `<script>`, SQL) never enter the map.
- OpenAPI exports are valid: operationIds are unique, every path parameter is declared, same-shape templates are one path.
- MCP port scans count against the server's request budget and follow its `-rate`.
- `roles`: a 4xx, or an error answered with 200, is a refusal (an owner-only object was `signed-in only`). With `-json`, stderr holds the summary only.
- `watch` exits with its run's code.
- With `-json`, every line on stderr is JSON: failures and limits are in the summary, and an error is a summary with `error` and `exit`.
- A name behind a CDN is scanned on its web ports only on every address, IPv6 included (CloudFront's IPv6 ranges read as plain AWS).
- A GraphQL server that refuses the full introspection query for any reason but having introspection off is asked for the names.
- `plan` and options refused as a usage error leave no database file behind.
- `show URL -json` (flags after the argument) works for every command.
- Hosts on a provider's shared domain (an S3 bucket, `*.herokuapp.com`) are not enumerated or looked up in RDAP as if they were the tenant's domain.

## v0.6.0

Every line Azhaq prints can now be trusted by whatever reads it, a person, a script or an assistant.

### Breaking changes

- `run -json` prints the map as JSON lines on stdout; the summary is one JSON object on **stderr** (`"type":"summary"`). `run` no longer prints `db …`, the stats line and a JSON summary on stdout.
- Exit codes: 0 complete, 1 error, 2 usage, 3 finished with failures, 4 stopped by a limit. `-fail-on-errors` and `-fail-on-capped` now only widen what counts (fan-out failures, depth caps).
- `probe -json` uses httpx's meanings: `host` is the name (it was the address), `host_ip` the address, `a`/`aaaa` the addresses the name resolved to, plus `port`, `scheme`, `path`, `input` as given. Empty fields are left out. The favicon is hashed only with `-favicon`, and probe sends one request per service (no catch-all check).
- Requests to targets carry a current browser's User-Agent instead of `azhaq/VERSION` (`-header 'User-Agent: …'` replaces it).
- Found URLs whose names say a GET would change something (`logout`, `delete`, `save`, `reset`, `create`, …) are no longer requested (`-all-gets` restores it). `logout` left the built-in paths.
- `roles -jsonl` rows carry `answers`, `verdict`, `found_by` and `template`; which rows are listed follows the verdicts (`-all` lists every endpoint).
- Default subdomain sources: crt.sh is read from `/json` natively; riddler, recon.cloud, sub.md, threatminer and certificatedetails.com are out of the default set, reconeer needs a key.
- Names nobody resolved are `unresolved`, not `live`.

### New

- `azhaq help COMMAND`, `help -json` (every command and flag), `--version`, `azhaq docs` (offline documentation).
- A summary on every command: failures (retryable or not), unreachable targets, skipped targets and requests with the reason, the limit that stopped the work, the command that resumes it. `-timeout` everywhere.
- Scope, pace and budget flags on every command that sends requests; targets outside the scope are listed, never requested.
- `azhaq plan`: everything a run would take, skip, run and send, without sending anything.
- Scripts: the requests they make (method, query names, body fields) worked out from literals, template literals and variables.
- API descriptions: per-operation parameters by location, body fields, security; the document kept; parameterless GETs asked; Swagger UI pages that build their document's URL at run time.
- `export -format openapi` keeps the target's own description and adds what scripts call and forms send. New `-format names`.
- `roles`: an access matrix; every endpoint asked with every session, path parameters filled from identifiers in the answers, answers compared by status, size, body and JSON fields.
- `azhaq query` and `azhaq show`.
- `azhaq ingest` reads subfinder, dnsx, httpx, katana, naabu, nuclei, gau and ffuf output and Azhaq's own export.
- `azhaq mcp`: an MCP server with the scope and budget locked at start.
- `watch` reports removed URLs and pages that answer differently, and ignores query values that change on every request.
- `subs -db` keeps every name; `subs -json` gives each name's sources.
- `-browser` reaches the pages of hash-routed apps and carries the login's sessionStorage.
- HTTP connects to the addresses the run resolved, IPv6 first where routable.
- Release checksums are signed with sigstore.

### Fixed

- A failed request is `error`, not `visited`; failures and refusals are never silent.
- The catch-all check compares JSON by fields and size.
- Error pages are not crawled for links; junk URLs (`NaN`, cut-off archive links, scanner payloads) stay out.
- Free-text scope entries are one skipped entry; registrars are not owners; parser tables are not secrets.
