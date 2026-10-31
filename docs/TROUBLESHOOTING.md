# Troubleshooting

`azhaq docs troubleshooting` prints this page.

**Why is my URL `hint`?** Azhaq knows it (from a script, an API description, an archive or a link) but no GET proved it: it takes a path parameter, or only another method (scripts call it with POST), or a GET there answers 404 while scripts call it. Send the method its operations name. `azhaq show -db W URL` gives the call site.

**Why is a live endpoint `gone`?** It answered 404 or 410 to a GET. If scripts call it with another method, it is a `hint` instead; if it is `gone`, nothing Azhaq read says it takes another method. Archived URLs are often gone.

**Why was `/exec` (or `/logout`, `/createdb`) not requested?** Its name says a GET there could change something. A directory named after a verb (`/vulnerabilities/exec/`, `/admin/user/add/`) is a section with a form and is requested; one under an API path (`/api/jobs/run/`) is not. It is listed under "left alone" with the word. `-get-words exec` requests the URLs left alone for that word only, `-all-gets` all of them, if you accept the side effect.

**The map looks thin.** The app may draw its links with scripts. The summary suggests `-browser` when a page leaves its links to its scripts. Behind a login, give a session (`-cookie`, `-header`, `-login`).

**`roles` lists nothing.** Check the notes first: a dead session (`refused wherever a session matters`) means the tokens expired; use `-role-cmd` for short-lived ones. Every endpoint answering every role alike is listed with `-all`.

**Exit 3, but the results look fine.** Exit 3 means the results are usable and something failed: a source, a host that did not answer, a dead session. The summary's `failed` list and notes say what; `azhaq query -db W -failed` lists every failed target.

**`crawl` lists fewer URLs than katana, or a path katana prints is missing.** Look in `crawl -json -rejected`: every string katana's patterns take from a script or a page is either a URL of the crawl or a rejected candidate with its reason (a media type, an expression, a file name, library code, another host, a link outside the scope). A path of katana's that is in neither is a bug. A link to another host is not followed unless `-fs rdn` (a name of the same domain) or `-ns` says so; `-do` lists what was left out.

**`crawl` says a host answered 429 or 503.** It waited (1 s doubling to 30 s, or the host's `Retry-After`) and asked again, up to three times; the summary names the host and how many requests still got it, and those are listed with that status. Lower the pace with `-rl`, `-hrl` or `-c`.

**Exit 4.** A limit stopped the run with work left (`-max-requests`, `-timeout`, Ctrl-C, or the kill file). `azhaq resume -db W` continues it.

**The run stopped at once with exit 4 and a kill file.** The file `W.stop` (or the one `-kill-file` names; `roles.stop` in the `-dir` of `roles`, where it stops the runs of the roles and not the replay after them) exists, from an earlier stop too, and `stopped` says `the kill switch`. Nothing more is sent while it exists. Remove it, then `azhaq resume -db W`.

**Chrome does not start.** Azhaq looks for Chrome or Chromium on the usual paths; `AZHAQ_CHROME=/path/to/chrome` names it. Where Chrome cannot start its sandbox (some containers), the error says so; `AZHAQ_CHROME_NO_SANDBOX=1` runs it without one. Do this only where you accept that the pages Chrome loads are untrusted.

**The Wayback Machine answers 429, Common Crawl refuses.** Both rate-limit or block some networks. The summary lists them as failures; the other archives still count. Run again later, or from another network. `urls -retries N` sets how often a refused request is asked again, `-urls-pause` the wait between an archive's requests, `-proxy` sends them through another address.

**`urls` printed fewer URLs than I expected.** The host alone is asked unless `-subs` is given. A `note` in the summary says when an archive stopped at its page cap (`-urls-pages 0` removes the cap, `-fail-on-capped` exits 4 on it), when URLs went past `-urls-max`, and when an archive was left out because it cannot apply a `-mc`, `-fc`, `-mt`, `-ft`, `-from` or `-to` filter. An archive that failed is listed as failed and the exit code is 3.

**`urls -providers` says a name is not an archive.** `-providers` takes archive names (`wayback,commoncrawl,otx,urlscan,arquivo`). The API-key file is `-provider-config FILE`; a value with a `/` or naming a file that exists is still read as that file.

**A notification did not arrive.** `azhaq watch` prints `azhaq watch: POST https://host/…: reason` for each webhook or provider that failed and exits 3; `azhaq notify` lists them in its summary (`custom failed: … (id ops)`), also exit 3. The reason names the host and the answer (`500 …`, `connection refused`), never the URL's path or token. A 429 or 5xx is tried three times first (`-v` shows each try); a 400, 401, 403 or 404 means the URL or the token is wrong. A Retry-After over a minute is reported instead of waited.

**`notify: provider config: … field … not found`.** The config has a key the schema does not (`slack_webhok_url`). Fix the spelling; azhaq does not skip it silently.

**`params` exits 3 with `HTTP 429 from the target: it limits requests`.** The page (or a firewall before it) limits requests, and kept doing so after Azhaq waited as its `Retry-After` or 1, 2 and 4 s said. The names found before stay in the result; the rest of the list was not tried. Lower `-rate` (`-rate 2`), use `-stable`, or run it again later. The same exit and a note say requests got no answer (a server that drops connections under a long query: try `-c 100`).

**`params` says `the page changes by itself`.** The page answers the same request with bodies of very different sizes, or with another status, so a change caused by a name could not be told from its own. Give the URL of a page that is stable (a search route, an API route).

**Where did my database go?** `run` without `-db` writes `azhaq-TIME-PID.db` in the current directory (or `$AZHAQ_DB`) and remembers it in `.azhaq-last` for `query` and `show`. Drop-ins (`subs`, `probe`, `dirs`, …) without `-db` use a temporary one, gone when they end.

**`dirs` hid a page I know exists.** The calibration drops a guess that answers like a path that cannot exist: the same status and size (ffuf's rule), the same word and line counts where the not-found pages differ in size among themselves, or a size within the path's length where they repeat the path. A real page that is byte-for-byte the not-found page cannot be told apart by any size or count; `-fs`, `-fw` and `-fl` do not undo the calibration. Use `fuzz -ac=false -mc all` to see every answer.

**`dirs` says `N of M guesses were answered 429`.** The service is rate-limiting the sweep. A 429 is not in the default `-mc`, so those guesses were not judged and the paths may exist. The exit code is 3. Lower `-rate` or `-t` and run again.

**`dirs -u URL/path` found less than a sweep of the root.** A URL with a path is swept under that path only (`/api/WORD`); it does not also sweep `/`. Give both URLs to sweep both.

**A UDP port is `open|filtered`.** The port stayed silent when asked every way its protocol has (a port with no known protocol is asked four ways) and no ICMP port unreachable came back: a service that ignores a request it does not understand, or a filter. On a loopback or LAN address it usually means the first; a closed port there answers with an ICMP error and is `closed`. Across a firewall that drops ICMP, closed ports also read `open|filtered`; a host that rate-limits its ICMP replies leaves closed ports silent too, and the summary says when that may be the case (`udp: N silent ports on a host that refused others …`). `ports -json` lists them; the plain output lists only the open ones.

**`probe` shows a redirect, not the page.** `probe` follows no redirect, as httpx. `-fr` follows them inside the site (`-fhr`: the same host; `-maxr N` stops at the Nth redirect, as httpx counts it, so follows N-1); `status_code`, `title` and the rest are then the last answer's.

**`probe -timeout 5` is refused.** `-timeout` bounds the whole run and takes a duration (`5m`); httpx's per-request `-timeout` is `-req-timeout 5s` here. A run stopped by `-timeout` exits 4 and `azhaq resume` continues it.

**A `probe` row has `failed: true`.** The target did not answer: it does not resolve, the port is closed, the host stopped answering after `-maxhr` tries, or the scope left it out. `error` says which; the summary counts them under `without an answer`, and exit 3 follows when the failure is worth another try. `-probe` prints `[FAILED]` lines in the text output.

**A name resolves only through a wildcard, and `probe` still asks it.** The names given to `probe` are the ones you want asked; the summary notes how many were wildcard answers. `subs -live`, `dns` and `run` still leave them out.

**`probe -kb` says the model is not there.** The classifier reads `~/.dit/model.json` (or `$AZHAQ_DIT_MODEL`); azhaq never downloads it. Fetch it once from the address in the message.

**`probe -x POST` sent requests.** `-x`, `-body` and `-rr` send what you give to the targets in scope, and a POST, PUT or DELETE can change data there. Each request is counted, paced by `-rate` and in the ledger; the summary lists the methods sent.

**`subs` returns different names from run to run.** Some passive sources answer differently each time (subdomain.center returns a random sample of its names on each call). Azhaq keeps the names it found in `names/DOMAIN.json` (under `$AZHAQ_DATA_DIR`, else `$XDG_DATA_HOME/azhaq`, else `~/.local/share/azhaq`) and asks them again as the `history` source, so a name that resolves still comes back. The `coverage:` note says how much of what the sources know the run holds. `-no-history` turns the file off.

**`subs` lists names with `"unverified": true`.** Without `-live`, subs does not look names up in DNS. The names only subdomain.center guessed (most of its answer is made up) or only the name history held are listed, flagged, and counted in `unverified`; `-live` checks them and leaves out what does not resolve.

**A source answered 429.** The source is asked again after its `Retry-After`, up to three times; the summary says how long that took (`crtname answered 429; it was asked again 1 times after 2 s`). A source that asks for more than 30 s, or keeps refusing, is not waited for and its names are missing from the run: the note says so and the source's row has `gave_up_429`. Slow the sources with `-source-rate N`, or leave the source out with `-exclude-sources`.

**`subs -live` lists a name with no address.** It is a CNAME whose target gives no address (or does not exist). `dnsx -a -cname` lists it too; `cname` holds the chain, and a dangling one is also in the summary's `takeover`.

**The `subs` summary says `degraded`** (in the text summary, `DEGRADED: N of M sources failed` on its first line). A source in the default set failed (`sources failed` is above 0), so the names may be incomplete. The exit code is not changed; the failed sources are listed. `azhaq subs -v` shows what each source returned and its error.

**`shots` says `screenshot … not taken`.** The page's images, scripts and styles count against `-max-requests`, and too few were left; the note says how many the page needs and how many were left. Raise `-max-requests`.

**`shots` on a port Chrome refuses (6000, 6666, 10080) says `net::ERR_UNSAFE_PORT`.** Chrome keeps a list of ports it will not open; `shots` and `run -screenshots` allow them by default. `-unsafe-ports=false` brings Chrome's refusal back.

**`shots -u URL` with a path takes a picture of that page.** The URLs a run finds itself are shot only when they are front pages; a URL you give is shot as given, one file per page (`http_host_port_path_hash.png`).

**`shots` of a page that calls `alert()` on load.** The dialog is accepted and the page is shot; nothing waits for a click.

**`shots` says `screenshot … is partial` and exits 3.** The picture was taken while some of the page's images, styles or scripts had not loaded (the row has `"partial":true`, `unloaded` and `resources`). The page was slow, or `-rate` is low for it: a page of 40 requests at `-rate 2` needs 20 seconds, and its time runs from when it last moved, so a slow pace alone does not cut it short; a server that stops answering does. Raise `-rate`, or give the page more time.

**`gallery` says `N of M pages: the picture file is not on disk` and exits 3.** The workspace names a picture file that is no longer where the run wrote it (`file_path`) or beside the database. Keep the `shots -dir` folder with the workspace, or copy it back; the page still lists those pages, with their headers and record, and no picture.

**`gallery` finds no pictures in a workspace, or no groups.** It lists only what `shots` and `run -screenshots` took (`azhaq-shots` rows). A workspace made by an older azhaq has no perceptual hash (no look-alike groups) or no status (a status filter does not list the page); a banner says how many. Take the pages again.

**`gallery`: a `body:` search finds nothing.** Page text is searched only for pages taken with `shots -shot-html`; the banner and Statistics say for how many it was kept. A free word still matches the URL and the title.

**`gallery` does not show a page taken after it started.** It reads the workspace once at start. Stop it (Ctrl-C) and start it again.


**`note: path checks: 28 skipped (an API description was already found)`.** Not a failure. The checks that guess where an API description sits stop once one is found on that origin; every other check was still asked.

**An open TCP port has no `service` or `product`.** The port said nothing and none of the protocols azhaq asks (about 30, one request each, at most 24 connects per port) answered, or it answered in a protocol azhaq does not know. The row keeps the first bytes of any answer in `banner`. A port that accepts a connection and closes it without a word is `tcpwrapped`. When the summary says `open ports whose protocol was not probed`, a firewall or tarpit accepts connects on many ports and the list was not run for the rest.

**A port I know is open is missing.** A port that neither accepts nor refuses a connect is asked once more; if it stays silent, the summary lists it (`ports that neither accepted nor refused a connect…`, rows: `filtered_ports`). A firewall or a loaded host can do that; scan it again. `-retries 3` asks the silent ones three more times, `-connect-timeout 3s` waits longer for a far host.

**`fuzz` found fewer matches than ffuf (or more).** Compare the filters first: the summary says what calibration added (`auto-calibration filtered out answers with size 1234`) and notes when it is off because `-fs` and its kind were given. ffuf's default is no calibration; `-ac=false` gives it. A different `Size` on a compressed page means a different `Accept-Encoding`: azhaq decodes gzip, deflate and brotli, as ffuf, so the same header gives the same size. `fuzz` and `dirs` send no `Accept` header, as ffuf sends none, so an app that negotiates by it (Express's redirect body) answers the same size. The `User-Agent` is a Chrome's, not ffuf's; send `-H 'User-Agent: Fuzz Faster U Fool v2.1.0'` where an app answers by it.

**`fuzz` says `the report … was not written` or `-o … is a directory`.** `-o` names a file. A report that cannot be written is a failure in the summary (exit 3), with the reason; the place is tested before the first request, so a bad path is usually found at once.

**`fuzz` stopped with `over 95% of the first 50 or more answers were 403`.** That is `-sf` (or `-sa`) doing what it says: the target refuses or the run is blocked. The summary gives the command that goes on (`-start N`). `-sa` also stops at over 20% 429, which means the target is rate limiting: lower `-rate` or `-t`.

**`fuzz -x` or `-replay-proxy` shows nothing in the proxy.** Go sends traffic for loopback addresses through a proxy only when it is named with `-x`; the environment's `HTTP_PROXY` is not read. A proxy URL needs its scheme (`http://127.0.0.1:8080`). The summary counts the matches sent through `-replay-proxy` and the ones that failed.

**`fuzz` says `preflight/postflight failed … cannot choose where requests go`.** The value read from the answer ended up in the host, scheme or port of a request (a `Host: TOKEN` line, a `TOKEN/path`). Values come from the target and the request carries your cookies and headers, so azhaq does not allow it, and has no `-preflight-anyhost`. Put the host in the file. `… is outside the scope` means the file names a host the run may not touch: `-allow HOST` adds it.

**`dns -json` prints rows for names that do not exist.** As dnsx does, `-json` gives a row for every name a resolver answered, with its `status_code` (`NXDOMAIN`, `SERVFAIL`, ...). Ask for a type (`-a -json`) to get only the names that have such a record, or select with `jq 'select(.status_code=="NOERROR")'`.

**`dns -timeout 5s` did not stop the run after 5 seconds.** In `dns`, `-timeout` is how long one DNS answer is waited for, as in dnsx (3 s by default); `run` and the other commands use it as the time of the whole run. `dns -maxtime SECONDS` bounds the run: it exits 4 and says which `-start` to go on from.

**`dns -dns-rate 5` still sent more than 5 queries a second.** `-dns-rate` paces each resolver (a second's worth of queries may go out at once after a pause), so the total is the rate times the resolvers (six by default). `-rl N` paces names over all resolvers, as dnsx's `-rl`; with one resolver, or with `-rl`, the total is the rate you gave (a name asked for several types sends one query per type). `-t N` bounds the names in flight.

**`dns -d 192.0.2.0/24` printed nothing.** Addresses and ranges are looked up only with `-ptr` (reverse names) and are otherwise left out; the summary says so under `left out`. An AS number (`AS13335`) expands to the prefixes RIPEstat lists for it.

**`dns -axfr` found no zone.** A name server that refuses a transfer is common. The summary's notes say, per server, whether it refused, did not answer, or was left alone because the scope does not allow it (`-allow` the server's name or address to ask it). Only the name servers of the name and the `-resolvers` you gave are asked.

**`ports -timeout 500` is refused.** `-timeout` is how long the whole run may take (`90s`); the wait for one connect is `-connect-timeout` (`500` is milliseconds there).

**`ports` on a CDN name scans four ports.** An address in a CDN or WAF range is asked 80, 443, 8080 and 8443 only (the row has `cdn`, the summary says so). `-cdn-full` scans it in full.

**`ports` on a range says addresses "answered neither a connect to 80 nor to 443".** That is `-wn`: an address is up when 80 or 443 accepts or refuses. A host that drops both reads as down; scan without `-wn` to ask every address.

**`ports -T4` or a high `-rate` finds fewer ports than before.** A short connect timeout and few retries lose ports on a lossy path; the summary lists the ports that stayed silent. Raise `-connect-timeout` or `-retries`.
