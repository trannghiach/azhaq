# Troubleshooting

Find your symptom, read why it happens, and follow the fix. `azhaq docs troubleshooting` prints this page.

Entries are grouped by what you were doing:

- [Reading a map](#reading-a-map): `hint`, `gone`, a URL not requested, a thin map.
- [Exit codes and stopped runs](#exit-codes-and-stopped-runs): exit 3, exit 4, the kill file, the database.
- [Chrome](#chrome)
- [roles](#roles), [crawl](#crawl), [urls](#urls), [watch and notify](#watch-and-notify), [params](#params), [dirs](#dirs)
- [ports](#ports), [probe](#probe), [subs](#subs), [shots and gallery](#shots-and-gallery)
- [fuzz](#fuzz), [dns](#dns)

## Reading a map

### Why is my URL `hint`?

**Why:** azhaq knows the URL from a script, an API description, an archive or a link. No GET proved it. These are the cases:

- it takes a path parameter;
- it takes only another method, which scripts call it with, such as POST;
- a GET there answers 404 while scripts call it.

**Fix:**

- Send the method its operations name.
- `azhaq show -db W URL` gives the call site.
- [Coverage](CONCEPTS.md#coverage-what-azhaq-did-with-a-url) lists every state and what to do next.

### Why is a live endpoint `gone`?

**Why:** It answered 404 or 410 to a GET. If scripts call it with another method, it is a `hint` instead. If it is `gone`, nothing azhaq read says it takes another method. Archived URLs are often gone.

**Fix:** [Coverage](CONCEPTS.md#coverage-what-azhaq-did-with-a-url) says what to try next.

### Why was `/logout` (or `/exec`, `/createdb`) requested?

**Why:** azhaq sends a GET to every URL it finds in scope. It cannot know what a GET does on the server: a name says nothing reliable, and the same name is a read-only page on one app and a state change on another. So no name keeps a URL out. Writes (POST, PUT, PATCH, DELETE) are different: they are sent only with their flags.

**Fix:** Say which paths must not be requested, with your own rule.

- `-deny-path '^/(logout|createdb)'` keeps those paths out of every request, Chrome's included. The URL stays in the map as `skipped`, and the summary lists it as `-deny-path ^/(logout|createdb)`.
- `azhaq plan` lists the rules a run would hold to, and the ledger records everything that was sent.
- A request that ended your session is noticed: see below.

### The run says `the session ended`

**Why:** A request ended the session of a signed-in run: a logout link, or an expiry. azhaq noticed because its check page, the one that answers differently with the session and without it, no longer answered as it did.

- With `-login`, the run signs in again, asks again the pages requested since the last good check, and says so in a note: `the session ended after /logout was requested; signed in again; 37 requests asked again`.
- With `-cookie` or `-header` it cannot sign in again. It refuses every later request, lists `azhaq-session` as a failure and exits 3, so nothing after the loss is mistaken for an anonymous answer.

**Fix:** Give a fresh session and `azhaq resume -db W`, or keep the URL that ends it out with `-deny-path`. [Sessions](CONCEPTS.md#sessions) has the rules.

### The map looks thin

**Why:** The app may draw its links with scripts.

**Fix:**

- The summary suggests `-browser` when a page leaves its links to its scripts.
- Behind a login, give a session with `-cookie`, `-header` or `-login`.

### `note: path checks: 28 skipped (an API description was already found)`

**Why:** This is not a failure. The checks that guess where an API description sits stop once one is found on that origin. Every other check was still asked.

**Fix:** None is needed.

## Exit codes and stopped runs

### Exit 3, but the results look fine

**Why:** Exit 3 means the results are usable and something failed. That can be a source, a host that did not answer, or a dead session.

**Fix:** The summary's `failed` list and notes say what failed. `azhaq query -db W -failed` lists every failed target.

### Exit 4

**Why:** A limit stopped the run with work left. The limits are `-max-requests`, `-daily-requests`, `-max-items`, `-timeout`, Ctrl-C or `kill`, and the kill file. SIGINT, SIGTERM and SIGHUP stop a run alike.

**Fix:** `azhaq resume -db W` continues it.

### The run stopped at once with exit 4 and a kill file

**Why:** The kill file exists, perhaps from an earlier stop. By default it is `W.stop`, next to the workspace `W`. `-kill-file` names another file in its place. The `stopped` line says `the kill switch`. Nothing more is sent while the file exists.

In `roles` the file is `roles.stop` in the `-dir`. There it stops the runs of the roles, and not the replay after them.

**Fix:** Remove the file, then run `azhaq resume -db W`.

### Where did my database go?

**Why:** `run` without `-db` writes `azhaq-TIME-PID.db` in the current directory, or uses the file `$AZHAQ_DB` names. A new file is remembered in `.azhaq-last` for `query` and `show`: see [the workspace](OUTPUT.md#the-workspace). Drop-ins (`subs`, `probe`, `dirs`, …) without `-db` use a temporary one, gone when they end.

**Fix:** Give a drop-in `-db FILE` to keep its results.

## Chrome

### Chrome does not start

**Why:** azhaq looks for Chrome or Chromium on the usual paths. In some containers Chrome cannot start its sandbox, and the error says so.

**Fix:**

- `AZHAQ_CHROME=/path/to/chrome` names the browser.
- `AZHAQ_CHROME_NO_SANDBOX=1` runs it without a sandbox. Do this only where you accept that the pages Chrome loads are untrusted.

## roles

### `roles` lists nothing

**Why:** Check the notes first. A dead session, written `refused wherever a session matters`, means the tokens expired. Every endpoint answering every role alike is listed only with `-all`.

**Fix:**

- Use `-role-cmd` for short-lived tokens.
- `-all` lists the endpoints that answer every role alike.

## crawl

### `crawl` lists fewer URLs than katana, or a path katana prints is missing

**Why:** Every string katana's patterns take from a script or a page is one of two things. It is a URL of the crawl, or it is a rejected candidate with its reason. The reasons include a media type, an expression, a file name, library code, another host, and a link outside the scope. A path of katana's that is in neither is a bug.

**Fix:**

- Look in `crawl -json -rejected`.
- A link to another host is not followed unless `-fs rdn` or `-ns` says so. `-fs rdn` follows a name of the same domain.
- `-do` lists what was left out.

### `crawl` says a host answered 429 or 503

**Why:** `crawl` waited and asked again, up to three times. The wait is 1 s doubling to 30 s, or the host's `Retry-After`. The summary names the host and how many requests still got the status. Those requests are listed with it.

**Fix:** Lower the pace with `-rl`, `-hrl` or `-c`.

## urls

### The Wayback Machine answers 429, Common Crawl refuses

**Why:** Both rate-limit or block some networks. azhaq asks again for as long as the archive's `-urls-timeout` and the run's `-timeout` allow. `-urls-timeout` is 3 minutes by default.

- A 429 or 503 is asked again after its `Retry-After`, or after 2, 5, 10, 20, then 30 s.
- A refused connection is asked again 3 times.
- The failure then names the tries and the server's words, as in `wayback: failed after 7 tries, 429 Too Many Requests (waited 2m)`.
- The summary says what each archive gave, as in `URLs by archive: otx 26, wayback 0 (…)`. The other archives still count.

**Fix:**

- Run again later, or from another network.
- `urls -retries N` makes the asking a count instead.
- `-urls-timeout` gives the archive more time.
- `-urls-pause` sets the wait between an archive's requests.
- `-proxy` sends the requests through another address.

### `urls` printed fewer URLs than I expected

**Why:** The host alone is asked unless `-subs` is given. A `note` in the summary says when:

- an archive stopped at its page cap;
- URLs went past `-urls-max`;
- an archive cannot apply a `-mt`, `-ft`, `-from` or `-to` filter (OTX has no type or date).

For the last case the note reads like `otx has no type of its captures: its 13 URLs are not filtered by -mt`. Those URLs are listed, not judged by the filter. An archive that failed is listed as failed, and the exit code is 3.

**Fix:**

- Add `-subs` for the subdomains.
- `-urls-pages 0` removes the page cap. `-fail-on-capped` exits 4 on it.

### `urls -providers` says a name is not an archive

**Why:** `-providers` takes archive names: `wayback,commoncrawl,otx,urlscan,arquivo`.

**Fix:** The API-key file is `-provider-config FILE`. A value with a `/`, or one that names a file that exists, is still read as that file.

## watch and notify

### A notification did not arrive

**Why:** `azhaq watch` prints `azhaq watch: POST https://host/…: reason` for each webhook or provider that failed, and exits 3. `azhaq notify` lists them in its summary, as in `custom failed: … (id ops)`, and also exits 3. The reason names the host and the answer, such as `500 …` or `connection refused`. It never shows the URL's path or token.

**Fix:**

- A 429 or 5xx is tried three times first. `-v` shows each try.
- A 400, 401, 403 or 404 means the URL or the token is wrong.
- A `Retry-After` over a minute is reported instead of waited.

### `notify: provider config: … field … not found`

**Why:** The config has a key the schema does not, such as `slack_webhok_url`. azhaq does not skip it silently.

**Fix:** Fix the spelling.

## params

### `params` exits 3 with `HTTP 429 from the target: it limits requests`

**Why:** The page, or a firewall before it, limits requests. It kept doing so after azhaq waited as its `Retry-After` said, or 1, 2 and 4 s. The names found before stay in the result. The rest of the list was not tried.

The same exit and a note also say when requests got no answer. A server that drops connections under a long query does that.

**Fix:**

- Lower `-rate`, for example `-rate 2`.
- Use `-stable`, or run it again later.
- For dropped connections, try `-c 100`.

### `params` says `the page changes by itself`

**Why:** The page answers the same request with bodies of very different sizes, or with another status. A change caused by a name could not be told from its own.

**Fix:** Give the URL of a page that is stable, such as a search route or an API route.

## dirs

### `dirs` hid a page I know exists

**Why:** The calibration drops a guess that answers like a path that cannot exist. It uses three rules:

- the same status and size, which is ffuf's rule;
- the same word and line counts, where the not-found pages differ in size among themselves;
- a size within the path's length, where the not-found pages repeat the path.

A real page that is byte-for-byte the not-found page cannot be told apart by any size or count.

**Fix:** Give a filter of your own, such as `-fs 2410`: a filter turns the calibration off and every other answer is listed. Or use `fuzz -mc all` to see every answer.

### `dirs` says `N of M guesses were answered 429`

**Why:** The service is rate-limiting the sweep. A 429 is not in the default `-mc`, so those guesses were not judged and the paths may exist. The exit code is 3.

**Fix:** Lower `-rate` or `-t` and run again.

### `dirs -u URL/path` found less than a sweep of the root

**Why:** A URL with a path is swept under that path only, as `/api/WORD`. It does not also sweep `/`.

**Fix:** Give both URLs to sweep both.

## ports

### A UDP port is `open|filtered`

**Why:** The port stayed silent when asked every way its protocol has, and no ICMP port unreachable came back. A port with no known protocol is asked four ways. Two causes are possible: a service that ignores a request it does not understand, or a filter.

- On a loopback or LAN address it usually means the first. A closed port there answers with an ICMP error and is `closed`.
- Across a firewall that drops ICMP, closed ports also read `open|filtered`.
- A host that rate-limits its ICMP replies leaves closed ports silent too. The summary says when that may be the case, as in `udp: N silent ports on a host that refused others …`.

`ports` lists these ports as rows, `host:port/udp open|filtered`, and `"state":"open|filtered"` in `-json`. It counts them in `results`. A range leaves out an address that answered no UDP port at all, and the summary counts those. [UDP, products and versions](commands/ports.md#udp-products-and-versions) has the states.

### An open TCP port has no `service` or `product`

**Why:** One of two things happened. The port said nothing, and none of the protocols azhaq asks answered. azhaq asks about 30 protocols, one request each, and at most 24 connects per port. Or the port answered in a protocol azhaq does not know.

- The row keeps the first bytes of any answer in `banner`.
- A port that accepts a connection and closes it without a word is `tcpwrapped`.
- A container's port is `tcpwrapped` too while its daemon is still starting: docker's proxy accepts and closes until the daemon listens. Scan again once it is up.
- A daemon that greets a second or two late is named by its greeting.
- When the summary says `open ports whose protocol was not probed`, a firewall or tarpit accepts connects on many ports. The protocol list was not run for the rest.

**Fix:** Read `banner`. [How an open port is named](commands/ports.md#how-an-open-port-is-named) lists what is asked.

### A port I know is open is missing

**Why:** A port that neither accepts nor refuses a connect is asked once more. If it stays silent, the summary lists it, as in `ports that neither accepted nor refused a connect…`. The rows are `filtered_ports`. A firewall or a loaded host can do that.

**Fix:**

- Scan it again.
- `-retries 3` asks the silent ports three more times.
- `-connect-timeout 3s` waits longer for a far host.

### `ports -timeout 500` is refused

**Why:** `-timeout` is how long the whole run may take, such as `90s`.

**Fix:** The wait for one connect is `-connect-timeout`, and `500` is milliseconds there.

### `ports` on a CDN name scans four ports

**Why:** `-ec` (`-exclude-cdn`, or `-port-exclude-cdn` in `run`) limits an address in a CDN or WAF range to 80, 443, 8080 and 8443. The row has `cdn`, and the summary says so. Without `-ec` it is scanned in full.

**Fix:** Drop `-ec`.

### `ports` on a range says addresses "answered neither a connect to 80 nor to 443"

**Why:** That is `-wn`. An address is up when 80 or 443 accepts or refuses. A host that drops both reads as down.

**Fix:** Scan without `-wn` to ask every address.

### `ports -T4` or a high `-rate` finds fewer ports than before

**Why:** A short connect timeout and few retries lose ports on a lossy path. The summary lists the ports that stayed silent.

**Fix:** Raise `-connect-timeout` or `-retries`.

## probe

### `probe` shows a redirect, not the page

**Why:** `probe` follows no redirect, as httpx does.

**Fix:**

- `-fr` follows redirects inside the site. `-fhr` follows them on the same host only.
- `-maxr N` stops at the Nth redirect, as httpx counts it, so it follows N-1.
- `status_code`, `title` and the other fields are then the last answer's.

### `probe -timeout 5` is refused

**Why:** `-timeout` bounds the whole run and takes a duration, such as `5m`. A run stopped by `-timeout` exits 4, and `azhaq resume` continues it.

**Fix:** httpx's per-request `-timeout` is `-req-timeout 5s` here.

### A `probe` row has `failed: true`

**Why:** The target did not answer. One of these happened:

- it does not resolve;
- the port is closed;
- the host stopped answering after `-maxhr` tries;
- the scope left it out.

**Fix:**

- `error` says which.
- The summary counts these rows under `without an answer`.
- Exit 3 follows when the failure is worth another try.
- `-probe` prints `[FAILED]` lines in the text output.

### A name resolves only through a wildcard, and `probe` still asks it

**Why:** The names given to `probe` are the ones you want asked. The summary notes how many were wildcard answers.

**Fix:** None is needed. `subs -live`, `dns` and `run` still leave such names out.

### `probe -kb` says the model is not there

**Why:** The classifier reads `~/.dit/model.json`, or `$AZHAQ_DIT_MODEL`. azhaq never downloads it. See [probe](commands/probe.md#page-kinds--kb).

**Fix:** Fetch the model once from the address in the message.

### `probe -x POST` sent requests

**Why:** `-x`, `-body` and `-rr` send what you give to the targets in scope. A POST, PUT or DELETE can change data there. Each request is counted, paced by `-rate` and in the ledger. The summary lists the methods sent.

**Fix:** Use them only on targets you may write to.

## subs

### `subs` returns different names from run to run

**Why:** Some passive sources answer differently each time. subdomain.center returns a random sample of its names on each call.

azhaq keeps the names it found in `names/DOMAIN.json`. The file is under `$AZHAQ_DATA_DIR`, else `$XDG_DATA_HOME/azhaq`, else `~/.local/share/azhaq`. azhaq asks those names again as the `history` source, so a name that resolves still comes back. The `coverage:` note says how much of what the sources know the run holds: see [Coverage estimate](commands/subs.md#coverage-estimate). [Name history](commands/subs.md#name-history) has the file and its limits.

**Fix:** `-no-history` turns the file off.

### `subs -live` takes longer on a later run

**Why:** `-live` also resolves the names the history holds, so after a first run the second has more names to ask. At a low `-dns-rate` the pace is the same and the time grows with the names.

**Fix:** `-no-history` resolves only the names of this run. A higher `-dns-rate` shortens the wait where the resolvers allow it.

### `subs` lists names with `"unverified": true`

**Why:** Without `-live`, `subs` does not look names up in DNS. Two kinds of name are then listed, flagged, and counted in `unverified`:

- names that only subdomain.center guessed, because most of its answer is made up;
- names that only the name history held. No source gave them this run. A name a source gave again is not flagged.

**Fix:** `-live` checks them and leaves out what does not resolve.

### A source says `answered 200 with an error, not names`

**Why:** The server sent its quota or error page with a success status, which a plain reader takes for an empty list. azhaq reads it as a failure and quotes the page, such as `API count exceeded - Increase Quota with Membership`. The source's names are missing from the run.

**Fix:**

- Wait.
- Give the source a key in the provider file.
- Leave it out with `-exclude-sources`.

### `subs` takes half a minute and every source but one answered in seconds

**Why:** The run waits for its slowest source, and that is almost always crt.sh.

- crt.sh is asked in its public PostgreSQL first (port 5432), which answers a large domain in a few seconds, and in its JSON API only when the database fails or has no names. On a large domain such as tesla.com or hackerone.com, the JSON answer takes 20 to 40 seconds. The database query is limited to 10000 rows, as subfinder's is; a domain with more gets a second query for the rest, and then the JSON API. A note in `-v` says `crt.sh database: ...; asked the JSON API` when that happened, or that a full page was asked again.
- The database needs a direct connection to crt.sh:5432 or a SOCKS5 `-source-proxy`. Behind an HTTP proxy, or a network that blocks that port, every run falls back to the JSON API and is as slow as it was.
- The database may use 60% of `-source-timeout`, so that the JSON API still has the rest when the database hangs.
- When crt.sh is busy, nothing comes back before the 30 seconds that `-source-timeout` allows. It is busy when several large domains are asked at once from one address.
- The other sources are done in two to four seconds.

`-v` and the `sources` block of `-json` show it, in `seconds`. A note says `crtsh took 30 s, the next slowest source 3 s, so it held the run`. The progress line every 10 seconds names it, as in `still waiting for crtsh (20s, 3 domains)`.

The default stops where subfinder does, because its per-request limit is 30 seconds too. azhaq waits no longer than subfinder for crt.sh and loses nothing subfinder keeps. When crt.sh is cut off, its names are missing and the source is listed as failed, `partial`.

**Fix:**

- `-source-timeout 60s` or more waits for crt.sh on a large domain, when completeness matters more than time.
- `-exclude-sources crtsh` leaves it out.
- `-db FILE -timeout 40s` stops the whole run at 40 seconds with exit 4 and the names found so far. Then `azhaq resume -db FILE` asks crt.sh again without the others.

### A source answered 429

**Why:** The source is asked again after its `Retry-After`, up to three times. The summary says how long that took, as in `crtname answered 429; it was asked again 1 times after 2 s`. A source that asks for more than 30 s, or keeps refusing, is not waited for. Its names are missing from the run. The note says so, and the source's row has `gave_up_429`.

**Fix:** Slow the sources with `-source-rate N`, or leave the source out with `-exclude-sources`.

### `subs -live` lists a name with no address

**Why:** It is a CNAME whose target gives no address, or does not exist. `dnsx -a -cname` lists it too. `cname` holds the chain. A dangling one is also in the summary's `takeover`.

**Fix:** Read `cname`, and confirm a takeover candidate by hand.

### The `subs` summary says `degraded`

**Why:** The text summary says `DEGRADED: N of M sources failed` on its first line. A source in the default set failed, so `sources failed` is above 0 and the names may be incomplete. The exit code is not changed.

**Fix:** The failed sources are listed. `azhaq subs -v` shows what each source returned and its error.

## shots and gallery

### `shots` says `screenshot … not taken`

**Why:** The page's images, scripts and styles count against `-max-requests`, and too few were left. The note says how many the page needs and how many were left.

**Fix:** Raise `-max-requests`.

### `shots` on a port Chrome refuses says `net::ERR_UNSAFE_PORT`

**Why:** Chrome keeps a list of ports it will not open, such as 6000, 6666 and 10080. `shots` and `run -screenshots` allow them by default.

**Fix:** `-unsafe-ports=false` brings Chrome's refusal back.

### `shots -u URL` with a path takes a picture of that page

**Why:** The URLs a run finds itself are shot only when they are front pages. A URL you give is shot as given, one file for each page, named like `http_host_port_path_hash.png`.

**Fix:** None is needed.

### `shots` of a page that calls `alert()` on load

**Why:** The dialog is accepted and the page is shot. Nothing waits for a click.

**Fix:** None is needed.

### `shots` says `screenshot … is partial` and exits 3

**Why:** The picture was taken while some of the page's images, styles or scripts had not loaded. The row has `"partial":true`, `unloaded` and `resources`. The page was slow, or `-rate` is low for it. A page of 40 requests at `-rate 2` needs 20 seconds. The page's time runs from when it last moved, so a slow pace alone does not cut it short. A server that stops answering does.

**Fix:** Raise `-rate`, or give the page more time.

### `shots` says `screenshot … is partial: 3 requests to cdn.jsdelivr.net outside the scope were blocked`

**Why:** The page loads its styles, fonts or scripts from a host outside the scope, such as a CDN. Chrome is held to the scope like every request of the run, so the picture is drawn without them, as an unstyled page.

- The exit code is not changed. The scope is yours, so this is a mark and a note, not a failure.
- A picture whose own assets did not load, as in the entry above, still exits 3.
- The row has `"partial":true`, `blocked` and `blocked_hosts`.
- The text line ends `partial (3 off-scope assets blocked: cdn.jsdelivr.net)`.

**Fix:** Name the hosts you accept, and the page's own host too. Any `-allow` replaces the default scope, which is the page's own site.

```
azhaq shots -u http://app.test:9090/ -allow app.test -allow cdn.jsdelivr.net
```

The allowed hosts are then requested, counted and in the ledger.

### `gallery` says `N of M pages: the picture file is not on disk` and exits 3

**Why:** The workspace names a picture file that is no longer where the run wrote it, in `file_path`, or beside the database. The page still lists those pages, with their headers and record, and no picture.

**Fix:** Keep the `shots -dir` folder with the workspace, or copy it back.

### `gallery` finds no pictures in a workspace, or no groups

**Why:** It lists only what `shots` and `run -screenshots` took, the `azhaq-shots` rows. A workspace made by an older azhaq has no perceptual hash, so no look-alike groups. It may also have no status, so a status filter does not list the page. A banner says how many.

**Fix:** Take the pages again.

### `gallery`: a `body:` search finds nothing

**Why:** Page text is searched only for pages taken with `shots -shot-html`. The banner and Statistics say for how many it was kept. A free word still matches the URL and the title.

**Fix:** Take the pages again with `-shot-html`.

### `gallery` does not show a page taken after it started

**Why:** It reads the workspace once, at start.

**Fix:** Stop it with Ctrl-C and start it again.

## fuzz

### `fuzz` found fewer matches than ffuf, or more

**Why:** Compare the filters first.

- With `-ac`, the summary says what calibration added, as in `auto-calibration filtered out answers with size 1234`.
- Without `-ac`, `fuzz` does not calibrate, as ffuf does not. Then `-ac` is the only difference to check.
- A different `Size` on a compressed page means a different `Accept-Encoding`. azhaq decodes gzip, deflate and brotli, as ffuf does, so the same header gives the same size.
- `fuzz` and `dirs` send no `Accept` header, as ffuf sends none. An app that negotiates by it, such as Express's redirect body, answers the same size.
- The `User-Agent` is a Chrome's, not ffuf's.

**Fix:** Send `-H 'User-Agent: Fuzz Faster U Fool v2.1.0'` where an app answers by the `User-Agent`.

### `fuzz` says `the report … was not written` or `-o … is a directory`

**Why:** `-o` names a file. A report that cannot be written is a failure in the summary, with the reason, and exit 3. The place is tested before the first request, so a bad path is usually found at once.

**Fix:** Give `-o` a file path.

### `fuzz` stopped with `over 95% of the first 50 or more answers were 403`

**Why:** That is `-sf`, or `-sa`, doing what it says. The target refuses, or the run is blocked. `-sa` also stops at over 20% 429, which means the target is rate limiting.

**Fix:**

- The summary gives the command that goes on, with `-start N`.
- For rate limiting, lower `-rate` or `-t`.

### `fuzz -x` or `-replay-proxy` shows nothing in the proxy

**Why:** Go sends traffic for loopback addresses through a proxy only when `-x` names it. The environment's `HTTP_PROXY` is not read.

**Fix:**

- Name the proxy with `-x`.
- A proxy URL needs its scheme, such as `http://127.0.0.1:8080`.
- The summary counts the matches sent through `-replay-proxy` and the ones that failed.

### `fuzz` says `preflight/postflight failed … cannot choose where requests go`

**Why:** The value read from the answer ended up in the host, scheme or port of a request, such as a `Host: TOKEN` line or a `TOKEN/path`. Values come from the target, and the request carries your cookies and headers. So azhaq does not allow it, and it has no `-preflight-anyhost`.

**Fix:**

- Put the host in the file.
- `… is outside the scope` means the file names a host the run may not touch. `-allow HOST` adds it.

## dns

### `dns -json` prints no row for a name that does not exist

**Why:** As dnsx does, `-json` gives a row for each name that has a record of the type asked, which is A when no type flag is given. A name that does not exist, or has no such record, is counted as `did not resolve` in the summary.

**Fix:** `-rcode nxdomain` (or `noerror`, `servfail`, a number) prints those names with their `status_code`. `-mx`, `-txt`, `-aaaa` and the other type flags ask for other records.

### `dns -timeout 5s` did not stop the run after 5 seconds

**Why:** In `dns`, `-timeout` is how long one DNS answer is waited for, as in dnsx. `run` and the other commands use `-timeout` as the time of the whole run. See [Time and pace](commands/dns.md#time-and-pace).

**Fix:** `dns -maxtime SECONDS` bounds the run. It exits 4 and says which `-start` to go on from.

### `dns -dns-rate 5` still sent more than 5 queries a second

**Why:** `-dns-rate` paces each resolver, so the total is the rate times the number of resolvers. There are six by default. See [Time and pace](commands/dns.md#time-and-pace).

**Fix:**

- `-rl N` paces names over all resolvers, as dnsx's `-rl`.
- With one resolver, or with `-rl`, the total is the rate you gave.
- `-t N` bounds the names in flight.

### `dns -d 192.0.2.0/24` printed nothing

**Why:** Addresses and ranges are looked up only with `-ptr`, which gives reverse names. Otherwise they are left out, and the summary says so under `left out`.

**Fix:** Add `-ptr`. An AS number such as `AS13335` expands to the prefixes RIPEstat lists for it.

### `dns -axfr` found no zone

**Why:** A name server that refuses a transfer is common. The summary's notes say, for each server, one of three things: it refused, it did not answer, or it was not asked because the scope does not allow it. Only the name servers of the name, and the `-resolvers` you gave, are asked.

**Fix:** `-allow` the server's name or address to ask a server the scope left out.
