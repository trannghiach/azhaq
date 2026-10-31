# Recipes

Short answers to "how do I…". Each gives the command, what to look at, and the catch. `azhaq docs recipes` prints this page. Only test what you are allowed to test.

## 1. Map a single-page app and get its API into Burp

```
azhaq run -url https://app.example.com/ -db app.db
azhaq query -db app.db -role api -fields key,methods,params,body
azhaq export -db app.db -format openapi > app.openapi.json
```

Look at the `api` rows: the routes the app's JavaScript calls, with methods and body fields. Import the OpenAPI file in Burp, Postman or ZAP. `azhaq show -db app.db URL` says where a route was found (`main.js:6472:88  this.http.post(…)`).

Catch: an app that draws its links with scripts may need `-browser` (the summary says so in a `next:` line).

## 2. Map behind a login

```
azhaq run -url https://app.example.com/ -cookie 'session=…' -db app.db
azhaq run -url https://app.example.com/ -header 'Authorization: Bearer …' -db app.db
azhaq run -url https://app.example.com/ -login https://app.example.com/login -login-user me@example.com -login-pass '…' -allow app.example.com -db app.db
```

`-login` signs in with Chrome and keeps the cookies and the token the page stored. A signed-in run never requests a logout URL.

## 3. Find IDOR and BOLA with two accounts

```
azhaq roles -role anon -role "alice=Authorization: Bearer $TA" -role "bob=Authorization: Bearer $TB" -- -url https://app.example.com/
```

Rows like `401 → 200 → 200  …/rest/basket/8  [bob reads alice's object] proved` are the findings, worst first: `proved` rows need the least checking, `guess` rows the most. The evidence after the route says why the object is alice's, and what the same route returned for a made-up identifier (a route that answers any ID is flagged `answers any identifier`, not a finding). Check one by hand with bob's token before you report it: `azhaq roles show -dir DIR URL` prints each role's answer, how it differs from alice's, and a curl line to run with `BOB_TOKEN` set.

`azhaq report -dir DIR` writes each finding up as a report to submit (recipe 14).

Catch: a role given as headers carries only those headers. Where the app keeps the session in a cookie the headers do not hold (Juice Shop's `/rest/user/whoami` answers `{"user":{}}` to a Bearer token alone), that behaviour does not show; give such a role its cookie too (`-role 'alice=Authorization: Bearer …' -role 'alice=Cookie: …'` is one role with both) or sign in with `-role-login`.

Catch: copied tokens expire. Roles says so (`its token expired at …`, exit 3); see recipe 4.

**From what you browsed.** Sign in as each account in a browser (or through Burp or Caido), use the app as that account would, save each history (HAR, or Burp "Save items"), and run `azhaq roles -har alice=alice.har -har bob=bob.har`. No headers to copy, no crawl. Add `-replay-writes put,patch` to replay each account's writes with the other sessions (they change data: use accounts of your own).

## 4. Tokens that live a few minutes

```
azhaq roles -role anon -role-cmd 'alice=./token.sh alice' -role-cmd 'bob=./token.sh bob' -- -url https://app.example.com/
```

The command prints `Header: value` lines, or a bare token (sent as `Authorization: Bearer`). It runs before each role's run, again before the replay, and whenever the role's canary (its `/me`, or `-canary URL`) says the session died during the replay; what was asked since the last good check is asked again.

## 5. Test writes across accounts

```
azhaq roles -replay-writes post,put,patch -har alice=alice.har -role anon -role "alice=…" -role "bob=…" -- -url https://app.example.com/ -allow app.example.com
```

Save alice's traffic as a HAR (browser developer tools, or Burp). Her POST, PUT and PATCH are replayed with bob's and the visitor's sessions. Without a HAR, the PUT and PATCH the routes take are asked with an empty body on each role's own objects, filled from each role's identifiers (JWT claims, `/me`, list items, `-id`) — including routes that only take a write and have no GET, such as `PUT /users/v1/{username}/email`. `-dry-writes` lists them and sends nothing.

A cross-role write is reported only when it is proven. Azhaq reads the owner's object as the owner before and after the write, and lists `[bob writes alice's object]` only when that object changed the way the write asks (or was deleted); it looks for a readable object even when the write's own URL is not one (`/users/v1/alice/email` is checked against `/users/v1/alice`). A write that answers 2xx but leaves the owner's object unchanged — an app that writes the caller's own object whatever the path says — is listed as `answered 2xx but changed nothing of the owner's` under `-all`, not as a finding; a POST to a collection is `creates in another role's collection`, never a cross write. So add `-id alice:username=…` when identifiers are not in the answers, and check the `owner_by` line, which quotes what proved the write.

Catch: writes change data on the target. A HAR write replayed with another session changes *that* session's own object to the HAR's value when the app writes the caller's object whatever the path says (replaying bob's `PUT …/email` with alice's session sets alice's email to bob's). Replay in accounts whose data you may change. Add `delete` only if deleting test data is fine.

## 6. Map a bug bounty program inside its scope and a budget

```
azhaq plan -scope hackerone -program acme -max-requests 5000
azhaq run -scope hackerone -program acme -max-requests 5000 -rate 5 -db acme.db
```

`plan` says what the run would ask, and sends nothing. The run never touches a host outside the program's scope, Chrome included.

## 7. Continue a run a limit stopped

```
azhaq resume -db acme.db
```

A run stopped by `-max-requests`, `-timeout`, Ctrl-C or a crash continues where it stopped, without asking again what it already asked. A run's session is never stored, so a run behind a sign-in is resumed with its credentials again (`azhaq resume -db app.db -login-user me -login-pass …`, or the cookie or header it carried); the `stopped:` line of a login run prints the exact command. The single-job commands (`subs`, `probe`, `dirs`, …) resume the same way when they were given a `-db`; without one their workspace is temporary and gone.

## 8. Watch a program and get alerts

```
azhaq watch -db acme.db -every 24h -notify https://hooks.slack.com/services/… -- -scope hackerone -program acme
```

A webhook URL is a secret, and `ps` shows a command line to every user: put it in a file (`-notify @hooks.txt`, one URL a line) or in `AZHAQ_NOTIFY`. Several providers, or Teams, Pushover, e-mail, Google Chat, Gotify and a custom endpoint, come from notify's `provider-config.yaml`: `-notify-config provider-config.yaml`. A message that did not arrive is exit 3.

It reports new names, services, URLs, open ports, pages whose status or title changed, and API listings that grew or shrank. It also reports the API routes a deploy changed, each tied to the script that calls it (`+ POST /api/v2/export {format, userId}  (main.js)`: a new route; `~ /api/orders/{id}: +DELETE`: a method added; `~ PUT /api/profile: +role`: a body name added; `- /api/legacy/report`: a route gone from its script). No change, no message.

## 8b. Send any output to chat or e-mail

```
azhaq subs -d example.com -live | azhaq notify -bulk -pc provider-config.yaml
azhaq notify -i findings.txt -p slack,smtp -id recon -mf 'recon {{date}}:\n{{data}}'
```

The flags and the config are [notify's](https://github.com/projectdiscovery/notify): a file written for it works. One message goes out per line, or with `-bulk` as many lines as fit in `-cl` characters; a longer line goes in pieces. `-rl` paces the requests (default 1 a second) and a 429 is waited out. The tokens are in the config, not on the command line; `$NAME` in it is that environment variable. The summary lists each entry a message did not reach, and the exit code is then 3.

## 9. Feed other tools, and take their results in

```
azhaq export -db acme.db -format targets | nuclei -l -
azhaq export -db acme.db -format burp > scope.json
httpx -l hosts.txt -json | azhaq ingest - -db acme.db
```

`ingest` reads subfinder, dnsx, httpx, katana, naabu, nuclei and gau JSON lines and ffuf output. Lines it cannot read are skipped and counted.

The names of a program, as dnsx reads them, with the records that matter and at a rate you set:

```
azhaq dns -l names.txt -mx -txt -json -r 1.1.1.1,tcp:9.9.9.9 -rl 5 -t 5 -o records.jsonl
azhaq dns -l 192.0.2.0/28 -ptr -resp                  # reverse names of a range
azhaq dns -d example.com -axfr -allow example.com     # ask the name servers for the zone
```

`-r` takes a file or a comma list, over UDP, `tcp:`, `dot:` or `doh:`; `-rl` is names a second over all resolvers, and `-timeout` is one answer's wait, as in dnsx.

Content discovery in the ffuf way, from a directory, with ffuf's filters:

```
azhaq dirs -u https://app.example.com/api/                 # built-in common.txt, swept under /api/
azhaq dirs -u https://app.example.com/ -w big.txt -fs 4242 -fc 404 -e .php,.bak
```

`dirs` calibrates like `ffuf -ac`; with `-fs`/`-fw`/`-fl` the sizes, word and line counts are ffuf's, so a filter value moves over from a ffuf run.

## 10. Read a GraphQL schema

```
azhaq run -url https://app.example.com/ -graphql -allow app.example.com -db app.db
azhaq export -db app.db -format sdl > schema.graphql
```

Introspection is a POST, held to the targets given (or the `-allow`/`-scope` named). A run that finds GraphQL without `-graphql` suggests the command.

## 10b. Find the parameters a page reads

```
azhaq params -u https://app.example.com/search                  # the built-in list (6,500 names)
azhaq params -u https://app.example.com/search -w small -rate 5 -oJ params.json
azhaq params -i burp-export.xml -allow app.example.com -passive # pages from Burp, names the archives hold too
```

The built-in lists are SecLists' `burp-parameter-names.txt` (MIT) and names Azhaq found itself. Names the page's own form fields and scripts hold are tried first. A page that rate-limits it fails with exit 3 and says so. `-X POST`, `-X JSON` and `-X XML` send the names in a body, which may change data on the target: they need `-allow` or `-scope` to name the targets, or a single page.

## 11. Retry what failed

```
azhaq query -db acme.db -failed
```

Every failed target with its error and whether a retry may help. Exit 3 means the results are usable and something failed.

## 12. Hand Azhaq to an assistant

```
claude mcp add azhaq -- azhaq mcp -allow example.com -max-requests 5000 -rate 5
```

The scope, the budget and the pace are fixed when the server starts; no tool argument can widen them. Without `-allow` or `-scope` the server does not start, unless `-unlocked` says so.

## 13. Start a test from a map

```
azhaq run -url https://app.example.com/ -db app.db
azhaq hunt -db app.db
azhaq roles -json -role anon -role 'user=Authorization: Bearer …' -- -url https://app.example.com/ > roles.jsonl
azhaq hunt -db app.db -roles roles.jsonl -limit 10
```

A map of thousands of routes does not say where to start. `hunt` ranks it: one row per route template, each with its score, the reasons for it (`signal: detail`) and the command to run next. It reads the workspace and sends nothing. The first list holds what the map alone shows: an identifier in the path, a parameter that takes a URL or a file, a backup or key file, an API description, a takeover candidate, a credential in a script. The second adds what `roles` proved: a role reading or writing another role's object, with its evidence and confidence quoted, carries the heaviest weights. Run the `next` command of the top row. [OUTPUT.md](OUTPUT.md#hunt) lists the signals.

Catch: `hunt` ranks what the map holds. A thin map gives a short list (see Troubleshooting), and a row is a place to look, not a finding.

## 14. Write a finding up

```
azhaq report -dir azhaq-roles-20261028-101500
azhaq report -dir azhaq-roles-20261028-101500 -url https://app.example.com/rest/basket/6 -redact
```

`report` turns what `roles` listed into one Markdown report per finding: a title naming the bug class, steps with curl commands (the sessions as `$ALICE_TOKEN` and `$BOB_TOKEN`), the evidence, the control (what a made-up identifier returned), why the object is the owner's, impact and remediation. The first command writes them to `DIR/reports`, `proved` first; the second writes one to standard output with hosts and identifiers masked, for a report that leaves the engagement. It sends nothing: it reads `DIR/roles.db`.

Catch: the severity is a labelled guess. What the evidence does not hold (a row with no control, a body that was not kept) is named in the report under "Missing from the evidence store", not filled in. Read a redacted report once before you share it: an identifier that no kept body names in an identifier field is not masked.

## 15. Deconfliction and audit

```
azhaq run -url https://app.example.com/ -db app.db
azhaq ledger -verify app.db.ledger.jsonl
azhaq ledger -csv app.db.ledger.jsonl > sent.csv
touch app.db.stop
```

Every run with a workspace writes `app.db.ledger.jsonl` next to it: one line for each request or connection sent to a target, with its time, URL or `ip:port`, the scope rule that allowed it and the collector, each line holding the hash of the one before. Give the client's blue team `azhaq ledger -csv`, and show `-verify` passing on the file as delivered (exit 0; an edited, removed or reordered line is exit 3 naming the first bad line). `-summary` counts by kind, host, method and scope rule.

`touch app.db.stop` from another terminal stops the run: within a tenth of a second nothing more is sent, not even requests already waiting for `-rate`, and the run exits 4. Remove the file and `azhaq resume -db app.db` continues.

Catch: DNS queries and the third-party sources of `subs` and `urls` are not in the ledger; they are not targets. A drop-in command without `-db` writes a ledger only with `-ledger FILE`.

## 16. Archived URLs, as gau gives them

```
azhaq urls example.com | httpx -silent                                  # the host alone, each URL as its page arrives
azhaq urls -d example.com -subs -providers wayback,commoncrawl -o urls.txt
azhaq urls -d example.com -mc 200 -mt text/html -from 2024 -blacklist png,jpg,css,js -fp
azhaq urls -d example.com -sort -json | jq -r .url                      # held until every archive answered, sorted
azhaq urls -d example.com -raw                                          # what the archives said, nothing changed
azhaq urls -d example.com -urls-pause 0 -urls-pages 0 -retries 5        # as fast as the archives answer, no page cap
```

Piped, `urls` prints each URL once, as soon as its page arrives, so the next tool starts at once; a stop (Ctrl-C, `-timeout`) keeps what was printed. On a terminal, or with `-sort`, it waits for every archive and prints the URLs sorted. The domain alone is the default, as in gau; `-subs` asks for `*.DOMAIN` too. `azhaq run` keeps asking for the subdomains.

| gau | azhaq `urls` |
| --- | --- |
| `gau example.com a.com` | `urls example.com a.com`, `-d` (repeatable), `-dL FILE`, or domains on stdin |
| `--subs` | `-subs` |
| `--providers wayback,otx` | `-providers wayback,otx` (the archives are `wayback`, `commoncrawl`, `otx`, `urlscan`, `arquivo`; the API-key file moved to `-provider-config`, and `-providers FILE` still works for a path) |
| `--mc/--fc/--mt/--ft`, `--from/--to` | `-mc -fc -mt -ft -from -to`; an archive that keeps no status, type or date (OTX; urlscan.io keeps dates only) is not asked, and the summary says so |
| `--blacklist ttf,woff` | `-blacklist ttf,woff` (with or without the dot) |
| `--fp` | `-fp` (the first URL of each host and path) |
| `--threads N` | `-threads N` (domains asked at once; the five archives of a domain always run together) |
| `--retries N` | `-retries N` (waits of 2, 5, 10 s between tries; 0 makes the first refusal final) |
| `--proxy URL` | `-proxy URL` (http, https or socks5) |
| `--timeout S` | `-urls-timeout` bounds each archive per domain; `-timeout` stops the whole run |
| `--o FILE` | `-o FILE` (appends) |
| `--json` | `-json` (`{"url","source"}`) |
| `--config`, `~/.gau.toml` | `-config FILE`, and `~/.gau.toml` is read when it exists; flags win |
| `--version` | `-version` |

Several values for one filter (`-mc 200,301`) are alternatives of one filter sent to the archive; gau sends one filter for each value, which the archive ANDs, so it keeps nothing. gau's `--blacklist png` matches nothing (it compares `.png` with `png`) and its `--fp` prints nothing (version 2.2.4); `-blacklist` takes either spelling and `-fp` keeps the first of each host and path.

What differs on purpose: URLs are normalized and the scanner junk archives hold is dropped (`-raw` turns both off, and the deduplication too); a URL that two archives hold is printed once; TLS certificates are checked. An archive that failed, a source stopped at the page cap (`-urls-pages`, default 50, 0 for none) and archives left out by a filter are named in the summary; `-fail-on-capped` makes the cap exit 4.

## 17. Move an ffuf command line, or replay it through Burp

```
azhaq fuzz -u https://app.example.com/FUZZ -w common.txt -mc all -fc 404 -fs 4242 -o ffuf.json -x http://127.0.0.1:8080
azhaq fuzz -request login.req -request-proto https -w pass.txt:PASS -mc all -fc 401 -o login.csv -of csv
azhaq fuzz -u https://app.example.com/FUZZ -w common.txt -replay-proxy http://127.0.0.1:8080 -rate 5
azhaq fuzz -u https://app.example.com/FUZZ -w common.txt -rate 5 -control ctl &  echo 'fs 4242' >> ctl
```

An ffuf line works as it is: same flags, same counts, same report files (`jq .results[0]` reads them as it reads ffuf's). `-request` takes the file Burp's "copy to file" gives, with `FUZZ` in it; the keyword is looked for in the method, URL, headers and body. `-replay-proxy` sends only the matches through the proxy, so Burp's history holds the hits; `-x` sends every request through it. Neither copy to a proxy counts toward `-max-requests` and `-rate`, because it is not a request to the target; the requests to the target do, `-ac` calibration included.

Catch: a line with `-fs`, `-fc`, `-fw`, `-fl`, `-fr` or `-ft` runs without calibration, as it did in ffuf; add `-ac` for it. Calibration is paced by `-rate`, so with `-rate 5` the first six requests take over a second.

A form that wants a one-use token: save the page request and the login as files, and read the token from the page.

```
azhaq fuzz -request login.req -request-proto https -w pass.txt:PASS -mc all -fc 403 \
  -preflight page.req -preflight-var-auto 'TOKEN:csrf'
```

`TOKEN` in `login.req` (body, header or path) is replaced by the value of the field `csrf` in the answer to `page.req`, asked again before each request (`-preflight-mode per-thread` asks once for each thread, for tokens that last). `-preflight-var 'TOKEN:regexp'` takes the first group of a regexp from the body, then the headers; `-preflight-var-auto 'TOKEN:[meta]csrf-token'` names the source (`form`, `meta`, `cookie`, `header`). The flight requests count against `-max-requests` and `-rate`, must be in scope, and say so in the summary (`4 preflight/postflight requests were sent`); one that fails is a `failed` entry (exit 3), and with `-preflight-error ignore` the request goes on without the value. A value that would move a request to another host is refused, always.

## 18. Screenshots at a polite pace, for a report

```
azhaq shots -l services.txt -dir shots -rate 3 -json -o shots.jsonl -csv shots.csv -db shots.db
azhaq export -db shots.db -format html > shots.html
```

Each page is taken whole, or marked `partial` with a note and exit 3: at `-rate 3` a page of 40 requests takes about 13 seconds, and its time runs from when it last moved, so the pace alone never blanks a picture. `-p small|medium|large` and address ranges (`-u 192.0.2.0/28`) find the services; `-nmap scan.xml` and `-nessus scan.nessus` take them from a scan; `-shot-format jpeg -shot-fullpage` makes smaller, taller pictures. `shots.html` is one file with its pictures embedded, grouped by how they look, and opens from any directory.

To go through thousands of pictures, open the workspace in the gallery instead:

```
azhaq shots -l services.txt -dir shots -db shots.db -shot-html
azhaq gallery -db shots.db            # http://127.0.0.1:7180/
azhaq gallery -workspace ./recon      # every *.db of a directory, merged
```

The gallery is a local page that reads the workspace and sends nothing to any target. It shows a grid of thumbnails with each page's URL, title, status and technologies; filters by status, technology, host, title, partial and look-alike group; one picture for each group of look-alikes (so thirty copies of a login portal are one tile); and searches URL, title and, with `-shot-html`, page text (`title:login tech:nginx body:"sign in" -status:404`). A page opens to its picture, headers, cookies, TLS, network log, console and the `azhaq show` command for its URL. The same data is at `/api/` for scripts: `curl -s 'http://127.0.0.1:7180/api/shots?status=200&collapse=1&limit=20'`. It does not take pictures or submit URLs; run `shots` for that.

## 19. Crawl an app the way katana does

```
azhaq crawl -u https://app.example.com/ -d 3 -silent                      # the URLs, one per line
azhaq crawl -u https://app.example.com/ -d 3 -jsonl > crawl.jsonl         # katana's lines
azhaq crawl -u https://app.example.com/ -rl 5 -hrl 2 -ct 10m -db app.db   # polite, resumable
azhaq crawl -u https://app.example.com/ -fs rdn -do                       # follow subdomains, list what was left out of scope
azhaq crawl -u https://app.example.com/ -f rdn,qpath -em php,html          # katana's fields and extension match
azhaq crawl -u https://app.example.com/ -json -rejected                    # strings read from scripts and kept out, with the reason
```

`-d N` is katana's depth. Scripts, forms, routes in JavaScript and API descriptions are read without `-jc`, `-jsl` or `-fx`, which are accepted and ignored. A GET form is asked once with neutral values. A POST form is sent only with `-submit-forms`:

```
azhaq crawl -u http://127.0.0.1:5030/ -submit-forms -allow 127.0.0.1 -ledger crawl.ledger.jsonl
```

Catch: `-submit-forms` changes data on the target (a sign-up form creates an account). Use it on a target you may write to; the ledger lists every submission and the summary counts them. A form whose address looks like it would change something (`logout`, `delete`) and a form that uploads a file are left alone, and the summary says so. Without `-sweep`, `crawl` does not ask the built-in paths (`/admin`, `/.git/HEAD`, API description names); `-kf all` asks only `robots.txt` and the sitemaps and reads every entry.

## 20. Probe web services like httpx

```
azhaq probe -l hosts.txt -p 80,443,8000-8100 -mc 200,401 -ms admin -title -td -sc
azhaq probe -l hosts.txt -fr -tls-grab -hash md5 -jarm -json -o web.jsonl
azhaq probe -l hosts.txt -sr -srd out -irh -irr -json     # every request and response, kept
azhaq probe -l hosts.txt -mdc 'status_code == 200 && contains(body, "login")' -json
azhaq probe -u https://app.example.com -x GET,OPTIONS -path /api,/admin -rate 5
```

Each target given ends as a row, a failure or a skip; with `-json`, a target with no answer is a row with `failed: true`. Matchers and filters read the response as sent (headers and body); the summary says how many rows they left out. `-x POST -body …` and `-rr FILE` send writes: they can change data on the target, count against `-max-requests` and `-rate`, and are in the ledger.

## 21. The live subdomains of a domain, politely

```
azhaq subs -d example.com -live -dns-rate 5 -resolvers two.txt -source-rate 2 -db subs.db -json > names.jsonl
azhaq subs -d example.com -live -m '*.dev.example.com' -oI
azhaq subs -d example.com,example.org -json | jq 'select(.unverified | not)'
```

The first line is `subfinder | dnsx` at a pace: `-dns-rate` is queries a second per resolver (two resolvers in `two.txt` make twice that), `-source-rate` is requests a second to each passive source. The summary's `counts` add up (`from sources` less `did not resolve`, plus what DNS found as CNAME targets, is `results`) and the `count:` note writes the sum out.

Without `-live` nothing is looked up in DNS, so the names subdomain.center only guessed and the ones only the name history held carry `"unverified": true`; the last line leaves them out. A name that is only a CNAME is listed with `-live` too (`cname`, no `a`), as `dnsx -a -cname` lists it.

Catch: subdomain.center answers a random 500 names per call and its real names differ between calls, so two runs list different names. A run asks it again only while a round gives a new name that resolves; the name history brings back names an earlier run found.
