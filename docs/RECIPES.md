# Recipes

Task by task: the commands, what to look at, and the catches. `azhaq docs recipes` prints this page. Only test what you are allowed to test.

## How to read the commands

- `app.example.com` and `example.com` stand for your target, and `acme` for your program.
- `$TA` and `$TB` hold the tokens of two accounts. `…` is a value of yours.
- Files such as `hosts.txt`, `names.txt` or `alice.har` are yours, unless the text says another command writes them.
- A command that needs a config, a key, a lab or a tool says so beside it.

## Contents

Map and test an app

- [Map a single-page app and get its API into Burp](#map-a-single-page-app-and-get-its-api-into-burp)
- [Map an app behind a login](#map-an-app-behind-a-login)
- [Find IDOR and BOLA with two accounts](#find-idor-and-bola-with-two-accounts)
- [Use tokens that live a few minutes](#use-tokens-that-live-a-few-minutes)
- [Test writes across accounts](#test-writes-across-accounts)
- [Read a GraphQL schema](#read-a-graphql-schema)
- [Start a test from a map](#start-a-test-from-a-map)
- [Write a finding up](#write-a-finding-up)

Run safely, repeat, audit

- [Map a bug bounty program inside its scope and a budget](#map-a-bug-bounty-program-inside-its-scope-and-a-budget)
- [Continue a run a limit stopped](#continue-a-run-a-limit-stopped)
- [Retry what failed](#retry-what-failed)
- [Deconfliction and audit](#deconfliction-and-audit)
- [Watch a program and get alerts](#watch-a-program-and-get-alerts)
- [Send any output to chat or e-mail](#send-any-output-to-chat-or-e-mail)
- [Hand azhaq to an assistant](#hand-azhaq-to-an-assistant)
- [Feed other tools, and take their results in](#feed-other-tools-and-take-their-results-in)

Use azhaq in place of another tool

- [The live subdomains of a domain, politely](#the-live-subdomains-of-a-domain-politely) (subfinder and dnsx)
- [Resolve names the dnsx way](#resolve-names-the-dnsx-way)
- [Content discovery in the ffuf way](#content-discovery-in-the-ffuf-way)
- [Find the parameters a page reads](#find-the-parameters-a-page-reads)
- [Archived URLs, as gau gives them](#archived-urls-as-gau-gives-them)
- [Move an ffuf command line, or replay it through Burp](#move-an-ffuf-command-line-or-replay-it-through-burp)
- [Crawl an app the way katana does](#crawl-an-app-the-way-katana-does)
- [Probe web services like httpx](#probe-web-services-like-httpx)
- [Screenshots at a polite pace, for a report](#screenshots-at-a-polite-pace-for-a-report)

## Map a single-page app and get its API into Burp

1. Map the app into a workspace.
2. List the API routes.
3. Export them as an OpenAPI file.

```
azhaq run -url https://app.example.com/ -db app.db
azhaq query -db app.db -role api -fields key,methods,params,body
azhaq export -db app.db -format openapi > app.openapi.json
```

**You get:** the `api` rows are the routes the app's JavaScript calls, with methods and body fields. Import the OpenAPI file in Burp, Postman or ZAP.

`azhaq show -db app.db URL` says where a route was found, such as `main.js:6472:88  this.http.post(…)`.

**Catch:** an app that draws its links with scripts may need `-browser`. The summary says so in a `next:` line.

## Map an app behind a login

Pick the way you hold the session:

```
# a cookie you copied
azhaq run -url https://app.example.com/ -cookie 'session=…' -db app.db
# a header you copied
azhaq run -url https://app.example.com/ -header 'Authorization: Bearer …' -db app.db
# sign in with Chrome
azhaq run -url https://app.example.com/ -login https://app.example.com/login -login-user me@example.com -login-pass '…' -allow app.example.com -db app.db
```

**You get:** `-login` signs in with Chrome. It keeps the cookies and the token the page stored. A signed-in run requests every URL it finds, a logout link included, and checks its session as it goes: if a request ended it, the run signs in again and asks again what the lost session answered. Add `-deny-path 'logout'` to keep that URL out.

## Find IDOR and BOLA with two accounts

1. Give each account a role, and map the app once for each.

   ```
   azhaq roles -role anon -role "alice=Authorization: Bearer $TA" -role "bob=Authorization: Bearer $TB" -- -url https://app.example.com/
   ```

2. Read the findings, worst first. A finding looks like this:

   ```
   401 → 200 → 200  …/rest/basket/8  [bob reads alice's object] proved
   ```

3. Check one by hand with bob's token before you report it. `azhaq roles show -dir DIR URL` prints each role's answer and how it differs from alice's. It also prints a curl line to run with `BOB_TOKEN` set.
4. Write each finding up with `azhaq report -dir DIR` ([Write a finding up](#write-a-finding-up)).

How to read a row:

- `proved` rows need the least checking. `guess` rows need the most.
- The evidence after the route says why the object is alice's.
- The evidence also says what the same route returned for a made-up identifier.
- A route that answers any ID is flagged `answers any identifier`. It is not a finding.

**Catches**

- A role given as headers carries only those headers. Where the app keeps the session in a cookie the headers do not hold, that behaviour does not show. Juice Shop's `/rest/user/whoami` answers `{"user":{}}` to a Bearer token alone.
- Give such a role its cookie too. `-role 'alice=Authorization: Bearer …' -role 'alice=Cookie: …'` is one role with both. Or sign in with `-role-login`.
- Copied tokens expire. `roles` says so with `its token expired at …` and exit 3. See [Use tokens that live a few minutes](#use-tokens-that-live-a-few-minutes).

### From what you browsed

1. Sign in as each account in a browser, or through Burp or Caido.
2. Use the app as that account would.
3. Save each history, as a HAR or as Burp "Save items".
4. Run `roles` on the files:

   ```
   azhaq roles -har alice=alice.har -har bob=bob.har
   ```

You copy no headers, and nothing is crawled. Add `-replay-writes put,patch` to replay each account's writes with the other sessions. Writes change data, so use accounts of your own.

## Use tokens that live a few minutes

```
azhaq roles -role anon -role-cmd 'alice=./token.sh alice' -role-cmd 'bob=./token.sh bob' -- -url https://app.example.com/
```

- The command prints `Header: value` lines, or a bare token. A bare token is sent as `Authorization: Bearer`.
- azhaq runs it before each role's run, and again before the replay.
- It runs again whenever the role's canary says the session died during the replay. The canary is the role's `/me`, or `-canary URL`.
- What was asked since the last good check is asked again.

## Test writes across accounts

1. Save alice's traffic as a HAR, with the browser's developer tools or Burp.
2. Replay it with the other sessions:

   ```
   azhaq roles -replay-writes post,put,patch -har alice=alice.har -role anon -role "alice=…" -role "bob=…" -- -url https://app.example.com/ -allow app.example.com
   ```

3. Read the rows. A cross-role write is listed as `[bob writes alice's object]`.

What is sent:

- Alice's POST, PUT and PATCH go out with bob's session and the visitor's.
- Without a HAR, azhaq asks the PUT and PATCH that the routes take. The body is empty, and it goes to each role's own objects.
- It fills the objects from each role's identifiers: JWT claims, `/me`, list items and `-id`.
- That includes routes that only take a write and have no GET, such as `PUT /users/v1/{username}/email`.
- `-dry-writes` lists the writes and sends nothing.

How a write is judged ([roles, Details](commands/roles.md#details) has the rules):

- A cross-role write is reported only when it is proven. azhaq reads the owner's object as the owner, before and after the write.
- azhaq looks for a readable object even when the write's own URL is not one. `/users/v1/alice/email` is checked against `/users/v1/alice`.
- A write that answers 2xx and leaves the owner's object unchanged is not a finding. Under `-all` it is `answered 2xx but changed nothing of the owner's`.
- A POST to a collection is `creates in another role's collection`, never a cross write.
- Add `-id alice:username=…` when identifiers are not in the answers. Check the `owner_by` line, which quotes what proved the write.

**Catches**

- Writes change data on the target.
- Some apps write the caller's own object whatever the path says. A HAR write replayed with another session then changes *that* session's object to the HAR's value. Replaying bob's `PUT …/email` with alice's session sets alice's email to bob's.
- Replay only in accounts whose data you may change. Add `delete` only if deleting test data is fine.

## Read a GraphQL schema

```
azhaq run -url https://app.example.com/ -graphql -allow app.example.com -db app.db
azhaq export -db app.db -format sdl > schema.graphql
```

Introspection is a POST. It is held to the targets given, or to the `-allow` or `-scope` named. A run that finds GraphQL without `-graphql` suggests the command.

## Start a test from a map

```
azhaq run -url https://app.example.com/ -db app.db
azhaq hunt -db app.db
azhaq roles -json -role anon -role 'user=Authorization: Bearer …' -- -url https://app.example.com/ > roles.jsonl
azhaq hunt -db app.db -roles roles.jsonl -limit 10
```

A map of thousands of routes does not say where to start. `hunt` ranks it, with one row per route template. Each row has its score, the reasons for it as `signal: detail`, and the command to run next. `hunt` reads the workspace and sends nothing.

- The first list holds what the map alone shows:
  - an identifier in the path;
  - a parameter that takes a URL or a file;
  - a backup or key file;
  - an API description;
  - a takeover candidate;
  - a credential in a script.
- The second list adds what `roles` proved. A role reading or writing another role's object carries the heaviest weights, with its evidence and confidence quoted.

**You get:** run the `next` command of the top row. [hunt's Output](commands/hunt.md#output) lists the signals.

**Catch:** `hunt` ranks what the map holds. A thin map gives a short list, see [The map looks thin](TROUBLESHOOTING.md#the-map-looks-thin). A row is a place to look, not a finding.

## Write a finding up

```
azhaq report -dir azhaq-roles-20261028-101500
azhaq report -dir azhaq-roles-20261028-101500 -url https://app.example.com/rest/basket/6 -redact
```

The directory is the one a `roles` run made and named, `azhaq-roles-DATE-TIME`.

`report` turns what `roles` listed into one Markdown report per finding. A report holds:

- a title that names the bug class;
- steps with curl commands, with the sessions as `$ALICE_TOKEN` and `$BOB_TOKEN`;
- the evidence;
- the control, which is what a made-up identifier returned;
- why the object is the owner's;
- impact and remediation.

The first command writes the reports to `DIR/reports`, `proved` first. The second writes one report to standard output, with hosts and identifiers masked, for a report that leaves the engagement. `report` sends nothing, because it reads `DIR/roles.db`.

**Catches**

- The severity is a labelled guess.
- What the evidence does not hold is named in the report under "Missing from the evidence store", not filled in. Examples are a row with no control and a body that was not kept.
- Read a redacted report once before you share it. An identifier that no kept body names in an identifier field is not masked.

## Map a bug bounty program inside its scope and a budget

```
azhaq plan -scope hackerone -program acme -max-requests 5000
azhaq run -scope hackerone -program acme -max-requests 5000 -rate 5 -db acme.db
```

- `plan` says what the run would ask, and sends nothing.
- `-program` names a program in the platform's public list. `security` is one on HackerOne and `tesla` one on Bugcrowd. `acme` stands for yours.
- A name that is not in the list stops the command with `no program "acme" in the list`.
- The run never touches a host outside the program's scope, Chrome included.

## Continue a run a limit stopped

```
azhaq resume -db acme.db
```

A run stopped by `-max-requests`, `-timeout`, Ctrl-C or a signal continues where it stopped and does not ask again what it already asked. After a crash or SIGKILL, a read whose answer was lost is asked again and a write is never sent twice: see [Workspaces, runs and resuming](CONCEPTS.md#workspaces-runs-and-resuming).

- A run's session is never stored, so give a run behind a sign-in its credentials again. Use `azhaq resume -db app.db -login-user me -login-pass …`, or the cookie or header it carried.
- The `stopped:` line of a login run prints the exact command.
- The single-job commands (`subs`, `probe`, `dirs`, …) resume the same way when they were given a `-db`. Without one their workspace is temporary and gone.

## Retry what failed

```
azhaq query -db acme.db -failed
```

**You get:** every failed target, with its error and whether a retry may help. Exit 3 means the results are usable and something failed.

## Deconfliction and audit

1. Run with a workspace.
2. Check the ledger, and export it for the client.
3. Stop the run from another terminal when you must.

```
azhaq run -url https://app.example.com/ -db app.db
azhaq ledger -verify app.db.ledger.jsonl
azhaq ledger -csv app.db.ledger.jsonl > sent.csv
touch app.db.stop
```

Every run with a workspace writes `app.db.ledger.jsonl` next to it. It has one line for each request or connection sent to a target. A line holds the time, the URL or `ip:port`, the scope rule that allowed it and the collector. Each line also holds the hash of the one before.

- Give the client's blue team `azhaq ledger -csv`.
- Show `-verify` passing on the file as delivered. It exits 0 when the file is intact. An edited, removed or reordered line is exit 3, and the message names the first bad line.
- `-summary` counts by kind, host, method and scope rule.

`touch app.db.stop` stops the run. Within a tenth of a second nothing more is sent, not even requests already waiting for `-rate`, and the run exits 4. Remove the file, and `azhaq resume -db app.db` continues.

**Catches**

- DNS queries and the third-party sources of `subs` and `urls` are not in the ledger, because they are not targets.
- A drop-in command without `-db` writes a ledger only with `-ledger FILE`.

## Watch a program and get alerts

```
azhaq watch -db acme.db -every 24h -notify https://hooks.slack.com/services/… -- -scope hackerone -program acme
```

`watch` runs the recon again and again and messages you what changed:

- new names, services, URLs and open ports;
- pages whose status or title changed;
- API listings that grew or shrank;
- API routes a deploy changed, each tied to the script that calls it.

No change, no message. The route lines look like this:

| Line | Meaning |
| --- | --- |
| `+ POST /api/v2/export {format, userId}  (main.js)` | A new route. |
| `~ /api/orders/{id}: +DELETE` | A method was added. |
| `~ PUT /api/profile: +role` | A body name was added. |
| `- /api/legacy/report` | The route is gone from its script. |

**Catches**

- A webhook URL is a secret, and `ps` shows a command line to every user. Put the URL in a file with `-notify @hooks.txt`, one URL a line. Or put it in `AZHAQ_NOTIFY`.
- Several providers, or Teams, Pushover, e-mail, Google Chat, Gotify and a custom endpoint, come from notify's `provider-config.yaml`. Use `-notify-config provider-config.yaml`.
- A message that did not arrive is exit 3.

## Send any output to chat or e-mail

```
azhaq subs -d example.com -live | azhaq notify -bulk -pc provider-config.yaml
azhaq notify -i findings.txt -p slack,smtp -id recon -mf 'recon {{date}}:\n{{data}}' -pc provider-config.yaml
```

- Both lines need a provider config. Without one `notify` stops with exit 2 and sends nothing.
- Here `provider-config.yaml` holds `slack` and `smtp` entries with the id `recon`. [MIGRATING.md](MIGRATING.md#notify-azhaq-notify) has a sample. [commands/notify.md](commands/notify.md#providers) lists the keys of each provider.
- `findings.txt` is any text file.
- The flags and the config are [notify's](https://github.com/projectdiscovery/notify), so a file written for it works.

How messages go out:

- One message goes out for each line. With `-bulk` it is as many lines as fit in `-cl` characters. A longer line goes in pieces.
- `-rl` paces the requests, at 1 a second by default. A 429 is waited out.
- The tokens are in the config, not on the command line. `$NAME` in the config is that environment variable.
- The summary lists each entry a message did not reach. The exit code is then 3.

## Hand azhaq to an assistant

```
claude mcp add azhaq -- azhaq mcp -allow example.com -max-requests 5000 -rate 5
```

`claude mcp add` is Claude Code's command. Any other MCP client runs the same `azhaq mcp …` command from its own configuration, see [MCP.md](MCP.md).

- The scope, the budget and the pace are fixed when the server starts. No tool argument can widen them.
- Without `-allow` or `-scope` the server does not start, unless `-unlocked` says so.

## Feed other tools, and take their results in

```
azhaq export -db acme.db -format targets | nuclei -l -
azhaq export -db acme.db -format burp > scope.json
httpx -l hosts.txt -json | azhaq ingest - -db acme.db
```

`acme.db` is the workspace of [Map a bug bounty program](#map-a-bug-bounty-program-inside-its-scope-and-a-budget). `nuclei` and `httpx` are separate tools, and `hosts.txt` is yours.

`ingest` reads the JSON lines of subfinder, dnsx, httpx, katana, naabu, nuclei and gau, and ffuf output. Lines it cannot read are skipped and counted.

## The live subdomains of a domain, politely

```
azhaq subs -d example.com -live -dns-rate 5 -resolvers two.txt -source-rate 2 -db subs.db -json > names.jsonl
azhaq subs -d example.com -live -m '*.dev.example.com' -oI
azhaq subs -d example.com,example.org -json | jq 'select(.unverified | not)'
```

The first line is `subfinder | dnsx` at a pace.

- `-dns-rate` is queries a second per resolver. `two.txt` lists two resolver addresses, one a line, so the pace is twice that.
- `-source-rate` is requests a second to each passive source.
- The summary's `counts` add up. `from sources`, less `did not resolve`, plus what DNS found as CNAME targets and the names `-w` asked, is `results`. The `count:` note writes the sum out.

Without `-live` nothing is looked up in DNS. Two kinds of name then carry `"unverified": true`:

- names that only subdomain.center guessed;
- names that only the name history held, because no source gave them this run.

The last command leaves them out. A name that is only a CNAME is listed with `-live` too, with `cname` and no `a`, as `dnsx -a -cname` lists it.

**Catch:** subdomain.center answers a random 500 names per call, and its real names differ between calls. Two runs list different names. A run asks it again only while a round gives a new name that resolves. The name history brings back names an earlier run found.

## Resolve names the dnsx way

Resolve the names of a program, as dnsx reads them, with the records that matter and at a rate you set:

```
azhaq dns -l names.txt -mx -txt -json -r 1.1.1.1,tcp:9.9.9.9 -rl 5 -t 5 -o records.jsonl
azhaq dns -l 192.0.2.0/28 -ptr -resp                  # reverse names of a range
azhaq dns -d example.com -axfr -allow example.com     # ask the name servers for the zone
```

- `-r` takes a file or a comma list. A resolver is reached over UDP, `tcp:`, `dot:` or `doh:`.
- `-rl` is names a second over all resolvers.
- `-timeout` is one answer's wait, as in dnsx.

## Content discovery in the ffuf way

Sweep from a directory, with ffuf's filters:

```
azhaq dirs -u https://app.example.com/api/                 # built-in common.txt, swept under /api/
azhaq dirs -u https://app.example.com/ -w big.txt -fs 4242 -fc 404 -e .php,.bak
```

`big.txt` is a wordlist of yours.

`dirs` calibrates like `ffuf -ac`, unless you give `-fc`, `-fs`, `-fw`, `-fl` or `-fr`. `fuzz` calibrates only with `-ac`, as ffuf does. With `-fs`, `-fw` and `-fl` the sizes, word counts and line counts are ffuf's, so a filter value moves over from a ffuf run.

## Find the parameters a page reads

```
azhaq params -u https://app.example.com/search                  # the built-in list (6,500 names)
azhaq params -u https://app.example.com/search -w small -rate 5 -oJ params.json
azhaq params -i burp-export.xml -allow app.example.com -passive # pages from Burp, names the archives hold too
```

`burp-export.xml` is a Burp "Save items" file of yours.

- The built-in lists are SecLists' `burp-parameter-names.txt` (MIT) and names azhaq found itself.
- Names the page's own form fields and scripts hold are tried first.
- A page that rate-limits it fails with exit 3 and says so.
- `-X POST`, `-X JSON` and `-X XML` send the names in a body. A body may change data on the target, so these need `-allow` or `-scope` to name the targets, or a single page.

## Archived URLs, as gau gives them

```
azhaq urls example.com | httpx -silent                                  # the host alone, each URL as its page arrives
azhaq urls -d example.com -subs -providers wayback,commoncrawl -o urls.txt
azhaq urls -d example.com -mc 200 -mt text/html -from 2024 -blacklist png,jpg,css,js -fp
azhaq urls -d example.com -sort -json | jq -r .url                      # held until every archive answered, sorted
azhaq urls -d example.com -raw                                          # what the archives said, nothing changed
azhaq urls -d example.com -urls-pause 0 -urls-pages 0 -retries 5        # as fast as the archives answer, no page cap
```

`httpx` and `jq` here are separate tools.

- Piped, `urls` prints each URL once, as soon as its page arrives, so the next tool starts at once. A stop with Ctrl-C or `-timeout` keeps what was printed.
- On a terminal, or with `-sort`, it waits for every archive and prints the URLs sorted.
- The domain alone is the default, as in gau. `-subs` asks for `*.DOMAIN` too. `azhaq run` keeps asking for the subdomains.

[MIGRATING.md](MIGRATING.md#gau-azhaq-urls) sets each gau flag beside its azhaq flag, and [commands/urls.md](commands/urls.md#flags) lists every azhaq flag. Its "What differs on purpose" lists where azhaq departs from gau. In short:

- OTX records a status for its URLs and urlscan.io a status and a type, so `-mc` and `-fc` judge them; a URL with no recorded status is not kept by `-mc`. OTX keeps no type or date: it is asked all the same and its URLs are kept unfiltered, with a note such as `otx has no type of its captures: its 13 URLs are not filtered by -mt`.
- URLs are normalized and the scanner junk archives hold is dropped. `-raw` turns both off, and the deduplication too.
- A URL that two archives hold is printed once.
- TLS certificates are checked.
- The summary names an archive that failed, an archive that stopped at the page cap, and archives left out by a filter. The page cap is `-urls-pages`, 50 by default and 0 for none. `-fail-on-capped` makes the cap exit 4.

## Move an ffuf command line, or replay it through Burp

```
azhaq fuzz -u https://app.example.com/FUZZ -w common.txt -mc all -fc 404 -fs 4242 -o ffuf.json -x http://127.0.0.1:8080
azhaq fuzz -request login.req -request-proto https -w pass.txt:PASS -mc all -fc 401 -o login.csv -of csv
azhaq fuzz -u https://app.example.com/FUZZ -w common.txt -replay-proxy http://127.0.0.1:8080 -rate 5
azhaq fuzz -u https://app.example.com/FUZZ -w common.txt -rate 5 -control ctl &  echo 'fs 4242' >> ctl
```

- `common.txt` and `pass.txt` are wordlists of yours. `fuzz` has no built-in list, but `dirs` has.
- `login.req` is a raw request saved from Burp, with `FUZZ` or `PASS` in it.
- `-x` and `-replay-proxy` expect a proxy, such as Burp's, listening on `127.0.0.1:8080`.

An ffuf line works as it is. It takes the same flags, gives the same counts and writes the same report files. `jq .results[0]` reads them as it reads ffuf's.

- `-request` takes the file Burp's "copy to file" gives. The keyword is looked for in the method, URL, headers and body.
- `-replay-proxy` sends only the matches through the proxy, so Burp's history holds the hits. `-x` sends every request through it.
- Neither copy to a proxy counts toward `-max-requests` and `-rate`, because it is not a request to the target. The requests to the target do, `-ac` calibration included.

**Catch:** `fuzz` calibrates only with `-ac`, as ffuf does. A line moved over gives ffuf's matches, and a catch-all answer is listed unless you ask for `-ac` or a filter. Calibration is paced by `-rate`. The default strategy asks 6 guesses, so with `-rate 5` it takes about a second: see [fuzz](commands/fuzz.md#calibration).

### A form that wants a one-use token

1. Save the page request as `page.req` and the login as `login.req`, both as raw request files.
2. Read the token from the page:

   ```
   azhaq fuzz -request login.req -request-proto https -w pass.txt:PASS -mc all -fc 403 \
     -preflight page.req -preflight-var-auto 'TOKEN:csrf'
   ```

How it works:

- `TOKEN` in `login.req` is replaced by the value of the field `csrf` in the answer to `page.req`. `TOKEN` can sit in the body, a header or the path.
- The page is asked again before each request. `-preflight-mode per-thread` asks once for each thread, for tokens that last.
- `-preflight-var 'TOKEN:regexp'` takes the first group of a regexp from the body, then the headers.
- `-preflight-var-auto 'TOKEN:[meta]csrf-token'` names the source: `form`, `meta`, `cookie` or `header`.

**Catches**

- The flight requests count against `-max-requests` and `-rate`, and must be in scope. The summary says so, as in `4 preflight/postflight requests were sent`.
- A flight request that fails is a `failed` entry with exit 3. With `-preflight-error ignore` the request goes on without the value.
- A value that would move a request to another host is refused, always.

## Crawl an app the way katana does

```
azhaq crawl -u https://app.example.com/ -d 3 -silent                      # the URLs, one per line
azhaq crawl -u https://app.example.com/ -d 3 -jsonl > crawl.jsonl         # katana's lines
azhaq crawl -u https://app.example.com/ -rl 5 -hrl 2 -ct 10m -db app.db   # polite, resumable
azhaq crawl -u https://app.example.com/ -fs rdn -do                       # follow subdomains, list what was left out of scope
azhaq crawl -u https://app.example.com/ -f rdn,qpath -em php,html          # katana's fields and extension match
azhaq crawl -u https://app.example.com/ -json -rejected                    # strings read from scripts and kept out, with the reason
```

- `-d N` is katana's depth.
- Scripts, forms, routes in JavaScript and API descriptions are read without `-jc`, `-jsl` or `-fx`. Those flags are accepted and ignored.
- A GET form is asked once with neutral values.
- A POST form is sent only with `-submit-forms`.

### Submit forms

```
azhaq crawl -u http://127.0.0.1:5030/ -submit-forms -allow 127.0.0.1 -ledger crawl.ledger.jsonl
```

The target is an app of yours with forms on port 5030, such as a DVWA container, that you may write to.

**Catches**

- `-submit-forms` changes data on the target. A sign-up form creates an account. Use it on a target you may write to.
- The ledger lists every submission, and the summary counts them.
- Three kinds of form are not sent, and the summary says so:
  - a form that uploads a file;
  - a form that posts outside the crawl's scope;
  - a form whose address a `-deny-path` rule matches.
- A form that posts to its own page, with an empty action, is sent.
- Without `-sweep`, `crawl` does not ask the built-in paths: `/admin`, `/.git/HEAD` and API description names.
- `-kf all` asks only `robots.txt` and the sitemaps, and reads every entry.

## Probe web services like httpx

```
azhaq probe -l hosts.txt -p 80,443,8000-8100 -mc 200,401 -ms admin -title -td -sc
azhaq probe -l hosts.txt -fr -tls-grab -hash md5 -jarm -json -o web.jsonl
azhaq probe -l hosts.txt -sr -srd out -irh -irr -json     # every request and response, kept
azhaq probe -l hosts.txt -mdc 'status_code == 200 && contains(body, "login")' -json
azhaq probe -u https://app.example.com -x GET,OPTIONS -path /api,/admin -rate 5
```

- Each target given ends as a row, a failure or a skip. With `-json`, a target with no answer is a row with `failed: true`.
- Matchers and filters read the response as sent, headers and body. The summary says how many rows they left out.
- `-x POST -body …` and `-rr FILE` send writes. They can change data on the target, count against `-max-requests` and `-rate`, and are in the ledger.

## Screenshots at a polite pace, for a report

```
azhaq shots -l services.txt -dir shots -rate 3 -json -o shots.jsonl -csv shots.csv -db shots.db
azhaq export -db shots.db -format html > shots.html
```

`shots` needs Chrome or Chromium on the machine. `services.txt` lists URLs or `host:port`, one a line.

- Each page is taken whole, or marked `partial` with a note and exit 3.
- At `-rate 3` a page of 40 requests takes about 13 seconds. Its time runs from when it last moved, so the pace alone never blanks a picture.
- `-p small|medium|large` and address ranges such as `-u 192.0.2.0/28` find the services.
- `-nmap scan.xml` and `-nessus scan.nessus` take the services from a scan.
- `-shot-format jpeg -shot-fullpage` makes smaller, taller pictures.
- `shots.html` is one file with its pictures embedded, grouped by how they look. It opens from any directory.

### Go through thousands of pictures in the gallery

```
azhaq shots -l services.txt -dir shots -db shots.db -shot-html
azhaq gallery -db shots.db            # http://127.0.0.1:7180/
azhaq gallery -workspace ./recon      # every *.db of a directory, merged
```

The gallery is a local page that reads the workspace. It sends nothing to any target.

- It shows a grid of thumbnails, with each page's URL, title, status and technologies.
- It filters by status, technology, host, title, partial and look-alike group.
- It shows one picture for each group of look-alikes, so thirty copies of a login portal are one tile.
- It searches the URL, the title and, with `-shot-html`, the page text. A query looks like `title:login tech:nginx body:"sign in" -status:404`.
- A page opens to its picture, headers, cookies, TLS, network log, console and the `azhaq show` command for its URL.
- The same data is at `/api/` for scripts: `curl -s 'http://127.0.0.1:7180/api/shots?status=200&collapse=1&limit=20'`.
- It does not take pictures or submit URLs. Run `shots` for that.
