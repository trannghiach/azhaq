# What Azhaq prints

Every command follows the same contract, so a script or an assistant can read any of them the same way.

- **stdout** carries results only: one per line, or one JSON object per line with `-json`.
- **stderr** carries progress, failures as they happen (the first three of each kind), and a **summary** at the end. With `-json` every stderr line is JSON and the summary is one object with `"type":"summary"`. With `-silent` the summary is printed only when something failed or was cut short (a source or archive that failed counts, though the exit code stays 0). A takeover candidate is a finding, not a note, so `-silent` prints one line for each on stderr, `[takeover] shop.example.org -> gone.azurewebsites.net (Azure, dangling)`, and stdout stays one result per line. A command that is still working after 10 seconds says so every 10 seconds, so a run paced at a request a second is not taken for a hung one: `azhaq: 1m30s, 62 requests sent (1/s), 38 tasks left; -max-requests 80 ends it in about 18 s` (the pace is that of the last interval, the tasks are those known so far, and the end is the sooner of the request cap and `-timeout`), or with `-json` the object `{"type":"progress","seconds":90,"requests":62,"requests_per_second":1,"tasks_done":70,"tasks_left":38,"ends_by":"-max-requests 80","ends_in_seconds":18}`. A run paced slowly says so as it starts (`-rate 1 paces requests to 1/s: the cap of 80 requests …`). `-quiet` and `-silent` print neither, and a run that ends within 10 seconds prints no progress line. Nothing of this goes to stdout.
- The **exit code** says whether the work is complete.

`azhaq help -json` lists every command and flag with its type and default.

## Exit codes

| Code | Meaning | What to do |
| --- | --- | --- |
| 0 | Complete. | Use the results. |
| 1 | Error: the command could not do its job (a database it cannot open, Chrome missing for `-browser`). | Read the message. |
| 2 | Usage: bad flags or input, such as targets that are all outside the scope given (`every target is outside the scope (2 left out): 127.0.0.2, 127.0.0.3`: the message names them; a range no allow rule touches counts, and `ports` and `dns` say it too), or a header that names a host (`Host`, `X-Forwarded-Host`, `X-Host`, `X-Original-Host`) outside a scope rule: `-H 'Host: secret.lab'` with `-deny secret.lab`, or a request file's or import's header whose host is not a target. Nothing was sent. | `azhaq help COMMAND`; for a scope refusal, the target or `-allow`/`-scope`. |
| 3 | Finished, but some sources or requests failed. The results are usable. | The summary lists each failure, whether it is worth retrying, and its targets. |
| 4 | Stopped by a limit (`-max-requests`, `-timeout`, `-daily-requests`, `-max-items`), by the kill file (`-kill-file`, default `DB.stop`) or by a signal (Ctrl-C, `kill`, SIGHUP: SIGINT, SIGTERM and SIGHUP all stop a command the same way, with its summary and its ledger sealed) with work left. | `azhaq resume -db FILE` continues where it stopped; with a kill file, remove it first. |

`watch` and `ledger`: see [commands/watch.md](commands/watch.md#summary-and-exit-codes) and [commands/ledger.md](commands/ledger.md#summary-and-exit-codes).

A run keeps the answers it got in its workspace until nothing is left to resume, so `azhaq resume` does not ask again what the run already asked: the requests of a run stopped and resumed add up to a few more than those of one uninterrupted run, not twice as many. A port scan the budget (or the kill file) cut short keeps the open ports it found and the ports it asked in a row marked `"partial":true` with `asked_ports`; `azhaq resume` asks only the others, prints the open ports it finds as `ports` does (`-json` for objects, `-quiet` for the summary only; the ports an earlier run printed are not printed again, so the runs' rows add up to the scan's), and its row, and `query` and `show` after it, hold every open port. A drop-in (`subs`, `probe`, `dirs`, …) run without `-db` uses a temporary database and cannot be resumed; `run` without `-db` writes `azhaq-TIME-PID.db` in the current directory (or `$AZHAQ_DB`).

Failures on fan-out are listed with `"fanout": true` and do not make the exit code 3: the map of what you asked about is still complete. Fan-out is what you did not ask about: a name found on the way, and the third-party lookups (subdomain sources, archives, RDAP) of a domain that is only the domain of a URL you mapped. Ask for the domain itself (`-domain`, `subs -d`, `urls -d`) and their failures count, except a source that failed while other sources answered for the same domain: it is listed with `"partial": true` and does not make the exit code 3 (sources fail all the time; an exit code that is always 3 says nothing). crt.sh is one of these: it holds the most names of any certificate log, but it is also the flakiest (gateway 5xx are common), and a run that got its names from the other sources should not fail a CI gate over a transient crt.sh blip — the failure is still listed. `-fail-on-errors` counts every failure, crt.sh's among them. A name answered SERVFAIL on every attempt, by two resolvers or more, on two passes, is not a failure: the resolvers answered alike, and the name's own DNS is broken (a lame delegation) for everyone; it is dead, with `result` `servfail`. Resolvers that time out or answer REFUSED (refusing this machine), or SERVFAIL from one resolver alone, are a failure. One resolver's NXDOMAIN, or an answer without an address (`nodata`, a CNAME chain that ends without one), is not a name dead either: a second resolver is asked once (another operator's, with the default pool: 1.1.1.1 is checked with 8.8.4.4, not 1.0.0.1), and the name is dead only when both agree; a public resolver answers NODATA now and then for a name every other one resolves. Names under a wildcard zone and special-use names are not asked twice.

## The summary

```json
{"type":"summary","command":"run","version":"0.6.0","complete":false,"exit":3,
 "results":148,"counts":{"URLs":123,"api":33,"auth":12},"seconds":7.4,"requests":195,
 "db":"app.db","run_id":"…",
 "unreachable":["http://testphp.vulnweb.com/"],
 "failed":[{"collector":"azhaq-http","error":"timeout","retryable":true,"count":34,
            "targets":["http://testphp.vulnweb.com/login.php","…"]}],
 "skipped":[{"target":"engage.tesla.com","reason":"outside the scope"}],
 "stopped":"the request budget of 500 is spent, 41 tasks known and not done (the cap holds for each run: azhaq resume sends up to 500 more, or as many as its -max-requests says, 0 for no cap)","resume":"azhaq resume -db app.db",
 "notes":["…"],"next":["azhaq query -db app.db -type Hostname"]}
```

| Field | Meaning |
| --- | --- |
| `complete`, `exit` | As in the table above. |
| `results` | What the command printed on stdout: names, web services, map rows. |
| `counts` | A breakdown of the results, per command. |
| `requests` | Requests sent to targets, port connects included (not those to third-party sources). |
| `db` | The database the results are in (absent when it was temporary). |
| `unreachable` | Targets you gave that never answered. |
| `takeover` | Names another party may take over, each with `host`, `service`, `target` (the CNAME target), `evidence` and `strength`. `strong`: the name's CNAME points at a hosting service whose own page says nobody claimed the name (GitHub Pages' "There isn't a GitHub Pages site here.", S3's `NoSuchBucket`, Heroku's no-such-app page, Pantheon, Ghost, WordPress.com, Help Scout, ReadMe, ngrok, Bitbucket, Surge), or at a name whose ICANN domain is not registered (a cloud's shared suffix such as `elb.amazonaws.com` is no registry and never counts). `dangling`: the CNAME points at a web name on Azure (App Service, Cloud Services, CDN, API Management, Container Instances, HDInsight, Blob Storage), Elastic Beanstalk or Fly.io that does not resolve. `page`: one of those services' own pages with no CNAME known; where DNS shows the name points elsewhere, nothing is said. Read from DNS answers (`subs -live`, `dns`, `run`) and front pages (`probe`, `run`); confirm by hand before reporting. The text summary prints each as `! takeover candidate`; with `-silent` and nothing else to report, each is printed alone as `[takeover] name -> target (service, strength)` on stderr. `dns` and `subs -live` rows carry the same object as `takeover`. |
| `failed` | Work that did not get its answer, grouped by collector, source and error, most frequent first. `retryable` is true for timeouts, dropped connections, 429 and 5xx. `source` names a third-party source (crtsh, wayback). `targets` names up to 100; `azhaq query -db FILE -failed` lists every failed target, the list to retry. |
| `skipped` | Targets and requests Azhaq chose not to touch, with the reason: outside the scope, would end the session, a scope entry a run cannot use. Chrome's requests outside the scope are refused before they leave and listed here without their query string, `outside the scope (Chrome)` (`outside the site (Chrome)` without a scope: the registrable domain or address of the pages it was pointed at), the first 100 URLs of a run; `notes` gives the number of requests when there were more. Chrome sends GET, HEAD and OPTIONS only (outside signing in): a write a page or its scripts would send (a POST, PUT, PATCH or DELETE, a beacon, a form a script posts) is refused before it leaves and listed as `a page's script would send a write`, by method and URL without its query (`POST http://127.0.0.1:3001/api/track`); its route is mapped with that method (`ops` with `source` `browser`). With `-browser-writes` pages send their writes, which change data on the target, and nothing is listed. Chrome saves nothing to disk: a download (a URL that is a file, an `<a download>`, a `Content-Disposition: attachment` answer) is refused for the whole browser and listed as `Chrome would download it`, by URL without its query and the name Chrome would have given the file (`http://127.0.0.1:3001/ftp/incident-support.kdbx (incident-support.kdbx)`); the request itself was sent and counted, only what it answered is dropped. |
| `junk` | `urls`: how many URLs on the domains were left out as junk, by reason (`"scanner payload": 3`, `"scanner probe"` (a scanner's own file or tag, a NUL byte `%00` in the path or query, a query that is only punctuation or a dot and an extension: `?.`, `?.tst`, `?.bak`), `"directory listing sort link"`, `"script placeholder (NaN, undefined, null)"`, `"dot segment"`, `"malformed link (wildcard, quote, bracket, ellipsis)"`, `"link cut at the end of its sentence"`), each URL once; `counts` has the total as `dropped as junk`, and a note says it (`7 URLs dropped as junk (…; -raw keeps them)`). `-raw` prints them and drops none. |
| `sources` | `subs` and `urls`: how many sources (for `urls`, archives) answered, which failed and why, and what each gave. `asked`, `answered`, `failed` (sources in the default set or named with `-sources`) and `off_by_default_failed` (ran only because of `-all-sources`) count each source once for each domain, as `counts` does, so `asked` is `answered` plus `failed` plus `off_by_default_failed`; a source skipped for want of a key is not asked. `names` (`urls` has `urls` instead) is what each source gave, before any DNS check or filter. `seconds` is how long each source took (the longest over the domains): the largest one set the run's time, and a note names it when it held the run (`crtsh took 30 s, the next slowest source 3 s, so it held the run`). `failed_sources` has each failed source's reason (`"wayback": "web.archive.org answered 429"`; with several domains each reason starts with its domain). The text summary ends with the same, and says why the exit code is what it is: `23 of 33 sources answered, 10 failed (listed above); exit 0 because other sources answered for the same domain (-fail-on-errors makes it 3)`. `dns` asks resolvers, not sources, and has no such block. |
| `partial` (in `failed`) | A third-party source failed while other sources answered for the same target. |
| `degraded` | `subs` only: true when `sources failed` ([commands/subs.md](commands/subs.md#details)) is above 0, so a source the run relies on did not answer and the names may be incomplete. The text summary says it on its first line (`DEGRADED: 7 of 38 sources failed`). It does not change the exit code: a failure the other sources made up for is listed as `partial` and the exit stays 0 (3 with `-fail-on-errors`). Failures of sources that ran only because of `-all-sources` never set it on their own. |
| `stopped`, `resume` | The limit that stopped the work and the command that continues it. |
| `notes` | Caps that were hit and other things worth knowing that are not failures: `ledger: 148 requests and connections recorded in app.db.ledger.jsonl (azhaq ledger -verify app.db.ledger.jsonl)`; `path checks: 28 skipped (an API description was already found)`; `screenshot of URL not taken: the page needs about 26 requests and 8 were left (raise -max-requests)` (or `the budget was spent before the page loaded`); `GraphQL URL: introspection disabled: schema recovered (partial: query Query: 2 fields (1 client, 1 probe), 140 words tried; not proof there is nothing more)` or `introspection: full schema`; for `subs`, the `coverage` line ([commands/subs.md](commands/subs.md#details)). |
| `next` | Commands worth running next. A run without `-browser` whose target pages leave their links to their scripts (three or more `{{templates}}` in the text; or Markdown in the text, whose links are read as text, or an empty shell of a front page, with fewer than 10 routes found on its origin) gets `azhaq run -url ORIGIN/ -browser …` with the page that showed it: `(/learn/vulnerability/a1_injection and 11 more pages: Markdown its scripts turn into links; read as text here, Chrome sees the page as rendered)`. A run that found a GraphQL endpoint and did not read its schema (no `-graphql`, or its host outside the scope) gets `azhaq run -url ORIGIN/ -graphql -allow HOST …   (/graphql and /graphiql answer like GraphQL; -graphql reads the schema by introspection)`. A run without a session (`-login`, `-cookie`, `-header`) whose target site shows a sign-in form (a form that takes a password) gets `azhaq run -url ORIGIN/ -login PAGE -login-user USER -login-pass PASS -allow HOST …`. |

## run

`run`: see [commands/run.md](commands/run.md).

## Drop-in commands

Their `-json` output uses the field names of the tool they stand in for, so existing `jq` filters keep working.

| Command | Fields |
| --- | --- |
| `subs` | see [commands/subs.md](commands/subs.md) |
| `dns` | see [commands/dns.md](commands/dns.md) |
| `probe` | see [commands/probe.md](commands/probe.md) |
| `crawl` | see [commands/crawl.md](commands/crawl.md) |
| `urls` | see [commands/urls.md](commands/urls.md) |
| `ports` | see [commands/ports.md](commands/ports.md) |
| `dirs` | see [commands/dirs.md](commands/dirs.md) |
| `fuzz` | see [commands/fuzz.md](commands/fuzz.md) |
| `params` | see [commands/params.md](commands/params.md) |
| `asn` | see [commands/asn.md](commands/asn.md) |
| `shots` | see [commands/shots.md](commands/shots.md) |
| `notify` | see [commands/notify.md](commands/notify.md) |

`probe`, `dns`, `ports`, `dirs`, `fuzz`, `params` and `shots` print each result as it is found; `subs` without `-live` prints a domain's names when its sources have answered, and with `-live` when the run ends (a name is live only once DNS has answered for the whole run).

## roles

`roles`: see [commands/roles.md](commands/roles.md).

## report

`report`: see [commands/report.md](commands/report.md).

## diff

`diff`: see [commands/diff.md](commands/diff.md).

## watch

`watch`: see [commands/watch.md](commands/watch.md).

## notify

`notify`: see [commands/notify.md](commands/notify.md).

## query, show, plan, ingest

- `query`: see [commands/query.md](commands/query.md).
- `show`: see [commands/show.md](commands/show.md).
- `plan`: see [commands/plan.md](commands/plan.md).
- `ingest`: see [commands/ingest.md](commands/ingest.md).

## hunt

`hunt`: see [commands/hunt.md](commands/hunt.md).

## ledger

Every run with a workspace writes `DB.ledger.jsonl` next to it (`-ledger FILE` writes it elsewhere, `-ledger off` not at all; a drop-in command without `-db` writes one only with `-ledger FILE`; `azhaq roles` writes `roles.ledger.jsonl` in its `-dir`). It has one JSON line for each request or connection sent to a target, and `azhaq resume` and later runs into the workspace append to it. A run that ends writes a last line of kind `seal`, so lines cut from the end of the file show. DNS queries and third-party sources (the RDAP registry too) are not targets and are not listed. A line has:

| Field | Meaning |
| --- | --- |
| `seq` | the line's number, from 1 |
| `time` | when it was sent, UTC |
| `kind` | `http`, `tcp` (a connect of `ports`, or a TLS handshake of `ports` or `azhaq-tls`), `udp`, `chrome` (a request Chrome sent, listed once it left: one Chrome dropped before sending is not, nor counted; a WebSocket handshake is `ws://host:port/path?query`, and `wss://host:port` inside TLS), or `seal`: the end of a run, with no target |
| `method` | the HTTP method (not on `tcp` and `udp` lines) |
| `target` | the URL as sent, query string included (a password in its user info is masked), for `http` and `chrome`; `ip:port` for `tcp` and `udp` |
| `host` | the host the request was for |
| `rule` | the scope rule that allowed it (`-allow`, `-scope`); empty when the run has no rules |
| `collector` | what sent it, for the lines that say |
| `prev`, `hash` | the previous line's hash, and the hex sha256 of `prev` and this line's JSON without `hash` |

`ledger`: see [commands/ledger.md](commands/ledger.md).

`-kill-file PATH` (default `DB.stop`; `roles.stop` in the `-dir` of `roles`, which stops the runs of the roles but not the replay after them) is the kill switch: the file is looked for every 100 ms, and once it exists nothing more is sent, not even a request already waiting for `-rate`. The run exits 4, and its `stopped` says `the kill switch: kill file PATH exists, N tasks known and not done (remove it, then azhaq resume)`. A drop-in command without `-db` has no default kill file.

## export

`export`: see [commands/export.md](commands/export.md).

## gallery

`gallery`: see [commands/gallery.md](commands/gallery.md).

## crawl

`crawl`: see [commands/crawl.md](commands/crawl.md).
