# What azhaq prints

Every command follows the same contract, so a script or an assistant can read any of them the same way. `azhaq help -json` lists every command and flag with its type and default. Each command's own fields are on its page: the command table in the [README](../README.md) links them, and `azhaq docs COMMAND` prints one.

## stdout and stderr

- **stdout** carries results only: one per line, or one JSON object per line with `-json`.
- **stderr** carries progress, failures as they happen (the first three of each kind) and a **summary** at the end.
- With `-json`, every stderr line is JSON, and the summary is one object with `"type":"summary"`.
- With `-silent`, the summary is printed only when something failed or was cut short. A source or archive that failed counts, though the exit code stays 0.
- The **exit code** says whether the work is complete: see [Exit codes](#exit-codes).

With `-json`, the drop-in commands use the field names of the tool they stand in for, so existing `jq` filters keep working.

### When results are printed

- `probe`, `dns`, `ports`, `dirs`, `fuzz`, `params` and `shots` print each result as it is found.
- `subs` without `-live` prints a domain's names when its sources have answered.
- `subs` with `-live` prints them when the run ends. A name is live only once DNS has answered for the whole run.

### Takeover lines with -silent

A takeover candidate is a finding, not a note. `-silent` prints one line for each on stderr, and stdout stays one result per line:

```
[takeover] shop.example.org -> gone.azurewebsites.net (Azure, dangling)
```

### Progress lines

A command that is still working after 10 seconds says so every 10 seconds. A run paced at a request a second is then not taken for a hung one.

```
azhaq: 1m30s, 62 requests sent (1/s), 38 tasks left; -max-requests 80 ends it in about 18 s
```

- The pace is that of the last interval.
- The tasks are those known so far.
- The end is the sooner of the request cap and `-timeout`.
- With `-json`, the line is an object:

```json
{"type":"progress","seconds":90,"requests":62,"requests_per_second":1,"tasks_done":70,"tasks_left":38,"ends_by":"-max-requests 80","ends_in_seconds":18}
```

A run paced slowly says so as it starts: `-rate 1 paces requests to 1/s: the cap of 80 requests …`. `-quiet` and `-silent` print neither line. A run that ends within 10 seconds prints no progress line. Nothing of this goes to stdout.

## Exit codes

| Code | Meaning | What to do |
| --- | --- | --- |
| 0 | Complete. | Use the results. |
| 1 | Error: the command could not do its job. | Read the message. |
| 2 | Usage: bad flags or input. Nothing was sent. | `azhaq help COMMAND`. For a scope refusal, check the target, `-allow` or `-scope`. |
| 3 | Finished, but some sources or requests failed. The results are usable. | The summary lists each failure, whether it is worth retrying, and its targets. |
| 4 | Stopped with work left, by a limit, the kill file or a signal. | `azhaq resume -db FILE` continues where it stopped. With a kill file, remove it first. |

`watch` and `ledger` add their own rules: see [watch](commands/watch.md#summary-and-exit-codes) and [ledger](commands/ledger.md#summary-and-exit-codes).

### Exit 1

The command could not do its job: a database it cannot open, or Chrome missing for `-browser`.

### Exit 2

- The targets are all outside the scope given: `every target is outside the scope (2 left out): 127.0.0.2, 127.0.0.3`. The message names them. A range that no allow rule touches counts. `ports` and `dns` say it too.
- A header names a host (`Host`, `X-Forwarded-Host`, `X-Host`, `X-Original-Host`) outside a scope rule. For example `-H 'Host: secret.lab'` with `-deny secret.lab`, or a request file's or import's header whose host is not a target. See [Hosts named in headers](CONCEPTS.md#hosts-named-in-headers).
- Nothing was sent.

### Exit 3

Some work failed and did not get its answer. Fan-out and partial failures are listed but do not make it 3: see [Failures](CONCEPTS.md#failures-fan-out-partial-and-degraded).

### Exit 4

- A limit stopped the run: `-max-requests`, `-timeout`, `-daily-requests` or `-max-items`.
- The kill file stopped it: `-kill-file`, default `DB.stop`. See [the kill file](CONCEPTS.md#the-kill-file).
- A signal stopped it: Ctrl-C, `kill` or SIGHUP. All three stop a command the same way, with its summary printed and its ledger sealed.
- Work is left. `azhaq resume -db FILE` continues. See [Workspaces, runs and resuming](CONCEPTS.md#workspaces-runs-and-resuming).

## The summary

```json
{"type":"summary","command":"run","version":"0.10.0","complete":false,"exit":4,
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
| `type`, `command`, `version`, `seconds` | Always `summary`, the command, azhaq's version, and the run time in seconds. |
| `complete`, `exit` | As in the exit codes above: `complete` is true when `exit` is 0. |
| `results` | What the command printed on stdout: names, web services, map rows. |
| `counts` | A breakdown of the results, per command. |
| `requests` | Requests sent to targets, port connects included. Requests to third-party sources are not counted. |
| `db` | The database the results are in. Absent when it was temporary. |
| `unreachable` | Targets you gave that never answered. |
| `takeover` | Names another party may take over: `host`, `service`, `target` (the CNAME target), `evidence`, `strength`. See [takeover](#takeover). |
| `failed` | Work that did not get its answer, grouped by collector, source and error, most frequent first. See [failed](#failed). |
| `skipped` | Targets and requests azhaq chose not to touch, with the reason. See [skipped](#skipped). |
| `junk` | `urls` only: the URLs left out as junk, by reason. See [junk](#junk). |
| `sources` | `subs` and `urls`: which sources answered, which failed and why, and what each gave. See [sources](#sources). |
| `partial` (in `failed`) | A third-party source failed while other sources answered for the same target. |
| `degraded` | `subs` only: a source the run relies on did not answer, so the names may be incomplete. See [degraded](#degraded). |
| `stopped`, `resume` | The limit that stopped the work and the command that continues it. |
| `notes` | Caps that were hit and other things worth knowing that are not failures. See [notes](#notes). |
| `next` | Commands worth running next. See [next](#next). |

### takeover

- Strengths, services and what each means: see [Takeover candidates](CONCEPTS.md#takeover-candidates). Confirm each by hand before reporting.
- The text summary prints each candidate as `! takeover candidate`.
- With `-silent` and nothing else to report, each is printed alone on stderr as `[takeover] name -> target (service, strength)`.
- `dns` and `subs -live` rows carry the same object as `takeover`.

### failed

- `retryable` is true for timeouts, dropped connections, 429 and 5xx.
- `source` names a third-party source, such as `crtsh` or `wayback`.
- `targets` names up to 100. `azhaq query -db FILE -failed` lists every failed target: the list to retry.
- `partial` and `fanout` failures do not make the exit code 3: see [Failures](CONCEPTS.md#failures-fan-out-partial-and-degraded).

### skipped

- The reasons: outside the scope, would end the session, or a scope entry a run cannot use.
- Chrome's requests outside the scope are refused before they leave. They are listed without their query string as `outside the scope (Chrome)`.
- Without a scope, the reason is `outside the site (Chrome)`. The site is the registrable domain or address of the pages Chrome was pointed at.
- The first 100 URLs of a run are listed. `notes` gives the number of requests when there were more.
- Chrome sends GET, HEAD and OPTIONS only, outside signing in: see [Chrome](CONCEPTS.md#chrome).
- A write a page or its scripts would send is refused before it leaves. That covers a POST, PUT, PATCH or DELETE, a beacon, and a form a script posts.
- It is listed as `a page's script would send a write`, by method and URL without its query: `POST http://127.0.0.1:3001/api/track`. Its route is mapped with that method (`ops` with `source` `browser`).
- With `-browser-writes`, pages send their writes, which change data on the target. Nothing is listed.
- A download is refused for the whole browser. A download is a URL that is a file, an `<a download>`, or a `Content-Disposition: attachment` answer. Chrome saves nothing to disk.
- It is listed as `Chrome would download it`, by URL without its query and the name Chrome would have given the file: `http://127.0.0.1:3001/ftp/incident-support.kdbx (incident-support.kdbx)`.
- The request itself was sent and counted. Only what it answered is dropped.

### junk

`urls` counts the URLs on the domains that it left out as junk, by reason. Each URL is counted once.

- `"scanner payload"`: for example 3.
- `"scanner probe"`: a scanner's own file or tag, a NUL byte (`%00`) in the path or query, or a query that is only punctuation or a dot and an extension (`?.`, `?.tst`, `?.bak`).
- `"directory listing sort link"`.
- `"script placeholder (NaN, undefined, null)"`.
- `"dot segment"`.
- `"malformed link (wildcard, quote, bracket, ellipsis)"`.
- `"link cut at the end of its sentence"`.

`counts` has the total as `dropped as junk`, and a note says it: `7 URLs dropped as junk (…; -raw keeps them)`. `-raw` prints them and drops none.

### sources

- `asked`, `answered`, `failed` and `off_by_default_failed` count each source once for each domain, as `counts` does.
- `failed` counts sources in the default set, or named with `-sources`. `off_by_default_failed` counts sources that ran only because of `-all-sources`.
- `asked` is `answered` plus `failed` plus `off_by_default_failed`. A source skipped for want of a key is not asked.
- `names` is what each source gave, before any DNS check or filter. For `urls` the field is `urls`.
- `seconds` is how long each source took, the longest over the domains. The slowest source set the run's time. A note names it when it held the run: `crtsh took 30 s, the next slowest source 3 s, so it held the run`.
- `failed_sources` has each failed source's reason, such as `"wayback": "web.archive.org answered 429"`. With several domains, each reason starts with its domain.
- `dns` asks resolvers, not sources, and has no such block.

The text summary ends with the same, and says why the exit code is what it is:

```
23 of 33 sources answered, 10 failed (listed above); exit 0 because other sources answered for the same domain (-fail-on-errors makes it 3)
```

### degraded

- True when `sources failed` ([subs](commands/subs.md#details)) is above 0. A source the run relies on did not answer, so the names may be incomplete.
- The text summary says it on its first line: `DEGRADED: 7 of 38 sources failed`.
- It does not change the exit code. A failure the other sources made up for is listed as `partial`, and the exit stays 0. With `-fail-on-errors` it is 3.
- Failures of sources that ran only because of `-all-sources` never set it on their own.

### notes

Examples of what `notes` holds:

- `ledger: 148 requests and connections recorded in app.db.ledger.jsonl (azhaq ledger -verify app.db.ledger.jsonl)`
- `path checks: 28 skipped (an API description was already found)`
- `screenshot of URL not taken: the page needs about 26 requests and 8 were left (raise -max-requests)`, or `the budget was spent before the page loaded`
- `GraphQL URL: introspection disabled: schema recovered (partial: query Query: 2 fields (1 client, 1 probe), 140 words tried; not proof there is nothing more)`, or `introspection: full schema`
- For `subs`, the `coverage` line: see [subs](commands/subs.md#details).

### next

`next` suggests a command in three cases:

- A run without `-browser` whose target pages leave their links to their scripts gets `azhaq run -url ORIGIN/ -browser …`, with the page that showed it. The signs are three or more `{{templates}}` in the text, or Markdown in the text whose links are read as text, or an empty shell of a front page. The last two count only when fewer than 10 routes were found on the page's origin. Example: `(/learn/vulnerability/a1_injection and 11 more pages: Markdown its scripts turn into links; read as text here, Chrome sees the page as rendered)`.
- A run that found a GraphQL endpoint and did not read its schema gets `azhaq run -url ORIGIN/ -graphql -allow HOST …   (/graphql and /graphiql answer like GraphQL; -graphql reads the schema by introspection)`. That is a run with no `-graphql`, or with the endpoint's host outside the scope.
- A run without a session (`-login`, `-cookie`, `-header`) whose target site shows a sign-in form gets `azhaq run -url ORIGIN/ -login PAGE -login-user USER -login-pass PASS -allow HOST …`. A sign-in form is a form that takes a password.

## The ledger

The ledger is one JSON line for each request or connection sent to a target. What it is, the chain of hashes and the seal are in [Concepts](CONCEPTS.md#the-ledger-and-its-seal). `azhaq ledger` checks, counts and exports it: see the [`ledger` page](commands/ledger.md).

A line has:

| Field | Meaning |
| --- | --- |
| `seq` | The line's number, from 1. |
| `time` | When it was sent, UTC. |
| `kind` | `http`, `tcp`, `udp`, `chrome` or `seal`. See below. |
| `method` | The HTTP method. Not on `tcp` and `udp` lines. |
| `target` | The URL as sent, query string included, for `http` and `chrome`. `ip:port` for `tcp` and `udp`. |
| `host` | The host the request was for. |
| `rule` | The scope rule that allowed it (`-allow`, `-scope`). Empty when the run has no rules. |
| `collector` | What sent it, for the lines that say. |
| `prev`, `hash` | The previous line's hash, and the hex sha256 of `prev` and this line's JSON without `hash`. |

- `tcp`: a connect of `ports`, or a TLS handshake of `ports` or `azhaq-tls`.
- `chrome`: a request Chrome sent, listed once it left. One that Chrome dropped before sending is not listed, and not counted.
- A Chrome WebSocket handshake is `ws://host:port/path?query`, and `wss://host:port` inside TLS.
- `seal`: the end of a run, with no target.
- A password in a `target` URL's user info is masked.

## The workspace

A workspace is one SQLite file, set with `-db`. Its files:

| File | What it is |
| --- | --- |
| `DB` | The workspace. |
| `DB.ledger.jsonl` | The [ledger](CONCEPTS.md#the-ledger-and-its-seal), next to the workspace. |
| `DB.stop` | The default [kill file](CONCEPTS.md#the-kill-file). |

- A drop-in command (`subs`, `probe`, `dirs`, …) without `-db` uses a temporary database and cannot be resumed.
- `run` without `-db` writes `azhaq-TIME-PID.db` in the current directory, or uses the file `$AZHAQ_DB` names.
- `azhaq roles` keeps its files in its `-dir`: `roles.ledger.jsonl`, `roles.stop` and `roles.db`.
