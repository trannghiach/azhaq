# What Azhaq prints

Every command follows the same contract, so a script or an assistant can read any of them the same way.

- **stdout** carries results only: one per line, or one JSON object per line with `-json`.
- **stderr** carries progress, failures as they happen (the first three of each kind), and a **summary** at the end. With `-json` the summary is one JSON object with `"type":"summary"`. With `-silent` the summary is printed only when something failed or was cut short.
- The **exit code** says whether the work is complete.

`azhaq help -json` lists every command and flag with its type and default.

## Exit codes

| Code | Meaning | What to do |
| --- | --- | --- |
| 0 | Complete. | Use the results. |
| 1 | Error: the command could not do its job (a database it cannot open, Chrome missing for `-browser`). | Read the message. |
| 2 | Usage: bad flags or input. Nothing was sent. | `azhaq help COMMAND`. |
| 3 | Finished, but some sources or requests failed. The results are usable. | The summary lists each failure, whether it is worth retrying, and its targets. |
| 4 | Stopped by a limit (`-max-requests`, `-timeout`, `-daily-requests`, `-max-items`) with work left. | `azhaq resume -db FILE` continues where it stopped. |

Failures on fan-out are listed with `"fanout": true` and do not make the exit code 3: the map of what you asked about is still complete. Fan-out is what you did not ask about: a name found on the way, and the third-party lookups (subdomain sources, archives, RDAP) of a domain that is only the domain of a URL you mapped. Ask for the domain itself (`-domain`, `subs -d`, `urls -d`) and their failures count. `run -fail-on-errors` counts every failure.

## The summary

```json
{"type":"summary","command":"run","version":"0.6.0","complete":false,"exit":3,
 "results":148,"counts":{"URLs":123,"api":33,"auth":12},"seconds":7.4,"requests":195,
 "db":"app.db","run_id":"…",
 "unreachable":["http://testphp.vulnweb.com/"],
 "failed":[{"collector":"azhaq-http","error":"timeout","retryable":true,"count":34,
            "targets":["http://testphp.vulnweb.com/login.php","…"]}],
 "skipped":[{"target":"engage.tesla.com","reason":"outside the scope"}],
 "stopped":"the request budget of 500 is spent, 41 tasks left","resume":"azhaq resume -db app.db",
 "notes":["…"],"next":["azhaq query -db app.db -type Hostname"]}
```

| Field | Meaning |
| --- | --- |
| `complete`, `exit` | As in the table above. |
| `results` | What the command printed on stdout: names, web services, map rows. |
| `counts` | A breakdown of the results, per command. |
| `requests` | Requests sent to targets (not to third-party sources). |
| `db` | The database the results are in (absent when it was temporary). |
| `unreachable` | Targets you gave that never answered. |
| `failed` | Work that did not get its answer, grouped by collector, source and error, most frequent first. `retryable` is true for timeouts, dropped connections, 429 and 5xx. `source` names a third-party source (crtsh, wayback). |
| `skipped` | Targets and requests Azhaq chose not to touch, with the reason: outside the scope, would end the session, a scope entry a run cannot use. |
| `stopped`, `resume` | The limit that stopped the work and the command that continues it. |
| `notes` | Caps that were hit and other things worth knowing that are not failures. |

## run

The map, one row per entity, best first: the target's own pages and APIs, then what it led to. `-json` prints one object per row:

```json
{"type":"URL","key":"http://127.0.0.1:3001/api/Users","scope":"target","coverage":"visited","role":"auth",
 "status":401,"title":"UnauthorizedError: No Authorization header was found","methods":["GET","POST"],
 "params":["email","password"],"proof":"status=401 …","first_seen":"2026-10-26T14:23:40Z"}
```

| Field | Values |
| --- | --- |
| `type` | `URL`, `Hostname`, `Domain`, `IPAddress`, `Organization`, … |
| `scope` | `target`: what you asked about. `fanout`: found on the way (other hosts, CNAME targets). |
| `coverage` (URLs) | `visited`: fetched and answered as a page of its own. `catchall`: answered with the page every unknown path gets (a single-page app's shell). `error`: requested, no answer. `gone`: answered 404 or 410 (found in an archive or a link, not there now). `hint`: found (in a script, an API description, an archive) but not requested, or called by scripts only with POST or PUT. `skipped`: found, not requested because its name says a GET would change something. `capped`: left when a limit was hit. |
| `role` (URLs) | `app` (a front page), `auth` (401), `forbidden` (403), `api`, `page`, `script`, `asset`, `sourcemap`. |
| `role` (names) | `live` (resolves; one of your targets), `sibling` (resolves; found on the way), `unresolved` (from a source or a list, not looked up), `dead`, `wildcard`. |
| `ops` | each operation on the route: `method`, `query`, `path`, `header`, `body` (field names), `body_type`, `auth` (the description asks for credentials), `source` (`js-call`, `openapi`). |
| `body` | the body field names of all its operations. |
| `status`, `title` | The URL's own answer (the first hop of a redirect). |
| `methods`, `params` | From API descriptions, call sites in scripts, forms and links. |
| `forms` | `{"method","action","fields"}` for each form on the page. |
| `template`, `count` | Pages that differ only by an ID are folded: `/product?id={n}` with the number of URLs folded. |

The text map prints the same rows, one per line, with forms and parameters indented below.

## Drop-in commands

Their `-json` output uses the field names of the tool they stand in for, so existing `jq` filters keep working.

| Command | Fields |
| --- | --- |
| `subs` | `host`, `input` (the domain), `source` (the first source that gave the name), `sources` (all of them); with `-live`, `a`. |
| `dns` | `host`, `a`, `aaaa`, `cname`, `status_code`, `cdn_name`. |
| `probe` | httpx's: `url`, `input` (the target as given), `host` (the name), `host_ip` (the address the request connected to), `a` and `aaaa` (the addresses the name resolved to; `host_ip` is one of them), `port`, `scheme`, `path`, `method`, `status_code`, `title`, `webserver`, `content_type`, `tech`, `content_length`, `words`, `lines`, `time`, `favicon` (with `-favicon`), `cdn`, `cdn_name`, `cdn_type`, `final_url`, `chain_status_codes`, `location`, `timestamp`. Empty fields are left out, as httpx does. |
| `crawl` | `url` and the map row's fields (`coverage`, `role`, `status`, `methods`, `params`, `forms`). |
| `urls` | `url`. |
| `ports` | naabu's: `host`, `ip`, `port`, `protocol`, `tls`, `timestamp`, plus `service` and `banner`. |
| `dirs` | `url`, `status`, `length`, `words`, `lines`, `redirectlocation`. |
| `params` | `url`, `method`, `params`, and `why` (what changed in the answer for each name). |
| `asn` | `as_number`, `as_name`, `prefix`. |
| `shots` | `url`, `file`, `title`, `final_url`, `phash`. |

`probe`, `dns`, `ports`, `dirs`, `params` and `shots` print each result as it is found.

## roles

One row per endpoint whose answer depends on the session (`-all`: every endpoint compared):

```json
{"url":"http://localhost:5000/books/v1/bookTitle55","verdict":"every signed-in role reads the same object",
 "template":"http://localhost:5000/books/v1/{book_title}","found_by":["name1","admin"],
 "status":{"anon":401,"name1":200,"admin":200},
 "answers":{"anon":{"status":401,"length":95,"hash":"…"},"name1":{"status":200,"length":83,"hash":"9f…","keys":["book_title","owner","secret"]},"admin":{…}}}
```

`status` has 0 for a role that was never asked. `template` is set on an object URL made by filling a route's path parameters with values the roles' answers held. Verdicts: `every signed-in role reads the same object`, `anyone reads the same object, signed in or not`, `same answer for a session that did not find it`, `signed-in only`, `some roles refused`, `different fields per role`, `status differs`, and, with `-all`, `different data per role`, `same for every role`. The summary counts each verdict.

## query, show, plan, ingest

- `query -json` prints map rows (as `run -json`), or only the `-fields` asked for. The summary says how many rows matched when `-limit` cut them.
- `show -json` prints one object: `row` (the map row), `links` (`rel`, `dir` in or out, `type`, `key`) and `observations` (`collector`, `kind`, `source`, `observed_at`, `payload`).
- `plan -json` prints one object: `targets` (each with the collectors that would run on it), `skipped`, `collectors` (what each does to whom), `active`, `builtin_paths`, `limits`, `sends`.
- `ingest` prints only its summary: `results` is the facts read, `counts` the lines read per format.
