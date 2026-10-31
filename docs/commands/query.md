# azhaq query

Ask a database a precise question instead of reading the whole map.

## Synopsis

```
azhaq query -db FILE [-type T] [-role R] [-coverage C] [-status N] [-method M] [-host H] [-match TEXT] [-new] [-fields A,B] [-limit N] [-json]
```

## Examples

```
# Rows with the role auth
azhaq query -db app.db -role auth

# API routes that take POST, with only the fields you need, as JSON
azhaq query -db app.db -role api -method POST -fields key,methods,body -json

# URLs that answered with a server error
azhaq query -db app.db -type URL -status 5xx

# Hostnames the last run saw and the run before it did not
azhaq query -db h1.db -type Hostname -new

# Every target whose work failed: the list to retry
azhaq query -db app.db -failed
```

## What it does

`azhaq query` reads the map of a workspace (`-db`, default the last run's) and prints the rows that match the flags you give. The best rows come first.

The filters are `-type`, `-role`, `-coverage`, `-evidence`, `-status`, `-method`, `-host`, `-scope`, `-since`, `-new` and `-match`. Each takes the values listed in Flags. `-match` is a case-insensitive text match on the key, or a regular expression with `-re`.

## Output

Plain output is the matching rows of the map. `-json` prints one JSON object per row.

| Form | What it prints |
| --- | --- |
| `-json` | Map rows as `run -json` prints them, with `found_in`. |
| `-json -fields A,B` | Only the fields you ask for. |
| `-failed` | Every failed target instead of map rows. See the table below. |

`query -failed` prints one line for each failed target: the target, the collector (with `source` and the source's name for a source), the error, and `retryable`, tab separated. With `-json` each row has these fields:

| Field | Meaning |
| --- | --- |
| `target` | The target whose work failed. |
| `collector` | The collector that did the work. |
| `source` | The third-party source, when a source failed. |
| `error` | What went wrong. |
| `retryable` | True for timeouts, dropped connections, 429 and 5xx. |

The fields mean what they mean in the `failed` list of the summary: see [OUTPUT.md](../OUTPUT.md).

## Summary and exit codes

`query` prints every row that matches, unless `-limit` says otherwise. The summary then says how many matched.

The summary and the exit codes are the shared ones: see [OUTPUT.md](../OUTPUT.md#exit-codes).

## Flags

<!-- flags:begin query -->
| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-coverage` | string |  | coverage, comma-separated: visited, catchall, error, gone, hint, skipped, capped |
| `-db` | string |  | the database (default: the last run's) |
| `-evidence` | string |  | how the route is known, comma-separated: answered, browser, described, called, linked, archived, guessed, given |
| `-failed` | bool |  | list every target whose work failed (timeouts, refusals, a source's errors): the list to retry |
| `-fields` | string |  | print only these fields, comma-separated: key, type, role, coverage, status, answer, evidence, evidence_from, title, methods, params, body, scope, first_seen, found_in, watch, guard, protocol, namespace |
| `-host` | string |  | entities on this host or under this domain |
| `-json` | bool |  | one JSON object per row, and the summary as JSON on stderr |
| `-limit` | int |  | rows at most, best first (default 0: all) |
| `-match` | string |  | keys that contain this text (case-insensitive), or match it as a regular expression with -re |
| `-method` | string |  | routes with this method: GET, POST, … |
| `-new` | bool |  | only what the last run saw that the run before it did not (a workspace) |
| `-re` | bool |  | -match is a regular expression |
| `-role` | string |  | roles, comma-separated: app, auth, forbidden, api, page, client-route, websocket, live, sibling, unresolved, dead, … |
| `-scope` | string |  | target (what was asked about) or fanout (found on the way) |
| `-since` | duration |  | only what was first seen within this long |
| `-status` | string |  | statuses, comma-separated: 200, 401, 4xx, 5xx |
| `-type` | string |  | entity types, comma-separated: URL, Hostname, Domain, IPAddress, … |
<!-- flags:end -->
