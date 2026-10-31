# azhaq query

Ask a database a precise question instead of reading the whole map.

## Synopsis

```
azhaq query -db FILE [-type T] [-role R] [-coverage C] [-status N] [-method M] [-host H] [-match TEXT] [-new] [-fields A,B] [-limit N] [-json]
```

## Examples

```
azhaq query -db app.db -role auth
azhaq query -db app.db -role api -method POST -fields key,methods,body -json
azhaq query -db app.db -type URL -status 5xx
azhaq query -db h1.db -type Hostname -new
```

## Output

The matching rows of the map, best first.

`query -json` prints map rows (as `run -json`, with `found_in`), or only the `-fields` asked for; every row that matches, unless `-limit` says otherwise (the summary then says how many matched). `query -failed` prints every failed target instead: `target`, `collector`, `source`, `error`, `retryable`.

## Summary and exit codes

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
