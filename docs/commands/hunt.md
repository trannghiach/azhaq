# azhaq hunt

Where to look first: the mapped routes, hosts and files ranked, each with its evidence and the next command.

## Synopsis

```
azhaq hunt -db FILE [-roles roles.jsonl] [-limit 25] [-since 168h] [-json]
```

## Examples

```
azhaq hunt -db app.db
azhaq roles -json -role anon -role 'user=Authorization: Bearer …' -- -url https://app.example.com/ > roles.jsonl; azhaq hunt -db app.db -roles roles.jsonl
```

## Output

One row per route template: rank, score, key, the reasons, and the command to run next (-json: rank, score, key, type, reasons, next)

`azhaq hunt -db FILE [-roles roles.jsonl] [-limit 25] [-since 168h]` ranks the mapped routes, hosts and files by what a tester should open first. It reads the workspace and sends nothing. One row per route template: a key with `{n}`, `{uuid}`, `{hex}` or `={v}` is a template folding several URLs, and a key seen once is the URL itself.

- Text: one row per line, `rank  score  key  reason; reason  → next: COMMAND`. A reason is `signal: detail`.
- `-json`: one object per row: `rank`, `score`, `key`, `type` (`URL` or `Hostname`), `reasons` (an array of `{signal, detail}`) and `next`. The summary on stderr counts `rows`, and a note says how many rows had a signal when `-limit` cut the list.

The score is the sum of the row's signals, each counted once at its highest weight. A row with no signal of its own is left out; one whose only signal is `new` never ranks. Static assets, scripts, catch-all pages and pages that are gone are never rows. Ties go to the target before fan-out, then to the row with more distinct signals, then by key. `-roles` reads the JSONL `azhaq roles -json` printed (repeatable); `-since` is how long ago a row is first seen to count as new, and `new` is added only when the workspace also holds URLs older than that.

| Signal | Raised by |
| --- | --- |
| `cross-role` | a `-roles` verdict that one role reached another's data: `reads another role's object`, `writes another role's object`, `anyone writes another role's object`, `anyone reads sensitive fields`; the weight is scaled by the row's confidence (`proved` whole, `likely` 85%, `guess` 60%) and the reason quotes its evidence |
| `takeover` | a name another party may take over (`strong` weighs more than `dangling` and `page`) |
| `secret` | a credential a script carries, weighed by its severity; the file is named |
| `sourcemap` | a source map served |
| `exposed-file` | a `.kdbx`, `.pem`, `.key`, `.env`, `.sql`, `.db`, `.bak`, `.old`, `.orig`, `.swp`, `.zip` or `.tar.gz` file, or a `.git` directory, served; named or refused, it weighs less |
| `listing` | a directory listing |
| `api-description` | an API description served |
| `graphql` | a GraphQL endpoint, whose schema was read, or whose IDE answers (weighs more), or that answers like GraphQL |
| `object-id` | `{name}` in the path, or an `id` parameter; a route with no GET weighs less |
| `unauth-write` | POST, PUT, PATCH or DELETE that no description asks credentials for, on a route that did not turn the plain request away; it weighs less when no GET showed that it answers |
| `upload` | a file field in a form, or an operation whose body is `multipart/form-data` or a file |
| `xml` | an operation whose body is XML (`application/xml`, `text/xml`): a parser that may read entities |
| `state-change` | a GET left alone because its name says it changes something (a logout is left out) |
| `password-in-url` | a GET form with a password field: it lands in logs and history |
| `gated` | a 401 or 403: a session is needed, a target for `azhaq roles` |
| `server-error` | a 5xx, by what shows beside it: SQL error text in the body (50), a framework's debug page (35), a parameter whose value came back (30), a stack trace (25; 15 when the request lacked the input the route takes), another role's answer to the same route (a 5xx for one role, an answer for another: 40). Alone it weighs 10, and 3 when the plain request carried none of the input the route takes (the row's `answer` is `500 without input`): a lead, not a finding |
| `input` | the route takes query, body or form names (more when a write sends named fields) |
| `new` | first seen within `-since` |
| `path-auth`, `path-search` | a word in the path says it signs in or issues a session (`login`, `signin`, `auth`, `oauth`, `sso`, `token`, `reset`, `forgot`, `register`, `2fa`, …: 45), or searches and filters (`search`, `find`, `filter`, `query`, `lookup`: 35). A route that a script or a description gives methods for counts in full even when it was not asked; a named route nobody calls weighs half |
| `param-command`, `param-url`, `param-file`, `param-debug`, `param-redirect`, `param-query`, `param-callback` | a parameter name that says what it takes |
| `path-admin`, `path-debug`, `path-config`, `path-env`, `path-doc`, `path-function`, `path-data` | a word in the path says what the route is for; the first five also read the labels of a host name that resolves |

`next` is a real command, chosen by the signal that weighs most in the row: `azhaq roles show -dir /abs/azhaq-roles-… URL` (with `-method` for a write) for a `cross-role` row, with the `-dir` of the roles run that listed it (the row's `dir`, else the folder of the `-roles` file when it holds `roles.db`, else the newest `azhaq-roles-*` folder of the current directory; when none is found the row's command is `azhaq show`); `azhaq roles -role anon -role 'user=Authorization: Bearer …' -- -url ORIGIN/` for `object-id`; `azhaq params -u URL -w WORDLIST` for `input`; `azhaq show -db FILE URL` for the rest.

## Summary and exit codes

The summary and the exit codes are the shared ones: see [OUTPUT.md](../OUTPUT.md#exit-codes).

## Details

### Where to look first

A map of thousands of routes does not say where to start. `azhaq hunt -db app.db` ranks it. It reads the workspace and sends nothing. One row per route template (`/rest/basket/6` and `/rest/basket/7` are one row), each with its score, the reasons for it and the command to run next:

```
$ azhaq hunt -db app.db
  1   57  http://app/api/orders/{id}  object-id: {id} in the path; path-data: "orders" in /api/orders/{id}, named, not requested; unauth-write: DELETE: nothing that names it asks for credentials (not tried)  → next: azhaq roles -role anon -role 'user=Authorization: Bearer …' -- -url http://app/
  2   33  http://app/api/v2/export  object-id: identifier parameter userId; unauth-write: POST: nothing that names it asks for credentials (not tried); input: takes format, userId  → next: azhaq roles -role anon -role 'user=Authorization: Bearer …' -- -url http://app/
$ azhaq roles -json -role anon -role 'user=Authorization: Bearer …' -- -url https://app/ > roles.jsonl
$ azhaq hunt -db app.db -roles roles.jsonl -limit 10
```

The score is the sum of a row's signals, each counted once. What raises a row: a role reading or writing another role's object (from `-roles`, with the evidence and its confidence quoted; the heaviest weights, 95 to 110, scaled by confidence); a name another party may take over; a credential in a script (the file is named) or a source map; a backup, key or database file, a directory listing; admin, debug, config and internal paths; API descriptions and GraphQL endpoints; an object identifier in the path or an `id` parameter; parameters that take a URL, a file, a command, a redirect or a query; a write method no description asks credentials for; a file upload form; a GET that looks state-changing; a server error. First seen within `-since` (default 7 days) adds a little when the workspace holds older URLs too, and a row with only that never ranks. Static assets, scripts, catch-all pages and pages that are gone never rank. Ties go to the target before fan-out, then to the row with more distinct signals, then by key. `-limit` (default 25) keeps the best rows.

The `next` command is a real invocation: `azhaq roles show -dir DIR URL` for a cross-role row (DIR is the `-dir` of the roles run), `azhaq roles …` for an identifier, `azhaq params -u URL -w WORDLIST` for a page that takes input, `azhaq show -db FILE URL` for the rest. [Output](#output) lists the signals.

## Flags

<!-- flags:begin hunt -->
| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-db` | string |  | workspace database (default: the last run's) |
| `-json` | bool |  | one JSON object per row, and the summary as JSON on stderr |
| `-limit` | int | `25` | rows at most, best first |
| `-roles` | string, repeatable |  | the JSONL azhaq roles -json printed: rows where one role reached another's data rank first |
| `-since` | duration | `168h0m0s` | first seen within this long is new: a bonus, never the reason a row ranks |
<!-- flags:end -->
