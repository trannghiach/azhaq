# azhaq hunt

Where to look first: the mapped routes, hosts and files ranked, each with its evidence and the next command.

A map of thousands of routes does not say where to start. `hunt` ranks the mapped routes, hosts and files by what a tester should open first. It gives one row per route template, each with its score, the reasons for it and the command to run next. It reads the workspace and sends nothing.

## Synopsis

```
azhaq hunt -db FILE [-roles roles.jsonl] [-limit 25] [-since 168h] [-json]
```

## Examples

```
# rank what the map holds
azhaq hunt -db app.db

# add what roles proved: rows where one role reached another's data rank first
azhaq roles -json -role anon -role 'user=Authorization: Bearer …' -- -url https://app.example.com/ > roles.jsonl
azhaq hunt -db app.db -roles roles.jsonl

# show only the ten best rows
azhaq hunt -db app.db -roles roles.jsonl -limit 10
```

## What it does

1. Reads the workspace, and the JSONL files of `-roles` if you give any. It sends nothing.
2. Folds URLs into route templates, so `/rest/basket/6` and `/rest/basket/7` are one row.
3. Raises signals on each row, such as an identifier in the path, a backup file or a role reading another role's object. [Signals](#signals) lists them.
4. Scores each row as the sum of its signals, and drops rows with no signal.
5. Sorts by score and prints the best `-limit` rows (default 25), each with a command to run next.

## Output

Text form: one row per line.

```
rank  score  key  reason; reason  → next: COMMAND
```

A reason is `signal: detail`. With `-json`, stdout holds one object per row. The summary goes to stderr, as JSON with `-json`, and counts `rows`. A note says how many rows had a signal when `-limit` cut the list.

```
$ azhaq hunt -db app.db
  1   57  http://app/api/orders/{id}  object-id: {id} in the path; path-data: "orders" in /api/orders/{id}, named, not requested; unauth-write: DELETE: nothing that names it asks for credentials (not tried)  → next: azhaq roles -role anon -role 'user=Authorization: Bearer …' -- -url http://app/
  2   33  http://app/api/v2/export  object-id: identifier parameter userId; unauth-write: POST: nothing that names it asks for credentials (not tried); input: takes format, userId  → next: azhaq roles -role anon -role 'user=Authorization: Bearer …' -- -url http://app/
```

| Field (`-json`) | Meaning |
| --- | --- |
| `rank` | Position in the list, best first. |
| `score` | The sum of the row's signal weights. |
| `key` | A route template, host or file. A template folds several URLs and holds `{n}`, `{uuid}`, `{hex}` or `={v}`. A key seen once is the URL. |
| `type` | `URL` or `Hostname`. |
| `reasons` | An array of `{signal, detail}`, one per signal. |
| `next` | The command to run next. [The next command](#the-next-command) says how it is chosen. |

### Signals

| Signal | Raised by |
| --- | --- |
| `cross-role` | A `-roles` verdict that one role reached another's data. The heaviest signal: see [Cross-role rows](#cross-role-rows). |
| `takeover` | A name another party may take over. |
| `secret` | A credential a script carries. The reason names the file. |
| `sourcemap` | A source map served. |
| `exposed-file` | A backup, key, database or archive file, or a `.git` directory, served: see [Exposed files](#exposed-files). |
| `listing` | A directory listing. |
| `api-description` | An API description served. |
| `graphql` | A GraphQL endpoint: its schema was read, its IDE answers, or it answers like GraphQL. |
| `object-id` | `{name}` in the path, or an `id` parameter. |
| `unauth-write` | A POST, PUT, PATCH or DELETE that no description asks credentials for, on a route that did not turn the plain request away. |
| `upload` | A file field in a form, or an operation whose body is `multipart/form-data` or a file. |
| `xml` | An operation whose body is XML (`application/xml`, `text/xml`): a parser that may read entities. |
| `state-change` | A GET left alone because its name says it changes something. A logout is left out. |
| `password-in-url` | A GET form with a password field: the password lands in logs and history. |
| `gated` | A 401 or 403: a session is needed, so a target for `azhaq roles`. |
| `server-error` | A 5xx, weighed by what shows beside it: see [Server errors](#server-errors). |
| `input` | The route takes query, body or form names. |
| `new` | First seen within `-since`. |
| `path-auth`, `path-search` | A word in the path says it signs in or issues a session, or that it searches and filters: see [Words in paths](#words-in-paths). |
| `param-command`, `param-url`, `param-file`, `param-debug`, `param-redirect`, `param-query`, `param-callback` | A parameter name that says what it takes. |
| `path-admin`, `path-debug`, `path-config`, `path-env`, `path-doc`, `path-function`, `path-data` | A word in the path says what the route is for. The first five also read the labels of a host name that resolves. |

## Summary and exit codes

The summary and the exit codes are the shared ones: see [the summary](../OUTPUT.md#the-summary) and [exit codes](../OUTPUT.md#exit-codes).

## Details

### Which rows appear

- A row with no signal of its own is left out.
- A row whose only signal is `new` never ranks.
- Static assets, scripts, catch-all pages and pages that are gone are never rows.

### Score and order

- The score is the sum of the row's signals. Each signal counts once, at its highest weight.
- Ties go to the target before fan-out, then to the row with more distinct signals, then by key. [Concepts](../CONCEPTS.md#reading-a-map-row) explains target and fan-out.
- `-limit` (default 25) keeps the best rows.

### Weights

- `takeover`: `strong` weighs more than `dangling` and `page`.
- `secret`: weighed by the credential's severity.
- `object-id`: a route with no GET weighs less.
- `unauth-write`: weighs less when no GET showed that the route answers.
- `input`: weighs more when a write sends named fields.
- `graphql`: an endpoint whose IDE answers weighs more.

### Cross-role rows

`-roles FILE` reads the JSONL that `azhaq roles -json` printed. It is repeatable. A row gets `cross-role` when a role's verdict is one of these:

- `reads another role's object`
- `writes another role's object`
- `anyone writes another role's object`
- `anyone reads sensitive fields`

The reason quotes the row's evidence and its confidence.

These rows have the heaviest weights, 95 to 110. The row's confidence scales the weight: `proved` whole, `likely` 85%, `guess` 60%.

### New rows

`-since` is how long ago a row is first seen to count as new. The default is 7 days (`168h`). `new` adds a little, and only when the workspace also holds URLs older than `-since`.

### Exposed files

`exposed-file` covers a `.kdbx`, `.pem`, `.key`, `.env`, `.sql`, `.db`, `.bak`, `.old`, `.orig`, `.swp`, `.zip` or `.tar.gz` file, or a `.git` directory, served. A file that is named or refused weighs less than one that is served.

### Server errors

A 5xx is a lead, not a finding. Its weight depends on what shows beside it:

- SQL error text in the body: 50.
- Another role's answer to the same route, a 5xx for one role and an answer for another: 40.
- A framework's debug page: 35.
- A parameter whose value came back: 30.
- A stack trace: 25, or 15 when the request lacked the input the route takes.
- Alone: 10.
- Alone, when the plain request carried none of the input the route takes: 3. The map row's `answer` is then `500 without input`; see [Evidence](../CONCEPTS.md#evidence-how-azhaq-knows-a-url).

### Words in paths

- `path-auth`: a word that says the route signs in or issues a session, such as `login`, `signin`, `auth`, `oauth`, `sso`, `token`, `reset`, `forgot`, `register`, `2fa`. Weight 45.
- `path-search`: a word that says the route searches or filters: `search`, `find`, `filter`, `query`, `lookup`. Weight 35.
- A route that a script or a description gives methods for counts in full, even when it was not asked.
- A named route that nobody calls weighs half.

### The next command

`next` is a real command, chosen by the signal that weighs most in the row.

| Row | `next` |
| --- | --- |
| `cross-role` | `azhaq roles show -dir /abs/azhaq-roles-… URL`, with `-method` for a write |
| `object-id` | `azhaq roles -role anon -role 'user=Authorization: Bearer …' -- -url ORIGIN/` |
| `input` | `azhaq params -u URL -w WORDLIST` |
| everything else | `azhaq show -db FILE URL` |

For a `cross-role` row, the `-dir` is that of the roles run that listed it. `hunt` looks in this order:

1. The `dir` of the roles row.
2. The folder of the `-roles` file, when it holds `roles.db`.
3. The newest `azhaq-roles-*` folder of the current directory.

When none is found, the row's command is `azhaq show`.

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
