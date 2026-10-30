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

It reports new names, services, URLs, open ports, pages whose status or title changed, and API listings that grew or shrank. It also reports the API routes a deploy changed, each tied to the script that calls it (`+ POST /api/v2/export {format, userId}  (main.js)`: a new route; `~ /api/orders/{id}: +DELETE`: a method added; `~ PUT /api/profile: +role`: a body name added; `- /api/legacy/report`: a route gone from its script). No change, no message.

## 9. Feed other tools, and take their results in

```
azhaq export -db acme.db -format targets | nuclei -l -
azhaq export -db acme.db -format burp > scope.json
httpx -l hosts.txt -json | azhaq ingest -in - -db acme.db
```

`ingest` reads subfinder, dnsx, httpx, katana, naabu, nuclei and gau JSON lines and ffuf output. Lines it cannot read are skipped and counted.

## 10. Read a GraphQL schema

```
azhaq run -url https://app.example.com/ -graphql -allow app.example.com -db app.db
azhaq export -db app.db -format sdl > schema.graphql
```

Introspection is a POST, held to the targets given (or the `-allow`/`-scope` named). A run that finds GraphQL without `-graphql` suggests the command.

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
