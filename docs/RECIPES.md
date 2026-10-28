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

Rows like `401 → 200 → 200  …/rest/basket/8  [bob reads alice's object] proved` are the findings, worst first; `proved` rows first, `guess` rows need a look. The evidence after the route says why the object is alice's and what a made-up identifier got. Check one by hand with bob's token before you report it: `azhaq roles show -dir DIR URL` prints each role's answer, how it differs from alice's, and a curl line to run with `BOB_TOKEN` set.

Catch: copied tokens expire. Roles says so (`its token expired at …`, exit 3); see recipe 4.

## 4. Tokens that live a few minutes

```
azhaq roles -role anon -role-cmd 'alice=./token.sh alice' -role-cmd 'bob=./token.sh bob' -- -url https://app.example.com/
```

The command prints `Header: value` lines, or a bare token (sent as `Authorization: Bearer`). It runs before each role's run, again before the replay, and whenever the role's canary (its `/me`, or `-canary URL`) says the session died during the replay; what was asked since the last good check is asked again.

## 5. Test writes across accounts

```
azhaq roles -replay-writes post,put,patch -har alice=alice.har -role anon -role "alice=…" -role "bob=…" -- -url https://app.example.com/ -allow app.example.com
```

Save alice's traffic as a HAR (browser developer tools, or Burp). Her POST, PUT and PATCH are replayed with bob's and the visitor's sessions. Without a HAR, the PUT and PATCH the routes take are asked with an empty body on each role's own objects. `-dry-writes` lists them and sends nothing.

Catch: writes change data on the target. Add `delete` only if deleting test data is fine.

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

A run stopped by `-max-requests`, `-timeout`, Ctrl-C or a crash continues where it stopped, without asking again what it asked. Drop-ins given `-db` resume too.

## 8. Watch a program and get alerts

```
azhaq watch -db acme.db -every 24h -notify https://hooks.slack.com/services/… -- -scope hackerone -program acme
```

It reports new names, services, URLs, open ports, pages whose status or title changed, and API listings that grew or shrank. No change, no message.

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

Introspection is a POST, so it needs a scope. A run that finds GraphQL without `-graphql` suggests the command.

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
