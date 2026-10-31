# azhaq roles

Map the same target once per session and show where the answers differ (access control).

## Synopsis

```
azhaq roles -role NAME[=Header: value] -role … [-role-login NAME=USER:PASS -login URL] [-id [ROLE:]NAME=VALUE] [-jsonl] -- RUN FLAGS; roles show -dir DIR URL [-method M]
```

## Examples

```
azhaq roles -role anon -role 'user=Authorization: Bearer eyJ…' -- -url https://api.example.com/
azhaq roles -role anon -role 'alice=Authorization: Bearer eyJ…' -role 'bob=Authorization: Bearer eyJ…' -id 'alice:book_title=Alice book' -- -url https://api.example.com/
azhaq roles -role anon -role 'alice=Authorization: Bearer eyJ…' -role 'alice=Cookie: token=eyJ…' -- -url https://app/
azhaq roles -login https://app/login -role anon -role-login 'alice=a@x.test:pw' -role-login 'bob=b@x.test:pw' -- -url https://app/
azhaq roles show -dir azhaq-roles-20261028-101500 https://app/rest/basket/6
```

## Output

One row per endpoint whose answer depends on the session: status, length and body per role, and a verdict (a role reading another role's object, sensitive fields anyone reads, …); a role refused wherever a session matters is named in a note (exit 3). A role sends only the headers it is given: what an app reads from a cookie (Juice Shop's /rest/user/whoami) needs NAME=Cookie: …, or -role-login, which carries the cookies and the stored token.

## Summary and exit codes

The summary and the exit codes are the shared ones: see [OUTPUT.md](../OUTPUT.md#exit-codes).

## Flags

<!-- flags:begin roles -->
| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-all` | bool |  | also list endpoints that answer every role the same, or with each role's own data |
| `-allow` | string, repeatable |  | HOST: an origin of the history that is the target besides the ones most of a role's requests go to (the others, analytics and CDNs, are left out) |
| `-burp` | string, repeatable |  | NAME=FILE: the same from a Burp "Save items" XML file (repeat a name to add files) |
| `-canary` | string, repeatable |  | [ROLE:]URL[=REGEX]: what checks a session during the replay: a URL only a live session reads, and what its body holds (default: the role's own /me-like answer, or a page the anonymous role is refused) |
| `-canary-every` | int | `50` | replay requests between two checks of a role's session (0: no checks) |
| `-dir` | string |  | directory for one database per role (default: azhaq-roles-<time>) |
| `-dry-writes` | bool |  | with -replay-writes: list the writes it would send, with whose and why, and send none |
| `-har` | string, repeatable |  | NAME=FILE: the requests account NAME sent, as a browser or proxy saved them (HAR). Every GET is a page the role reached, its Authorization and Cookie headers of the latest request are its session (unless -role gives headers), its writes are replayed with -replay-writes. Without -- run options this is the whole input: no crawl |
| `-id` | string, repeatable |  | [ROLE:]NAME=VALUE: also fill routes with this identifier. NAME is a path parameter (book_title), a JSON field holding such values (basket_id) or a route (/rest/basket/{id}); with ROLE, VALUE names ROLE's own object, and another role that reads it is listed |
| `-json` | bool |  | one JSON object per endpoint, and only the summary, as JSON, on stderr |
| `-jsonl` | bool |  | one JSON object per endpoint (same as -json) |
| `-login` | string |  | the login page for -role-login |
| `-no-anon` | bool |  | with -har or -burp: do not add the anonymous role |
| `-proxy` | string |  | send every request through this proxy (http, https or socks5 URL): the runs, the history reads and the replay |
| `-rate` | float |  | requests per second for the history reads and the replay, when the run options give none |
| `-refusal` | string |  | REGEX: a 2xx answer whose body matches is a refusal, for every role (a 200 "Access denied" page); each origin's own refusal page is learned besides |
| `-replay` | bool | `true` | ask every endpoint one session reached with every other session, and each role's objects with the others (GETs that change nothing only) |
| `-replay-max` | int | `2000` | requests the replay may send, over all roles |
| `-replay-writes` | string |  | also replay writes with every other role's session: post,put,patch (add delete to delete objects). They change data on the target and go only to the -url hosts, or the -allow/-scope given in the run options. The writes are each role's own from -har or -burp (sent only to the history's origins, never a logout), and the PUT and PATCH (an empty object, the owner's first: a server that replaces on PUT may clear the owner's own object) and DELETE the runs' routes take, on each role's objects. A cross-role write is claimed only when the owner's object, read as the owner before and after, changed the way the write asks |
| `-replay-writes-canary` | bool |  | with -replay-writes: change one short string field of a PUT or PATCH body to a unique value for each role it is replayed with, before it is sent, so a write that would otherwise replay the owner's own value back (no change to read back) can still be proved; never on by default, since it changes data, and restoring the field afterward is not done |
| `-role` | string, repeatable |  | NAME, or NAME=Header: value (repeat a name to add headers; a role with none is anonymous). Only these headers are sent: a session the app reads from a cookie needs NAME=Cookie: … |
| `-role-cmd` | string, repeatable |  | NAME=COMMAND: a role whose headers a shell command prints, one Header: value per line (a bare token is sent as Authorization: Bearer); run before the role's run and again before the replay, for tokens that live minutes |
| `-role-login` | string, repeatable |  | NAME=USER:PASSWORD: a role that signs in on the -login page with Chrome, and sends the cookies and the token the login left |
<!-- flags:end -->

### roles show

<!-- flags:begin roles show -->
| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-body` | string |  | print the answer ROLE got, as kept (secrets taken out), and nothing else |
| `-dir` | string |  | the -dir of the roles run (it holds roles.db) |
| `-json` | bool |  | one JSON object: the row, and each answer with its curl line and its differences |
| `-method` | string |  | the method of a write row (-replay-writes); a read's row by default |
<!-- flags:end -->
