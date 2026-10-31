# azhaq roles

Map the same target once per session and show where the answers differ (access control).

`azhaq roles` maps the target once for each role. It then asks every endpoint any role reached with every other role's session, and compares the answers. You see endpoints that answer differently by session, objects one role reads or writes that belong to another, and sensitive fields that anyone reads.

## Synopsis

```
azhaq roles -role NAME[=Header: value] -role … [-role-login NAME=USER:PASS -login URL] [-id [ROLE:]NAME=VALUE] [-jsonl] -- RUN FLAGS; roles show -dir DIR URL [-method M]
```

## Examples

```
# an anonymous role and one signed-in role
azhaq roles -role anon -role 'user=Authorization: Bearer eyJ…' -- -url https://api.example.com/

# two users, with an identifier you know is alice's
azhaq roles -role anon -role 'alice=Authorization: Bearer eyJ…' -role 'bob=Authorization: Bearer eyJ…' -id 'alice:book_title=Alice book' -- -url https://api.example.com/

# an app that reads its session from a cookie: send the cookie as a header too
azhaq roles -role anon -role 'alice=Authorization: Bearer eyJ…' -role 'alice=Cookie: token=eyJ…' -- -url https://app/

# sign in with Chrome instead of copying tokens
azhaq roles -login https://app/login -role anon -role-login 'alice=a@x.test:pw' -role-login 'bob=b@x.test:pw' -- -url https://app/

# also ask alice's recorded writes with bob's session (this changes data on the target)
azhaq roles -role anon -role 'alice=Authorization: Bearer eyJ…' -role 'bob=Authorization: Bearer eyJ…' -har alice=alice.har -replay-writes post,put,patch -- -url https://api.example.com/

# one row's answers side by side, with a curl per role
azhaq roles show -dir azhaq-roles-20261028-101500 https://app/rest/basket/6
```

## What it does

1. Runs the map once for each role. The run options after `--` say what to map. A role sends only the headers it is given.
2. Reads the requests an account sent, if you give a history file with `-har` or `-burp`. See [History files](#history-files).
3. Asks every endpoint any role reached with every other role's session. This is the replay. It sends the GETs that change nothing.
4. Fills `{id}` routes with each role's own objects. The identifiers come from the sessions and the answers, or from `-id`.
5. Compares the answers and gives each endpoint a verdict. A cross-role read or write also gets a `confidence` and the evidence for it.
6. Asks each cross-role read again with a made-up identifier, to catch a route that answers any identifier. See [Negative controls](#negative-controls).
7. Checks each session during the replay and renews one that died. See [Canaries](#canaries).
8. With `-replay-writes`, also asks each role's writes with every other role's session. See [Writes](#writes).
9. Keeps the answers behind the rows in `roles.db`, in `-dir`. `roles show`, `report` and `hunt` read it. See [Evidence and roles show](#evidence-and-roles-show).

A role is one of four things:

- anonymous, with no headers
- headers you give it with `-role`
- headers a command prints, with `-role-cmd`, for tokens that live minutes
- a Chrome sign-in, with `-role-login`

## Output

One row per endpoint whose answer depends on the session. Each row has the status, length and body per role, and a verdict. With `-all`, every endpoint compared is a row. With `-replay-writes`, there is one more row per write asked, with `method` set.

The text table names the roles and fields in brackets after the verdict. With `-json` or `-jsonl`, stdout holds one JSON object per row.

```json
{"url":"http://localhost:5000/books/v1/aliceBook","verdict":"reads another role's object",
 "template":"http://localhost:5000/books/v1/{book_title}","found_by":["alice"],"owner":"alice",
 "owner_by":"item of /books/v1: user alice names alice (sub claim of alice's token); the answer's owner alice names alice (sub claim of alice's token)",
 "readers":["bob"],"sensitive":["secret"],"status":{"anon":401,"alice":200,"bob":200},
 "confidence":"proved",
 "evidence":"bob got alice's answer (the same body, 79 bytes); item of /books/v1: user alice names alice; the answer's owner alice names alice; a made-up qmxreHtgf got bob 404; both ways: alice reads bob's too",
 "control":{"url":"http://localhost:5000/books/v1/qmxreHtgf","value":"qmxreHtgf","answers":{"bob":{"status":404,…}}},"both_ways":true,
 "answers":{"anon":{"status":401,"length":95,"hash":"…","error":true},
            "alice":{"status":200,"length":79,"hash":"9f…","keys":["book_title","owner","secret"],"sensitive":["secret"]},"bob":{…}}}
```

### Fields

| Field | Meaning |
| --- | --- |
| `url` | The endpoint's URL. |
| `verdict` | What the answers show. See [Verdicts](#verdicts). |
| `status` | Each role's status. `0` for a role that was never asked. |
| `dir` | The run's `-dir`, as an absolute path. `roles show`, `report` and `hunt` find the answers behind the row there. |
| `answers` | Each role's answer. See [Answers](#answers). |
| `found_by` | The roles whose own runs reached the URL, or, for an object URL, whose answers held its identifier. |
| `template` | For an object URL, the route it fills, such as `/books/v1/{book_title}`. |
| `owner` | The role whose own object it is. See [Who owns an object](#who-owns-an-object). |
| `owner_by` | What says the object is the owner's, to check in one look. See [owner_by](#owner_by). |
| `confidence` | `proved`, `likely` or `guess`: how surely the object is the owner's. See [Confidence](#confidence). |
| `evidence` | Why, in one line. See [evidence and control](#evidence-and-control). |
| `control` | What its readers got for a made-up identifier on the same route. |
| `both_ways` | The owner reads one of its reader's objects on the same route too. |
| `session_suspect` | An answer was asked after its role's session last proved alive. See [Canaries](#canaries). |
| `readers` | For verdicts that say who reads it: those roles. |
| `sensitive` | For verdicts about sensitive fields, and on object rows: the fields. |

`template` holds the path parameters filled with identifiers the roles' answers held, or given with `-id`. `owner`, `owner_by`, `confidence`, `evidence` and `control` appear on rows where a role reads or writes another role's object.

The text table prints `confidence` and `evidence` after the route. It marks a `session_suspect` answer with `?`, and the row with `· session suspect: bob`. A 2xx answer that counts as refused shows as `200:refused`.

### Verdicts

Verdicts are listed worst first, as `-json` gives them. A role reads an endpoint when it gets a 2xx answer that is not an error. [Reads and refusals](#reads-and-refusals) says what counts as a refusal.

| Verdict | Meaning |
| --- | --- |
| `anyone reads sensitive fields` | The anonymous role reads passwords, secrets, keys or card numbers, at any depth of the JSON, or a token another session reads too. |
| `reads another role's object` | A role reads the owner's object as the owner does, and a made-up identifier on the same route is not answered alike. |
| `answers any identifier` | As above, but the route answered a made-up identifier as a real object too. `confidence` is `guess`. |
| `every signed-in role reads the same object` | An object URL every signed-in role reads alike, owner unknown. |
| `roles read the same sensitive fields` | Several roles read the same values of sensitive fields: no session's own. |
| `same answer for a session that did not find it` | A role that never reached the URL gets the answer the role that found it got. |
| `signed-in only` | The anonymous role is refused, and every signed-in role reads it. |
| `only one role reads it` | Every other role is refused. |
| `some roles refused` | Some signed-in roles read it, and others are refused. |
| `different fields per role` | Every role reads it with the same status, with different nested fields. |
| `anyone reads the same object, signed in or not` | An object URL the anonymous role reads as the others do. Listed once per route. |
| `status differs` | Anything else, such as other redirects and 5xx. |

With `-all`, four more verdicts appear: `different data per role`, `same for every role`, `no role reads it` and `not answered`.

The text table writes the roles and fields in brackets:

- `[anyone reads sensitive fields: password]`
- `[bob, admin read alice's object]`
- `[answers any identifier: bob read alice's object and a made-up 1000014 alike]`
- `[alice, bob read the same sensitive fields: deluxeToken]`
- `[only admin reads it]`
- `[bob writes alice's object]`

The summary counts the verdicts of the rows listed. A note counts the endpoints compared and not listed:

```
58 more endpoints compared and not listed (34 same for every role, 23 no role reads it, 1 different data per role); -all lists them
```

#### Write verdicts

With `-replay-writes`, these verdicts join the list. Proved cross writes keep the top, above the reads. The "Listed" column says whether a row shows by default or only with `-all`.

| Verdict | Listed | Meaning |
| --- | --- | --- |
| `anyone writes another role's object` | yes | The anonymous role's write changed the owner's object. Proven. |
| `writes another role's object` | yes | A signed-in role's write changed the owner's object. Proven. The row has `readers`. |
| `writes another role's object: accepted; the change cannot be read back to confirm` | yes | Another role's write was answered 2xx, and nothing shows whether the owner's object changed. See Details. |
| `would be sent (-dry-writes)` | yes | `-dry-writes`: nothing was sent. |
| `answered 2xx but changed nothing of the owner's` | `-all` | A 2xx answer, but the owner's object did not change as the write asked, or could not be read. Not a finding. |
| `creates in another role's collection` | `-all` | A POST a role was let to send: a create, never another role's object written. |
| `only its owner writes it` | `-all` | The others were refused. |
| `the owner's own write was refused` | `-all` | The owner was not let, or its empty write changed its object: nothing to compare. |
| `the other roles were refused` | `-all` | A DELETE, never asked of its owner, that no other role was let to send. |
| `the other roles' writes failed with a server error (5xx): neither refused nor accepted` | `-all` | Every other role's write was answered 5xx: nothing is said about who may write. |

## Summary and exit codes

The summary and the exit codes are the shared ones: see [the summary](../OUTPUT.md#the-summary) and [exit codes](../OUTPUT.md#exit-codes). What is specific to `roles`:

- **Exit 3:** a signed-in role was refused wherever a session matters. The summary names it in a note. See [Dead sessions](#dead-sessions).
- **Exit 3:** a token has expired and nothing more can be said of it. A note says so. See [Expired tokens](#expired-tokens).
- **Exit 4:** a role's run was stopped by a limit. The summary marks it `stopped`.
- **Exit 2:** a header names a host outside the scope rule. Nothing is sent. See [Headers that name a host](#headers-that-name-a-host).
- A role whose run could not be done, such as a failed sign-in, ends `roles` with a summary whose `notes` say why.
- With `-json`, stderr holds the summary only. The roles' runs print nothing. The summary says what they did not finish: `failed`, `unreachable`, `skipped` and `notes`.

## Details

### Verdict details

- `anyone reads sensitive fields` holds even when every role gets the same answer.
- `reads another role's object`: the owner's object counts as read alike when the body is the same, or the fields are the same around the same identifier.
- An owner inferred from the answers whose object the anonymous role reads alike is public instead, so it is not `reads another role's object`.
- `answers any identifier`: the route's 2xx says nothing about who may read what.
- `roles read the same sensitive fields`: a token only its own session gets is not listed.
- `different fields per role`: fields under a list one role has empty are data, not fields. So is a field of a list's items that only holds true or false (`data[].liked`) and only one role gets.
- `anyone reads the same object, signed in or not`: `-all` lists every object, not one per route.

### Reads and refusals

A role reads an endpoint when it gets a 2xx answer that is not an error. A refusal is any of these:

- any 4xx
- an error answered with a 2xx status
- a 2xx page that is its origin's refusal, such as `200 Access denied` (see [Refusal pages](#refusal-pages))
- a redirect to a sign-in page: a path such as `/login`, `/users/sign_in` or `/auth/…`, another site's sign-in service, or the `-login` page
- a redirect to the site's front page while another role reads the endpoint

On a cookie-session app, the visitor sent to `/login` makes a page `signed-in only`.

### Roles and sessions

- A role given with `-role` sends those headers and nothing else. Behaviour an app ties to a cookie is not reached with a header alone.
- Juice Shop's `/rest/user/whoami` reads the `token` cookie. It answers `{"user":{}}` to an `Authorization` header.
- Give the cookie as one of the role's headers, as in `-role 'alice=Cookie: token=eyJ…'`. This is what `-cookie` sends in a run.
- Or use `-role-login`. It carries the cookies and the token the login stored.
- `-role-cmd 'alice=./token.sh alice'` gives a role whose headers a shell command prints: one `Header: value` per line, or a bare token sent as `Authorization: Bearer`.
- The `-role-cmd` command runs before the role's run and again before the replay. It suits tokens that live minutes.
- A `-role-cmd` command's own requests are not azhaq's and are not in the ledger or held to the scope; give tokens directly or use `-role-login` to keep every request in the ledger. What the command prints is still held to the scope (see below).
- `-role-cmd` is not offered over MCP.

### Headers that name a host

A role's headers are held to the scope like any header that names a host. [What Azhaq sends](../CONCEPTS.md#what-azhaq-sends) has the rule.

- `-role 'bob=Host: secret.lab'` with `-deny secret.lab` stops the command with exit 2 before the first request. `X-Forwarded-Host`, `X-Host` and `X-Original-Host` behave the same.
- What a `-role-cmd` prints was not typed by you. It is held to the `-url` targets and the histories' origins, or to the rule.
- A command that prints a host outside them stops the command as soon as it has run, before that role is sent.

### Expired tokens

`roles` reads the `exp` of a JSON Web Token a role sends as its credential, before anything is sent. It looks in `Authorization`, and in a header or cookie named for one: `X-Auth-Token`, `token`, `jwt`, `session` and similar. An analytics cookie is not read.

- An expired token is said at once on stderr.
- A token that expires within 15 minutes is noted too.
- The end of the run says what came of an expired token. It is one of three things.

The three outcomes:

- A dead session: `its token expired at …`.
- A site that still took the token, when it was the role's only credential. This is a finding. The note reads as below.
- With nothing to tell, a note and exit 3.

```
role alice's token expired at …, yet the site still let it read 3 endpoints the anonymous role is refused: check that it verifies token expiry
```

### Dead sessions

A signed-in role whose session looks expired or wrong is named in a note, and `roles` exits 3. The note quotes what the site says when that role asks one such endpoint again:

```
role x was refused wherever a session matters (the site said "Signature expired. Please log in again."): its session looks expired or wrong; its rows show what a visitor gets
```

A role is judged dead when both of these hold:

1. It was refused on every endpoint the anonymous role is refused and another signed-in role reads, or on every endpoint another role reads.
2. It read no `/me`-like endpoint unlike the anonymous role.

When no signed-in role reads anything the anonymous role is refused, each role is judged alone. This happens when tokens copied at the same time expire together. A role is then dead when it was refused on every endpoint the anonymous role is refused, and given nothing more than the anonymous role anywhere.

A role that read an endpoint the anonymous role did not is known to the site and alive. So is a role that was forbidden (403) where the anonymous role was asked to sign in (401).

Every value the role sent is taken out of the quoted reason: its headers, its cookie values and the credential after `Bearer` or `Basic`. So is anything shaped like a credential.

### Canaries

A session can die during the replay: a token that lives minutes, or a server that logs a session out. `roles` checks each signed-in role's session on an endpoint only a live session reads.

- `-canary [ROLE:]URL[=REGEX]` names the endpoint. Without ROLE it applies to every signed-in role not given one of its own. With REGEX, a live session's body must match it.
- Without `-canary`, `roles` picks the role's own `/me`-like answer, one of its own objects, or an endpoint the anonymous role was refused. It never picks one the anonymous role reads alike. It prefers JSON, then the shortest URL.
- The check runs before each role's replay, every `-canary-every` requests, and after the replay. The default is 50. `0` means no checks.
- The check must answer as the role's run got it: the same body, the same JSON fields, or the same page title.
- When a check fails, the session is renewed. `-role-cmd` runs again, or `-role-login` signs in again with Chrome.
- A role's session is renewed at most 5 times. It is not renewed again once a new session fails its first check.
- What was asked since the last good check is asked again.
- A session that cannot be renewed (`-role` headers) or does not come back leaves the answers asked after its last good check `session_suspect`, with a note.
- A signed-in role with nothing to check it by is named in a note.
- The checks and the requests asked again count against `-replay-max`.

The notes read:

```
role alice's session failed its check (/api/Cards → 401) during the replay; its -role-cmd gave a new one, and the 50 requests asked since the last good check were asked again
role bob's session failed its check (/me → 401) during the replay and did not come back: 31 answers asked after it was last seen alive (session_suspect)
```

### Negative controls

Each row where a role reads another role's object is asked again by each of its readers. The request uses a made-up identifier of the same shape on the same route:

- a number: 1000003 past the real one, so `/rest/basket/1000022` for `/rest/basket/19`
- a UUID: a random UUID
- anything else: a random string of the same length and the same kinds of characters

A route that answers the made-up identifier as a real object answers any identifier. The row becomes `answers any identifier`. A made-up identifier counts as answered as a real object when all of these hold:

- the status is 2xx, and the answer is not an error and not a refusal
- the body is the same, or the same nested fields hold data besides the made-up identifier and what echoes it

Also:

- A reader the route answers so, beside one it refuses, is dropped from the row's readers.
- Each reader is asked once per route and shape of identifier.
- The controls count against what `-replay-max` leaves after the replay.

### Refusal pages

Some sites refuse with a 2xx page. `roles` learns each origin's refusal page from what the anonymous role got on endpoints a signed-in role reads otherwise. A page is a refusal when:

- its title and first heading, or its JSON message, says so, such as `Access denied`, `Forbidden` or `Please sign in`. One endpoint is enough.
- or it asks to sign in, on two endpoints or more.

`roles` tells the page by its status, what it says and its JSON fields. When the page does not change, it also uses the body's hash.

- Every role's 2xx answer that matches the page counts as refused. The text table shows `200:refused`.
- A note names the page.
- `-refusal REGEX` says what a refusal body looks like when the page does not say it in words. Every 2xx answer whose body matches is refused, for every role.

```
http://app refuses with a 200 page saying "Access denied" (the anonymous role got it on 3 endpoints a signed-in role reads otherwise): such an answer counts as refused for every role
```

### History files

`-har NAME=FILE` and `-burp NAME=FILE` give the requests account NAME sent. Both are repeatable, and the same NAME adds files. A HAR comes from browser devtools, Caido or Burp. Burp's file is the "Save items" XML. NAME is a `-role` of that name, or a new role.

- **Session.** A role with no `-role` headers, no `-role-cmd` and no `-role-login` takes the `Authorization` and `Cookie` header of its most recent request to the target. `Bearer null` and `Bearer undefined` are no session. A role whose history carries none is anonymous.
- **Target origins.** For each account, the origin most of its requests go to, and any other with a quarter of them. `-allow HOST` adds one. Requests to other origins, such as analytics and CDNs, are neither sent nor read from. A note names them.
- **Pages.** Each GET on the target a history reached is asked once, as the account. Its answer is the account's own, as if its run had found it. `/rest/basket/6` and `/rest/basket/7` in two histories are the route `/rest/basket/{id}`.
- **After the read.** Replay, identity, controls, evidence and `roles show` work as after a crawl.
- **Without run options.** Without `--` run options nothing is crawled, and the target is the history's origins. With them, the crawl's pages are added.
- **Flags.** `-no-anon` leaves the anonymous role out. `-rate N` paces the history reads and the replay. The history reads count against `-replay-max`.
- **Writes.** With `-replay-writes`, the history's writes of the methods named are replayed. They go to the target's origins only, and DELETE only when named. A name decides nothing: a logout the history sent is replayed like any write you asked for, and the role's session check says when it ended that role's session.
- **Proof.** A write is proved in the field it sets, against the object as the owner's last write left it. A short 2xx answer that says no, such as `Only Admins may delete users!` or `forbidden`, is a refusal.

### Identifiers you give

`-id [ROLE:]NAME=VALUE` is repeatable. It fills routes with an identifier of your own. NAME is one of three things:

- a path parameter, such as `book_title`
- a JSON field that holds such values: `basket_id` and `BasketId` fill `/rest/basket/{id}`
- a route, such as `/rest/basket/{id}`

With ROLE, VALUE names that role's own object, so another role reading it is `reads another role's object`. Without ROLE, VALUE is tried like an identifier the answers held. An object given with `-id ROLE:…` stays that role's.

Each route is also filled with up to 5 of each role's own identifiers and 6 others. Among the role's own, those named by who the role is come first. Numbers are taken in order of value.

The replay asks objects in this order:

1. objects given with `-id`
2. the roles' own objects
3. what the runs reached
4. other objects

It takes a URL only while `-replay-max` holds every role's request for it.

### Who owns an object

`owner` is the role whose own object the row is about. It comes from one of three places:

- `-id ROLE:…`
- who the role is
- an identifier only that role's answers held

The last is an identifier in the route's own list, such as `/api/Addresss` for `/api/Addresss/{id}`, while the same list read by another role did not hold it. Or it is in a field named after the parameter, and nowhere in the other roles' answers.

What the object's own answer says of its owner confirms, names or undoes it, as far as what filled the route allows.

#### Who each role is

Who a signed-in role is tells its own objects apart without `-id`. `roles` uses:

- the claims of a JSON Web Token its headers or cookies carry: `sub`, `id`, `email`, `username`, `data.id` and identifiers such as Juice Shop's `bid`
- its own answer to a `/me`-like endpoint (`/me`, `/whoami`, `/userinfo`), when the anonymous role gets another
- for `-role-login`, what the login answered and left in `localStorage` and `sessionStorage`

Each role's own objects are asked of every other role.

#### Which identifier fills a route

An identifier is a role's own only for objects of its kind. The route's noun tells the kind: the path segment before the parameter, singular or plural, in any case.

- An identifier the session holds fills a route when its name is that noun's. `basketId` and `basket_id` fill `/rest/basket/{id}`. `userId`, `uid` and the `id` of the user object in a token or a `/me` answer fill `/api/Users/{id}`.
- A short name is the initials of the noun's words, such as `bid`. It fills a route only when no other noun has those initials.
- A short name is not used when another route has the initials. With `/api/books/{id}` beside `/rest/basket/{id}`, `bid` is neither's. The session's value is tried on both, as no one's object.
- A short name is not used when a reference field the answers hold has the initials, such as `BrandId`.
- `bid` does not fill `/api/BasketItems/{id}`, whose initials are `biid`. It does not fill `/api/basketitems/{id}` beside a `basket` route either.
- A short name alone is a guess. The object is the role's only if its own answer says so.

#### Owners from list items

- A list item whose own fields name a role is that role's object. Two kinds of field do it: an owner field that names the role, or a reference field that points at an object the role's session names. Owner fields are `owner`, `user`, `username`, `userId`, `email`, `createdBy` and similar.
- A reference field names its kind in full. `BasketId` 8 is alice's basket when her session holds basket 8 as `basketId`, or as `bid` while `bid` stands for the basket route alone. `BookId` 8 is not.
- An account, a customer or a member is not the user. `accountId`, `customerId` and `memberId` are reference fields. They are matched against the session's own `accountId`, `customerId` or `memberId`, never against its user id.
- The item's identifier is the field the route's parameter maps to, such as `book_title` for `/books/v1/{book_title}`. In the route's own list, or a list of the same noun, it is the item's `id`.
- An item of another kind lends its owner only to the object its owner or reference field points at. The `UserId` of an address fills `/api/Users/{id}`. The `ProductId` of alice's basket item is not alice's product.

#### What the object's own answer says

Once every role has asked an object, its own answer has its say on whose it is. `roles` reads the answer, or the object its envelope carries, such as `data`. The answers of every role that reads it must agree.

- An owner or reference field that names the owner confirms it. One that names a role makes an object no one owned that role's.
- Past that, it depends on what filled the route.
- **A short name alone** (`bid`): the owner goes unless the answer names that role. It goes to the role the answer names instead.
- **A list item, or a field in the role's answers alone:** the owner goes to the role the answer names. It goes altogether in one case: a field's value is not that role's, while its session holds one of the same kind and shape. Kinds include a user id, an email and a basket id. `/api/BasketItems/8` with `BasketId` 5 is not alice's, though her `bid` is 8.
- **An identifier the session holds under the route's full name** (`basketId`, a user id), **or the role's own list:** the owner stays, whatever another field says. `/api/transactions` holds alice's transaction alone. Alice's project in her other organisation is still hers. An `accountId` equal to bob's user id does not make it bob's.
- Only a field that names another role by an identifier that role's session holds under the same name hands the object to that role. Examples are its `email`, and its user id as `UserId`.
- A name is spelled too many ways to say an object is not the role's.

### `owner_by`

`owner_by` says in one line what makes the object the owner's. It takes these forms:

- `bid claim of alice's token → /rest/basket/{id}`: an identifier the role's session holds, where it was read, and the route it fills.
- `authentication.bid in alice's login answer → /rest/basket/{id}`: the same, read from a login answer.
- `item of /books/v1: user alice names alice (sub claim of alice's token)`: a list item whose own fields name the role.
- `in alice's /api/Addresss and not the other roles'`
- `in alice's answers alone`
- `given with -id alice:book_title=My book`

After `; `, it says what the object's answer says:

- `the answer's UserId 27 names alice (data.id claim of alice's token)`
- `the answer's BasketId 8 is alice's basket (bid claim of alice's token)`

For a write, `owner_by` says where the write came from, such as `alice.har` or `PUT /api/BasketItems/{id} with an empty body`. See [Writes](#writes).

### Confidence

`confidence` is on rows where a role reads or writes another role's object. It says how surely the object is the owner's.

- `proved`: what filled the route named the owner from its session, or from the role's own list, or from `-id`. The object's own answer confirms it. Naming from the session means an identifier the session holds by its full name, or a list item that names the role by it.
- `likely`: one of those two is missing. For example a short name such as `bid` that the answer bears out, an owner the answer alone names, or an `-id` the answer does not speak to.
- `guess`: an identifier only the owner's answers held and nothing more, or a route that answers any identifier.
- A proven cross write is always `proved`: the owner's object is shown to have changed.

### Answers

Each role's entry in `answers` has these keys:

| Key | Meaning |
| --- | --- |
| `status` | The HTTP status. |
| `length` | The body's length. |
| `hash` | A hash of the body. |
| `keys` | A JSON answer's field paths, nested: `data.user.email`, `data[].id`. |
| `error` | A JSON answer shaped like an error, such as `{"status":"error"}`. |
| `refusal` | A 2xx answer that is its origin's refusal page, or that `-refusal` matches. |
| `sensitive` | Its fields that hold passwords, secrets, keys, tokens or card numbers. |
| `location` | Where a redirect sends the role. |
| `session_suspect` | See [Canaries](#canaries). |

Every answer is compared by its body. A URL the `-paths` list found keeps its status only, so it is asked again with the role's session.

### `evidence` and `control`

`evidence` says why in one line, on the rows where a role reads or writes another role's object. It holds:

- who got what the owner got: `bob got alice's answer (the same body, 155 bytes)`, or `the same fields around 8`
- `owner_by` without the routes and where each value was read
- what a made-up identifier got: `a made-up 1000022 got bob 404`
- `both ways: alice reads bob's too`

For a write, `evidence` says who was let, as the owner was, and where the write came from:

```
bob got 200:80, as alice did (200:80); PUT /api/BasketItems/{id} with an empty body
```

- `control` is on a row where a role reads another role's object. It holds what its readers got for a made-up identifier on the same route. Its keys are `url`, `value`, each reader's `answers`, and `alike`: the readers it answered as a real object.
- `both_ways` is said in a note once per route and pair: `alice and bob read each other's objects on /rest/basket/{id}`.

### Writes

`-replay-writes METHODS` also asks each role's writes with every other role's session, after the reads. METHODS is `post`, `put`, `patch` or `delete`, comma-separated.

Writes change data on the target. They go only to the hosts of the run options' `-url` values, or to the scope `-allow` or `-scope` names. [What Azhaq sends](../CONCEPTS.md#what-azhaq-sends) lists them with the other requests.

#### Which writes are sent

- **Writes a role sent, from a HAR** (`-har NAME=FILE`, as a browser's developer tools or Burp save it). They are its requests with those methods on the run's hosts, one each. Each goes with its body and `Content-Type`, `Accept` and `X-Requested-With`. It never carries the session that sent it: cookies, `Authorization` or a CSRF token. It is replayed whatever its URL is called: only the method decides.
- **Writes the map finds.** These are the PUT, PATCH and DELETE that the routes the runs found take, from API descriptions and scripts. They go on each role's own objects, filled with each role's own identifiers. That is the identity the read replay uses: JWT claims, `/me` answers, list items and `-id`.
- This includes routes that only take a write and have no GET, such as `PUT /users/v1/{username}/email`.

A map write has an empty body:

- PATCH with an empty JSON object asks for the write and changes nothing.
- PUT with an empty JSON object changes nothing on a server that updates the fields sent. It may clear the owner's own object on a server that replaces it on PUT.
- DELETE has no body.

A route whose write takes a form, and a POST, which creates in a collection, are left to the HAR.

#### Proving a cross-role write

A cross-role write is claimed only when it is proven. Before and after another role's write, `roles` reads the owner's object again, as the owner. It reads:

1. the write's own URL, for a PUT, PATCH or DELETE on an object
2. a readable ancestor, when the write's own URL is not readable: `/users/v1/alice/email` becomes `/users/v1/alice`
3. when neither shows the field the write sets, another GET the map already has an answer for, whose body holds the object's identifier or that field

The third case covers a debug or admin endpoint that lists everyone's fields, such as `/users/v1/_debug`. It was found and flagged while reading. It is now read again as the owner, to confirm a write it could not otherwise show.

For a POST that creates in a collection, `roles` also reads the created object back. It does so when the map already knows the member URL the object would answer at: the collection's path plus a value the body sets. This is evidence the create is more than a 2xx.

- `writes another role's object` is reported only when the owner's object changed the way the write asks, or was deleted. Changed means one of the body's values is now in it.
- The row names the URL the change was read back at when it is not the write's own.
- A write answered 2xx that left the owner's object unchanged is `answered 2xx but changed nothing of the owner's`. It is not a finding. An app that writes the caller's own object whatever the path says does this.
- A POST to a collection is never a cross write. A role let to send it `creates in another role's collection`.

#### Canary values

Replaying the owner's own recorded body is idempotent when the value it sets is already there. Nothing changes, so nothing can be proven either way.

`-replay-writes-canary` fixes that. Before a PUT or PATCH body is sent, it changes one short string field to a value unique to each role it is sent with. The read-back then has something only that role's write could have put there.

- It never changes an identifier, an owner or reference field, a credential, or a timestamp.
- It is never on by default, since it changes data on the target.
- The field is not restored afterward.
- The row's evidence says which field changed and that it was a canary.

#### Order and limits

1. A map write (empty body) is first sent with its owner's session.
2. When the owner is let, its object is read again. If a value it held changed, timestamps aside, nobody else is asked: `the owner's own write was refused`.
3. Then the anonymous roles are asked, then the other signed-in roles.
4. A DELETE goes to the others alone, the anonymous role first. It stops at the first proven.

- A write is let when it is answered 2xx and not with an error shaped as data. It is proven by the owner's object changing.
- Proved cross writes keep the top of the list, above the reads. The unproven rows rank below the proved reads: `answered 2xx but changed nothing` and `creates in another role's collection`.
- Every request counts against `-replay-max` (what the read replay left) and the run's `-max-requests`, at the run's `-rate`. That includes each write and each read of the owner's object to verify it.
- Every request is sent without following a redirect.

#### What the write verdicts mean

- `writes another role's object: accepted; the change cannot be read back to confirm`: another role's write on the owner's object was answered 2xx. The row says which, such as `accepted (204)`. No GET the map knows shows the field the write sets, or the object cannot be read at all. The GETs the map knows are the object's own, an ancestor, or another endpoint that holds its identifier or the field written.
- That verdict is neither proved nor disproved. Check it by hand, or give `-replay-writes-canary` if the write would otherwise replay a value already there. It is never reported as "changed nothing".
- `answered 2xx but changed nothing of the owner's`: the owner's object did not change the way the write asked, or could not be read to verify it. Not a finding; check by hand.
- `the other roles' writes failed with a server error (5xx)`: every other role's write was answered 5xx. Examples are a unique key the server already held, and a crash.
- A write row's `owner_by` says what proved it. Examples: `after bob's PUT the owner's object changed to match it` and `after bob's DELETE the owner's object is gone (404)`.
- `confidence` is `proved` on a proven cross write, and `evidence` says who was let.
- `azhaq roles show -dir DIR -method PUT URL` prints each role's curl line with the write's body.

### Evidence and roles show

The answers behind the rows listed are kept in `roles.db` in `-dir`. It holds each role's answer to each row, and to its control. A body is gzipped and cut at 256 KB.

Kept bodies have these replaced by `[redacted 1a2b3c4d]`:

- the values of sensitive fields: passwords, tokens, keys and secrets
- JSON Web Tokens
- every value a role sent: its headers, its cookie values and the credential after `Bearer`

The same value shows the same tag within a run. The tag tells nothing of the value. A role may not be named `roles`.

`azhaq roles show -dir DIR URL` prints the answers side by side for one row. Add `-method M` for a write's row. It prints:

- the row's verdict, `confidence`, `evidence` and `owner_by`
- per role, its status, length and type
- per role, a curl line that asks it again with the role's session as a shell variable, never its value
- how the role's body differs from the owner's, or from the first role's that reads it, field by field, at most 20 lines

```
-H "Authorization: Bearer $ALICE_TOKEN"
-b "$BOB_COOKIE"
-H "X-Api-Key: $BOB_X_API_KEY"
```

The diff lines look like this:

```
- data.id  19
+ detail  "No authorization token provided"
~ user.name  "alice" → "bob"
```

`-` is the owner's only, `+` is this role's only, and `~` is a changed value.

- `-method PUT` picks a write's row.
- `-body ROLE` prints the body ROLE got, as kept, and nothing else.
- `-json` gives the row and each answer with its `curl` and `diff`.
- The curl lines need the variables set to the sessions the roles sent. `roles` keeps none of them.

## Flags

<!-- flags:begin roles -->
**Sessions**

| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-role` | string, repeatable |  | NAME, or NAME=Header: value (repeat a name to add headers; a role with none is anonymous). Only these headers are sent: a session the app reads from a cookie needs NAME=Cookie: … |
| `-role-cmd` | string, repeatable |  | NAME=COMMAND: a role whose headers a shell command prints, one Header: value per line (a bare token is sent as Authorization: Bearer); run before the role's run and again before the replay, for tokens that live minutes; the command's own requests are not azhaq's: not in the ledger, not held to the scope |
| `-role-login` | string, repeatable |  | NAME=USER:PASSWORD: a role that signs in on the -login page with Chrome, and sends the cookies and the token the login left |
| `-login` | string |  | the login page for -role-login |
| `-har` | string, repeatable |  | NAME=FILE: the requests account NAME sent, as a browser or proxy saved them (HAR). Every GET is a page the role reached, its Authorization and Cookie headers of the latest request are its session (unless -role gives headers), its writes are replayed with -replay-writes. Without -- run options this is the whole input: no crawl |
| `-burp` | string, repeatable |  | NAME=FILE: the same from a Burp "Save items" XML file (repeat a name to add files) |
| `-no-anon` | bool |  | with -har or -burp: do not add the anonymous role |
| `-canary` | string, repeatable |  | [ROLE:]URL[=REGEX]: what checks a session during the replay: a URL only a live session reads, and what its body holds (default: the role's own /me-like answer, or a page the anonymous role is refused) |
| `-canary-every` | int | `50` | replay requests between two checks of a role's session (0: no checks) |

**What to replay**

| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-replay` | bool | `true` | ask every endpoint one session reached with every other session, and each role's objects with the others (reads only, by method: GET; a write is replayed only with -replay-writes) |
| `-replay-max` | int | `2000` | requests the replay may send, over all roles |
| `-replay-writes` | string |  | also replay writes with every other role's session: post,put,patch (add delete to delete objects). They change data on the target and go only to the -url hosts, or the -allow/-scope given in the run options. The writes are each role's own from -har or -burp (sent only to the history's origins), and the PUT and PATCH (an empty object, the owner's first: a server that replaces on PUT may clear the owner's own object) and DELETE the runs' routes take, on each role's objects. A cross-role write is claimed only when the owner's object, read as the owner before and after, changed the way the write asks |
| `-replay-writes-canary` | bool |  | with -replay-writes: change one short string field of a PUT or PATCH body to a unique value for each role it is replayed with, before it is sent, so a write that would otherwise replay the owner's own value back (no change to read back) can still be proved; never on by default, since it changes data, and restoring the field afterward is not done |
| `-dry-writes` | bool |  | with -replay-writes: list the writes it would send, with whose and why, and send none |
| `-id` | string, repeatable |  | [ROLE:]NAME=VALUE: also fill routes with this identifier. NAME is a path parameter (book_title), a JSON field holding such values (basket_id) or a route (/rest/basket/{id}); with ROLE, VALUE names ROLE's own object, and another role that reads it is listed |
| `-refusal` | string |  | REGEX: a 2xx answer whose body matches is a refusal, for every role (a 200 "Access denied" page); each origin's own refusal page is learned besides |
| `-allow` | string, repeatable |  | HOST: an origin of the history that is the target besides the ones most of a role's requests go to (the others, analytics and CDNs, are left out) |
| `-all` | bool |  | also list endpoints that answer every role the same, or with each role's own data |

**Pace and network**

| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-rate` | float |  | requests per second for the history reads and the replay, when the run options give none |
| `-proxy` | string |  | send every request through this proxy (http, https or socks5 URL): the runs, the history reads and the replay |

**Output**

| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-dir` | string |  | directory for one database per role (default: azhaq-roles-<time>) |
| `-json` | bool |  | one JSON object per endpoint, and only the summary, as JSON, on stderr |

<details>
<summary>Other names (1)</summary>

| Flag | Type | Default | Meaning | Kind |
| --- | --- | --- | --- | --- |
| `-jsonl` | bool |  | one JSON object per endpoint (same as -json) | other name |

</details>
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
