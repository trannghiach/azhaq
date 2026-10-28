# What Azhaq prints

Every command follows the same contract, so a script or an assistant can read any of them the same way.

- **stdout** carries results only: one per line, or one JSON object per line with `-json`.
- **stderr** carries progress, failures as they happen (the first three of each kind), and a **summary** at the end. With `-json` every stderr line is JSON and the summary is one object with `"type":"summary"`. With `-silent` the summary is printed only when something failed or was cut short.
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

`watch` exits with the code of its run (one run, without `-every`).

A run keeps the answers it got in its workspace until nothing is left to resume, so `azhaq resume` does not ask again what the run already asked: the requests of a run stopped and resumed add up to about those of one uninterrupted run (Juice Shop: 207 against 202 with `-max-requests 50`; a 4,750-word path sweep: 4,812 against 4,801). A port scan the budget cut short scans that address again. A drop-in (`subs`, `probe`, `dirs`, …) run without `-db` uses a temporary database and cannot be resumed; `run` without `-db` writes `azhaq-TIME-PID.db` in the current directory (or `$AZHAQ_DB`).

Failures on fan-out are listed with `"fanout": true` and do not make the exit code 3: the map of what you asked about is still complete. Fan-out is what you did not ask about: a name found on the way, and the third-party lookups (subdomain sources, archives, RDAP) of a domain that is only the domain of a URL you mapped. Ask for the domain itself (`-domain`, `subs -d`, `urls -d`) and their failures count, except a source that failed while other sources answered for the same domain: it is listed with `"partial": true` and does not make the exit code 3 (sources fail all the time; an exit code that is always 3 says nothing). crt.sh is never partial: it holds the most names of any certificate log, and the others do not make up for it. `-fail-on-errors` counts every failure. A name answered SERVFAIL on every attempt, by two resolvers or more, on two passes, is not a failure: the resolvers answered alike, and the name's own DNS is broken (a lame delegation) for everyone; it is dead, with `result` `servfail`. Resolvers that time out or answer REFUSED (refusing this machine), or SERVFAIL from one resolver alone, are a failure.

## The summary

```json
{"type":"summary","command":"run","version":"0.6.0","complete":false,"exit":3,
 "results":148,"counts":{"URLs":123,"api":33,"auth":12},"seconds":7.4,"requests":195,
 "db":"app.db","run_id":"…",
 "unreachable":["http://testphp.vulnweb.com/"],
 "failed":[{"collector":"azhaq-http","error":"timeout","retryable":true,"count":34,
            "targets":["http://testphp.vulnweb.com/login.php","…"]}],
 "skipped":[{"target":"engage.tesla.com","reason":"outside the scope"}],
 "stopped":"the request budget of 500 is spent, 41 tasks known and not done","resume":"azhaq resume -db app.db",
 "notes":["…"],"next":["azhaq query -db app.db -type Hostname"]}
```

| Field | Meaning |
| --- | --- |
| `complete`, `exit` | As in the table above. |
| `results` | What the command printed on stdout: names, web services, map rows. |
| `counts` | A breakdown of the results, per command. |
| `requests` | Requests sent to targets, port connects included (not those to third-party sources). |
| `db` | The database the results are in (absent when it was temporary). |
| `unreachable` | Targets you gave that never answered. |
| `takeover` | Names another party may take over, each with `host`, `service`, `target` (the CNAME target), `evidence` and `strength`: `strong` when a hosting service's own page says nobody claimed the name ("There isn't a GitHub Pages site here.", S3's `NoSuchBucket`, Heroku's "No such app", …) or the CNAME target's domain is not registered (its ICANN domain answers NXDOMAIN; a cloud's shared suffix such as `elb.amazonaws.com` is no registry and never counts); `dangling` when the CNAME points at a name on a service where anyone may create it (Azure, Elastic Beanstalk, Fly.io) that does not resolve. Read from DNS answers (`subs -live`, `dns`, `run`) and front pages (`probe`, `run`); confirm by hand before reporting. The text summary prints each as `! takeover candidate`. |
| `failed` | Work that did not get its answer, grouped by collector, source and error, most frequent first. `retryable` is true for timeouts, dropped connections, 429 and 5xx. `source` names a third-party source (crtsh, wayback). `targets` names up to 100; `azhaq query -db FILE -failed` lists every failed target, the list to retry. |
| `skipped` | Targets and requests Azhaq chose not to touch, with the reason: outside the scope, would end the session, a scope entry a run cannot use. Chrome's requests outside the scope are refused before they leave and listed here without their query string, `outside the scope (Chrome)` (`outside the site (Chrome)` without a scope: the registrable domain or address of the pages it was pointed at), the first 100 URLs of a run; `notes` gives the number of requests when there were more. Chrome sends GET, HEAD and OPTIONS only (outside signing in): a write a page or its scripts would send (a POST, PUT, PATCH or DELETE, a beacon, a form a script posts) is refused before it leaves and listed as `a page's script would send a write`, by method and URL without its query (`POST http://127.0.0.1:3001/api/track`); its route is mapped with that method (`ops` with `source` `browser`). With `-browser-writes` pages send their writes, which change data on the target, and nothing is listed. |
| `partial` (in `failed`) | A third-party source failed while other sources answered for the same target. |
| `stopped`, `resume` | The limit that stopped the work and the command that continues it. |
| `notes` | Caps that were hit and other things worth knowing that are not failures. |
| `next` | Commands worth running next. A run without `-browser` whose target pages leave their links to their scripts (three or more `{{templates}}` in the text; or Markdown in the text, whose links are read as text, or an empty shell of a front page, with fewer than 10 routes found on its origin) gets `azhaq run -url ORIGIN/ -browser …` with the page that showed it: `(/learn/vulnerability/a1_injection and 11 more pages: Markdown its scripts turn into links; read as text here, Chrome sees the page as rendered)`. A run that found a GraphQL endpoint and did not read its schema (no `-graphql`, or its host outside the scope) gets `azhaq run -url ORIGIN/ -graphql -allow HOST …   (/graphql and /graphiql answer like GraphQL; -graphql reads the schema by introspection)`. |

## run

The map, one row per entity, best first: the target's own pages and APIs, then what it led to. `-json` prints one object per row:

```json
{"type":"URL","key":"http://127.0.0.1:3001/api/Users","scope":"target","coverage":"visited","role":"auth",
 "status":401,"title":"UnauthorizedError: No Authorization header was found","methods":["GET","POST"],
 "params":["email","password"],"proof":"status=401 …","first_seen":"2026-10-26T14:23:40Z"}
{"type":"URL","key":"http://127.0.0.1:3001/rest/2fa/verify","scope":"target","coverage":"hint","role":"api",
 "methods":["POST"],"body":["tmpToken","totpToken"],"ops":[{"method":"POST","body":["tmpToken","totpToken"],"source":"js-call"}],
 "found_in":[{"script":"http://127.0.0.1:3001/main.js","line":6472,"col":88,
              "snippet":"this.http.post(`${F$.hostServer}/rest/2fa/verify`,{tmpToken:localStorage.getItem(`totp_tmp_token`),totpToken:t})"}]}
{"type":"URL","key":"http://127.0.0.1:3001/#/administration","scope":"target","coverage":"hint","role":"client-route",
 "guard":"canActivate","proof":"guard=canActivate","found_in":[{"script":"http://127.0.0.1:3001/main.js","line":6622,"col":727,
 "snippet":"…AboutComponent});var pN=[{path:`administration`,component:Su,canActivate:[cs]},{path:`accounting`,"}]}
{"type":"URL","key":"ws://127.0.0.1:3001/socket.io","scope":"target","coverage":"hint","role":"websocket","protocol":"socket.io"}
```

| Field | Values |
| --- | --- |
| `type` | `URL`, `Hostname`, `Domain`, `IPAddress`, `Organization`, … |
| `scope` | `target`: what you asked about. `fanout`: found on the way (other hosts, CNAME targets). |
| `coverage` (URLs) | `visited`: fetched and answered as a page of its own. `catchall`: answered with the page every unknown path gets (a single-page app's shell). `error`: requested, no answer. `gone`: answered 404 or 410 (found in an archive or a link, not there now). `hint`: found (in a script, an API description, an archive) but not requested, or called by scripts only with POST or PUT, or written to only by a page in Chrome (a GET that answers 404, 405 or the catch-all page says nothing about such a route), or named only in scripts with no GET call among them while a GET answers 404 (`proof` says `GET answers 404; found only in scripts, method unknown`). `skipped`: found (by a link, a script's call, an API description or an archive), not requested because its name says a GET would change something; `word` names the verb, and the summary lists it under `skipped` (`left alone`). `capped`: left when a limit was hit. A version prefix alone that only a script's strings name (`/v3`) is left out of the map when it answers 404 or the catch-all page. |
| `role` (URLs) | `app` (a front page), `auth` (401), `forbidden` (403), `api`, `page`, `script`, `asset`, `sourcemap`, `manifest` (a bundler's build manifest: Vite's `.vite/manifest.json`, Create React App's `asset-manifest.json`, Angular's `ngsw.json`, Nuxt's build meta), `client-route` and `websocket` (below). |
| `client-route` | A view a single-page app's router draws, read from its route table (Angular's `RouterModule`, React Router's `<Route>` and `createBrowserRouter`, Vue Router): `http://host/#/administration` for an app that routes by the hash, else its path (`http://host/admin`), parameters as `{name}`, nested routes joined to their parents'. Never requested: the server answers every view with the app's shell. `guard` is what the router checks before it draws the view, a parent's guard holding for its children: Angular's `canActivate`, `canMatch`, `canLoad` or `canActivateChild` (with the guard's name when the build keeps it, `canLoad AdminGuard`), Vue's `meta.requiresAuth` (or another meta key about sessions or roles) or `beforeEnter`, a React wrapper such as `RequireAuth` or `PrivateRoute`. A string in a script that names a view (a router link, `router.navigate(['/order-completion', id])`) is that view's, listed in its `found_in`, not a page of its own. With `-browser`, Chrome does not open the views. |
| `websocket` | A WebSocket endpoint a script opens (`new WebSocket(…)`, `SockJS`, a `ws://` or `wss://` URL, a socket.io client's `io(url, {path})`), as `ws://` or `wss://` (the page's scheme when the script builds the URL from `location.host`). Never requested. `protocol` is `socket.io` for a socket.io endpoint, whose `namespace` (`/chat`) is given when the app's call names one; the library's default path, `/socket.io`, stands when the app's call cannot be read. Third parties' sockets (chat widgets, analytics) are left out. |
| `role` (names) | `live` (resolves; a host you gave, or a name under a domain you gave), `sibling` (resolves; found on the way, under another domain), `unresolved` (from a source or a list, not looked up), `dead`, `wildcard`. |
| `ops` | each operation on the route: `method`, `query`, `path`, `header`, `body` (field names), `body_type`, `auth` (the description asks for credentials), `summary`, `operation_id`, `source` (`js-call`, `openapi`, `graphql`; `browser`: a write a page in Chrome sent or was refused, with the names its query and body carried, never their values). |
| `body` | the body field names of all its operations, whatever described them: a script's call, an API description (served or found), a GraphQL schema (argument names), a request taken in from katana. |
| `status`, `title` | The URL's own answer (the first hop of a redirect). Without a scope, a redirect is followed only within the site (same registrable domain or address); with one, only inside it. Chrome is held to the same rule for everything a page asks for. |
| `methods`, `params` | From API descriptions and call sites in scripts; `params` also holds the names in the URL's own query string. The query names of the links on a page are on the links' rows, not the page's. |
| `forms` | `{"method","action","enctype","fields","files"}` for each form on the page. A form whose action is empty or `#` submits to the page itself: `action` is the page's URL with its query. `enctype` is a POST form's encoding (`application/x-www-form-urlencoded`, `multipart/form-data` or `text/plain`), `files` the fields that are file inputs. |
| `found_in` | Where scripts name the route, up to three places, calls first (for a route on another host than the page whose script named it, the script on that host, which is also what links to it in `show`): `script` (its URL; the page's for a script inside the page, with `inline` true and the page's line numbers), `line` and `col` (bytes, from 1), `snippet` (up to 120 bytes: the call as written, or the string with the code around it; credentials in it, such as JSON Web Tokens, bearer tokens, secrets set to a literal or in a query string and long keys, read `[redacted]`), and `source`, the original file, when the route was read from a source map's sources (`line` and `col` are then that file's). |
| `watch` | Parameter and body names worth trying first, by what their name says they take: `returnUrl (redirect)`, `url (url)`, `file (file)`, `cmd (command)`, `isAdmin (debug)`, `userId (id)`, `callback (callback)`. The text map prints them on a `watch:` line under the row. |
| `template`, `count` | Pages that differ only by an ID are folded: `/product?id={n}` with the number of URLs folded. A query value that names a page (`index.jsp?content=about.htm`, `view=grid`) is not an ID: each is a page of its own. Three URLs of a template are requested (`-per-template N` changes it). |

A GraphQL endpoint whose schema was read with `-graphql` has one op per query, mutation and subscription: `method` `POST`, `summary` its signature (`mutation login(username: String, password: String): Login`), `operation_id` the field name, `body` the argument names, `source` `graphql`.

A run's summary counts `client routes` and `websockets` apart from `URLs`. The text map lists them after the routes of the server with the same rank, with `guard=…`, `protocol=…` and `namespace=…` as their proof.

The text map prints the same rows, one per line, with forms and parameters indented below, and a GraphQL endpoint's operations by their signatures (the first 50; the rest are in `-json` and the exports). `azhaq show URL` prints where scripts name it under `found in`, one place per line as `script:line:col  snippet`:

```
found in
  http://127.0.0.1:3001/main.js:6472:88  this.http.post(`${F$.hostServer}/rest/2fa/verify`,{tmpToken:localStorage.getItem(`totp_tmp_token`),totpToken:t})
```

## Drop-in commands

Their `-json` output uses the field names of the tool they stand in for, so existing `jq` filters keep working.

| Command | Fields |
| --- | --- |
| `subs` | `host`, `input` (the domain), `source` (the first source that gave the name), `sources` (all of them; `dns-brute` or `permute` for a name found by `-w` or `-permute`); with `-live`, dnsx's `a` and `aaaa` (the addresses), `cname` (the chain) and `cdn` (the CDN or WAF in front). Takeover candidates are in the summary (`takeover`). |
| `dns` | `host`, `a`, `aaaa`, `cname`, `status_code`, `cdn_name`. |
| `probe` | httpx's: `url`, `input` (the target as given), `host` (the name), `host_ip` (the address the request connected to), `a` and `aaaa` (the addresses the name resolved to; `host_ip` is one of them), `port`, `scheme`, `path`, `method`, `status_code` (the first answer: a redirect stays 302, as httpx prints it), `title`, `webserver`, `content_type`, `tech`, `content_length`, `words`, `lines`, `time`, `favicon` (with `-favicon`), `cdn`, `cdn_name`, `cdn_type`, `final_url` and `final_status_code` (where a redirect inside the scope, or without one inside the site, ended; title and tech describe that page), `chain_status_codes`, `location`, `timestamp`. Empty fields are left out, as httpx does. Every target given ends as a row, a failure or a skip: a name that resolved and got neither an answer nor a recorded failure is listed as failed, `no answer and no failure recorded`. |
| `crawl` | `url` and the map row's fields (`coverage`, `role`, `status`, `methods`, `params`, `forms`, `found_in`, and for a view or a socket `guard`, `protocol`, `namespace`). Views (`client-route`) and sockets (`websocket`) are listed with `-json` only, as routes with a parameter are: no GET gets them. |
| `urls` | `url`. |
| `ports` | naabu's: `host`, `ip`, `port`, `protocol`, `tls`, `timestamp`, plus `service` and `banner`, and for a TLS port the certificate's `subject_cn` and `subject_an` (httpx's names). A service that speaks first (`ssh`, `ftp`, `smtp`, …) is named from what it says. One that waits is asked once: `HEAD / HTTP/1.0` on the open connection (an HTTP answer is `http`, its banner the `Server` header or the status line), and without one, or with a 400, a TLS handshake on a second connection, counted like a connect (`tls`; `https` when HTTP answers inside it, `tls` true). A name ending in `?` is only the port's usual service. Raw printing ports (9100–9107) are never asked anything. A second name on the same address has its web and TLS ports asked again under its own name. One row per address: a name's IPv4 and IPv6 addresses are both scanned, IPv6 where this machine can reach it; where it cannot, the summary's notes say so (`IPv6 addresses of 1 name not scanned: no IPv6 route from this machine`). A port that neither accepts nor refuses a connect (a timeout, an ICMP unreachable) is asked once more after the others, when such ports are at most 64 or a tenth of the scan (a loaded or lossy host drops a connect now and then; a firewall that drops nearly everything would only double the scan). A service on a port that usually speaks first (22, 21, 25, 3306, …) is given a second wait for its greeting before it is asked anything. In `run` and `query`, a scanned address's `ports` row counts these silent ports in `filtered`, and lists them in `filtered_ports` when there are no more than 64; the summary names them (`ports that neither accepted nor refused a connect, asked twice: scanme.nmap.org (45.33.32.156) port 80; …`), since an open port may hide among them. |
| `dirs` | `url`, `status`, `length` (the whole body, as ffuf; up to 64 MB), `words`, `lines` (from the first MB), `redirectlocation`. |
| `params` | `url`, `method`, `params`, and `why` (what changed in the answer for each name: `status`, `size`, or `reflected`, its value came back more often than random names' values do). A page that answers names it does not read (most names of a group, or nearly every name tried alone, change its answer, and so do as many random names made like them) is listed in the summary's `notes`; the names of that group are dropped and the search stops there, names found in earlier groups stay. |
| `asn` | `as_number`, `as_name`, `prefix`. |
| `shots` | `url`, `file`, `title`, `final_url`, `phash`. |

`probe`, `dns`, `ports`, `dirs`, `params` and `shots` print each result as it is found. `run` prints its ranked map at the end; with `-stream` it also prints, as they are found and once each, the names that resolve, the URLs found, the answers (`found  answer http://app/openapi.json  [200]`) and the open ports, before the map (with `-json`, objects with `"type":"found"`, `kind` (`name`, `url`, `answer`, `ports`), `key` (the name, the URL, or the host), `collector`, and for an answer its `status` and `title`, for ports the `ip` and the `open` list).

## roles

One row per endpoint whose answer depends on the session (`-all`: every endpoint compared), and with `-replay-writes`, one per write asked (its `method` set):

```json
{"url":"http://localhost:5000/books/v1/aliceBook","verdict":"reads another role's object",
 "template":"http://localhost:5000/books/v1/{book_title}","found_by":["alice"],"owner":"alice",
 "owner_by":"item of /books/v1: user alice names alice (sub claim of alice's token); the answer's owner alice names alice (sub claim of alice's token)",
 "readers":["bob","admin"],"sensitive":["secret"],"status":{"anon":401,"alice":200,"bob":200,"admin":200},
 "answers":{"anon":{"status":401,"length":95,"hash":"…","error":true},
            "alice":{"status":200,"length":79,"hash":"9f…","keys":["book_title","owner","secret"],"sensitive":["secret"]},"bob":{…},"admin":{…}}}
```

| Field | Meaning |
| --- | --- |
| `status` | Each role's status; 0 for a role that was never asked. |
| `answers` | Each role's answer: `status`, `length`, `hash` of the body, `keys` (a JSON answer's field paths, nested: `data.user.email`, `data[].id`), `error` (a JSON answer shaped like an error, such as `{"status":"error"}`), `sensitive` (its fields that hold passwords, secrets, keys, tokens, card numbers), `location` (where a redirect sends the role). Every answer is compared by its body: one the run kept without it (a URL the `-paths` list found keeps its status only) is asked again, with the role's session. |
| `found_by` | The roles whose own runs reached the URL, or, for an object URL, whose answers held its identifier. |
| `template` | The route an object URL fills: its path parameters filled with identifiers the roles' answers held, or given with `-id`. |
| `owner` | The role whose own object it is: given with `-id ROLE:…`; known from who the role is (see below); or an identifier only that role's answers held (in the route's own list, such as `/api/Addresss` for `/api/Addresss/{id}`, while the same list read by another role did not; or in a field named after the parameter, and nowhere in the other roles' answers). What the object's own answer says of its owner confirms, names or undoes it, as far as what filled the route allows (see below). |
| `owner_by` | What says the object is the owner's, to check in one look: `bid claim of alice's token → /rest/basket/{id}` (an identifier the role's session holds, where it was read, and the route it fills), `authentication.bid in alice's login answer → /rest/basket/{id}`, `item of /books/v1: user alice names alice (sub claim of alice's token)` (a list item whose own fields name the role), `in alice's /api/Addresss and not the other roles'`, `in alice's answers alone`, `given with -id alice:book_title=My book`, and, after `; `, what the object's answer says: `the answer's UserId 27 names alice (data.id claim of alice's token)`, `the answer's BasketId 8 is alice's basket (bid claim of alice's token)`. The text table prints it after the route of a `reads another role's object` row, without the route and where each value was read (`· alice's by bid claim of alice's token; the answer's UserId 27 names alice`). |
| `readers` | For the verdicts that say who reads it: those roles. |
| `sensitive` | For the verdicts about sensitive fields, and on object rows: the fields. |

A role reads an endpoint when it gets a 2xx answer that is not an error. A refusal is any 4xx, an error answered with a 2xx status, a redirect to a sign-in page (a path such as `/login`, `/users/sign_in`, `/auth/…`, another site's sign-in service, or the `-login` page), and a redirect to the site's front page while another role reads the endpoint: on a cookie-session app, the visitor sent to `/login` makes a page `signed-in only`. Verdicts, worst first, as `-json` gives them (the text table names the roles and fields, as in brackets):

| Verdict | Meaning |
| --- | --- |
| `anyone reads sensitive fields` | The anonymous role reads passwords, secrets, keys or card numbers, at any depth of the JSON, or a token another session reads too, even when every role gets the same answer (`[anyone reads sensitive fields: password]`). |
| `reads another role's object` | A role reads the owner's object as the owner does (the same body, or the same fields around the same identifier) (`[bob, admin read alice's object]`). An owner inferred from the answers whose object the anonymous role reads alike is public instead. |
| `every signed-in role reads the same object` | An object URL every signed-in role reads alike, owner unknown. |
| `roles read the same sensitive fields` | Several roles read the same values of sensitive fields: no session's own (`[alice, bob read the same sensitive fields: deluxeToken]`). A token only its own session gets is not listed. |
| `same answer for a session that did not find it` | A role that never reached the URL gets the answer the role that found it got. |
| `signed-in only` | The anonymous role is refused, every signed-in role reads it. |
| `only one role reads it` | Every other role is refused (`[only admin reads it]`). |
| `some roles refused` | Some signed-in roles read it, others are refused. |
| `different fields per role` | Every role reads it with the same status, with different nested fields. Fields under a list one role has empty are data, not fields; so is a field of a list's items that only holds true or false (`data[].liked`) and only one role gets. |
| `anyone reads the same object, signed in or not` | An object URL the anonymous role reads as the others do. Listed once per route (`-all`: every object). |
| `status differs` | Anything else (other redirects, 5xx). |

With `-all` also: `different data per role`, `same for every role`, `no role reads it`, `not answered`. The summary counts the verdicts of the rows listed; a note counts the endpoints compared and not listed (`58 more endpoints compared and not listed (34 same for every role, 23 no role reads it, 1 different data per role); -all lists them`).

Who each signed-in role is tells its own objects apart without `-id`: the claims of a JSON Web Token its headers or cookies carry (`sub`, `id`, `email`, `username`, `data.id`, …, and identifiers such as Juice Shop's `bid`), its own answer to a `/me`-like endpoint (`/me`, `/whoami`, `/userinfo`, …) when the anonymous role gets another, and, for `-role-login`, what the login answered and left in `localStorage` and `sessionStorage`. Each role's own objects are asked of every other role.

An identifier is a role's own only for objects of its kind, told by the route's noun (the path segment before the parameter), singular or plural, in any case. One the role's session holds fills a route when its name is that noun's: `basketId` and `basket_id` fill `/rest/basket/{id}`, `userId`, `uid` and the `id` of the user object in a token or a `/me` answer fill `/api/Users/{id}`. A short name, the initials of the noun's words (`bid`), fills it only when no other noun has those initials: not that of another route (`/api/books/{id}` beside `/rest/basket/{id}`: `bid` is neither's, and the session's value is tried on both as no one's object) nor that of a reference field the answers hold (`BrandId`). `bid` does not fill `/api/BasketItems/{id}` (`biid`), nor `/api/basketitems/{id}` beside a `basket` route. A short name alone is a guess: the object is the role's only if its own answer says so (see below). A list item whose own fields name a role is that role's object: an owner field (`owner`, `user`, `username`, `userId`, `email`, `createdBy`, …) that names the role, or a reference field that points at an object the role's session names. A reference field names its kind in full: `BasketId` 8 is alice's basket when her session holds basket 8 as `basketId`, or as `bid` while `bid` stands for the basket route alone; `BookId` 8 is not. An account, a customer or a member is not the user: `accountId`, `customerId` and `memberId` are reference fields, matched against the session's own `accountId`, `customerId` or `memberId`, never against its user id. Its identifier is the field the route's parameter maps to (`book_title` for `/books/v1/{book_title}`) or, in the route's own list or a list of the same noun, its `id`. An item of another kind lends its owner only to the object its owner or reference field points at (the `UserId` of an address fills `/api/Users/{id}`), not to the others it names (the `ProductId` of alice's basket item is not alice's product).

Once every role has asked an object, its own answer has its say on whose it is (the answer, or the object its envelope carries, such as `data`; the answers of every role that reads it must agree). An owner or reference field that names the owner confirms it; one that names a role makes an object no one owned that role's. Past that, it depends on what filled the route. An owner a short name alone gave (`bid`) goes unless the answer names that role, and goes to the role it names instead. An owner a list item or a field in the role's answers alone gave goes to the role the answer names, and goes altogether when a field's value is not that role's while its session holds one of the same kind and shape (a user id, an email, a basket id): `/api/BasketItems/8` with `BasketId` 5 is not alice's, though her `bid` is 8. An owner proved by an identifier the session holds under the route's full name (`basketId`, a user id) or by the role's own list (`/api/transactions` holds alice's transaction alone) stays, whatever another field says: alice's project in her other organisation is still hers, and an `accountId` equal to bob's user id does not make it bob's. Only a field that names another role by an identifier that role's session holds under the same name (its `email`, its user id as `UserId`) hands it to that role. A name is spelled too many ways to say an object is not the role's. An object given with `-id ROLE:…` stays that role's.

`-id [ROLE:]NAME=VALUE` (repeatable) fills routes with an identifier of your own: NAME is a path parameter (`book_title`), a JSON field that holds such values (`basket_id` and `BasketId` fill `/rest/basket/{id}`), or a route (`/rest/basket/{id}`). With ROLE, VALUE names that role's own object, so another role reading it is `reads another role's object`; without, it is tried like an identifier the answers held. Each route is also filled with up to 5 of each role's own identifiers (those who the role is names first) and 6 others, in order (numbers by value); the replay asks objects given with `-id` first, then the roles' own objects, then what the runs reached, then other objects, and takes a URL only while `-replay-max` holds every role's request for it.

A signed-in role whose session looks expired or wrong is named in a note, with what the site says when that role asks one such endpoint again: `role x was refused wherever a session matters (the site said "Signature expired. Please log in again."): its session looks expired or wrong; its rows show what a visitor gets`, and roles exits 3. It was refused on every endpoint the anonymous role is refused and another signed-in role reads, or on every endpoint another role reads, and it read no `/me`-like endpoint unlike the anonymous role. When no signed-in role reads anything the anonymous role is refused, as when tokens copied at the same time expire together, each is judged alone: refused on every endpoint the anonymous role is refused, and given nothing more than the anonymous role anywhere (a role that read an endpoint the anonymous role did not, or was forbidden, 403, where the anonymous role was asked to sign in, 401, is known to the site and alive). Every value the role sent (its headers, cookie values, the credential after `Bearer` or `Basic`) and anything shaped like a credential is taken out of the quoted reason.

A JSON Web Token a role sends as its credential (in `Authorization`, or a header or cookie named for one: `X-Auth-Token`, `token`, `jwt`, `session`, …; not an analytics cookie) is read for its `exp` before anything is sent. One that has expired is said at once on stderr, and the end of the run says what came of it: a dead session (`its token expired at …`), a site that still took it when it was the role's only credential (`role alice's token expired at …, yet the site still let it read 3 endpoints the anonymous role is refused: check that it verifies token expiry`, a finding), or, with nothing to tell, a note and exit 3. A token that expires within 15 minutes is noted too. For tokens that live minutes, `-role-cmd 'alice=./token.sh alice'` gives a role whose headers a shell command prints, one `Header: value` per line, or a bare token sent as `Authorization: Bearer`; the command runs before the role's run and again before the replay. `-role-cmd` is not offered over MCP.

A role given with `-role` sends those headers and nothing else, so behaviour an app ties to a cookie is not reached with a header alone: Juice Shop's `/rest/user/whoami` reads the `token` cookie, and answers `{"user":{}}` to an `Authorization` header. Give the cookie as one of the role's headers (`-role 'alice=Cookie: token=eyJ…'`, what `-cookie` sends in a run), or use `-role-login`, which carries the cookies and the token the login stored.

With `-json`, stderr holds the summary only: the runs of the roles print nothing, and what they did not finish is in it (`failed`, `unreachable`, `skipped`, `notes`; a role's run stopped by a limit is `stopped`, exit 4). A role whose run could not be done (a failed sign-in) ends roles with a summary whose `notes` say why.


### Writes (`-replay-writes`)

`-replay-writes METHODS` (`post`, `put`, `patch`, `delete`, comma-separated) also asks each role's writes with every other role's session, after the reads. It needs `-allow` or `-scope` in the run options: writes change data on the target. The writes are:

- the ones a role sent, from a HAR (`-har NAME=FILE`, as a browser's developer tools or Burp save it): its requests with those methods on the run's hosts, one each, with their bodies and `Content-Type`, `Accept` and `X-Requested-With`, never the session that sent them (cookies, `Authorization`, a CSRF token); a logout is never replayed;
- the PUT, PATCH and DELETE that the routes the runs found take (from API descriptions and scripts), on each role's own objects (the same as the read replay's): PUT and PATCH with an empty JSON object, which asks for the write and changes nothing, DELETE with no body. A route whose write takes a form, and a POST to an object, are left to the HAR.

A map write is first sent with its owner's session; when the owner is let, its object is read again, and if a value it held changed (timestamps aside) nobody else is asked (`the owner's own write was refused` or a note in `owner_by`). Then the anonymous roles, then the other signed-in roles. A DELETE goes to the others alone, the anonymous role first, and stops at the first that is let; its owner is then asked for the object (`afterwards its owner got 404 for it`). A write is let when it is answered 2xx and not with an error shaped as data. Every write counts against `-replay-max` (what the read replay left) and the run's `-max-requests`, at the run's `-rate`, and is sent without following a redirect.

| Verdict | Listed | Meaning |
| --- | --- | --- |
| `anyone writes another role's object` | yes | the anonymous role was let |
| `writes another role's object` | yes | a signed-in role other than the owner was let (`readers`) |
| `would be sent (-dry-writes)` | yes | `-dry-writes`: nothing was sent |
| `only its owner writes it` | `-all` | the others were refused |
| `the owner's own write was refused` | `-all` | the owner was not let, or its empty write changed its object: nothing to compare |

The row's `owner_by` says where the write came from (`alice.har`, `PUT /api/BasketItems/{id} with an empty body`).

## diff

A web page's answer is compared by status and title, and a JSON listing's also by how many items it holds (`json_items`): `watch` reports `/users/v1: [200] 5 items → [200] 6 items`. Bodies are not compared byte for byte: timestamps and tokens would make every run a change. A workspace with one run says so: a diff needs two.

`diff -jsonl` prints `added` and `removed` rows, `not_seen_again` rows and a `summary`. `removed` is what answered in the older run (a name that resolved, a page with a status, a host with open ports) and is gone from the newer. `not_seen_again` is what the older run only heard of (from a subdomain source, an archive, a link) and never checked: sources answer differently from day to day and fail, so its absence says little. The summary names the `failed_sources` of the newer run.

## query, show, plan, ingest

- `query -json` prints map rows (as `run -json`, with `found_in`), or only the `-fields` asked for; every row that matches, unless `-limit` says otherwise (the summary then says how many matched). `query -failed` prints every failed target instead: `target`, `collector`, `source`, `error`, `retryable`.
- `show -json` prints one object: `row` (the map row, with `found_in`), `links` (`rel`, `dir` in or out, `type`, `key`) and `observations` (`collector`, `kind`, `source`, `observed_at`, `payload`; an `azhaq-js` observation's payload holds the `found_in` of the page it read); for a hostname, `services`: its front pages with `coverage`, `status`, `title`, and the `error` of one that failed. A GraphQL endpoint read with `-graphql` has an `azhaq-graphql-schema` observation whose payload holds `queries`, `mutations`, `subscriptions` and `types` (names) and `schema`, the introspection's whole `__schema` object (past 8 MB without its descriptions; past that left out, with its size in `schema_bytes`). A server that refuses the full introspection query for its depth is asked for the names only, and `schema` is absent. A server with introspection turned off is asked for root fields by name, as clairvoyance does: its validation errors (`Cannot query field "pastez" on type "Query". Did you mean "pastes"?`, `Field "paste" of type "PasteObject" must have a sub selection`, required arguments) give the payload `queries`, `mutations`, `types` and `signatures` (`uploadPaste(content: String!, filename: String!): UploadPaste`), with `"recovered":"suggestions"`. Every document asked carries a field no schema has, so none passes validation and nothing runs. A GraphQL endpoint found by a run (an `azhaq-graphql` observation) has `get_queries` true when it answers `{__typename}` sent with GET.
- `plan -json` prints one object: `targets` (each with the collectors that would run on it), `skipped`, `collectors` (what each does to whom), `active`, `builtin_paths`, `limits`, `sends`, and `requests`: what is known of the requests before any is sent. `source_queries` counts, per collector, the queries to third-party sources about the targets listed (one per source asked; a source may page through its answer), `source_queries_total` adds them up, and `source_queries_not_counted` names the collectors that do not say before they run which sources they ask (none of the built-in ones; a connector may not). `found_domains_asked` is true when domains found on the way would be asked about too (inside the scope; without one, within `-depth` and `-max-items`). The requests to the targets are a bound, not a count: how many names resolve and answer is known only by asking (`max_names` of them at most are looked up). `per_web_service` is about what each web service costs before its links, scripts and archived URLs are followed (its page, the favicon, the built-in paths), and `cap` the requests to the targets at most, set by `cap_by` (`-max-requests`, or `-daily-requests`, of which a plan does not take off what the day's runs spent); 0 is no cap. `passive` is true when nothing goes to the targets.
- `ingest` prints only its summary: `results` is the facts read, `counts` the lines read per format.

## export

`azhaq export -db FILE -format F` writes the newest run of a workspace in one format on stdout.

| Format | Output |
| --- | --- |
| `jsonl` | Everything: one object per map row (`"kind":"entity"`), observation and edge. |
| `urls`, `hosts`, `names`, `targets` | One per line: every URL; names that resolve; every name; web services (front pages that answered, Azhaq's or taken in from httpx, katana or ffuf), for `nuclei -l` and `httpx`. |
| `openapi` | OpenAPI 3 JSON of one origin (`-origin`, default the one with the most API routes): the description the target serves, as it is, plus the routes scripts call, forms, the pages found with a query string of their own (a GET taking those names) and what answered. A route the run left alone (`skipped`) has no GET or HEAD in it: a tool importing the description would send one. A GET form's fields are query parameters of its action's GET; a POST form's are its request body, `application/x-www-form-urlencoded` or `multipart/form-data` as its `enctype` says, a file input `"format":"binary"`. A form adds the fields an operation the export made lacks; a served description's operations are left as they are. `x-azhaq` on each operation: `source`, `coverage`, `status`, `needs_credentials`. |
| `graphql` | The introspection result of each GraphQL endpoint read with `-graphql`, as InQL, Burp, Postman, graphql-voyager and clairvoyance read it. |
| `sdl` | The same schemas in the GraphQL schema language. |
| `burp` | Burp Suite project options with the run's target scope. |
| `html` | One self-contained page: web services, names, screenshots, secrets, API routes, the map. |
| `graphml` | The graph for Gephi, yEd or Cytoscape. |
| `secrets` | Credentials found in scripts: severity, kind, value, script, tab-separated. |

**openapi** is a valid OpenAPI document whatever went into it: every operationId is unique (a served description's keep theirs; a repeat, such as `/blog` and `/blog/` both `get_blog`, gets `_2`, `_3` in path order), templates that differ only by their parameter names are one path (the served description's, else the first), every `{name}` in a path is a declared path parameter, a parameter is listed once, and component names OpenAPI does not allow are renamed with their references. A GraphQL endpoint is one `POST` taking `{"query","operationName","variables"}`, not a made-up REST mapping; its operations are in `x-azhaq-graphql`: An API route left alone for its name (`/user/change-email`) whose callers do not say the method is described as a POST, with `x-azhaq.method` saying it is a guess; never as a GET.

```json
"x-azhaq-graphql":{"operations":[
  {"type":"query","name":"pastes","arguments":[{"name":"public","type":"Boolean"},{"name":"limit","type":"Int"}],"returns":"[PasteObject]"},
  {"type":"mutation","name":"createPaste","arguments":[{"name":"burn","type":"Boolean","default":"false"}],"returns":"CreatePaste"}]}
```

`type` is `query`, `mutation` or `subscription`; `default` is a GraphQL literal; `deprecated` is set on deprecated fields. A schema kept by names only gives `type` and `name`.

**graphql** prints `{"data":{"__schema":{…}}}`, the server's answer to the standard introspection query. With several endpoints it prints one object keyed by endpoint URL, `{"https://app/graphql":{"data":{"__schema":…}},…}`; `-origin` keeps the endpoints of one origin, or the one at a URL (`-origin https://app/graphql`), to get a file a tool loads as it is. **sdl** prints each endpoint's schema under a `# URL` comment: types, interfaces, unions, enums, input objects, custom scalars and directives with descriptions, defaults and `@deprecated`, without the built-in scalars and directives; a `schema { … }` block when the root types are not simply `Query`, `Mutation` and `Subscription`. Concatenated schemas of several endpoints are not one schema: pick one with `-origin`.

**burp** writes `{"target":{"scope":{"advanced_mode":true,"include":[…],"exclude":[…]}}}`. When the run had a scope, `include` holds its allow rules (`-scope` and `-allow`) and `exclude` its deny rules (the program's out-of-scope entries and `-deny`), each for any protocol, port and path: a domain is `{"enabled":true,"protocol":"any","host":"^(.*\\.)?example\\.com$"}` (it and its subdomains), one host `^api\\.example\\.com$`, an address `^192\\.0\\.2\\.7$`, a range as Burp takes it (`10.0.0.0/24`). The scope is read back from the run's options: a scope file again (stored by its full path), and a platform's program (`-scope hackerone -program x`) as it stands now, from bounty-targets-data. A run without allow rules, or whose scope file is gone (a note on stderr says so), includes every web service it found: `{"enabled":true,"protocol":"https","host":"^app\\.example\\.com$","port":"^443$","file":"^/.*"}`. `azhaq run -scope` reads the file back.
