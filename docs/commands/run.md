# azhaq run

Map a target: names, services, pages, scripts, APIs, forms, parameters, in one graph.

## Synopsis

```
azhaq run (-url URL | -domain D | -list FILE | -scope FILE|PLATFORM -program P | -asn AS | -cidr NET | -in seeds.jsonl) [flags]
```

## Examples

```
# Map one app into a workspace
azhaq run -url https://app.example.com/ -db app.db

# Map a program's scope, capped and paced
azhaq run -scope hackerone -program security -db h1.db -max-requests 5000 -rate 5

# Names only: nothing is sent to the targets
azhaq run -domain example.com -passive -json > map.jsonl

# Sign in with Chrome first, then map as that user
azhaq run -url https://app.example.com/ -browser -login https://app.example.com/login -login-user me@x.test -login-pass '…'
```

## What it does

1. Takes your seeds: a URL, a domain, a list, a program's scope, an AS number, an address range, or a seeds file.
2. Resolves names, probes web services, crawls pages and scripts, and reads API descriptions.
3. Follows what it finds in waves, as far as `-depth` allows.
4. Asks each web service for the built-in paths unless `-no-paths` says not to ([Path checks](#path-checks-stop-at-their-answer)).
5. Lists, but does not request, URLs whose names say a GET would change something. They get the coverage `skipped`.
6. Sends nothing to a host outside the scope, Chrome's requests included. `-passive` sends nothing to the targets at all.
7. Prints the ranked map when it ends and the summary on stderr.

[What azhaq sends](../CONCEPTS.md#what-azhaq-sends) lists every request by kind. `azhaq plan` prints what a run would do and send before anything goes out.

## Output

The map has one row per entity, best first: the target's own pages and APIs, then what they led to. The summary goes to stderr.

- Plain: one row per line, with forms and parameters indented below ([The text map](#the-text-map)).
- `-json`: one JSON object per row, and the summary as one JSON object on stderr.
- `-quiet`: no map and no progress lines, only the summary.
- `-stream`: also prints each name, service, URL and open port as it is found, before the map ([Streaming found lines](#streaming-found-lines)).

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

| Field | Meaning |
| --- | --- |
| `type` | `URL`, `Hostname`, `Domain`, `IPAddress`, `Organization`, … |
| `key` | The URL, name or address. |
| `scope` | `target`: what you asked about. `fanout`: found on the way (other hosts, CNAME targets). |
| `coverage` (URLs) | What azhaq did with the URL: `visited`, `catchall`, `error`, `gone`, `hint`, `skipped` or `capped`. See [Coverage](#coverage). |
| `evidence` (URLs) | How azhaq knows the row: the strongest level of its sources, from `answered` to `given`. See [Evidence](#evidence). |
| `evidence_from` | The collectors behind the evidence, sorted. |
| `answer` (URLs) | Set when the status says less than it looks, such as `500 without input`. See [Evidence](#evidence). |
| `role` (URLs) | What the URL is: `app` (a front page), `auth` (401), `forbidden` (403), `api`, `page`, `script`, `asset`, `sourcemap`, `manifest`, `client-route`, `websocket`. |
| `role` (names) | The status of a name: `live`, `sibling`, `unresolved`, `dead` or `wildcard`. [CONCEPTS](../CONCEPTS.md#names) defines them. |
| `proof` | Why the row is as it is, in one line: `status=401 …`, `guard=canActivate`. |
| `first_seen` | When the workspace first saw the entity. |
| `guard` | What a client route's router checks before it draws the view. See [Client routes](#client-routes). |
| `protocol`, `namespace` | `protocol` is `socket.io` for a socket.io endpoint; `namespace` is its namespace, when the app names one. See [WebSockets](#websockets). |
| `status`, `title` | The URL's own answer: the first hop of a redirect. See [Redirects](#redirects). |
| `methods`, `params` | From API descriptions and call sites in scripts. See [Methods and parameters](#methods-and-parameters). |
| `ops` | Each operation on the route: `method`, `query`, `path`, `header`, `body`, `body_type`, `auth`, `summary`, `operation_id`, `source`. See [Operations](#operations). |
| `body` | The body field names of all the route's operations, whatever described them. See [Operations](#operations). |
| `forms` | One object per form on the page: `method`, `action`, `enctype`, `fields`, `files`. See [Forms](#forms). |
| `found_in` | Up to three places where scripts name the route, calls first. See [found_in](#found_in). |
| `watch` | Names worth trying first, by what each says it takes: `returnUrl (redirect)`, `url (url)`, `file (file)`, `cmd (command)`, `isAdmin (debug)`, `userId (id)`, `callback (callback)`. |
| `template`, `count`, `not_asked` | A page that differs only by an ID is folded: its `{n}` template, how many URLs it holds, how many were not requested. See [Templates](#templates). |

## Summary and exit codes

The summary and the exit codes are the shared ones: see [OUTPUT.md](../OUTPUT.md#exit-codes). Two things are specific to `run`:

- The summary counts `client routes` and `websockets` apart from `URLs`.
- It counts the path checks it skipped, as a note ([Path checks](#path-checks-stop-at-their-answer)).

## Details

### The text map

- Rows are the JSON rows, one per line, best first. Forms and parameters are indented below the row.
- A GraphQL endpoint's operations are listed by their signatures: the first 50. The rest are in `-json` and the exports.
- A row that is not `answered` ends with its evidence: `[browser]`, `[described]`, `[called]`, `[linked]`, `[archived]`, `[guessed]` or `[given]`.
- A row that has an `answer` shows `500 without input` after its proof.
- Parameter and body names worth trying first are on a `watch:` line under the row.
- A folded template shows its count: `(30 urls, 27 not asked)`.
- Client routes and websockets come after the server's routes of the same rank. Their proof is `guard=…`, `protocol=…` and `namespace=…`.
- `azhaq show URL` prints where scripts name a route, under `found in`, one place per line as `script:line:col  snippet`:

```
found in
  http://127.0.0.1:3001/main.js:6472:88  this.http.post(`${F$.hostServer}/rest/2fa/verify`,{tmpToken:localStorage.getItem(`totp_tmp_token`),totpToken:t})
```

### Streaming found lines

- With `-stream`, `run` prints each name that resolves, URL found, answer and open port as it is found, once each. They come before the map.
- An answer line looks like `found  answer http://app/openapi.json  [200]`.
- With `-json`, each is an object with `"type":"found"` and these fields:

| Field | Meaning |
| --- | --- |
| `kind` | `name`, `url`, `answer` or `ports`. |
| `key` | The name, the URL, or the host. |
| `collector` | The collector that found it. |
| `status`, `title` | For an answer. |
| `ip`, `open` | For ports: the address and the list of open ports. |

### Coverage

[CONCEPTS](../CONCEPTS.md#coverage-what-azhaq-did-with-a-url) defines `visited`, `catchall`, `error`, `gone`, `hint`, `skipped` and `capped`. What follows is what is specific to `run`.

- `gone` is a URL found in an archive or a link that answered 404 or 410: it is not there now.
- `hint` means found, in a script, an API description or an archive, but not requested. It also covers these cases:
  - An archive's static assets, such as images and fonts, are never requested, whatever hides their extension.
  - A route that scripts call only with POST or PUT.
  - A route that only a page in Chrome writes to. A GET that answers 404, 405 or the catch-all page says nothing about such a route.
  - A route named only in scripts, with no GET call among them, while a GET answers 404. Its `proof` says `GET answers 404; found only in scripts, method unknown`.
- `skipped` means found by a link, a script's call, an API description or an archive. It was not requested: its name says a GET would change something.
  - `word` names the verb. The summary lists the URL under `skipped`, as `left alone`.
  - This is the map's rule. A wordlist sweep (`dirs`, `-dirs`, `fuzz`) asks every word, `/logout` included, as ffuf does. It holds words back only under a session (see [dirs](dirs.md)).
- `capped` means left when a limit was hit, or when its origin stopped answering.
  - An origin has stopped answering after 5 connects or timeouts in a row with no answer between them.
  - The rest of that origin's work is left for `azhaq resume`. It is listed under `left alone` as `ORIGIN stopped answering after 5 timeouts`, and `stopped` names the origin.
- A version prefix alone that only a script's strings name (`/v3`) is left out of the map when it answers 404 or the catch-all page.

### Evidence

- [CONCEPTS](../CONCEPTS.md#evidence-how-azhaq-knows-a-url) defines the levels, `evidence_from` and `answer`. It also lists where evidence shows: `query`, the text map and the exports.
- `azhaq query -fields key,evidence,evidence_from` shows the level. `azhaq query -evidence answered,described` keeps the rows with those levels.
- `answer` is `500 without input` for a 5xx that azhaq's plain request got from a route that takes names, in the query or the body. The request sent none of them.

### Roles of a URL

- `manifest` is a bundler's build manifest: Vite's `.vite/manifest.json`, Create React App's `asset-manifest.json`, Angular's `ngsw.json`, Nuxt's build meta.
- `client-route` and `websocket` are below.

### Client routes

A client route is a view that a single-page app's router draws.

- It is read from the app's route table: Angular's `RouterModule`, React Router's `<Route>` and `createBrowserRouter`, or Vue Router.
- Its key is `http://host/#/administration` for an app that routes by the hash, else its path, `http://host/admin`.
- Parameters are written `{name}`. Nested routes are joined to their parents'.
- A view after the hash is never requested: the server answers every one with the app's shell.
- A view in the path is asked for once with a GET, as the server may answer it itself.
  - A sign-in's 401 makes the row `auth`. A page the server renders makes it `page`. The guard stays on the row and in its `proof`.
  - A view the shell answers stays `client-route`, with coverage `catchall`.
  - A template such as `/reports/{id}` is not requested.
- A string in a script that names a view is that view's, listed in its `found_in`, not a page of its own. A router link and `router.navigate(['/order-completion', id])` are examples.
- With `-browser`, Chrome does not open the views.

`guard` is what the router checks before it draws the view. A parent's guard holds for its children.

- Angular: `canActivate`, `canMatch`, `canLoad` or `canActivateChild`, with the guard's name when the build keeps it, such as `canLoad AdminGuard`.
- Vue: `meta.requiresAuth`, or another meta key about sessions or roles, or `beforeEnter`.
- React: a wrapper such as `RequireAuth` or `PrivateRoute`.

### WebSockets

- A `websocket` row is an endpoint a script opens: `new WebSocket(…)`, `SockJS`, a `ws://` or `wss://` URL, or a socket.io client's `io(url, {path})`.
- Its key is `ws://` or `wss://`: the page's scheme when the script builds the URL from `location.host`.
- It is never requested.
- `protocol` is `socket.io` for a socket.io endpoint. `namespace` (`/chat`) is given when the app's call names one.
- When the app's call cannot be read, the library's default path, `/socket.io`, stands.
- Third parties' sockets, such as chat widgets and analytics, are left out.

### Operations

- `ops` has an entry for each operation on the route. `auth` means the description asks for credentials. `body` lists field names.
- `source` is `js-call`, `openapi`, `graphql` or `browser`. `browser` is a write that a page in Chrome sent or was refused. It carries the names its query and body held, never their values.
- The route's `body` is the body field names of all its operations, whatever described them:
  - a script's call;
  - an API description, served or found;
  - a GraphQL schema, as argument names;
  - a request taken in from katana.
- A GraphQL endpoint whose schema was read with `-graphql` has one op per query, mutation and subscription:
  - `method` is `POST`.
  - `summary` is its signature: `mutation login(username: String, password: String): Login`.
  - `operation_id` is the field name, `body` the argument names, and `source` is `graphql`.

### Redirects

- `status` and `title` are the URL's own answer: the first hop of a redirect.
- Without a scope, a redirect is followed only within the site: the same registrable domain or address. With a scope, it is followed only inside it.
- Chrome is held to the same rule for everything a page asks for.

### Methods and parameters

- `methods` and `params` come from API descriptions and call sites in scripts.
- `params` also holds the names in the URL's own query string.
- The query names of the links on a page are on the links' rows, not the page's.

### Forms

- Each form is `{"method","action","enctype","fields","files"}`.
- A form whose action is empty or `#` submits to the page itself. Its `action` is the page's URL with its query.
- `enctype` is a POST form's encoding: `application/x-www-form-urlencoded`, `multipart/form-data` or `text/plain`.
- `files` are the fields that are file inputs.

### found_in

- It lists where scripts name the route: up to three places, calls first.
- For a route on another host than the page whose script named it, it lists the script on that host. `show` links the route to that script too.
- Each place has:
  - `script`: its URL. For a script inside the page, the page's URL, with `inline` true and the page's line numbers.
  - `line` and `col`: in bytes, from 1.
  - `snippet`: up to 120 bytes, the call as written or the string with the code around it.
  - `source`: the original file, when the route was read from a source map's sources. `line` and `col` are then that file's.
- Credentials in a snippet read `[redacted]`: JSON Web Tokens, bearer tokens, secrets set to a literal or in a query string, and long keys.

### Templates

- Pages that differ only by an ID are folded: `/product?id={n}`.
- `count` is the number of URLs folded. `not_asked` is how many of them were found and not requested.
- Pages of one route that differ in which ID-like names they carry are one row: `/product?id={n}` and `/product?id={n}&store={n}`. Its `params` lists every name.
- A query value that names a page, such as `index.jsp?content=about.htm` or `view=grid`, is not an ID. Each is a page of its own.
- Three URLs of a template are requested. `-per-template N` changes that.
- The others are listed with `coverage: hint`, as rows of their own in `crawl`, in text and `-json`.

### Strings that are not routes

- A string in a script that is only the start of a path, `"/rest/user/" + id`, is not a route.
- Nor is a base that calls are built on, such as `this.hostServer + "/rest/web3"`, whose calls are `/rest/web3/submitKey`.
- It has no row and is never requested. It is kept as a rejected string with the reason `the start of a path a script joins more to`. `crawl -rejected` lists it.
- A string with a query, `"/search?q=" + q`, names its route and stays.

### Path checks stop at their answer

- The checks that guess where an API description sits are asked one at a time, likeliest first.
- The names include `openapi.json`, `swagger.json`, `api-docs` and `v3/api-docs`. The same names are asked again under each API base the run found, such as `/rest/` or `/v3/`.
- They stop at the first answer that is an OpenAPI or Swagger document with paths. A Swagger UI or ReDoc page that loads one counts too.
- Once an origin has served a description, here or through `azhaq-openapi`, its other locations are not asked. The summary counts them: `note: path checks: 28 skipped (an API description was already found)`.
- Every other check is still asked: `robots.txt`, `login`, `admin`, `graphql`, `.git/HEAD` and more.
- A Swagger UI whose script holds the document (Juice Shop's `/api-docs/`) is read from the script. The names next to it are not guessed.
- A page that is byte for byte what the site root answers for a made-up path is a single-page app's shell. That makes it the catch-all answer of a directory whose own baseline was not asked, so that baseline is not requested. A directory with answers of its own is still asked.

### Notes in the summary
Examples of what `notes` holds for a run:

- `path checks: 28 skipped (an API description was already found)`: see [Path checks](#path-checks-stop-at-their-answer).
- `screenshot of URL not taken: the page needs about 26 requests and 8 were left (raise -max-requests)`, or `the budget was spent before the page loaded`: see [shots](shots.md#screenshots-and-the-budget).
- `GraphQL URL: introspection disabled: schema recovered (partial: query Query: 2 fields (1 client, 1 probe), 140 words tried; not proof there is nothing more)`, or `introspection: full schema`.

### Next in the summary
`next` suggests a command in three cases:

- A run without `-browser` whose target pages leave their links to their scripts gets `azhaq run -url ORIGIN/ -browser …`, with the page that showed it. The signs are three or more `{{templates}}` in the text, or Markdown in the text whose links are read as text, or an empty shell of a front page. The last two count only when fewer than 10 routes were found on the page's origin. Example: `(/learn/vulnerability/a1_injection and 11 more pages: Markdown its scripts turn into links; read as text here, Chrome sees the page as rendered)`.
- A run that found a GraphQL endpoint and did not read its schema gets `azhaq run -url ORIGIN/ -graphql -allow HOST …   (/graphql and /graphiql answer like GraphQL; -graphql reads the schema by introspection)`. That is a run with no `-graphql`, or with the endpoint's host outside the scope.
- A run without a session (`-login`, `-cookie`, `-header`) whose target site shows a sign-in form gets `azhaq run -url ORIGIN/ -login PAGE -login-user USER -login-pass PASS -allow HOST …`. A sign-in form is a form that takes a password.

## Flags

<!-- flags:begin run -->
| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-all-gets` | bool |  | also request found URLs that look like a GET would change something (logout, delete, reset, save…); by default they are listed, not requested |
| `-all-sources` | bool |  | also run slower subdomain sources outside the default set |
| `-allow` | string, repeatable |  | a domain, host or address range the run may touch; with any -allow, nothing else is requested |
| `-asn` | string, repeatable |  | seed an autonomous system: its announced prefixes |
| `-backoff` | bool |  | when a host answers 429 or 503, wait (1 s doubling to 30 s, or its Retry-After) and ask again, up to 3 times; the summary says which hosts did |
| `-browser` | bool |  | also load pages in Chrome: the requests their scripts send and the links of the rendered page (needs Chrome) |
| `-browser-writes` | bool |  | let pages in Chrome send their writes (POST, PUT, DELETE…, beacons, forms posted on load) as a user's browser would: they change data on the target; by default Chrome sends only GET, HEAD and OPTIONS outside signing in, and maps the writes it does not send |
| `-chrome` | string |  | the Chrome or Chromium to run (default $AZHAQ_CHROME, else the first found) |
| `-chrome-profile` | string |  | a Chrome user data directory to use and keep: sessions it holds go with the pages (default: a temporary one) |
| `-chrome-proxy` | string |  | send Chrome's own connections through this http or socks5 proxy (default: -proxy, else the environment's); a plain http:// request reaches an http proxy as a proxy request, a page over TLS as a CONNECT tunnel |
| `-cidr` | string, repeatable |  | seed an address range such as 192.0.2.0/24 |
| `-cloud` | string |  | CloudAccount JSON inventory (local file) |
| `-cookie` | string, repeatable |  | Cookie name=value (repeatable; sent as one Cookie header) |
| `-cookie-jar` | bool |  | carry the cookies targets set (Set-Cookie) on the requests that follow, as a browser does; -cookie and -header values go first |
| `-crawl-any-host` | bool |  | follow links to any host, within -allow and -deny (katana's -ns) |
| `-crawl-in` | string, repeatable |  | follow only URLs that match this regex |
| `-crawl-out` | string, repeatable |  | never follow URLs that match this regex |
| `-crawl-scope` | string |  | the hosts a crawl follows links to: rdn (the start host's registrable domain and its subdomains), fqdn (the host only), dn (hosts that name its domain keyword) or a regex on the host (default: rdn for a name, the origin itself for an address) |
| `-daily-requests` | int |  | requests a day to the program's targets (-program, else this run's targets), counted over the runs in -db |
| `-db` | string |  | the workspace, a SQLite file (default: a new azhaq-TIME-PID.db in the current directory, or $AZHAQ_DB; query, show and export read it afterwards) |
| `-delay` | duration |  | pause before each uncached fetch |
| `-demo` | bool |  | run against the built-in fixture server (no internet) |
| `-deny` | string, repeatable |  | a domain, host or address range the run must not touch, even when given as a target |
| `-depth` | int | `4` | max fan-out waves (0 = seed wave only, not unlimited) |
| `-dirs` | string |  | guess paths on each web service from this wordlist, or @common for the built-in one (active; the targets given are the scope unless -allow) |
| `-dirs-depth` | int | `1` | directory levels to sweep; 2 also sweeps directories found |
| `-dirs-ext` | string |  | also try each word with these extensions, comma-separated (php,bak) |
| `-dirs-fc` | string |  | hide these statuses |
| `-dirs-fl` | string |  | hide these line counts |
| `-dirs-fr` | string |  | hide answers whose headers or body match this regular expression |
| `-dirs-fs` | string |  | hide these response sizes |
| `-dirs-fw` | string |  | hide these word counts |
| `-dirs-mc` | string |  | report only these statuses (comma-separated, ranges, or all; default ffuf's: 200-299,301,302,307,401,403,405,500) |
| `-dirs-ml` | string |  | report only these line counts |
| `-dirs-mr` | string |  | report only answers whose headers or body match this regular expression |
| `-dirs-ms` | string |  | report only these response sizes (values and ranges, 100-200) |
| `-dirs-mw` | string |  | report only these word counts |
| `-dirs-rate` | float |  | path guesses per second per host (0: no limit but -dirs-threads, as ffuf) |
| `-dirs-threads` | int | `40` | path guesses in flight per service (as ffuf) |
| `-dns-brute` | string |  | resolve WORD.domain for each word in this file (active; the targets given are the scope unless -allow) |
| `-dns-rate` | float |  | DNS queries per second per resolver (0: no pace but the queries in flight, as dnsx) |
| `-domain` | string, repeatable |  | seed Domain, for subdomain discovery |
| `-exclude-sources` | string |  | subdomain sources never to run, comma-separated |
| `-exec` | string |  | connector command (seeds on stdin, facts on stdout) |
| `-facts` | string |  | JSONL connector facts to ingest before native collectors |
| `-fail-on-capped` | bool |  | exit 4 also when the run hit -depth with hints left |
| `-fail-on-errors` | bool |  | exit 3 on every failure: also fan-out (a source for the domain of a URL) and a source that failed while others answered |
| `-fill-forms` | bool |  | ask the action of each GET form with neutral values in its fields (a search box gets a word): one request per form, GET only |
| `-get-words` | string |  | request found URLs left alone for these words only, comma-separated (exec,import): finer than -all-gets |
| `-graphql` | bool |  | read the schema of GraphQL endpoints with an introspection query (active; the targets given are the scope unless -allow) |
| `-graphql-wordlist` | string |  | extra probe words (one per line), tried and recombined with the built-in ones when a GraphQL endpoint's introspection is off and its schema has to be recovered from validation errors |
| `-header` | string, repeatable |  | extra request header K: V |
| `-host-parallel` | int |  | requests in flight per host (default 10, as katana) |
| `-host-rate` | float |  | requests per second to each host, besides -rate over all (0: none) |
| `-in` | string |  | JSONL seeds |
| `-interact` | bool |  | with -browser: click the buttons, links and menus of each page (up to -interact-clicks) to find what only a click brings; writes a click would send are mapped, not sent, and a click on log out, delete, … is not made |
| `-interact-clicks` | int | `12` | clicks -interact makes on each page |
| `-json` | bool |  | print the map as JSON lines, and the summary as one JSON object on stderr |
| `-kill-file` | string |  | stop all sending, at once, when this file exists, and exit 4; azhaq resume works once it is removed (default DB.stop) |
| `-known-files` | string |  | ask each web service only for its robots.txt and sitemaps and read every entry (all, robotstxt or sitemapxml); replaces the 32 built-in paths |
| `-ledger` | string |  | write every request and connection to a target to this file, a chain of hashes that azhaq ledger -verify checks (default DB.ledger.jsonl next to the workspace; off: none; with a temporary database, only when given) |
| `-list` | string |  | targets, one per line: URL, host, host:port or IP (- for stdin) |
| `-login` | string |  | sign in on this page with Chrome before the run; its cookies and token go with every request (needs -login-user and -login-pass) |
| `-login-pass` | string |  | password for -login (default $AZHAQ_LOGIN_PASS) |
| `-login-user` | string |  | user name or email for -login |
| `-max-body` | int |  | largest response body read from a subdomain source, in bytes (default 33554432), as subfinder -rsr |
| `-max-host-requests` | int |  | requests one host may be sent (0: no cap); the rest of its work is left for azhaq resume |
| `-max-ips` | int | `4096` | addresses expanded from -asn and -cidr prefixes, for the whole run |
| `-max-items` | int |  | max collector invocations (default 2048) |
| `-max-names` | int |  | max hostnames resolved (default 20000) |
| `-max-requests` | int |  | requests to targets this run may send (0: no cap); the work left over is for azhaq resume |
| `-max-response-size` | int |  | bytes read of a page or document (default 2097152; scripts and JSON get 16 MiB) |
| `-max-results` | int |  | most names one paging subdomain source gives (0: no cap), as subfinder -mr |
| `-max-time` | duration |  | wait this long for all subdomain sources of a domain, then go on with what they gave (0: -source-timeout and a short grace bound the wait), as subfinder -max-time |
| `-no-favicon` | bool |  | do not hash the favicon of front pages (one or two requests less per web service) |
| `-no-follow` | bool |  | do not follow redirects: each URL is asked once and its redirect recorded with the Location (httpx's default) |
| `-no-history` | bool |  | do not read or write the name history (names earlier runs found, kept under $AZHAQ_DATA_DIR, else ~/.local/share/azhaq; with -live each is checked by DNS in the run) |
| `-no-map-guess` | bool |  | do not ask for main.js.map next to a script that names no source map (a map a script or a header names is still read) |
| `-no-paths` | bool |  | do not ask each web service for the 32 built-in paths (robots.txt, sitemaps, API descriptions, .git/HEAD, backup, admin, …): some programs count that as scanning |
| `-no-tech` | bool |  | skip technology fingerprints (saves about 30 MB of memory) |
| `-obs` | bool |  | also print the observation log |
| `-org` | string |  | seed Organization name |
| `-parallel` | int |  | work items in flight (default 16) |
| `-params` | string |  | find query parameters pages read, from this wordlist or small, medium or large for a built-in one (active; the targets given are the scope unless -allow) |
| `-params-chunk` | int |  | names per parameter request at most (0: 500, and about 7.6 KB in a query; fewer where the server refuses a long query) |
| `-params-delay` | duration |  | wait before each parameter request, one at a time (arjun -d) |
| `-params-include` | string |  | sent with every parameter request: a query for GET; for a body a form, a JSON object or XML, or a template with $arjun$ where the names go |
| `-params-method` | string | `GET` | how names are sent: GET (query), POST (form body), JSON or XML. A body sends requests that may change data on the target: -params-writes must say it is wanted |
| `-params-per-host` | int | `20` | pages searched for parameters per host |
| `-params-rate` | float |  | parameter requests per second per host (0: no limit, as arjun) |
| `-params-stable` | bool |  | one parameter request at a time, 3 to 9 s apart, and 30 s after a refused connection (arjun --stable) |
| `-params-targets` | string |  | file of JSON: pages that are asked otherwise ({"URL":{"method":"POST","include":"a=1","header":["Name: value"]}}), as params -i writes it |
| `-params-threads` | int | `5` | parameter requests in flight per page (as arjun -t); 1 with -params-delay and -params-stable |
| `-params-timeout` | duration | `15s` | wait for each parameter request; one that times out is asked again with 5 s more, up to 20 s (arjun -T) |
| `-params-writes` | bool |  | let -params-method POST, JSON or XML send bodies (they may change data on the target); needs -allow or -scope, or a single target |
| `-passive` | bool |  | skip HTTP/crawl/JS/paths/TLS (no handshake to the target) |
| `-path-climb` | bool |  | also list and ask the parent directories of each link a page names (/a/b/c: /a/b/ and /a/) |
| `-paths` | string |  | extra path wordlist (one path per line) |
| `-per-template` | int |  | URLs of one template (/product?id={n}) to request; the rest are listed (default 3) |
| `-permute` | bool |  | resolve variations of found names (active; the targets given are the scope unless -allow) |
| `-port-all-ips` | bool |  | scan every address of a name, not the first two of each family |
| `-port-cdn-full` | bool |  | scan CDN and WAF addresses in full, not only their web ports |
| `-port-detect` | string | `all` | what is asked of an open port: all (its banner, then HTTP and TLS, then one request of each protocol that waits to be asked, each on its own connection, several at once while the scan has workers free: at most 24 connects after the first), banner (what it says on the one connection) or none (connect and close) |
| `-port-discover` | string |  | ask first whether an address is up, by a connect to 80 and 443: first (scan the ones that answer) or only (list them, scan nothing) |
| `-port-ip` | string |  | the address families of a name to scan: 4 or 6 (default both) |
| `-port-min-rate` | float |  | port connection attempts per second at least: raises -port-rate to this when lower |
| `-port-order` | string | `random` | the order a host's ports are asked in: random (the likeliest ports first, each tier shuffled) or asc |
| `-port-payload` | string |  | send this to each open TCP port before reading what it says (\r and \n are CR and LF) |
| `-port-proxy` | string |  | connect to TCP ports through this SOCKS5 proxy (host:port); a port is then asked its banner only, and UDP is not sent |
| `-port-proxy-auth` | string |  | user:password for -port-proxy |
| `-port-rate` | float |  | port connection attempts per second (0: 1500, as naabu's connect scan, and 127.0.0.1 unpaced) |
| `-port-retries` | int | `-1` | more passes over the ports that neither accepted nor refused: n passes over all of them, 0 none (default: one, when few did not answer) |
| `-port-seed` | int |  | make the random port order repeat (0: a new one each run) |
| `-port-source-ip` | string |  | connect from this local address |
| `-port-threshold` | int |  | stop asking a host after this many open ports: it answers every port (0: no limit) |
| `-port-timeout` | duration |  | wait this long for one port to accept or refuse a connect (0: 1.5s) |
| `-port-unnamed` | int |  | after this many open ports of an address that no protocol probe could name, ask its other silent ports their banner only (0: 6; -1: no limit; each probe is a connect) |
| `-port-workers` | int |  | port connects in flight at once, over all hosts (0: as many as the rate allows, up to 20000) |
| `-ports` | string |  | scan TCP ports: top-100, top-1000, full or a list of ports, ranges and these names, such as 22,80,8000-8100 or top-100,8888 (active; the targets given are the scope unless -allow) |
| `-ports-on` | string, repeatable |  | scan only these ports on a host: HOST=22,80 |
| `-ports-udp` | string |  | ask UDP ports (active): top (about 25 common ones), full or a list of ports, ranges and these names, such as 53,123,161,1-1024 or top,5354; a reply is open, an ICMP unreachable closed, neither open\|filtered (-ports none: UDP only) |
| `-probe` | bool |  | resolve and fetch each target once, print one line per web service, no crawl or enumeration |
| `-program` | string |  | the program to take from a -scope list (handle, name or URL) |
| `-providers` | string |  | API keys per source, YAML (default ~/.config/azhaq/providers.yaml, else subfinder's provider-config.yaml) |
| `-proxy` | string |  | send requests to targets through this proxy (http://, https:// or socks5://); Chrome too (default: $HTTP_PROXY, $HTTPS_PROXY) |
| `-quiet` | bool |  | print no map and no progress lines (a line every 10 s while the run works), only the summary (on stderr) |
| `-rate` | float |  | requests per second to targets, over all hosts (0: no pace) |
| `-request-timeout` | duration |  | time one request gets, headers and body (default: 10 s for headers, 30 s in all; not -timeout, the run's bound) |
| `-resolvers` | string |  | DNS resolvers: a file with one per line, or a comma list; each is ADDR, ADDR:PORT or udp:, tcp:, dot:, doh:URL[:get] and then the address (default: public resolvers) |
| `-retry` | int |  | ask again this many times when a host that answered before gives no answer (a timeout, a reset) |
| `-scope` | string |  | a program's scope: a file (HackerOne CSV, bounty-targets JSON, Burp options, lines) or hackerone, bugcrowd, intigriti, yeswehack |
| `-screenshots` | string |  | save a screenshot of each web service's front page in this directory (needs Chrome) |
| `-seal-to` | string |  | when the run ends, append the ledger's seal as one JSON line ({"time","ledger","seal","entries"}) to this file, or POST it to this URL: kept where the run's own files are not, so azhaq ledger -verify -seal can tell the ledger from one with lines removed and the rest re-chained to look intact |
| `-serve` | string |  | let azhaq worker processes take this run's work, at this address (127.0.0.1:7777) |
| `-shot-codes` | string |  | take only pages that answer with these statuses, comma-separated (default: any); the others are listed as skipped |
| `-shot-format` | string | `png` | screenshot format: png or jpeg |
| `-shot-fullpage` | bool |  | screenshot the whole page, not only the first screen (up to 16384 pixels tall) |
| `-shot-html` | bool |  | keep each page's rendered HTML beside its screenshot |
| `-shot-js` | string |  | a file of JavaScript to run on each page before its screenshot (it runs on the target's page) |
| `-shot-quality` | int | `80` | jpeg quality, 1 to 100 |
| `-shot-size` | string | `1440x900` | screenshot size in pixels, WIDTHxHEIGHT |
| `-shot-timeout` | duration | `30s` | time a page gets: with -rate, how long it may go without a request let go or an answer, not in all |
| `-shot-wait` | duration | `1.5s` | wait after a page's load event for scripts that draw after it, before the screenshot (0: none) |
| `-skip` | string |  | collectors not to run, comma-separated (see azhaq plan) |
| `-source-proxy` | string |  | send every subdomain source request through this proxy URL, as subfinder -proxy (else HTTP_PROXY and HTTPS_PROXY) |
| `-source-rate` | float |  | requests per second to each subdomain source, as subfinder -rl (0: each source's own pace); a source's lower own pace stays |
| `-source-rates` | string |  | pace single subdomain sources, as subfinder -rls: name=N/unit, comma-separated, unit s, m or h (hackertarget=10/m,crtsh=1/s) |
| `-source-timeout` | duration | `30s` | give each subdomain source this long, 30s as subfinder does; a slower one (crt.sh) is abandoned, listed as failed, and the names the others gave are kept; -source-timeout 60s or more waits for crt.sh on a large domain (not -timeout, the run's bound) |
| `-sources` | string |  | subdomain sources to run, comma-separated (default: the default set; none: no source, for a DNS-only run) |
| `-stream` | bool |  | also print each name, service, URL and open port as it is found (found lines, before the ranked map) |
| `-submit-forms` | bool |  | also submit POST forms with neutral values (crawl): CHANGES DATA on the target, each submission counts as a request and is in the ledger, the summary says how many; held to -allow, -deny and the crawl's scope |
| `-tabs` | int | `6` | Chrome tabs open at once for screenshots and -browser (gowitness -t) |
| `-timeout` | duration |  | stop after this long and keep what was found; azhaq resume continues (0: no limit) |
| `-unsafe-ports` | bool | `true` | let Chrome open the ports it refuses by default (6000, 6666, 10080 and others); -unsafe-ports=false keeps its refusal |
| `-url` | string |  | seed URL |
| `-urls` | string |  | write every archived URL of the run's domains to this file, one per line |
| `-urls-archive` | string, repeatable |  | ask NAME's archive at this address instead of its own, as NAME=URL (a mirror or a test server; repeatable) |
| `-urls-blacklist` | string |  | leave out URLs whose path ends in these extensions, comma-separated (png,jpg,svg) |
| `-urls-fc` | string |  | leave out URLs the archive recorded with these HTTP status codes, comma-separated; the archives that keep no status (OTX, urlscan.io) are asked all the same and their URLs kept, with a note |
| `-urls-fp` | bool |  | keep one URL for each host and path, dropping the variants that differ by parameters |
| `-urls-from` | string |  | only captures from this time on: YYYY, YYYYMM, YYYYMMDD or YYYYMMDDhhmmss; OTX, which dates no capture, is asked all the same and its URLs kept, with a note |
| `-urls-ft` | string |  | leave out URLs the archive recorded with these MIME types, comma-separated; the archives that keep no type (OTX, urlscan.io) are asked all the same and their URLs kept, with a note |
| `-urls-max` | int | `500000` | URLs kept for each domain (0: no cap); the summary counts the ones past it |
| `-urls-mc` | string |  | keep only URLs the archive recorded with these HTTP status codes, comma-separated (200,301); the archives that keep no status (OTX, urlscan.io) are asked all the same and their URLs kept, as gau keeps them, with a note |
| `-urls-mt` | string |  | keep only URLs the archive recorded with these MIME types, comma-separated (text/html); the archives that keep no type (OTX, urlscan.io) are asked all the same and their URLs kept, with a note |
| `-urls-pages` | int | `50` | pages read from each archive for a domain (0: no cap); an archive that stops at the cap says so in the summary |
| `-urls-pause` | duration |  | pause between the requests of one archive (default: 1 s for the Wayback Machine and Common Crawl, 0.5 s for OTX, 2 s for urlscan.io; 0 for none) |
| `-urls-proxy` | string |  | send the archive requests through this proxy: http://HOST:PORT, https:// or socks5:// |
| `-urls-raw` | bool |  | print the archived URLs exactly as the archives gave them: no normalising, junk filter or deduplication |
| `-urls-retries` | int |  | times an archive request is asked again after a 429, 503 or network error, after its Retry-After (seconds or a date, however long) or 2, 5, 10, 20, then 30 s; 0 makes the first refusal final (default: a 429 or 503 is asked again until the archive's time, -urls-timeout, or the run's is spent, a network error 3 times; a wait longer than the time left ends the request at once, with the reason) |
| `-urls-source` | bool |  | with -urls: each line is the URL, a tab, and the archive that gave it |
| `-urls-sources` | string |  | ask only these archives, comma-separated: wayback, commoncrawl, otx, urlscan, arquivo (default: all) |
| `-urls-subs` | bool | `true` | ask the archives for the subdomains of each domain too (false: only the name itself, as gau does without --subs) |
| `-urls-timeout` | duration | `3m0s` | time each archive source gets per domain (the Wayback Machine's answer for a large domain takes several minutes) |
| `-urls-to` | string |  | only captures up to this time, in the same form |
| `-v` | bool |  | print a line for every finished task, not only failures |
| `-web-ports` | string |  | ports to probe on each hostname, comma-separated (default: 443, falling back to 80) |
| `-web-scheme` | string |  | try a name or an address over this scheme only, http or https (default: https, then http) |
| `-worker-token` | string |  | the token workers give (default $AZHAQ_WORKER_TOKEN, else a new one) |
<!-- flags:end -->
