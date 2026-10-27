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

A run keeps the answers it got in its workspace until nothing is left to resume, so `azhaq resume` does not ask again what the run already asked: the requests of a run stopped and resumed add up to about those of one uninterrupted run (Juice Shop: 211 against 205 with `-max-requests 50`; a 4,750-word path sweep: 4,812 against 4,801). A port scan the budget cut short scans that address again. A command run without `-db` uses a temporary database and cannot be resumed.

Failures on fan-out are listed with `"fanout": true` and do not make the exit code 3: the map of what you asked about is still complete. Fan-out is what you did not ask about: a name found on the way, and the third-party lookups (subdomain sources, archives, RDAP) of a domain that is only the domain of a URL you mapped. Ask for the domain itself (`-domain`, `subs -d`, `urls -d`) and their failures count, except a source that failed while other sources answered for the same domain: it is listed with `"partial": true` and does not make the exit code 3 (sources fail all the time; an exit code that is always 3 says nothing). `-fail-on-errors` counts every failure. A name every resolver answers SERVFAIL or REFUSED for, on two passes, is not a failure: the resolvers answered, and the name's own DNS is broken (a lame delegation) for everyone; it is dead, with `result` `servfail`. Resolvers that time out are a failure.

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
| `failed` | Work that did not get its answer, grouped by collector, source and error, most frequent first. `retryable` is true for timeouts, dropped connections, 429 and 5xx. `source` names a third-party source (crtsh, wayback). `targets` names up to 100; `azhaq query -db FILE -failed` lists every failed target, the list to retry. |
| `skipped` | Targets and requests Azhaq chose not to touch, with the reason: outside the scope, would end the session, a scope entry a run cannot use. |
| `partial` (in `failed`) | A third-party source failed while other sources answered for the same target. |
| `stopped`, `resume` | The limit that stopped the work and the command that continues it. |
| `notes` | Caps that were hit and other things worth knowing that are not failures. |

## run

The map, one row per entity, best first: the target's own pages and APIs, then what it led to. `-json` prints one object per row:

```json
{"type":"URL","key":"http://127.0.0.1:3001/api/Users","scope":"target","coverage":"visited","role":"auth",
 "status":401,"title":"UnauthorizedError: No Authorization header was found","methods":["GET","POST"],
 "params":["email","password"],"proof":"status=401 …","first_seen":"2026-10-26T14:23:40Z"}
```

| Field | Values |
| --- | --- |
| `type` | `URL`, `Hostname`, `Domain`, `IPAddress`, `Organization`, … |
| `scope` | `target`: what you asked about. `fanout`: found on the way (other hosts, CNAME targets). |
| `coverage` (URLs) | `visited`: fetched and answered as a page of its own. `catchall`: answered with the page every unknown path gets (a single-page app's shell). `error`: requested, no answer. `gone`: answered 404 or 410 (found in an archive or a link, not there now). `hint`: found (in a script, an API description, an archive) but not requested, or called by scripts only with POST or PUT (a GET that answers 404, 405 or the catch-all page says nothing about such a route). `skipped`: found, not requested because its name says a GET would change something. `capped`: left when a limit was hit. |
| `role` (URLs) | `app` (a front page), `auth` (401), `forbidden` (403), `api`, `page`, `script`, `asset`, `sourcemap`. |
| `role` (names) | `live` (resolves; a host you gave, or a name under a domain you gave), `sibling` (resolves; found on the way, under another domain), `unresolved` (from a source or a list, not looked up), `dead`, `wildcard`. |
| `ops` | each operation on the route: `method`, `query`, `path`, `header`, `body` (field names), `body_type`, `auth` (the description asks for credentials), `summary`, `operation_id`, `source` (`js-call`, `openapi`, `graphql`). |
| `body` | the body field names of all its operations, whatever described them: a script's call, an API description (served or found), a GraphQL schema (argument names), a request taken in from katana. |
| `status`, `title` | The URL's own answer (the first hop of a redirect). Without a scope, a redirect is followed only within the site (same registrable domain or address); with one, only inside it. |
| `methods`, `params` | From API descriptions, call sites in scripts, forms and links. |
| `forms` | `{"method","action","fields"}` for each form on the page. |
| `template`, `count` | Pages that differ only by an ID are folded: `/product?id={n}` with the number of URLs folded. A query value that names a page (`index.jsp?content=about.htm`, `view=grid`) is not an ID: each is a page of its own. Three URLs of a template are requested (`-per-template N` changes it). |

A GraphQL endpoint whose schema was read with `-graphql` has one op per query, mutation and subscription: `method` `POST`, `summary` its signature (`mutation login(username: String, password: String): Login`), `operation_id` the field name, `body` the argument names, `source` `graphql`.

The text map prints the same rows, one per line, with forms and parameters indented below, and a GraphQL endpoint's operations by their signatures (the first 50; the rest are in `-json` and the exports).

## Drop-in commands

Their `-json` output uses the field names of the tool they stand in for, so existing `jq` filters keep working.

| Command | Fields |
| --- | --- |
| `subs` | `host`, `input` (the domain), `source` (the first source that gave the name), `sources` (all of them; `dns-brute` or `permute` for a name found by `-w` or `-permute`); with `-live`, `a`. |
| `dns` | `host`, `a`, `aaaa`, `cname`, `status_code`, `cdn_name`. |
| `probe` | httpx's: `url`, `input` (the target as given), `host` (the name), `host_ip` (the address the request connected to), `a` and `aaaa` (the addresses the name resolved to; `host_ip` is one of them), `port`, `scheme`, `path`, `method`, `status_code` (the first answer: a redirect stays 302, as httpx prints it), `title`, `webserver`, `content_type`, `tech`, `content_length`, `words`, `lines`, `time`, `favicon` (with `-favicon`), `cdn`, `cdn_name`, `cdn_type`, `final_url` and `final_status_code` (where a redirect inside the scope, or without one inside the site, ended; title and tech describe that page), `chain_status_codes`, `location`, `timestamp`. Empty fields are left out, as httpx does. Every target given ends as a row, a failure or a skip: a name that resolved and got neither an answer nor a recorded failure is listed as failed, `no answer and no failure recorded`. |
| `crawl` | `url` and the map row's fields (`coverage`, `role`, `status`, `methods`, `params`, `forms`). |
| `urls` | `url`. |
| `ports` | naabu's: `host`, `ip`, `port`, `protocol`, `tls`, `timestamp`, plus `service` and `banner`, and for a TLS port the certificate's `subject_cn` and `subject_an` (httpx's names). A service that speaks first (`ssh`, `ftp`, `smtp`, …) is named from what it says. One that waits is asked once: `HEAD / HTTP/1.0` on the open connection (an HTTP answer is `http`, its banner the `Server` header or the status line), and without one, or with a 400, a TLS handshake on a second connection, counted like a connect (`tls`; `https` when HTTP answers inside it, `tls` true). A name ending in `?` is only the port's usual service. Raw printing ports (9100–9107) are never asked anything. A second name on the same address has its web and TLS ports asked again under its own name. One row per address: a name's IPv4 and IPv6 addresses are both scanned, IPv6 where this machine can reach it; where it cannot, the summary's notes say so (`IPv6 addresses of 1 name not scanned: no IPv6 route from this machine`). A port that neither accepts nor refuses a connect (a timeout, an ICMP unreachable) is asked once more after the others, when such ports are at most 64 or a tenth of the scan (a loaded or lossy host drops a connect now and then; a firewall that drops nearly everything would only double the scan). A service on a port that usually speaks first (22, 21, 25, 3306, …) is given a second wait for its greeting before it is asked anything. In `run` and `query`, a scanned address's `ports` row counts these silent ports in `filtered`, and lists them in `filtered_ports` when there are no more than 64; the summary names them (`ports that neither accepted nor refused a connect, asked twice: scanme.nmap.org (45.33.32.156) port 80; …`), since an open port may hide among them. |
| `dirs` | `url`, `status`, `length` (the whole body, as ffuf; up to 64 MB), `words`, `lines` (from the first MB), `redirectlocation`. |
| `params` | `url`, `method`, `params`, and `why` (what changed in the answer for each name). |
| `asn` | `as_number`, `as_name`, `prefix`. |
| `shots` | `url`, `file`, `title`, `final_url`, `phash`. |

`probe`, `dns`, `ports`, `dirs`, `params` and `shots` print each result as it is found.

## roles

One row per endpoint whose answer depends on the session (`-all`: every endpoint compared):

```json
{"url":"http://localhost:5000/books/v1/aliceBook","verdict":"reads another role's object",
 "template":"http://localhost:5000/books/v1/{book_title}","found_by":["alice"],"owner":"alice","readers":["bob","admin"],
 "sensitive":["secret"],"status":{"anon":401,"alice":200,"bob":200,"admin":200},
 "answers":{"anon":{"status":401,"length":95,"hash":"…","error":true},
            "alice":{"status":200,"length":79,"hash":"9f…","keys":["book_title","owner","secret"],"sensitive":["secret"]},"bob":{…},"admin":{…}}}
```

| Field | Meaning |
| --- | --- |
| `status` | Each role's status; 0 for a role that was never asked. |
| `answers` | Each role's answer: `status`, `length`, `hash` of the body, `keys` (a JSON answer's field paths, nested: `data.user.email`, `data[].id`), `error` (a JSON answer shaped like an error, such as `{"status":"error"}`), `sensitive` (its fields that hold passwords, secrets, keys, tokens, card numbers), `location` (where a redirect sends the role). Every answer is compared by its body: one the run kept without it (a URL the `-paths` list found keeps its status only) is asked again, with the role's session. |
| `found_by` | The roles whose own runs reached the URL, or, for an object URL, whose answers held its identifier. |
| `template` | The route an object URL fills: its path parameters filled with identifiers the roles' answers held, or given with `-id`. |
| `owner` | The role whose own object it is: given with `-id ROLE:…`; known from who the role is (see below); or an identifier only that role's answers held (in the route's own list, such as `/api/Addresss` for `/api/Addresss/{id}`, while the same list read by another role did not; or in a field named after the parameter, and nowhere in the other roles' answers). |
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

Who each signed-in role is tells its own objects apart without `-id`: the claims of a JSON Web Token its headers or cookies carry (`sub`, `id`, `email`, `username`, `data.id`, …, and identifiers such as Juice Shop's `bid`), its own answer to a `/me`-like endpoint (`/me`, `/whoami`, `/userinfo`, …) when the anonymous role gets another, and, for `-role-login`, what the login answered and left in `localStorage` and `sessionStorage`. A list item whose owner field (`owner`, `user`, `username`, `userId`, `email`, `createdBy`, …) names a role is that role's object: the field the route's parameter maps to (`book_title` for `/books/v1/{book_title}`) is its identifier. An identifier the role's session holds for a route is its own too (`bid` fills `/rest/basket/{id}`). Each role's own objects are asked of every other role.

`-id [ROLE:]NAME=VALUE` (repeatable) fills routes with an identifier of your own: NAME is a path parameter (`book_title`), a JSON field that holds such values (`basket_id` and `BasketId` fill `/rest/basket/{id}`), or a route (`/rest/basket/{id}`). With ROLE, VALUE names that role's own object, so another role reading it is `reads another role's object`; without, it is tried like an identifier the answers held. Each route is also filled with up to 5 of each role's own identifiers (those who the role is names first) and 6 others, in order (numbers by value); the replay asks objects given with `-id` first, then the roles' own objects, then what the runs reached, then other objects, and takes a URL only while `-replay-max` holds every role's request for it.

A signed-in role whose session looks expired or wrong is named in a note, with what the site says when that role asks one such endpoint again: `role x was refused wherever a session matters (the site said "Signature expired. Please log in again."): its session looks expired or wrong; its rows show what a visitor gets`, and roles exits 3. It was refused on every endpoint the anonymous role is refused and another signed-in role reads, or on every endpoint another role reads, and it read no `/me`-like endpoint unlike the anonymous role. When no signed-in role reads anything the anonymous role is refused, as when tokens copied at the same time expire together, each is judged alone: refused on every endpoint the anonymous role is refused.

A JSON Web Token a role's headers carry (`Authorization`, a cookie, any header) is read for its `exp` before anything is sent. One that has expired is said at once on stderr, and the end of the run says what came of it: a dead session (`its token expired at …`), a site that still took it (`role alice's token expired at …, yet the site still let it read 3 endpoints the anonymous role is refused: check that it verifies token expiry`, a finding), or, with nothing to tell, a note and exit 3. A token that expires within 15 minutes is noted too. For tokens that live minutes, `-role-cmd 'alice=./token.sh alice'` gives a role whose headers a shell command prints, one `Header: value` per line, or a bare token sent as `Authorization: Bearer`; the command runs before the role's run and again before the replay. `-role-cmd` is not offered over MCP.

A role given with `-role` sends those headers and nothing else, so behaviour an app ties to a cookie is not reached with a header alone: Juice Shop's `/rest/user/whoami` reads the `token` cookie, and answers `{"user":{}}` to an `Authorization` header. Give the cookie as one of the role's headers (`-role 'alice=Cookie: token=eyJ…'`, what `-cookie` sends in a run), or use `-role-login`, which carries the cookies and the token the login stored.

With `-json`, stderr holds the summary only: the runs of the roles print nothing, and what they did not finish is in it (`failed`, `unreachable`, `skipped`, `notes`; a role's run stopped by a limit is `stopped`, exit 4). A role whose run could not be done (a failed sign-in) ends roles with a summary whose `notes` say why.

## diff

A web page's answer is compared by status and title, and a JSON listing's also by how many items it holds (`json_items`): `watch` reports `/users/v1: [200] 5 items → [200] 6 items`. Bodies are not compared byte for byte: timestamps and tokens would make every run a change. A workspace with one run says so: a diff needs two.

`diff -jsonl` prints `added` and `removed` rows, `not_seen_again` rows and a `summary`. `removed` is what answered in the older run (a name that resolved, a page with a status, a host with open ports) and is gone from the newer. `not_seen_again` is what the older run only heard of (from a subdomain source, an archive, a link) and never checked: sources answer differently from day to day and fail, so its absence says little. The summary names the `failed_sources` of the newer run.

## query, show, plan, ingest

- `query -json` prints map rows (as `run -json`), or only the `-fields` asked for; every row that matches, unless `-limit` says otherwise (the summary then says how many matched). `query -failed` prints every failed target instead: `target`, `collector`, `source`, `error`, `retryable`.
- `show -json` prints one object: `row` (the map row), `links` (`rel`, `dir` in or out, `type`, `key`) and `observations` (`collector`, `kind`, `source`, `observed_at`, `payload`); for a hostname, `services`: its front pages with `coverage`, `status`, `title`, and the `error` of one that failed. A GraphQL endpoint read with `-graphql` has an `azhaq-graphql-schema` observation whose payload holds `queries`, `mutations`, `subscriptions` and `types` (names) and `schema`, the introspection's whole `__schema` object (past 8 MB without its descriptions; past that left out, with its size in `schema_bytes`). A server that refuses the full introspection query for its depth is asked for the names only, and `schema` is absent.
- `plan -json` prints one object: `targets` (each with the collectors that would run on it), `skipped`, `collectors` (what each does to whom), `active`, `builtin_paths`, `limits`, `sends`, and `requests`: what is known of the requests before any is sent. `source_queries` counts, per collector, the queries to third-party sources about the targets listed (one per source asked; a source may page through its answer), `source_queries_total` adds them up, and `source_queries_not_counted` names the collectors that do not say before they run which sources they ask (none of the built-in ones; a connector may not). `found_domains_asked` is true when domains found on the way would be asked about too (inside the scope; without one, within `-depth` and `-max-items`). The requests to the targets are a bound, not a count: how many names resolve and answer is known only by asking (`max_names` of them at most are looked up). `per_web_service` is about what each web service costs before its links, scripts and archived URLs are followed (its page, the favicon, the built-in paths), and `cap` the requests to the targets at most, set by `cap_by` (`-max-requests`, or `-daily-requests` less what the day's runs in the workspace spent); 0 is no cap. `passive` is true when nothing goes to the targets.
- `ingest` prints only its summary: `results` is the facts read, `counts` the lines read per format.

## export

`azhaq export -db FILE -format F` writes the newest run of a workspace in one format on stdout.

| Format | Output |
| --- | --- |
| `jsonl` | Everything: one object per map row (`"kind":"entity"`), observation and edge. |
| `urls`, `hosts`, `names`, `targets` | One per line: every URL; names that resolve; every name; web services (front pages that answered, Azhaq's or taken in from httpx, katana or ffuf), for `nuclei -l` and `httpx`. |
| `openapi` | OpenAPI 3 JSON of one origin (`-origin`, default the one with the most API routes): the description the target serves, as it is, plus the routes scripts call, forms and what answered. `x-azhaq` on each operation: `source`, `coverage`, `status`, `needs_credentials`. |
| `graphql` | The introspection result of each GraphQL endpoint read with `-graphql`, as InQL, Burp, Postman, graphql-voyager and clairvoyance read it. |
| `sdl` | The same schemas in the GraphQL schema language. |
| `burp` | Burp Suite project options with the run's target scope. |
| `html` | One self-contained page: web services, names, screenshots, secrets, API routes, the map. |
| `graphml` | The graph for Gephi, yEd or Cytoscape. |
| `secrets` | Credentials found in scripts: severity, kind, value, script, tab-separated. |

**openapi** is a valid OpenAPI document whatever went into it: every operationId is unique (a served description's keep theirs; a repeat, such as `/blog` and `/blog/` both `get_blog`, gets `_2`, `_3` in path order), templates that differ only by their parameter names are one path (the served description's, else the first), every `{name}` in a path is a declared path parameter, a parameter is listed once, and component names OpenAPI does not allow are renamed with their references. A GraphQL endpoint is one `POST` taking `{"query","operationName","variables"}`, not a made-up REST mapping; its operations are in `x-azhaq-graphql`:

```json
"x-azhaq-graphql":{"operations":[
  {"type":"query","name":"pastes","arguments":[{"name":"public","type":"Boolean"},{"name":"limit","type":"Int"}],"returns":"[PasteObject]"},
  {"type":"mutation","name":"createPaste","arguments":[{"name":"burn","type":"Boolean","default":"false"}],"returns":"CreatePaste"}]}
```

`type` is `query`, `mutation` or `subscription`; `default` is a GraphQL literal; `deprecated` is set on deprecated fields. A schema kept by names only gives `type` and `name`.

**graphql** prints `{"data":{"__schema":{…}}}`, the server's answer to the standard introspection query. With several endpoints it prints one object keyed by endpoint URL, `{"https://app/graphql":{"data":{"__schema":…}},…}`; `-origin` keeps the endpoints of one origin, or the one at a URL (`-origin https://app/graphql`), to get a file a tool loads as it is. **sdl** prints each endpoint's schema under a `# URL` comment: types, interfaces, unions, enums, input objects, custom scalars and directives with descriptions, defaults and `@deprecated`, without the built-in scalars and directives; a `schema { … }` block when the root types are not simply `Query`, `Mutation` and `Subscription`. Concatenated schemas of several endpoints are not one schema: pick one with `-origin`.

**burp** writes `{"target":{"scope":{"advanced_mode":true,"include":[…],"exclude":[…]}}}`. When the run had a scope, `include` holds its allow rules (`-scope` and `-allow`) and `exclude` its deny rules (the program's out-of-scope entries and `-deny`), each for any protocol, port and path: a domain is `{"enabled":true,"protocol":"any","host":"^(.*\\.)?example\\.com$"}` (it and its subdomains), one host `^api\\.example\\.com$`, an address `^192\\.0\\.2\\.7$`, a range as Burp takes it (`10.0.0.0/24`). The scope is read back from the run's options: a scope file again (stored by its full path), and a platform's program (`-scope hackerone -program x`) as it stands now, from bounty-targets-data. A run without allow rules, or whose scope file is gone (a note on stderr says so), includes every web service it found: `{"enabled":true,"protocol":"https","host":"^app\\.example\\.com$","port":"^443$","file":"^/.*"}`. `azhaq run -scope` reads the file back.
