# Concepts and terms

What the words in Azhaq's output mean, in one place. `azhaq docs concepts` prints this page.

## Reading a map row

```
URL http://localhost:3000/rest/2fa/verify  target  hint  api  POST
    POST  body tmpToken totpToken
```

| Part | Here | Meaning |
| --- | --- | --- |
| type | `URL` | What the row is: `URL`, `Hostname`, `Domain`, `IPAddress`, … |
| key | `http://localhost:3000/rest/2fa/verify` | The URL, name or address. A template (`/api/Users/{id}`) stands for URLs that differ by an identifier. |
| scope | `target` | `target`: what you asked about. `fanout`: found on the way. |
| coverage | `hint` | What Azhaq did with the URL (below). |
| kind | `api` | What the URL is (below). |
| methods | `POST` | The methods its callers and descriptions use. |
| indented | `POST  body …` | One line per operation or form: the names it sends. |

`azhaq show -db W URL` prints everything known about one row, and where a script named it (`found in main.js:6472:88`).

## Coverage: what Azhaq did with a URL

| State | Meaning | What to do next |
| --- | --- | --- |
| `visited` | Requested; it answered as a page of its own (any status but 404 and 410). | Read it. |
| `catchall` | Requested; it answered with the page every unknown path gets (a single-page app's shell, a soft 404). Not proof the route exists. | Look at it in a browser, or use `-browser`. |
| `error` | Requested; no answer (timeout, refused, reset, TLS). | `azhaq query -db W -failed`, then try again. |
| `gone` | Requested; it answered 404 or 410. Usually an archived URL. | Try older API versions near it. |
| `hint` | Known (from a script, an API description, an archive, a link), not proven by a GET: not requested, or a route scripts call with another method. | Send the method in its operations yourself. |
| `skipped` | Not requested on purpose: its name says a GET would change something (the `word` field names the verb, such as `logout` or `delete`). Listed under "left alone". | `-get-words WORD` (or `-all-gets`) if you accept the side effect. |
| `capped` | Not requested: a limit (budget, depth, items) ran out first. | `azhaq resume -db W`. |

## Evidence: how Azhaq knows a URL

Coverage says what Azhaq did with a URL. Evidence says how it knows the URL at all. Every URL row has an `evidence` field, and `evidence_from` lists the collectors behind it, sorted. A row takes the strongest level any of its sources reaches, in this order:

| Level | Meaning |
| --- | --- |
| `answered` | This run requested it and the server answered: a status, not the origin's any-path answer, not a 404 or 410. |
| `described` | An API description the run read lists it (OpenAPI or Swagger, or a cloud inventory given to the run). |
| `called` | A script calls it (a `fetch` or XHR call with its method), or Chrome saw the request. |
| `linked` | A page links to it, a form submits to it, or a script names it in a string or as a route. |
| `archived` | Only archive sources (Wayback, Common Crawl, OTX, urlscan, Arquivo) hold it. |
| `guessed` | Only a wordlist guess found it, and the answer was a 404 or the origin's any-path answer. |

A 404 does not make a row `answered`: the server said it is not there, so the row keeps the level of whatever named it. A row folded into a template (`/product?id={n}`) takes the strongest level of its instances and lists the collectors of all of them. Only URL rows have a level.

It shows in `azhaq query -fields key,evidence,evidence_from` (`azhaq query -evidence answered,described` keeps the rows with those levels), at the end of a map row that is not `answered` (`[described]`, `[called]`, `[linked]`, `[archived]`, `[guessed]`), in `export -format jsonl` (`evidence`, `evidence_from`), in `export -format openapi` (`x-azhaq-evidence` on each operation) and in the Evidence column of `export -format html`.

## Kinds of URL

`app` (a front page), `auth` (401), `forbidden` (403), `api`, `page`, `script`, `asset`, `sourcemap`, `manifest` (a bundler's build manifest), `client-route` (a view a single-page app's router draws, such as `http://host/#/administration`, with the `guard` that keeps it), `websocket` (an endpoint scripts open a WebSocket to). Views after the hash and sockets are never requested, so they stay `hint`. A view in the path (`http://host/admin`) is asked for once. If the server answers it (`auth`, `page`), that answer stands, with the guard noted beside it. If the app's shell answers instead, it stays a `client-route`.

## Names

| Status | Meaning |
| --- | --- |
| `live` | Resolves; a host you gave, or a name under a domain you gave. |
| `sibling` | Resolves; found on the way, under another domain. |
| `unresolved` | From a source or a list, not looked up. |
| `dead` | Does not resolve (NXDOMAIN, no address, or SERVFAIL from every resolver). |
| `wildcard` | Resolves only because its zone answers for any name. |

Rows of the kinds `domain` (a domain you gave) and `addr` (an address) carry no status.

## Runs, failures and exit codes

| Term | Meaning |
| --- | --- |
| workspace | One SQLite file (`-db`). Every run into it adds to it. |
| run | One pass into a workspace. `azhaq resume` continues a run a limit stopped. |
| budget | `-max-requests`: requests to targets the run may send. Port connects and UDP datagrams count too. |
| ledger | `DB.ledger.jsonl`: one line for each request or connection a run sent to a target, each line holding the hash of the one before. `azhaq ledger -verify` checks the chain. |
| kill file | `-kill-file PATH` (default `DB.stop`): once it exists, nothing more is sent, and the run exits 4. Remove it and `azhaq resume`. |
| pace | `-rate`: requests per second to targets, over all hosts. Chrome's requests too. |
| fanout failure | A failure about something you did not ask about (a name found on the way). Listed with `"fanout": true`; the exit code stays 0. |
| partial | One source failed while others answered for the same domain. Listed with `"partial": true`; the exit code stays 0, except for crt.sh (no other source holds as many names, so its failure counts). |
| degraded | Every source or archive failed, so an empty answer is not an honest zero. In the `subs` summary, `degraded` is also set when a source in the default set failed while others answered: the names are listed, and the exit code is not changed. |
| left alone | URLs not requested because a GET there would change something. |
| takeover candidate | A name whose CNAME points at something gone (a service name anyone may create, a domain nobody holds), or whose front page is a hosting service's page for an unclaimed name. Confirm by hand. |
| next | Commands worth running next, in the summary. |

Exit codes: `0` complete, `1` error, `2` usage (nothing was sent), `3` finished with failures (the results are usable; the summary says what failed), `4` stopped by a limit or the kill file (`azhaq resume` continues).

## Access control (`azhaq roles`)

| Term | Meaning |
| --- | --- |
| role | A session: anonymous, headers (`-role`), headers from a command (`-role-cmd`), or a Chrome sign-in (`-role-login`). |
| replay | Every URL any role reached, asked with every other role. GETs only, unless `-replay-writes`. |
| reads | Answered 2xx, and not with an error shaped as data. |
| refused | Any 4xx, an error served with a 2xx status, the site's own `200 Access denied` page (or what `-refusal` matches), a redirect to a sign-in page, or a redirect to the front page when another role reads the endpoint directly. |
| owner, `owner_by` | Whose object it is, and the evidence (a token's claim, a list only that role sees, the object's own owner field). |
| `confidence`, `evidence` | How surely the object is the owner's (`proved`: the session or the owner's own list, and the object's answer; `likely`: one of them; `guess`), and why, in one line. |
| control | A made-up identifier of the same shape on the same route: a route that answers it like a real object answers any identifier. |
| canary | An endpoint only a role's live session reads, checked during the replay; a session that dies is renewed, or its answers are `session_suspect`. |
| evidence | The answers behind the listed rows, secrets taken out, in `roles.db`: `azhaq roles show -dir DIR URL`. |
| dead session | A role refused wherever a session matters: its token expired or is wrong. Said in a note; the exit code is 3. |
| report | `azhaq report -dir DIR`: each listed finding written up from the evidence as a Markdown report to submit. It sends nothing. |

Verdicts, worst first: anyone reads sensitive fields · reads another role's object · answers any identifier · every signed-in role reads the same object · roles read the same sensitive fields · same answer for a session that did not find it · signed-in only · only one role reads it · some roles refused · different fields per role · anyone reads the same object · status differs. With `-replay-writes`, three come before them all: anyone writes another role's object · writes another role's object · writes another role's object: accepted; the change cannot be read back to confirm.

## What Azhaq sends

| What | Method | When |
| --- | --- | --- |
| Pages, scripts, API descriptions, built-in paths, archived URL templates | GET | every run, inside the scope |
| Path and parameter guesses | GET | `-dirs`, `-params` (held to the targets given, or `-allow`/`-scope`) |
| GraphQL introspection | POST | `-graphql` (held to the targets given, or `-allow`/`-scope`) |
| A port's service | TCP connect, then for a port that says nothing: its own protocol's request on its usual number, one `HEAD /`, a TLS handshake, and one request of each of the other protocols until one answers (at most 24 more connects per port; a `GET /` for a web page whose head names no product) | `-ports`, `ports` |
| UDP ports | one datagram of the protocol's harmless request per port, more when none came back (a port with no known protocol is asked four ways) | `-ports-udp`, `ports -udp`, `-pu` |
| A wordlist in a request | the method and body you give it | `azhaq fuzz` (held to the host of `-u`, or `-allow`/`-scope`) |
| Chrome | what the page loads, inside the scope | `-browser`, `-login`, `shots`, `-role-login` |
| Writes of other roles | POST, PUT, PATCH, DELETE | `roles -replay-writes` (held to the `-url` hosts, or `-allow`/`-scope`) |

URLs whose names say a GET would change something are listed, not requested. Nothing goes to a host outside the scope. Every request and connection to a target goes in the ledger; DNS queries and third-party sources do not.
