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
| `skipped` | Not requested on purpose: its name says a GET would change something (`word` says which). Listed under "left alone". | `-all-gets` if you accept the side effect. |
| `capped` | Not requested: a limit (budget, depth, items) ran out first. | `azhaq resume -db W`. |

## Kinds of URL

`app` (a front page), `auth` (401), `forbidden` (403), `api`, `page`, `script`, `asset`, `sourcemap`, `manifest` (a bundler's build manifest), `client-route` (a view a single-page app's router draws, such as `http://host/#/administration`, with the `guard` that keeps it), `websocket` (an endpoint scripts open a WebSocket to). Views and sockets are never requested: `hint`.

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
| budget | `-max-requests`: requests to targets the run may send. Port connects count too. |
| pace | `-rate`: requests per second to targets, over all hosts. Chrome's requests too. |
| fanout failure | A failure about something you did not ask about (a name found on the way). Listed with `"fanout": true`; the exit code stays 0. |
| partial | One source failed while others answered for the same domain. Listed with `"partial": true`; the exit code stays 0, except for crt.sh. |
| degraded | Every source or archive failed, so an empty answer is not an honest zero. |
| left alone | URLs not requested because a GET there would change something. |
| next | Commands worth running next, in the summary. |

Exit codes: `0` complete, `1` error, `2` usage (nothing was sent), `3` finished with failures (the results are usable; the summary says what failed), `4` stopped by a limit (`azhaq resume` continues).

## Access control (`azhaq roles`)

| Term | Meaning |
| --- | --- |
| role | A session: anonymous, headers (`-role`), headers from a command (`-role-cmd`), or a Chrome sign-in (`-role-login`). |
| replay | Every URL any role reached, asked with every other role. GETs only, unless `-replay-writes`. |
| reads | Answered 2xx, and not with an error shaped as data. |
| refused | Any 4xx, an error answered 2xx, a redirect to a sign-in page, or to the front page while another role reads it. |
| owner, `owner_by` | Whose object it is, and the evidence (a token's claim, a list only that role sees, the object's own owner field). |
| dead session | A role refused wherever a session matters: its token expired or is wrong. Said in a note; the exit code is 3. |

Verdicts, worst first: anyone reads sensitive fields · reads another role's object · every signed-in role reads the same object · roles read the same sensitive fields · same answer for a session that did not find it · signed-in only · only one role reads it · some roles refused · different fields per role · anyone reads the same object · status differs. With `-replay-writes`, two come before them all: anyone writes another role's object · writes another role's object.

## What Azhaq sends

| What | Method | When |
| --- | --- | --- |
| Pages, scripts, API descriptions, built-in paths, archived URL templates | GET | every run, inside the scope |
| Path and parameter guesses | GET | `-dirs`, `-params` (need a scope) |
| GraphQL introspection | POST | `-graphql` (needs a scope) |
| A port's service | TCP connect, one `HEAD /` to a port that says nothing | `-ports`, `ports` |
| Chrome | what the page loads, inside the scope | `-browser`, `-login`, `shots`, `-role-login` |
| Writes of other roles | POST, PUT, PATCH, DELETE | `roles -replay-writes` (needs a scope) |

URLs whose names say a GET would change something are listed, not requested. Nothing goes to a host outside the scope.
