# Concepts and terms

What the words in azhaq's output mean, each defined once. Other pages link here instead of explaining them again. `azhaq docs concepts` prints this page.

In this page:

- Results: [map row](#reading-a-map-row), [coverage](#coverage-what-azhaq-did-with-a-url), [evidence](#evidence-how-azhaq-knows-a-url), [kinds of URL](#kinds-of-url), [names](#names)
- Safety: [scope](#scope), [budget, pace and the kill switch](#budget-pace-and-the-kill-switch), [the ledger and its seal](#the-ledger-and-its-seal), [what azhaq sends](#what-azhaq-sends)
- Runs: [workspaces, runs and resuming](#workspaces-runs-and-resuming), [failures](#failures-fan-out-partial-and-degraded), [takeover candidates](#takeover-candidates)
- Testing access: [roles](#access-control-azhaq-roles)

## Reading a map row

The map is what `azhaq run` and `azhaq crawl` print: one row for each thing found.

```
URL http://localhost:3000/rest/2fa/verify  target  hint  api  POST
    POST  body tmpToken totpToken
```

| Part | Here | Meaning |
| --- | --- | --- |
| type | `URL` | What the row is: `URL`, `Hostname`, `Domain`, `IPAddress`, … |
| key | `http://localhost:3000/rest/2fa/verify` | The URL, name or address. A template such as `/api/Users/{id}` stands for URLs that differ by an identifier. |
| scope | `target` | `target` is what you asked about. `fanout` was found on the way. |
| coverage | `hint` | What azhaq did with the URL: see [Coverage](#coverage-what-azhaq-did-with-a-url). |
| kind | `api` | What the URL is: see [Kinds of URL](#kinds-of-url). |
| methods | `POST` | The methods its callers and descriptions use. |
| indented | `POST  body …` | One line for each operation or form, with the names it sends. |

`azhaq show -db W URL` prints everything known about one row, and where a script named it (`found in main.js:6472:88`).

A row's `scope` (`target` or `fanout`) is not the request [scope](#scope) that `-allow` and `-scope` set.

## Coverage: what azhaq did with a URL

| State | Meaning | What to do next |
| --- | --- | --- |
| `visited` | Requested; it answered as a page of its own (any status but 404 and 410). | Read it. |
| `catchall` | Requested; it answered with the page every unknown path gets (an app shell, a soft 404). Not proof the route exists. | Look at it in a browser, or use `-browser`. |
| `error` | Requested; no answer: timeout, refused, reset or TLS failure. | `azhaq query -db W -failed`, then try again. |
| `gone` | Requested; it answered 404 or 410. Usually an archived URL. | Try older API versions near it. |
| `hint` | Known from a script, a description, an archive or a link, not proven by a GET. Not requested, or scripts call it with another method. | Send the method in its operations yourself. |
| `skipped` | Not requested on purpose: its name says a GET would change something. Listed under "left alone". | `-get-words WORD`, or `-all-gets`, if you accept the side effect. |
| `capped` | Not requested: a limit (budget, depth, items) ran out first. | `azhaq resume -db W`. |

A `skipped` row has a `word` field that names the verb, such as `logout` or `delete`.

## Evidence: how azhaq knows a URL

Coverage says what azhaq did with a URL. Evidence says how azhaq knows the URL at all, and so what its status and size are worth. An `answered` row's status and size are what the server returned to azhaq's own request. Every other level is something a script, a description or a page said, never asked. Every URL row has an `evidence` field, and `evidence_from` lists the collectors behind it, sorted.

A row takes the strongest level any of its sources reaches, in this order:

| Level | Meaning |
| --- | --- |
| `answered` | This run requested it and the server answered: a status, not the origin's any-path answer, not a 404 or 410. |
| `browser` | Chrome, loading the page (`-browser`), sent the request itself, or the write it would have sent. Seen on the wire, not only written in a script. |
| `described` | An API description the run read lists it: OpenAPI or Swagger, or a cloud inventory given to the run. |
| `called` | A script calls it, with a `fetch` or XHR call and its method. Not asked, and not seen to happen. |
| `linked` | A page links to it, a form submits to it, or a script names it in a string or as a route. |
| `archived` | Only archive sources hold it: Wayback, Common Crawl, OTX, urlscan, Arquivo. |
| `guessed` | Only a wordlist guess found it, and the answer was a 404 or the origin's any-path answer. |
| `given` | You named the URL and nothing else holds it. It did not answer, so the row is `error`. |

### Rules

- A 404 does not make a row `answered`. The server said it is not there, so the row keeps the level of whatever named it.
- A row folded into a template (`/product?id={n}`) takes the strongest level of its instances and lists the collectors of all of them.
- Only URL rows have a level. Coverage still says what was done: `skipped` is a URL deliberately not asked, with the level it was named at.

### A 5xx without input

A 5xx that azhaq's plain request got from a route that takes names (query or body) carries `answer`: `500 without input`. The request carried none of the names, so the failure says little about the route. It is a lead only with something more, such as an error text in the body or a different answer for another session.

### Where evidence shows

- `azhaq query -fields key,evidence,evidence_from` shows it. `azhaq query -evidence answered,described` keeps the rows with those levels.
- At the end of a map row that is not `answered`: `[browser]`, `[described]`, `[called]`, `[linked]`, `[archived]`, `[guessed]` or `[given]`.
- In `export -format jsonl`: `evidence`, `evidence_from` and `answer`.
- In `export -format openapi`: `x-azhaq-evidence` on each operation.
- In the Evidence column of `export -format html`.

## Kinds of URL

- `app`: a front page.
- `auth`: it answered 401.
- `forbidden`: it answered 403.
- `api`, `page`, `script`, `asset`, `sourcemap`.
- `manifest`: a bundler's build manifest.
- `client-route`: a view a single-page app's router draws, such as `http://host/#/administration`, with the `guard` that keeps it.
- `websocket`: an endpoint scripts open a WebSocket to.

Views after the hash and sockets are never requested, so they stay `hint`. A view in the path (`http://host/admin`) is asked for once. If the server answers it (`auth`, `page`), that answer stands, with the guard noted beside it. If the app's shell answers instead, it stays a `client-route`.

## Names

| Status | Meaning |
| --- | --- |
| `live` | Resolves. A host you gave, or a name under a domain you gave. |
| `sibling` | Resolves. Found on the way, under another domain. |
| `unresolved` | From a source or a list, not looked up. |
| `dead` | Does not resolve: NXDOMAIN, no address, or SERVFAIL from every resolver. |
| `wildcard` | Resolves only because its zone answers for any name. |

Rows of the kinds `domain` (a domain you gave) and `addr` (an address) carry no status. [Which DNS answers are failures](#which-dns-answers-are-failures) says when a name counts as dead.

## Scope

The scope is the set of hosts a run may send to. No request to a target goes to a host outside it, and Chrome's requests are included.

- `-allow` names the domains, hosts or address ranges a run may touch. With any `-allow`, nothing else is requested.
- `-deny` names what the run must not touch, even when given as a target.
- `-scope` reads a program's scope: a file, or `hackerone`, `bugcrowd`, `intigriti` or `yeswehack` with `-program`. `azhaq scope` prints what a run would take, exclude and skip.
- With no rule, the scope is the targets you named, and Chrome stays on the site.
- Options that send more than the map does are held to the targets given, or to `-allow` and `-scope`: see [what azhaq sends](#what-azhaq-sends).

Requests the scope refuses are listed in the summary under `skipped`: see [OUTPUT](OUTPUT.md#the-summary). Targets that are all outside the scope exit 2: see [exit codes](OUTPUT.md#exit-codes).

### Hosts named in headers

A header that names a host is held to the scope too, because a front end routes by it. The headers are `Host`, `X-Forwarded-Host`, `X-Host` and `X-Original-Host`.

- With no `-allow`, `-deny` or `-scope`, a host you name in a header joins the targets you named.
- With a rule, a header that names a host outside it is refused before anything is sent. The command exits 2.
- A request file, an import (`params -i`), a `-vi` line and a `-role-cmd` bring headers you did not type. They are held to the targets.

## Budget, pace and the kill switch

Three controls bound what a run sends. They hold for every request to a target, Chrome's included.

- **Budget.** `-max-requests` is how many requests to targets a run may send. Port connects and UDP datagrams count too. `0` means no cap.
- **Pace.** `-rate` is requests per second to targets, over all hosts. Chrome's requests count too.
- **Kill switch.** `-kill-file PATH` names a file that stops all sending when it exists. The default is `DB.stop`.

The budget holds for each run: `azhaq resume` sends up to as many more as its own `-max-requests` says. Other limits end a run the same way: [exit code 4](OUTPUT.md#exit-codes) lists them. `azhaq plan` prints what a run would send before anything goes out.

### The kill file

- Create the file. Within a tenth of a second (the file is looked for every 100 ms) nothing more is sent.
- That includes a request already waiting for `-rate`, and Chrome's requests.
- The run exits 4. Its `stopped` says `the kill switch: kill file PATH exists, N tasks known and not done (remove it, then azhaq resume)`.
- Remove the file, then run `azhaq resume -db DB` to continue.
- A drop-in command without `-db` has no default kill file.
- `azhaq roles` uses `roles.stop` in its `-dir`. It stops the runs of the roles, and `roles` exits 4. The replay that follows does not look for it.

### Signals

Ctrl-C, `kill` and a hangup (SIGINT, SIGTERM and SIGHUP) all stop a command the same way. It exits 4, prints its summary and seals its ledger.

## Workspaces, runs and resuming

- A **workspace** is one SQLite file, set with `-db`. Every run into it adds to it. `query`, `show`, `export`, `diff` and `watch` read it.
- A **run** is one pass into a workspace. `azhaq resume` continues a run that a limit stopped.
- A run keeps the answers it got in its workspace until nothing is left to resume. `azhaq resume` does not ask again what the run already asked.
- The requests of a run that was stopped and resumed add up to a few more than those of one uninterrupted run, not twice as many.

File names and the runs that have no `-db` are in [OUTPUT](OUTPUT.md#the-workspace).

### Partial port scans

A port scan that the budget or the kill file cut short keeps the open ports it found. It also keeps the ports it asked, in a row marked `"partial":true` with `asked_ports`.

- `azhaq resume` asks only the other ports.
- It prints the open ports it finds as `ports` does: `-json` for objects, `-quiet` for the summary only.
- Ports an earlier run printed are not printed again, so the rows of the runs add up to the scan's.
- Its row, and `query` and `show` after it, hold every open port.

## The ledger and its seal

The ledger is the record of what a run sent. It has one JSON line for each request or connection sent to a target:

- HTTP requests.
- Chrome's requests, each once it has left, and its WebSocket handshakes with their path.
- TCP connects and TLS handshakes.
- UDP datagrams.

Each line has its time, the URL or `ip:port`, the host, the scope rule that allowed it and the collector. [OUTPUT](OUTPUT.md#the-ledger) lists the fields.

- **Chain.** Each line carries the hash of the one before, so an edited, removed or reordered line is caught.
- **Seal.** A run that ends writes a `seal` line, so lines cut from the end are caught too. The summary names the seal (`sealed 3f9c…`), and `ledger -verify` prints the last one.
- **Limit.** The chain alone cannot tell a ledger from one with lines removed and the rest re-chained. A seal kept apart from the file can: see the [`ledger` page](commands/ledger.md#output).
- **Not listed.** DNS queries, the third-party sources of `subs` and `urls`, and the RDAP registry are not targets.
- **File.** `DB.ledger.jsonl` sits next to the workspace. Later runs into the workspace, and `azhaq resume`, append to it.
- **Options.** `-ledger FILE` writes it elsewhere, and `-ledger off` writes none. A drop-in command without `-db` writes one only with `-ledger FILE`.
- **Roles.** `azhaq roles` keeps one ledger, `roles.ledger.jsonl`, in its `-dir`.

`azhaq ledger -verify FILE` checks the chain and the seal. `-summary FILE` counts the lines. `-csv FILE` exports them for a client report or a blue team's deconfliction. The [`ledger` page](commands/ledger.md) has the details, including exit 3.

## Failures: fan-out, partial and degraded

A failure is work that did not get its answer. Exit code 3 says some failed: see [exit codes](OUTPUT.md#exit-codes). Fan-out and partial failures are still listed, but they do not make the exit code 3.

### Fan-out

Fan-out is what you did not ask about. It is a name found on the way, and the third-party lookups (subdomain sources, archives, RDAP) of a domain that is only the domain of a URL you mapped.

- A failure there is listed with `"fanout": true`. The exit code stays 0, because the map of what you asked about is still complete.
- Ask for the domain itself (`-domain`, `subs -d`, `urls -d`) and its failures count.

### Partial

A failure is partial when one source failed while other sources answered for the same domain.

- It is listed with `"partial": true`. The exit code stays 0. Sources fail all the time, and an exit code that is always 3 says nothing.
- crt.sh holds the most names of any certificate log, but it is also the flakiest: gateway 5xx are common. A run that got its names from other sources should not fail a CI gate over a transient crt.sh failure. The failure is still listed.
- The summary's `sources` block and its last line say how many sources answered and which failed. Exit 0 is then not read as "all answered".
- `-fail-on-errors` counts every failure, crt.sh's among them.

### Degraded

A run is degraded when every source or archive failed, so an empty answer is not an honest zero. `subs` also sets `degraded` when a source in the default set failed while others answered. Its names are listed, and the exit code does not change. The field is described in [OUTPUT](OUTPUT.md#the-summary).

### Which DNS answers are failures

- A name answered SERVFAIL on every attempt, by two resolvers or more, on two passes, is not a failure. The resolvers answered alike, so the name's own DNS is broken for everyone: a lame delegation. The name is dead, with `result` `servfail`.
- Resolvers that time out, answer REFUSED (refusing this machine), or give SERVFAIL from one resolver alone, are a failure.
- One resolver's NXDOMAIN does not make a name dead. Nor does an answer without an address: `nodata`, or a CNAME chain that ends without one.
- In those cases a second resolver is asked once, and the name is dead only when both agree. A public resolver answers NODATA now and then for a name every other one resolves.
- The second resolver is another operator's. With the default pool, 1.1.1.1 is checked with 8.8.4.4, not 1.0.0.1.
- Names under a wildcard zone and special-use names are not asked twice.

## Takeover candidates

A takeover candidate is a name whose CNAME points at something gone, or whose front page is a hosting service's page for an unclaimed name. The target is a service name anyone may create, or a domain nobody holds. Confirm each by hand before reporting it.

| Strength | Meaning |
| --- | --- |
| `strong` | The CNAME points at a hosting service whose own page says nobody claimed the name, or at a name whose ICANN domain is not registered. |
| `dangling` | The CNAME points at a web name on Azure, Elastic Beanstalk or Fly.io that does not resolve. |
| `page` | One of those services' own pages, with no CNAME known. Where DNS shows the name points elsewhere, nothing is said. |

- The hosting pages that make a name `strong`: GitHub Pages' "There isn't a GitHub Pages site here.", S3's `NoSuchBucket`, Heroku's no-such-app page, Pantheon, Ghost, WordPress.com, Help Scout, ReadMe, ngrok, Bitbucket and Surge.
- A cloud's shared suffix such as `elb.amazonaws.com` is no registry and never counts as an unregistered domain.
- The Azure services for `dangling`: App Service, Cloud Services, CDN, API Management, Container Instances, HDInsight and Blob Storage.
- azhaq reads DNS answers (`subs -live`, `dns`, `run`) and front pages (`probe`, `run`). Even a plain `subs -live` flags a candidate.
- How a candidate is printed: see the `takeover` field in [OUTPUT](OUTPUT.md#the-summary).

## Access control (`azhaq roles`)

| Term | Meaning |
| --- | --- |
| role | A session: anonymous, headers (`-role`), headers from a command (`-role-cmd`), or a Chrome sign-in (`-role-login`). |
| replay | Every URL any role reached, asked with every other role as a GET, unless `-replay-writes` adds writes. |
| reads | Answered 2xx, and not with an error shaped as data. |
| refused | One of the cases under "What counts as refused" below. |
| owner, `owner_by` | Whose object it is, and the evidence: a token's claim, a list only that role sees, or the object's own owner field. |
| `confidence`, `evidence` | How surely the object is the owner's, and why in one line. `confidence` is `proved`, `likely` or `guess`. |
| control | A made-up identifier of the same shape on the same route. A route that answers it like a real object answers any identifier. |
| canary | An endpoint only a role's live session reads, checked during the replay. A session that dies is renewed, or its answers are `session_suspect`. |
| evidence | The answers behind the listed rows, secrets taken out, in `roles.db`: `azhaq roles show -dir DIR URL`. |
| dead session | A role refused wherever a session matters: its token expired or is wrong. Said in a note; the exit code is 3. |
| report | `azhaq report -dir DIR` writes each listed finding up from the evidence as a Markdown report to submit. It sends nothing. |

### What counts as refused

- Any 4xx.
- An error served with a 2xx status.
- The site's own `200 Access denied` page, or what `-refusal` matches.
- A redirect to a sign-in page.
- A redirect to the front page, when another role reads the endpoint directly.

### Confidence

- `proved`: both the session (or the owner's own list) and the object's answer say whose it is.
- `likely`: one of those two does.
- `guess`.

### Verdicts

Worst first:

1. anyone reads sensitive fields
2. reads another role's object
3. answers any identifier
4. every signed-in role reads the same object
5. roles read the same sensitive fields
6. same answer for a session that did not find it
7. signed-in only
8. only one role reads it
9. some roles refused
10. different fields per role
11. anyone reads the same object
12. status differs

With `-replay-writes`, three more come before them all:

- anyone writes another role's object
- writes another role's object
- writes another role's object: accepted; the change cannot be read back to confirm

## What azhaq sends

| What | Method | When |
| --- | --- | --- |
| Pages, scripts, API descriptions (at the root and under each API base), archived URL templates | GET | Every run, inside the scope. |
| 32 built-in path checks per web service: `robots.txt`, sitemaps, API descriptions, `.git/HEAD`, `backup`, `admin`, … | GET | Every run. `-no-paths` turns them off. |
| Path and parameter guesses | GET. `params -X` sends the names in a POST, JSON or XML body. | `-dirs`, `-params`, held to the targets given or to `-allow` and `-scope`. |
| GraphQL introspection | POST | `-graphql`, held to the targets given or to `-allow` and `-scope`. |
| A port's service | A TCP connect, then for a port that says nothing: protocol probes, one `HEAD /`, a TLS handshake. | `-ports`, `ports` |
| UDP ports | One datagram of the protocol's harmless request for each port; more when none came back. | `-ports-udp`, `ports -udp`, `-pu` |
| A wordlist in a request | The method and body you give it, with the wordlist's words in them. | `azhaq fuzz`, held to the host of `-u` or to `-allow` and `-scope`. |
| Chrome | What the page loads, inside the scope. | `-browser`, `-login`, `shots`, `-role-login` |
| Writes of other roles | POST, PUT, PATCH, DELETE | `roles -replay-writes`, held to the `-url` hosts or to `-allow` and `-scope`. |

### Ports

- For a port that says nothing, azhaq sends its own protocol's request on its usual number, one `HEAD /`, a TLS handshake, and one request of each of the other protocols until one answers. That is at most 24 more connects for each port.
- On a web port whose head names no product, azhaq sends a `GET /`.
- On 5432, 6379 and 27017–27019, it sends that database's own first request.
- A UDP port with no known protocol is asked four ways: a DNS query, an SNMP get, memcached's version, then an empty datagram.
- A UDP datagram is a protocol's harmless request, such as a DNS `. NS` or an SNMP GET of `sysDescr.0` with community `public`. When none came back, azhaq sends the next way its protocol has.

### Chrome

- Chrome sends GET, HEAD and CORS preflights (OPTIONS).
- While signing in, it sends every method the page sends: its sign-in request, and whatever the page's own scripts send meanwhile, such as a socket's polling POSTs. All of them are in the ledger.
- A page's own writes are refused and mapped, unless `-browser-writes`.
- Every download is refused and listed. Chrome saves nothing to disk.
- A page read for its requests is loaded without its images, fonts and media.

### What is held back

- The map (`run`, `crawl`) lists, and does not request, URLs whose names say a GET would change something: `/logout`, `/createdb`, `?phpids=on`. These are the "left alone" URLs.
- A wordlist sweep (`dirs`, `-dirs`, `fuzz`) asks every word, `/logout` included, as ffuf does. With a session, `dirs` holds those words back and `-all-gets` asks them.
- A URL that carries a scanner's payload in its path or query never enters the map. Examples are `<script>`, `../../etc/passwd` and `union select`, as archives often keep them. A scanner's own test file never enters either.
- No request to a target goes to a host outside the [scope](#scope), Chrome's included. Without a scope, requests stay on the site.
- Third-party sources (subdomain lists, archives, RDAP) are asked about your domains. `-passive` sends nothing to the targets.
- Every request and connection to a target goes in the [ledger](#the-ledger-and-its-seal). DNS queries and third-party sources do not.
- `-rate` paces what is sent and `-max-requests` caps it: see [budget, pace and the kill switch](#budget-pace-and-the-kill-switch).
