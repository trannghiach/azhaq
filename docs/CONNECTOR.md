# Connector protocol (`azhaq.connector.v1`)

A connector is an external program that adds facts to an Azhaq graph. Use one for data Azhaq does not collect itself, such as a paid search API or an internal asset database. The connector keeps its own SDK and API keys, and Azhaq only reads its output. `cmd/azhaq-index-fixture` is a small working example.

There are two ways to use one:

```
azhaq run -url https://app.example.com/ -exec ./my-connector   # Azhaq starts it with the run's seeds
azhaq ingest facts.jsonl                                       # load output produced earlier (several files, or - for stdin; -in FILE too)
```

## What a connector does not count against

A connector is a separate program, and what it sends is its own. Azhaq does not see its requests, so they:

- do not count against `-max-requests`;
- are not paced by `-rate`;
- are not in the request ledger (`DB.ledger.jsonl`, which lists what Azhaq itself sent).

Facts taken in with `azhaq ingest` were not sent by this run, so they are not in the ledger either.

## Transport

- One JSON object per line. Blank lines and lines starting with `#` are ignored.
- Azhaq writes seeds to the connector's stdin, then closes it.
- The connector writes facts to stdout.
- Stderr is shown only if the connector fails.
- Exit code 0 means success.

On a non-zero exit, Azhaq:

1. keeps the lines it already parsed;
2. counts the failure in the run's `errors`;
3. continues with its own collectors.

The connector's failure is a failure like any other. The run ends with exit 3, and the results are usable. `-fail-on-errors` makes every failure count, fan-out ones included.

A connector run with `-exec` must write facts.

## Input: seeds

```json
{"kind":"seed","seed":{"type":"Domain","keys":{"domain":"example.com"}}}
```

`type` is one of `URL`, `Hostname`, `Domain`, `IPAddress`, `Organization`, `CloudAccount`. A URL seed is also expanded to its hostname and registrable domain before it is sent. A connector that only handles domains still receives one.

## Output: facts

| `kind` | Meaning |
| --- | --- |
| `observation` | a fact about an entity |
| `hint` | a new seed for Azhaq to process |
| `entity` | create a node; it is also treated as a hint |
| `seed` | same as `hint` |
| `hello`, `meta` | optional status lines; accepted and ignored |

### observation

```json
{"kind":"observation","entity_type":"Hostname","entity_key":"api.example.com","collector":"my-connector","obs_kind":"hostname","payload":{"fqdn":"api.example.com"}}
```

If `entity_key` is missing, Azhaq takes the entity from `payload.url`, `payload.domain` or `payload.fqdn`. The fields can also be nested under an `observation` object.

### hint

```json
{"kind":"hint","seed":{"type":"Hostname","keys":{"fqdn":"api.example.com"}}}
```

### hello and meta

```json
{"kind":"hello","protocol":"azhaq.connector.v1","name":"my-connector"}
{"kind":"meta","ok":true,"items":12,"errors":0}
```

Only `kind` is checked. The other fields are free-form for logs.

## Errors

A line that is not valid JSON, or has an unknown `kind`, is rejected with `line N: <reason>`.

## Loading other tools' output with `azhaq ingest`

`azhaq ingest` also reads what the usual tools write, so their results can join a graph without a connector. It reads:

- subfinder, dnsx, httpx, katana, naabu, nuclei and gau JSON lines;
- an ffuf JSON report (`-of json`) or its `-json` lines;
- Azhaq's own `export`: entities and their observations come back, and edges are rebuilt from the observations;
- plain lines of URLs, hostnames and addresses.

Each line is read by its fields, and the summary counts the lines of each format. Into a workspace, the facts join its newest run.

```
subfinder -d example.com -json | azhaq ingest - -db example.db
httpx -l hosts.txt -json -o httpx.jsonl && azhaq ingest httpx.jsonl katana.jsonl -db example.db
```

Names taken in this way are `unresolved` until a run or `azhaq dns` looks them up. The dnsx and httpx lines that carry addresses count as resolved.

### How an answer is recorded

An answer httpx, katana or ffuf got to a GET is recorded as Azhaq's own probe records one. It is an `application` observation with these fields:

`url`, `status`, `title`, `server`, `content_type`, `tech`, `length`, `words`, `lines`, `ms`, `ip`, `location`, `final_url`, `final_status`.

Exports then read it as theirs:

- `targets`, `burp` and `html` list it as a web service.
- The map and `openapi` show it as how the URL answered.

### httpx

- `status_code` after `-fr` is where the redirects ended. It is taken in as Azhaq's `status`, the first answer (`chain_status_codes[0]`). `final_status` is the last.
- A line that `failed` is a request with no answer (`error`).

### katana

- A request katana sent with another method (a form it filled), or saw a page's script send (`-xhr`), is what the route takes, not its answer.
- Such a request gives the method and the body's field names, as a call in a script does. The names are a JSON object's keys, or a urlencoded or multipart form's names.
- The forms katana read (`-fx`) are the page's forms.
- katana follows redirects unless run with `-dr`, and says nothing of them. A URL it reached through one is taken in with the final page's status, length and forms.
- Run katana with `-dr` for each URL's own answer.

### ffuf

An ffuf run with `-X` and another method says only that the route takes it.
