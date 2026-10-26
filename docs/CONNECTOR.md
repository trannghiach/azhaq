# Connector protocol (`azhaq.connector.v1`)

A connector is an external program that adds facts to an Azhaq graph. Use one for data Azhaq does not collect itself, such as a paid search API or an internal asset database. The connector keeps its own SDK and API keys, and Azhaq only reads its output.

There are two ways to use one:

```
azhaq run -url https://app.example.com/ -exec ./my-connector   # Azhaq starts it with the run's seeds
azhaq ingest -in facts.jsonl                                   # load output produced earlier
```

`azhaq ingest` also reads what the usual tools write, so their results can join a graph without a connector: subfinder, dnsx, httpx, katana, naabu, nuclei and gau JSON lines, an ffuf JSON report (`-of json`), Azhaq's own `export`, and plain lines of URLs, hostnames and addresses. Each line is read by its fields; the summary counts the lines of each format. Into a workspace, the facts join its newest run.

```
subfinder -d example.com -json | azhaq ingest -in - -db example.db
httpx -l hosts.txt -json -o httpx.jsonl && azhaq ingest -in httpx.jsonl -db example.db
```

Names taken in this way are `unresolved` until a run or `azhaq dns` looks them up; the dnsx and httpx lines that carry addresses count as resolved.

`cmd/azhaq-index-fixture` is a small working example.

## Transport

- One JSON object per line. Blank lines and lines starting with `#` are ignored.
- Azhaq writes seeds to the connector's stdin, then closes it.
- The connector writes facts to stdout. Stderr is shown only if the connector fails.
- Exit code 0 means success. On a non-zero exit, Azhaq keeps the lines it already parsed, counts the failure in the run's `errors`, and continues with its own collectors. With `-fail-on-errors`, `azhaq` exits 1 after printing the summary.

## Input: seeds

```json
{"kind":"seed","seed":{"type":"Domain","keys":{"domain":"example.com"}}}
```

`type` is one of `URL`, `Hostname`, `Domain`, `IPAddress`, `Organization`, `CloudAccount`. A URL seed is also expanded to its hostname and registrable domain before it is sent, so a connector that only handles domains still receives one.

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

`azhaq ingest` reads the output of `azhaq export` too: entities and their observations come back; edges are rebuilt from the observations. `-exec` connectors must write facts.
