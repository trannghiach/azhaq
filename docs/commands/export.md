# azhaq export

Write a database in another tool's format.

## Synopsis

```
azhaq export [-db FILE] [-format jsonl|urls|hosts|names|targets|openapi|graphql|sdl|burp|html|graphml|secrets] [-origin ORIGIN|URL] [-safe]
```

## Examples

```
# OpenAPI 3 description of the origin with the most API routes
azhaq export -db app.db -format openapi > app.openapi.json

# The introspection JSON of one GraphQL endpoint
azhaq export -db app.db -format graphql -origin https://app.example.com/graphql > schema.json

# The same schema in GraphQL SDL
azhaq export -db app.db -format sdl > schema.graphql

# A run's scope, as Burp Suite project options
azhaq export -db h1.db -format burp > scope.json

# Web services, for nuclei
azhaq export -db h1.db -format targets | nuclei -l -
```

## What it does

`azhaq export -db FILE -format F` writes the newest run of a workspace in one format on stdout. Without `-db` it uses the last run's database. `-format` defaults to `jsonl`.

## Output

The output is the format you chose, on stdout.

| Format | Output |
| --- | --- |
| `jsonl` | Everything: one object per map row (`"kind":"entity"`, with `evidence` and `evidence_from`), observation and edge. |
| `urls` | Every URL, one per line. |
| `hosts` | One per line: names that resolve, and addresses given as targets or serving the web. |
| `names` | Every name, one per line. |
| `targets` | Web services, one per line, for `nuclei -l` and `httpx`. See Details. |
| `openapi` | OpenAPI 3 JSON of one origin. See [openapi](#openapi). |
| `graphql` | The introspection result of each GraphQL endpoint read with `-graphql`. See [graphql and sdl](#graphql-and-sdl). |
| `sdl` | The same schemas in the GraphQL schema language. See [graphql and sdl](#graphql-and-sdl). |
| `burp` | Burp Suite project options with the run's target scope. See [burp](#burp). |
| `html` | One self-contained page. See [html](#html). |
| `graphml` | The graph for Gephi, yEd or Cytoscape. |
| `secrets` | Credentials found in scripts, tab-separated: severity, kind, value, script. |

## Summary and exit codes

A format that finds nothing writes nothing and says why on stderr. The exit code is 0.

```
azhaq export: nothing to write: the workspace holds no host names (a run of a URL or an address has none: …)
```

The summary and the other exit codes are the shared ones: see [OUTPUT.md](../OUTPUT.md#exit-codes).

## Details

### targets

`targets` lists the front pages that answered. They are azhaq's own, or taken in from httpx, katana or ffuf.

### html

- The page holds web services, names, screenshots, secrets, API routes (with an Evidence column) and the map.
- Screenshots are embedded, 560 pixels wide. The page opens from any directory.
- A picture file missing from where the run named it and from beside the database is listed as not found.
- For thousands of pictures use the interactive view, [gallery](gallery.md).

### openapi

`openapi` describes one origin: `-origin`, default the one with the most API routes. It holds:

- the description the target serves, as it is
- the routes that scripts call
- forms
- the pages found with a query string of their own (a GET taking those names)
- what answered

It is a valid OpenAPI document whatever went into it:

- Every `operationId` is unique. A served description's keep theirs. A repeat gets `_2`, `_3` in path order: `/blog` and `/blog/` are both `get_blog`.
- Templates that differ only by their parameter names are one path: the served description's, else the first.
- Every `{name}` in a path is a declared path parameter, and a parameter is listed once.
- Component names that OpenAPI does not allow are renamed, with their references.

#### Routes the run left alone

A route the run left alone (`skipped`) has no GET or HEAD of azhaq's making in it. A tool importing the description would send one.

- The served description may list such a route anyway, such as VAmPI's `GET /createdb`. Or azhaq may have guessed its POST.
- Each such operation carries `x-azhaq-skipped: true` and `x-azhaq-skipped-reason`, for example `looks like a GET would change something (createdb)`.
- `-safe` leaves those operations out, for a tool that must not touch them.
- An API route left alone for its name (`/user/change-email`), whose callers do not say the method, is described as a POST. `x-azhaq.method` says it is a guess. It is never described as a GET.

#### Forms

- A GET form's fields are query parameters of its action's GET.
- A POST form's fields are its request body: `application/x-www-form-urlencoded` or `multipart/form-data`, as its `enctype` says. A file input is `"format":"binary"`.
- A form adds the fields that an operation the export made lacks. A served description's operations are left as they are.

#### The x-azhaq fields

- `x-azhaq` on each operation holds `source`, `coverage`, `status` and `needs_credentials`.
- `x-azhaq-evidence` beside it is the evidence level of the route: `described` for a served description's operations, `linked` for a form's.

#### GraphQL in openapi

A GraphQL endpoint is one `POST` taking `{"query","operationName","variables"}`, not a made-up REST mapping. Its operations are in `x-azhaq-graphql`:

```json
"x-azhaq-graphql":{"operations":[
  {"type":"query","name":"pastes","arguments":[{"name":"public","type":"Boolean"},{"name":"limit","type":"Int"}],"returns":"[PasteObject]"},
  {"type":"mutation","name":"createPaste","arguments":[{"name":"burn","type":"Boolean","default":"false"}],"returns":"CreatePaste"}]}
```

- `type` is `query`, `mutation` or `subscription`.
- `default` is a GraphQL literal. `deprecated` is set on deprecated fields.
- A schema kept by names only gives `type` and `name`.
- A schema recovered from validation errors (see [show](show.md#recovering-a-schema-when-introspection-is-off)) adds `"introspection": false, "recovered": "suggestions", "partial": true, "complete": false` beside `operations`.
- The text map puts `GraphQL: introspection disabled, schema recovered (partial, may lack types and fields)` above the endpoint's operations.

### graphql and sdl

`graphql` prints `{"data":{"__schema":{…}}}`: the server's answer to the standard introspection query. Tools such as InQL, Burp, Postman, graphql-voyager and clairvoyance read it.

- With several endpoints it prints one object keyed by endpoint URL: `{"https://app/graphql":{"data":{"__schema":…}},…}`.
- `-origin` keeps the endpoints of one origin, or the one at a URL (`-origin https://app/graphql`). Use it to get a file that a tool loads as it is.

`sdl` prints each endpoint's schema under a `# URL` comment:

- It holds types, interfaces, unions, enums, input objects, custom scalars and directives, with descriptions, defaults and `@deprecated`.
- It leaves out the built-in scalars and directives.
- It adds a `schema { … }` block when the root types are not simply `Query`, `Mutation` and `Subscription`.
- Concatenated schemas of several endpoints are not one schema. Pick one with `-origin`.

#### A schema recovered from validation errors

When a server has introspection turned off, the schema is recovered from its validation errors. It is partial. `show` explains how it is recovered: see [show](show.md#recovering-a-schema-when-introspection-is-off).

- In `graphql`, `"x-azhaq": {"introspection": false, "recovered": "suggestions", "partial": true, "complete": false}` sits beside `data`. With several endpoints it sits inside each endpoint's object.
- Beside it are `validation_errors`, `client_operations`, `client_words` and `untyped_fields`, when known.
- `complete` is always `false` on a recovery: it cannot prove that a type has no more fields.
- In `sdl`, the schema starts with this comment:

```
# introspection disabled on URL; recovered from N validation errors and M client operations: partial, may lack types and fields; recovery does not prove there are no others
```

- Next comes a `# recovered fields: …` line. It gives each root type's field count, how the fields were found (client, probe, suggestion) and how many words were tried.
- Then come the root types, as far as they were recovered.
- Fields whose type was not recovered, and the client operations found in scripts, are listed in comments.

### burp

`burp` writes `{"target":{"scope":{"advanced_mode":true,"include":[…],"exclude":[…]}}}`.

- When the run had a scope, `include` holds its allow rules (`-scope` and `-allow`). `exclude` holds its deny rules: the program's out-of-scope entries and `-deny`.
- Each rule is for any protocol, port and path.
- The scope is read back from the run's options. A scope file is read again (it is stored by its full path). A platform's program (`-scope hackerone -program x`) is read as it stands now, from bounty-targets-data.
- A run without allow rules includes every web service it found. So does a run whose scope file is gone, and a note on stderr says so.
- `azhaq run -scope` reads the file back.

Rules look like this:

| Rule for | Looks like |
| --- | --- |
| A domain, and its subdomains | `{"enabled":true,"protocol":"any","host":"^(.*\\.)?example\\.com$"}` |
| One host | `^api\\.example\\.com$` |
| An address | `^192\\.0\\.2\\.7$` |
| A range, as Burp takes it | `10.0.0.0/24` |
| A web service, when there are no allow rules | `{"enabled":true,"protocol":"https","host":"^app\\.example\\.com$","port":"^443$","file":"^/.*"}` |

## Flags

<!-- flags:begin export -->
| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-db` | string |  | sqlite path (default: last run) |
| `-format` | string | `jsonl` | jsonl (everything), urls, hosts (names that resolve), names (every name), targets (web services, for nuclei -l), openapi, graphql (introspection JSON), sdl (GraphQL schema), burp (the run's scope), html, graphml, secrets |
| `-origin` | string |  | openapi: the origin to describe (default: the one with most API routes); graphql, sdl: the endpoints of an origin, or one endpoint's URL |
| `-safe` | bool |  | openapi: leave out the routes the run left alone as state-changing (otherwise they carry x-azhaq-skipped: true), for a tool that must not touch them |
<!-- flags:end -->
