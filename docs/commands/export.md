# azhaq export

Write a database in another tool's format.

## Synopsis

```
azhaq export [-db FILE] [-format jsonl|urls|hosts|names|targets|openapi|graphql|sdl|burp|html|graphml|secrets] [-origin ORIGIN|URL] [-safe]
```

## Examples

```
azhaq export -db app.db -format openapi > app.openapi.json
azhaq export -db app.db -format graphql -origin https://app.example.com/graphql > schema.json
azhaq export -db app.db -format sdl > schema.graphql
azhaq export -db h1.db -format burp > scope.json
azhaq export -db h1.db -format targets | nuclei -l -
```

## Output

The chosen format; graphql: {"data":{"__schema":…}} of a GraphQL endpoint read with -graphql (keyed by URL when there are several; -origin picks one), sdl: its schema in GraphQL SDL, burp: the run's scope, allow rules as include and deny rules as exclude.

`azhaq export -db FILE -format F` writes the newest run of a workspace in one format on stdout.

| Format | Output |
| --- | --- |
| `jsonl` | Everything: one object per map row (`"kind":"entity"`, with `evidence` and `evidence_from`), observation and edge. |
| `urls`, `hosts`, `names`, `targets` | One per line: every URL; names that resolve, and addresses given as targets or serving the web; every name; web services (front pages that answered, Azhaq's or taken in from httpx, katana or ffuf), for `nuclei -l` and `httpx`. |
| `openapi` | OpenAPI 3 JSON of one origin (`-origin`, default the one with the most API routes): the description the target serves, as it is, plus the routes scripts call, forms, the pages found with a query string of their own (a GET taking those names) and what answered. A route the run left alone (`skipped`) has no GET or HEAD of azhaq's making in it: a tool importing the description would send one. Where the served description lists such a route anyway (VAmPI's `GET /createdb`), or azhaq guessed its POST, each operation carries `x-azhaq-skipped: true` and `x-azhaq-skipped-reason` (`looks like a GET would change something (createdb)`), and `-safe` leaves those operations out, for a tool that must not touch them. A GET form's fields are query parameters of its action's GET; a POST form's are its request body, `application/x-www-form-urlencoded` or `multipart/form-data` as its `enctype` says, a file input `"format":"binary"`. A form adds the fields an operation the export made lacks; a served description's operations are left as they are. `x-azhaq` on each operation: `source`, `coverage`, `status`, `needs_credentials`; `x-azhaq-evidence` beside it is the level of the route (a served description's operations are `described`, a form's `linked`). |
| `graphql` | The introspection result of each GraphQL endpoint read with `-graphql`, as InQL, Burp, Postman, graphql-voyager and clairvoyance read it. A schema recovered from validation errors has `"x-azhaq": {"introspection": false, "recovered": "suggestions", "partial": true, "complete": false}` beside `data` (inside each endpoint's object when several are keyed by URL), with `validation_errors`, `client_operations`, `client_words` and `untyped_fields` when known. `complete` is always `false` on a recovery: it cannot prove a type has no more fields. |
| `sdl` | The same schemas in the GraphQL schema language. A schema recovered from validation errors, not read by introspection, starts with `# introspection disabled on URL; recovered from N validation errors and M client operations: partial, may lack types and fields; recovery does not prove there are no others`, a `# recovered fields: …` line with each root type's field count and how they were found (client, probe, suggestion) and how many words were tried, then the root types as far as they were recovered; fields whose type was not recovered, and the client operations found in scripts, are listed in comments. |
| `burp` | Burp Suite project options with the run's target scope. |
| `html` | One self-contained page: web services, names, screenshots (embedded, 560 pixels wide; the page opens from any directory), secrets, API routes (with an Evidence column), the map. A picture file missing from where the run named it and from beside the database is listed as not found. For thousands of pictures use `azhaq gallery`, the interactive view (see [gallery](gallery.md)). |
| `graphml` | The graph for Gephi, yEd or Cytoscape. |
| `secrets` | Credentials found in scripts: severity, kind, value, script, tab-separated. |

A format that finds nothing writes nothing and says why on stderr (`azhaq export: nothing to write: the workspace holds no host names (a run of a URL or an address has none: …)`); the exit code is 0.

**openapi** is a valid OpenAPI document whatever went into it: every operationId is unique (a served description's keep theirs; a repeat, such as `/blog` and `/blog/` both `get_blog`, gets `_2`, `_3` in path order), templates that differ only by their parameter names are one path (the served description's, else the first), every `{name}` in a path is a declared path parameter, a parameter is listed once, and component names OpenAPI does not allow are renamed with their references. A GraphQL endpoint is one `POST` taking `{"query","operationName","variables"}`, not a made-up REST mapping; its operations are in `x-azhaq-graphql`: An API route left alone for its name (`/user/change-email`) whose callers do not say the method is described as a POST, with `x-azhaq.method` saying it is a guess; never as a GET.

```json
"x-azhaq-graphql":{"operations":[
  {"type":"query","name":"pastes","arguments":[{"name":"public","type":"Boolean"},{"name":"limit","type":"Int"}],"returns":"[PasteObject]"},
  {"type":"mutation","name":"createPaste","arguments":[{"name":"burn","type":"Boolean","default":"false"}],"returns":"CreatePaste"}]}
```

`type` is `query`, `mutation` or `subscription`; `default` is a GraphQL literal; `deprecated` is set on deprecated fields. A schema kept by names only gives `type` and `name`. A schema recovered from validation errors (see `show`) adds `"introspection": false, "recovered": "suggestions", "partial": true, "complete": false` beside `operations`, and the text map puts `GraphQL: introspection disabled, schema recovered (partial, may lack types and fields)` above the endpoint's operations.

**graphql** prints `{"data":{"__schema":{…}}}`, the server's answer to the standard introspection query. With several endpoints it prints one object keyed by endpoint URL, `{"https://app/graphql":{"data":{"__schema":…}},…}`; `-origin` keeps the endpoints of one origin, or the one at a URL (`-origin https://app/graphql`), to get a file a tool loads as it is. **sdl** prints each endpoint's schema under a `# URL` comment: types, interfaces, unions, enums, input objects, custom scalars and directives with descriptions, defaults and `@deprecated`, without the built-in scalars and directives; a `schema { … }` block when the root types are not simply `Query`, `Mutation` and `Subscription`. Concatenated schemas of several endpoints are not one schema: pick one with `-origin`.

**burp** writes `{"target":{"scope":{"advanced_mode":true,"include":[…],"exclude":[…]}}}`. When the run had a scope, `include` holds its allow rules (`-scope` and `-allow`) and `exclude` its deny rules (the program's out-of-scope entries and `-deny`), each for any protocol, port and path: a domain is `{"enabled":true,"protocol":"any","host":"^(.*\\.)?example\\.com$"}` (it and its subdomains), one host `^api\\.example\\.com$`, an address `^192\\.0\\.2\\.7$`, a range as Burp takes it (`10.0.0.0/24`). The scope is read back from the run's options: a scope file again (stored by its full path), and a platform's program (`-scope hackerone -program x`) as it stands now, from bounty-targets-data. A run without allow rules, or whose scope file is gone (a note on stderr says so), includes every web service it found: `{"enabled":true,"protocol":"https","host":"^app\\.example\\.com$","port":"^443$","file":"^/.*"}`. `azhaq run -scope` reads the file back.

## Summary and exit codes

The summary and the exit codes are the shared ones: see [OUTPUT.md](../OUTPUT.md#exit-codes).

## Flags

<!-- flags:begin export -->
| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-db` | string |  | sqlite path (default: last run) |
| `-format` | string | `jsonl` | jsonl (everything), urls, hosts (names that resolve), names (every name), targets (web services, for nuclei -l), openapi, graphql (introspection JSON), sdl (GraphQL schema), burp (the run's scope), html, graphml, secrets |
| `-origin` | string |  | openapi: the origin to describe (default: the one with most API routes); graphql, sdl: the endpoints of an origin, or one endpoint's URL |
| `-safe` | bool |  | openapi: leave out the routes the run left alone as state-changing (otherwise they carry x-azhaq-skipped: true), for a tool that must not touch them |
<!-- flags:end -->
