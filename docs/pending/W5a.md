# W5a: how each row is known

## Evidence levels

Every URL row in the map says how azhaq knows it, in a field `evidence`; `evidence_from` lists the collectors behind it, sorted. A row takes the strongest level any of its sources reaches, in this order:

| level | meaning |
|---|---|
| answered | this run requested it and the server answered: a status, not the origin's any-path answer, not a 404 or 410 |
| described | an API description the run read lists it (OpenAPI or Swagger, or a cloud inventory given to the run) |
| called | a script calls it (a `fetch` or XHR call with its method), or Chrome saw the request |
| linked | a page links to it, a form submits to it, or a script names it in a string or as a route |
| archived | only archive sources (Wayback, Common Crawl, OTX, urlscan, Arquivo) hold it |
| guessed | only a wordlist guess found it, and the answer was a 404 or the origin's any-path answer |

A 404 does not make a row answered: the server said it is not there, so the row keeps the level of whatever named it. A row folded into a template (`/product?id={n}`) takes the strongest level of its instances and lists the collectors of all of them. Only URL rows have a level.

Where it shows:

- `azhaq query -fields key,evidence,evidence_from`; `azhaq query -evidence answered,described` keeps the rows with those levels.
- The map `run` prints: a row that is not answered ends with `[described]`, `[called]`, `[linked]`, `[archived]` or `[guessed]`.
- `export -format jsonl`: `evidence` and `evidence_from` on each entity line.
- `export -format openapi`: `x-azhaq-evidence` on each operation (the level of the route; a served description's operations are `described`, a form's are `linked`).
- `export -format html`: an Evidence column in the API and map tables.

## GraphQL schemas read without introspection

When a server refuses the introspection query, `-graphql` recovers root fields from its validation errors ("Did you mean ..."). That is not the server's schema: it lacks types, fields it never suggested, and the types of fields whose errors did not name them.

- `export -format sdl` starts each recovered endpoint with `# introspection disabled on URL; recovered from N validation errors and M client operations: partial, may lack types and fields`, then the root types as far as they were recovered. Fields whose type was not recovered are listed in a comment; the client operations found in scripts are listed in a comment too.
- `export -format graphql` adds `"x-azhaq": {"introspection": false, "recovered": "suggestions", "partial": true}` beside `data` (inside each endpoint's object when several are keyed by URL), with `validation_errors`, `client_operations` and `untyped_fields` when known.
- The `run` summary says `GraphQL URL: introspection disabled: schema recovered (partial)`, or `introspection: full schema`. The map rows' operation lists and the openapi `x-azhaq-graphql` carry the same mark.
- A whole schema, read by introspection, is not marked.
