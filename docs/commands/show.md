# azhaq show

Everything known about one URL, host or name: what found it, what it leads to, every observation.

## Synopsis

```
azhaq show -db FILE [-json] KEY
```

## Examples

```
azhaq show -db app.db https://app.example.com/api/users
```

## Output

The entity's row, its links and its observations.

`show -json` prints one object: `row` (the map row, with `found_in`), `links` (`rel`, `dir` in or out, `type`, `key`) and `observations` (`collector`, `kind`, `source`, `observed_at`, `payload`; an `azhaq-js` observation's payload holds the `found_in` of the page it read); for a hostname, `services`: its front pages with `coverage`, `status`, `title`, and the `error` of one that failed. A GraphQL endpoint read with `-graphql` has an `azhaq-graphql-schema` observation whose payload holds `queries`, `mutations`, `subscriptions` and `types` (names) and `schema`, the introspection's whole `__schema` object (past 8 MB without its descriptions; past that left out, with its size in `schema_bytes`). A server that refuses the full introspection query for its depth is asked for the names only, and `schema` is absent. A server with introspection turned off is asked for root fields by name, as clairvoyance does: its validation errors (`Cannot query field "pastez" on type "Query". Did you mean "pastes"?`, `Field "paste" of type "PasteObject" must have a sub selection`, required arguments) give the payload `queries`, `mutations`, `types` and `signatures` (`uploadPaste(content: String!, filename: String!): UploadPaste`), with `"recovered":"suggestions"`. Three kinds of word are tried, in this order: `client`, a GraphQL operation's field, argument and type names the map already found in HTML and scripts on the endpoint's origin (`client_words` counts them); `probe`, the built-in wordlist of verbs and nouns (get, list, all, create, update, delete, import, upload, system, health, diagnostics, user, paste, …), `-graphql-wordlist`, and the parts of names already recovered, recombined pairwise and with an "All" infix for CRUD conventions (`delete` + `all` + `pastes` tries `deleteAllPastes`); and `suggestion`, a name a validation error names outright. The payload's `recovery` object gives each root type's field count, how many were found each way (`"by":{"client":1,"probe":6}`) and how many words were tried (`words_tried`), and `complete` is always `false`: recovery cannot prove a type has no more fields than it found. That is not the server's schema: it lacks types, fields it never suggested, and the types of fields whose errors did not name them. The exports mark it as partial (below), and a whole schema read by introspection is not marked. Every document asked carries a field no schema has, so none passes validation and nothing runs. A GraphQL endpoint found by a run (an `azhaq-graphql` observation) has `get_queries` true when it answers `{__typename}` sent with GET.

## Summary and exit codes

The summary and the exit codes are the shared ones: see [OUTPUT.md](../OUTPUT.md#exit-codes).

## Flags

<!-- flags:begin show -->
| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-db` | string |  | the database (default: the last run's) |
| `-json` | bool |  | one JSON object |
<!-- flags:end -->
