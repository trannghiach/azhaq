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
