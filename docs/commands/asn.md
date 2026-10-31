# azhaq asn

The prefixes autonomous systems announce. Replaces asnmap.

## Synopsis

```
azhaq asn -a AS64500 | -l FILE | stdin  [-json]
```

## Examples

```
azhaq asn -a AS13335
```

## Output

One prefix per line; -json: {"as_number","as_name","prefix"}

`as_number`, `as_name`, `prefix`.

## Summary and exit codes

The summary and the exit codes are the shared ones: see [OUTPUT.md](../OUTPUT.md#exit-codes).

## Flags

<!-- flags:begin asn -->
| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-a` | string, repeatable |  | AS number such as AS64500 |
| `-db` | string |  | keep the graph in this database for query, show, export and diff (default: a temporary one) |
| `-json` | bool |  | JSONL output, and the summary as one JSON object on stderr |
| `-l` | string |  | file of AS numbers (- for stdin) |
| `-o` | string |  | also write results to this file |
| `-silent` | bool |  | results only: no progress; the summary only when something failed (a source that failed, a takeover candidate as a [takeover] line on stderr); stdout stays one result per line |
| `-timeout` | duration |  | stop after this long and keep what was found; azhaq resume continues (0: no limit) |
| `-v` | bool |  | print a line for every finished task, not only failures |
<!-- flags:end -->
