# azhaq new

What a workspace first saw lately.

## Synopsis

```
azhaq new -db WORKSPACE.db [-since 168h] [-json]
```

## Examples

```
azhaq new -db acme.db -since 24h
```

## Output

One entity per line with when it was first seen.

## Summary and exit codes

The summary and the exit codes are the shared ones: see [OUTPUT.md](../OUTPUT.md#exit-codes).

## Flags

<!-- flags:begin new -->
| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-db` | string |  | workspace database (required) |
| `-json` | bool |  | JSONL |
| `-since` | duration | `168h0m0s` | first seen within this long |
<!-- flags:end -->
