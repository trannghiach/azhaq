# azhaq hunt

Where to look first: the mapped routes, hosts and files ranked, each with its evidence and the next command.

## Synopsis

```
azhaq hunt -db FILE [-roles roles.jsonl] [-limit 25] [-since 168h] [-json]
```

## Examples

```
azhaq hunt -db app.db
azhaq roles -json -role anon -role 'user=Authorization: Bearer …' -- -url https://app.example.com/ > roles.jsonl; azhaq hunt -db app.db -roles roles.jsonl
```

## Output

One row per route template: rank, score, key, the reasons, and the command to run next (-json: rank, score, key, type, reasons, next)

## Summary and exit codes

The summary and the exit codes are the shared ones: see [OUTPUT.md](../OUTPUT.md#exit-codes).

## Flags

<!-- flags:begin hunt -->
| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-db` | string |  | workspace database (default: the last run's) |
| `-json` | bool |  | one JSON object per row, and the summary as JSON on stderr |
| `-limit` | int | `25` | rows at most, best first |
| `-roles` | string, repeatable |  | the JSONL azhaq roles -json printed: rows where one role reached another's data rank first |
| `-since` | duration | `168h0m0s` | first seen within this long is new: a bonus, never the reason a row ranks |
<!-- flags:end -->
