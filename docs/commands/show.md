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

## Summary and exit codes

The summary and the exit codes are the shared ones: see [OUTPUT.md](../OUTPUT.md#exit-codes).

## Flags

<!-- flags:begin show -->
| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-db` | string |  | the database (default: the last run's) |
| `-json` | bool |  | one JSON object |
<!-- flags:end -->
