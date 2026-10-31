# azhaq diff

Compare two runs.

## Synopsis

```
azhaq diff -a OLD.db -b NEW.db | -db WORKSPACE.db  [-jsonl] [-quiet]
```

## Examples

```
azhaq diff -db acme.db
```

## Output

Entities added and removed, new observations.

## Summary and exit codes

The summary and the exit codes are the shared ones: see [OUTPUT.md](../OUTPUT.md#exit-codes).

## Flags

<!-- flags:begin diff -->
| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-a` | string |  | old sqlite |
| `-b` | string |  | new sqlite (default: last run) |
| `-db` | string |  | workspace: compare the last two runs recorded in this database |
| `-jsonl` | bool |  | emit JSONL instead of a text report |
| `-quiet` | bool |  | entities and counts only (skip observation lines) |
<!-- flags:end -->
