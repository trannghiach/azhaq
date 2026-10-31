# azhaq ledger

Check, count or export the record of every request and connection a run sent to a target.

## Synopsis

```
azhaq ledger -verify FILE | -summary FILE [-json] | -csv FILE
```

## Examples

```
azhaq ledger -verify app.db.ledger.jsonl
azhaq ledger -summary app.db.ledger.jsonl
azhaq ledger -csv app.db.ledger.jsonl > sent.csv
```

## Output

Verify: entries and whether the hash chain is intact (exit 3, naming the first bad line, when not); summary: counts by kind, host, method and scope rule, first and last time; csv: one row per entry.

## Summary and exit codes

The summary and the exit codes are the shared ones: see [OUTPUT.md](../OUTPUT.md#exit-codes).

## Flags

<!-- flags:begin ledger -->
| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-csv` | string |  | print the ledger as CSV |
| `-json` | bool |  | with -summary: one JSON object |
| `-seal` | string |  | with -verify: a seal hash kept where the run's own files are not (or a file of one per line, or the JSON lines -seal-to writes) that must be one of the chain's seals; without it, -verify cannot tell the file from one with lines removed and the rest re-chained to look intact |
| `-summary` | string |  | count the ledger's requests and connections by kind, host and method, with the first and last time |
| `-verify` | string |  | check the ledger's chain of hashes and its seal: exit 0 when intact and sealed, 3 naming the first line that is not intact, or the lines after the last seal |
<!-- flags:end -->
