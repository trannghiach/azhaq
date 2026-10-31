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

`azhaq ledger -verify FILE` recomputes the chain and prints the number of entries and runs, whether it is intact and the hash of the last seal: exit 0 when it is intact and ends with a seal; exit 3 naming the first line that is not intact (`line 3: hash does not match the content: the line was edited`), or, when lines follow the last seal, saying how many (`NOT SEALED: the last 9 were written after the last seal`: a run killed, crashed or still running, or lines cut from the end). That proves only that no *recorded* line was edited, removed or reordered: a run of lines cut from the middle and the rest re-chained from there (new `seq`, `prev` and `hash`, written exactly as the ledger itself writes them) is internally consistent, so recomputing the chain alone calls it intact and sealed too, with a smaller entry count and a different last seal. Only a seal kept apart from the ledger's own file proves that did not happen: `-verify FILE -seal HASH` (or `-seal FILE` of one hash a line, or the JSON lines `-seal-to` writes, matched by their `seal` field) additionally requires that HASH be the hash of one of the chain's own seals, and fails, exit 3, when it is not (`the chain is intact, but none of its seals is the one given`). `-seal-to FILE` (a run flag) appends one line (`{"time","ledger","seal","entries"}`) when the run ends, to a file or by POSTing JSON to an `http(s)://` URL, so the seal lives somewhere the ledger's own files, and whoever could edit them, do not reach. `-summary FILE` and `-csv FILE` leave the seals out. `-summary` counts the lines by `kind`, `method`, `host` and `rule`, with the first and last time (`-json`: one object, `entries`, `file`, `first`, `last`, `kinds`, `methods`, `hosts`, `rules`). `-csv FILE` prints one row per line with the columns `seq`, `time`, `kind`, `method`, `target`, `host`, `rule`, `collector` and `hash`. A summary of a run that wrote a ledger has the note `ledger: N requests and connections recorded in FILE, sealed HASH (azhaq ledger -verify FILE -seal HASH; the seal alone proves no line was later removed and the rest re-chained)`.

## Summary and exit codes

`ledger -verify` exits 3 when the chain is broken or lines follow the last seal.

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
