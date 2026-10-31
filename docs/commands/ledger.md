# azhaq ledger

Check, count or export the record of every request, connection and query a run sent: to targets, to third-party sources and to resolvers.

## Synopsis

```
azhaq ledger -verify FILE | -summary FILE [-json] | -csv FILE
```

## Examples

```
# Is the chain intact, and does the run end with a seal?
azhaq ledger -verify app.db.ledger.jsonl

# Check it against a seal kept somewhere else
azhaq ledger -verify app.db.ledger.jsonl -seal HASH

# Count the requests by class, kind, method, host and scope rule
azhaq ledger -summary app.db.ledger.jsonl

# One row per request, for a spreadsheet
azhaq ledger -csv app.db.ledger.jsonl > sent.csv
```

## What it does

1. `-verify` recomputes the chain of hashes. It prints the number of entries and runs, whether the chain is intact, and the hash of the last seal.
2. `-summary` counts the lines by class, kind, method, host and scope rule, with the first and last time.
3. `-csv` prints one row per line.

`-summary` and `-csv` leave the seals out. The ledger file itself is described in [OUTPUT.md](../OUTPUT.md).

## Output

### -verify

It prints the number of entries and runs, whether the chain is intact, and the hash of the last seal. When something is wrong it says what, in one line. The messages are listed under Summary and exit codes.

### -summary

The text lists the counts by `class`, `kind`, `method`, `host` and `rule`, with the first and last time. A line without a class, from a ledger written before classes, counts as a `target`. With `-json` it is one object:

| Field | Meaning |
| --- | --- |
| `entries` | How many lines the ledger holds. |
| `file` | The ledger file. |
| `first`, `last` | The first and last time. |
| `classes`, `kinds`, `methods`, `hosts`, `rules` | The counts by each. |

### -csv

One row per line, with the columns `seq`, `time`, `class`, `kind`, `method`, `target`, `host`, `rule`, `collector` and `hash`.

## Summary and exit codes

`ledger -verify` exits 3 when the chain is broken or lines follow the last seal:

| Result of `-verify` | Exit |
| --- | --- |
| The chain is intact and ends with a seal. | 0 |
| A line is not intact. The output names the first one: `line 3: hash does not match the content: the line was edited`. | 3 |
| Lines follow the last seal. The output says how many: `NOT SEALED: the last 9 were written after the last seal`. | 3 |
| With `-seal`: the chain is intact, but none of its seals is the one given. | 3 |

Lines follow the last seal when a run was killed, crashed or is still running, or when lines were cut from the end.

The summary and the other exit codes are the shared ones: see [the summary](../OUTPUT.md#the-summary) and [exit codes](../OUTPUT.md#exit-codes).

## Details

### Classes

Each line has a class: `target` (a host the run was pointed at), `source` (a third party asked about the targets) or `dns` (a resolver). `-summary` counts by class, and `-csv` has a `class` column. A ledger written before classes has none on its lines: they read as targets and verify as before. The other way does not hold: an older azhaq cannot verify a ledger whose lines have a `class`.

### What -verify proves

- It proves only that no recorded line was edited, removed or reordered.
- It cannot see a run of lines cut from the middle, with the rest re-chained from there.
  - The re-chained lines have a new `seq`, `prev` and `hash`, written exactly as the ledger writes them.
  - The file is internally consistent, so recomputing the chain alone calls it intact and sealed.
  - It has a smaller entry count and a different last seal.
- Only a seal kept apart from the ledger's own file proves that this did not happen.

### Checking against a kept seal

- `-verify FILE -seal HASH` also requires that HASH be the hash of one of the chain's own seals.
- `-seal` also takes a file of one hash a line, or the JSON lines that `-seal-to` writes. They are matched by their `seal` field.
- It fails with exit 3 when no seal matches: `the chain is intact, but none of its seals is the one given`.

### Keeping the seal elsewhere

- `-seal-to FILE` is a flag of the run commands. When the run ends it appends one line, `{"time","ledger","seal","entries"}`.
- It appends to a file, or POSTs the JSON to an `http(s)://` URL.
- The seal then lives where the ledger's own files, and whoever could edit them, do not reach.

### The note in a run's summary

The summary of a run that wrote a ledger has this note:

```
ledger: N requests, connections and queries recorded in FILE, sealed HASH (azhaq ledger -verify FILE -seal HASH; the seal alone proves no line was later removed and the rest re-chained)
```

## Flags

<!-- flags:begin ledger -->
| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-verify` | string |  | check the ledger's chain of hashes and its seal: exit 0 when intact and sealed, 3 naming the first line that is not intact, or the lines after the last seal |
| `-seal` | string |  | with -verify: a seal hash kept where the run's own files are not (or a file of one per line, or the JSON lines -seal-to writes) that must be one of the chain's seals; without it, -verify cannot tell the file from one with lines removed and the rest re-chained to look intact |
| `-summary` | string |  | count the ledger's requests, connections and queries by class, kind, host and method, with the first and last time |
| `-json` | bool |  | with -summary: one JSON object |
| `-csv` | string |  | print the ledger as CSV |
<!-- flags:end -->
