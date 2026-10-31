# azhaq diff

Compare two runs: the entities added and removed, and the new observations.

## Synopsis

```
azhaq diff -a OLD.db -b NEW.db | -db WORKSPACE.db  [-jsonl] [-quiet]
```

## Examples

```
# Compare the last two runs of a workspace
azhaq diff -db acme.db

# Compare two database files
azhaq diff -a old.db -b new.db

# Print added, removed and not_seen_again rows and a summary as JSON lines
azhaq diff -db acme.db -jsonl
```

## What it does

1. Takes two runs: the last two recorded in a workspace (`-db`), or `-a` (old) and `-b` (new, default the last run).
2. Lists the entities that were added and removed, and the new observations. `-quiet` prints entities and counts only.
3. Compares a web page's answer by its status and title.
4. Compares a JSON listing's answer by its status, its title and how many items it holds (`json_items`). `watch` reports it as `/users/v1: [200] 5 items → [200] 6 items`.

A workspace with only one run says so: a diff needs two.

## Output

The text report lists the entities added and removed and the new observations.

`-jsonl` prints one JSON object per line:

| Row | Meaning |
| --- | --- |
| `added` | An entity in the newer run and not in the older. |
| `removed` | Something that answered in the older run and is gone from the newer. See Details. |
| `not_seen_again` | Something the older run only heard of and never checked. See Details. |
| `summary` | The totals. It names the `failed_sources` of the newer run. |

## Summary and exit codes

The summary and the exit codes are the shared ones: see [OUTPUT.md](../OUTPUT.md#exit-codes).

## Details

### What counts as removed

- `removed` is what answered in the older run: a name that resolved, a page with a status, a host with open ports.
- It is gone from the newer run.

### What counts as not seen again

- `not_seen_again` is what the older run only heard of: from a subdomain source, an archive or a link. The run never checked it.
- Sources answer differently from day to day, and they fail. Its absence says little.

### What is not compared

- Bodies are not compared byte for byte. Timestamps and tokens would make every run a change.

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
