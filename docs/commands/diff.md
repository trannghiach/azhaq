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

A web page's answer is compared by status and title, and a JSON listing's also by how many items it holds (`json_items`): `watch` reports `/users/v1: [200] 5 items → [200] 6 items`. Bodies are not compared byte for byte: timestamps and tokens would make every run a change. A workspace with one run says so: a diff needs two.

`diff -jsonl` prints `added` and `removed` rows, `not_seen_again` rows and a `summary`. `removed` is what answered in the older run (a name that resolved, a page with a status, a host with open ports) and is gone from the newer. `not_seen_again` is what the older run only heard of (from a subdomain source, an archive, a link) and never checked: sources answer differently from day to day and fail, so its absence says little. The summary names the `failed_sources` of the newer run.

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
