# azhaq new

What a workspace first saw lately.

## Synopsis

```
azhaq new -db WORKSPACE.db [-since 168h] [-json]
```

## Examples

```
# What the workspace first saw in the last day
azhaq new -db acme.db -since 24h
```

## What it does

1. Opens the workspace given with `-db`, which is required.
2. Takes the hostnames, URLs and IP addresses first seen within `-since`. The default is 168 hours, one week.
3. Leaves out what the newest run no longer saw: a page removed since is not new.
4. Leaves out URLs that answer with the catch-all page, and scripts, assets and source maps, whether the run read them as such or their address says so.
5. Lists them by type, newest first.

## Output

One entity per line with when it was first seen. A line is the local time of the first sighting, the type, the key, and a detail: the addresses of a name, or `[status] title` for a URL.

With `-json`, one object per line:

| Field | Meaning |
| --- | --- |
| `type`, `key` | The entity: its type, and its URL, name or address. |
| `first_seen`, `last_seen` | When the workspace first and last saw it. |
| `ips` | The addresses it resolved to, when there are any. |
| `status`, `title` | The URL's answer, when it has one. |

## Summary and exit codes

The summary and the exit codes are the shared ones: see [the summary](../OUTPUT.md#the-summary) and [exit codes](../OUTPUT.md#exit-codes).

## Flags

<!-- flags:begin new -->
| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-db` | string |  | workspace database (required) |
| `-since` | duration | `168h0m0s` | first seen within this long |
| `-json` | bool |  | JSONL |
<!-- flags:end -->
