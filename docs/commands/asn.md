# azhaq asn

Lists the prefixes an autonomous system announces. Replaces asnmap.

## Synopsis

```
azhaq asn -a AS64500 | -l FILE | stdin  [-json]
```

## Examples

```
# the prefixes of one AS
azhaq asn -a AS13335

# several AS numbers, as JSON
azhaq asn -a AS13335 -a AS64500 -json

# AS numbers from a file, or from stdin
azhaq asn -l asns.txt
echo AS13335 | azhaq asn -json
```

## What it does

1. Reads each AS number: `AS64500`, `as64500` or `64500`.
2. Asks RIPEstat (stat.ripe.net, no key) for the prefixes the AS announces and its holder's name.
3. Prints each prefix of an AS once.

Nothing is sent to the addresses of the AS: the prefixes are listed, not scanned.

## Output

Plain output is one prefix per line. With `-json` you get one object per prefix. `-silent` prints the prefixes only, with no progress.

| Field | Meaning |
| --- | --- |
| `as_number` | The AS number, such as `AS13335`. |
| `as_name` | The holder's name. |
| `prefix` | One announced prefix. |

## Summary and exit codes

The summary and the exit codes are the shared ones: see [OUTPUT.md](../OUTPUT.md#exit-codes).

## Flags

<!-- flags:begin asn -->
| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-a` | string, repeatable |  | AS number such as AS64500 |
| `-db` | string |  | keep the graph in this database for query, show, export and diff (default: a temporary one) |
| `-json` | bool |  | JSONL output, and the summary as one JSON object on stderr |
| `-l` | string |  | file of AS numbers (- for stdin) |
| `-o` | string |  | also write results to this file |
| `-silent` | bool |  | results only: no progress; the summary only when something failed (a source that failed, a takeover candidate as a [takeover] line on stderr); stdout stays one result per line |
| `-timeout` | duration |  | stop after this long and keep what was found; azhaq resume continues (0: no limit) |
| `-v` | bool |  | print a line for every finished task, not only failures |
<!-- flags:end -->
