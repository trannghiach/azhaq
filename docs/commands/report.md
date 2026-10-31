# azhaq report

Write each finding roles listed up as a report to submit (title, steps with curl, evidence, impact).

## Synopsis

```
azhaq report -dir DIR [-url URL [-method M]] [-format md|json] [-o FILE|DIR] [-redact]
```

## Examples

```
azhaq report -dir azhaq-roles-20261028-101500
azhaq report -dir azhaq-roles-20261028-101500 -url https://app/rest/basket/6 -redact
```

## Output

One Markdown report per cross-role read or write and per sensitive field anyone reads, best-evidenced first (proved, likely, guess), written to DIR/reports or -o; -url writes one to standard output. Every piece comes from the roles run's evidence (roles.db); what it does not hold is named in the report. -redact masks hosts and identifiers.

## Summary and exit codes

The summary and the exit codes are the shared ones: see [OUTPUT.md](../OUTPUT.md#exit-codes).

## Flags

<!-- flags:begin report -->
| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-dir` | string |  | the -dir of the roles run (it holds roles.db) |
| `-format` | string | `md` | md or json |
| `-method` | string |  | the method of a write row (-replay-writes); a read's row by default |
| `-o` | string |  | FILE for the reports (one file, or a directory with a report per file); without -url, DIR/reports; with -url, standard output |
| `-redact` | bool |  | also mask hosts and identifiers (a report to share outside the engagement) |
| `-url` | string |  | write up this one row (its URL as roles lists it); every cross-role finding by default |
<!-- flags:end -->
