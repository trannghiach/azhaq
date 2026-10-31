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

`azhaq report -dir DIR` writes up what `azhaq roles` found as one Markdown report per finding, ready to paste into HackerOne or Bugcrowd, or into a red team's client report. It reads the evidence the roles run kept in `DIR/roles.db` and sends nothing.

```
$ azhaq report -dir azhaq-roles-20261028-101500
azhaq report: 3 reports in azhaq-roles-20261028-101500/reports
  …/01-proved-get-books-v1-book-title.md  [proved] Broken object level authorization: bob reads alice's book via GET /books/v1/{book_title}
  …/02-proved-get-books-v1-book-title.md  [proved] Broken object level authorization: alice reads bob's book via GET /books/v1/{book_title}
  …/03-unrated-get-users-v1-debug.md  [unrated] Excessive data exposure: anyone reads password via GET /users/v1/_debug
```

Without `-url`, it writes a report for each listed row whose verdict is `reads another role's object`, `writes another role's object`, `anyone writes another role's object` or `anyone reads sensitive fields`, ordered by confidence (`proved`, `likely`, `guess`, then rows that carry none). With `-url URL` (and `-method M` for a write row) it writes that one report to standard output; a row that is not one of the four verdicts is refused.

| Flag | |
| --- | --- |
| `-dir DIR` | the `-dir` of the roles run (it holds `roles.db`) |
| `-url URL`, `-method M` | one row only |
| `-format md\|json` | Markdown (default), or the same content as structured fields |
| `-o PATH` | a file (the reports one after another, a JSON array for `json`), or a directory (`out/`, or an existing one) with a file per report; default: `DIR/reports` |
| `-redact` | also mask hosts (`<host>`) and identifiers (`<id-1>`) |

Each report has a title naming the bug class (broken object level authorization for a read, "(write)" for a write, excessive data exposure for sensitive fields anyone reads), a two-sentence summary, a severity that is labelled a guess and says why (sensitive fields and a write raise it), numbered steps with the curl commands from the evidence (the sessions as `$ALICE_TOKEN`, `$BOB_TOKEN`), the evidence (status, length and the relevant JSON fields of the owner's answer, the reader's, and the control: what a made-up identifier returned), the row's `owner_by` quoted as the reason the object is the owner's, impact and remediation by class, and notes (confidence, both ways, "found by azhaq roles, run DATE").

A report never says what the evidence does not hold. A row with no control, a body that was not kept, no `owner_by`, or an evidence file from an older azhaq (no run date) says so in the report, under "Missing from the evidence store". A write's before-and-after reads of the owner's object are not kept; the report says so.

`-redact` is for a report that leaves the engagement: the host becomes `<host>`, the identifier in the route and the values of identifier fields in the kept bodies (`id`, `*Id`, `username`, `owner`, `email`, …) become `<id-N>`, and any token is removed. Role names are the tester's own labels and stay. Read a redacted report once before sharing it: an identifier no kept body names in an identifier field is not masked.

`-format json` holds, per report: `title`, `class` (`bola_read`, `bola_write`, `excessive_data_exposure`), `method`, `url`, `route`, `verdict`, `confidence` (`unrated` when roles gave none), `summary`, `severity_guess` (`level`, `reason`), `variables`, `steps` (`n`, `text`, `curl`, `expect`), `evidence` (per answer: `role`, `kind` `owner`, `reader`, `other` or `control`, `request`, `status`, `length`, `content_type`, `body_kept`, `fields`), `owner_reason`, `impact`, `remediation`, `notes` (`confidence`, `both_ways`, `found_by`, `run`) and `missing`.

## Summary and exit codes

The summary and the exit codes are the shared ones: see [OUTPUT.md](../OUTPUT.md#exit-codes).

## Details

`azhaq report -dir DIR` writes up what `roles` found as one Markdown report per finding, ready to paste into HackerOne or Bugcrowd, or into a red team's client report. It reads the evidence the roles run kept in `DIR/roles.db` and sends nothing.

```
$ azhaq report -dir azhaq-roles-20261028-101500
azhaq report: 3 reports in azhaq-roles-20261028-101500/reports
  …/01-proved-get-books-v1-book-title.md  [proved] Broken object level authorization: bob reads alice's book via GET /books/v1/{book_title}
  …/02-proved-get-books-v1-book-title.md  [proved] Broken object level authorization: alice reads bob's book via GET /books/v1/{book_title}
  …/03-unrated-get-users-v1-debug.md  [unrated] Excessive data exposure: anyone reads password via GET /users/v1/_debug
```

Without `-url`, it writes a report for each listed row whose verdict is `reads another role's object`, `writes another role's object`, `anyone writes another role's object` or `anyone reads sensitive fields`, ordered by confidence (`proved`, `likely`, `guess`, then rows that carry none). With `-url URL` (and `-method M` for a write row) it writes that one report to standard output. `-format md|json` picks the form, `-o PATH` a file or a directory, `-redact` also masks hosts (`<host>`) and identifiers (`<id-1>`). Each report has a title naming the bug class, a two-sentence summary, a severity that is labelled a guess and says why, numbered steps with the curl commands from the evidence (the sessions as `$ALICE_TOKEN`, `$BOB_TOKEN`), the evidence (the owner's answer, the reader's, and the control: what a made-up identifier returned), the row's `owner_by` quoted as the reason the object is the owner's, impact and remediation by class, and notes. A report never says what the evidence does not hold: a row with no control, a body that was not kept or no `owner_by` says so under "Missing from the evidence store". Read a redacted report once before sharing it: an identifier no kept body names in an identifier field is not masked. [Output](#output) has the flags and the JSON fields.

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
