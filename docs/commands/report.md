# azhaq report

Write each finding `azhaq roles` listed up as a report to submit: title, steps with curl, evidence, impact.

Each report is ready to paste into HackerOne or Bugcrowd, or into a red team's client report. `report` reads the evidence the roles run kept in `DIR/roles.db` and sends nothing.

## Synopsis

```
azhaq report -dir DIR [-url URL [-method M]] [-format md|json] [-o FILE|DIR] [-redact]
```

## Examples

```
# one Markdown report per finding, in azhaq-roles-20261028-101500/reports
azhaq report -dir azhaq-roles-20261028-101500

# one row's report on standard output, with hosts and identifiers masked
azhaq report -dir azhaq-roles-20261028-101500 -url https://app/rest/basket/6 -redact
```

## What it does

1. Opens `DIR/roles.db`, the evidence store of an `azhaq roles` run. `-dir` is that run's `-dir`.
2. Picks the rows to write up. Without `-url`, a row gets a report when its verdict is one of these five:
   - `reads another role's object`
   - `writes another role's object`
   - `writes another role's object: accepted; the change cannot be read back to confirm`
   - `anyone writes another role's object`
   - `anyone reads sensitive fields`
3. Orders the reports by confidence: `proved`, `likely`, `guess`, then rows that carry none.
4. Writes one Markdown report per row. Every piece of a report comes from the evidence; what the evidence does not hold is named in the report.

With `-url URL`, `report` writes that one row's report to standard output. A write row also needs `-method M`. A row whose verdict is not one of the five is refused, with exit 1, and a `-url` that matches no row is exit 1 too.

When no row qualifies, `report` prints a note on stderr, writes nothing and exits 0.

## Output

`report` writes files. Without `-url` the reports go to `DIR/reports`, one file each, and stdout lists them. `-o` picks another place. With `-url`, one report goes to standard output instead.

```
$ azhaq report -dir azhaq-roles-20261028-101500
azhaq report: 3 reports in azhaq-roles-20261028-101500/reports
  …/01-proved-get-books-v1-book-title.md  [proved] Broken object level authorization: bob reads alice's book via GET /books/v1/{book_title}
  …/02-proved-get-books-v1-book-title.md  [proved] Broken object level authorization: alice reads bob's book via GET /books/v1/{book_title}
  …/03-unrated-get-users-v1-debug.md  [unrated] Excessive data exposure: anyone reads password via GET /users/v1/_debug
```

### The parts of a report

1. **Title.** It names the bug class. A read is broken object level authorization, and a write adds "(write)", or "(write accepted, not read back)" when the change could not be read back. Sensitive fields anyone reads are excessive data exposure.
2. **Summary.** Two sentences.
3. **Severity.** A level labelled a guess, with the reason. Sensitive fields and a write raise it.
4. **Steps.** Numbered, with the curl commands from the evidence. The sessions are shell variables: `$ALICE_TOKEN`, `$BOB_TOKEN`.
5. **Evidence.** For the owner's answer, the reader's and the control: status, length and the relevant JSON fields. The control is what a made-up identifier returned.
6. **Reason.** The row's `owner_by`, quoted as why the object is the owner's.
7. **Impact and remediation.** Written by class.
8. **Notes.** Confidence, both ways, and "found by azhaq roles, run DATE".
9. **Missing from the evidence store.** What the evidence does not hold; see Details.

### `-format json`

`-format json` gives the same content as structured fields, one object per report.

| Field | Meaning |
| --- | --- |
| `title` | The report title. |
| `class` | `bola_read`, `bola_write` or `excessive_data_exposure`. |
| `method`, `url`, `route` | The row the report is about. |
| `verdict` | The row's roles verdict. |
| `confidence` | `proved`, `likely` or `guess`; `unrated` when roles gave none. |
| `summary` | The two-sentence summary. |
| `severity_guess` | `level` and `reason`. |
| `variables` | The shell variables the curl steps use. |
| `steps` | Each step: `n`, `text`, `curl`, `expect`. |
| `evidence` | One entry per answer; the keys are listed below. |
| `owner_reason` | The row's `owner_by`. |
| `impact`, `remediation` | The text for the class. |
| `notes` | `confidence`, `both_ways`, `found_by`, `run`. |
| `missing` | What the evidence store does not hold. |

Each `evidence` entry has `role`, `kind`, `request`, `status`, `length`, `content_type`, `body_kept` and `fields`. `kind` is `owner`, `reader`, `other` or `control`.

## Summary and exit codes

The summary and the exit codes are the shared ones: see [OUTPUT.md](../OUTPUT.md#exit-codes).

## Details

### Where the reports go

- Default: `DIR/reports`, one Markdown file per report.
- `-o PATH` as a file: the reports one after another. With `-format json` the file holds a JSON array.
- `-o PATH` as a directory (`out/`, or an existing one): one file per report.
- With `-url`, the default is standard output; `-o` sends the report to a file or directory instead.

### What a report never claims

A report never says what the evidence does not hold. It says so under "Missing from the evidence store" when:

- the row has no control;
- a body was not kept;
- the row has no `owner_by`;
- the evidence file comes from an older azhaq, so it has no run date.

A write's before-and-after reads of the owner's object are not kept, and the report says so.

### Redaction

`-redact` is for a report that leaves the engagement.

- The host becomes `<host>`.
- The identifier in the route and the values of identifier fields in the kept bodies become `<id-1>`, `<id-2>` and so on. Identifier fields are `id`, `*Id`, `username`, `owner`, `email` and similar.
- Any token is removed.
- Role names stay: they are the tester's own labels.

Read a redacted report once before sharing it. An identifier that no kept body names in an identifier field is not masked.

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
