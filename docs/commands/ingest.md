# azhaq ingest

Add other tools' results to a database (subfinder, dnsx, httpx, katana, naabu, nuclei, gau and ffuf output, or connector facts).

## Synopsis

```
azhaq ingest FILE… | -in FILE | - [-db FILE]
```

## Examples

```
azhaq ingest httpx.jsonl katana.jsonl -db example.db
subfinder -d example.com -json | azhaq ingest - -db example.db
httpx -l hosts.txt -json | azhaq ingest -in - -db example.db && azhaq export -db example.db -format targets
```

## Output

The map of what was added.

`ingest` prints only its summary: `results` is the facts read (of every file given), `counts` the lines read per format. Files are arguments (`azhaq ingest a.jsonl b.jsonl`), `-` is stdin, and `-in FILE` still works.

## Summary and exit codes

The summary and the exit codes are the shared ones: see [OUTPUT.md](../OUTPUT.md#exit-codes).

## Flags

<!-- flags:begin ingest -->
| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-db` | string |  | the database to add to (default: a new file) |
| `-in` | string |  | a file of results (- for stdin): subfinder, dnsx, httpx, katana, naabu, nuclei or gau JSON lines, an ffuf JSON report or -json lines, azhaq export, connector facts, or lines of URLs, hostnames and addresses; files may also be given as arguments, several at once |
| `-json` | bool |  | the summary as JSON |
<!-- flags:end -->
