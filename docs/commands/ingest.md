# azhaq ingest

Add other tools' results to a database: subfinder, dnsx, httpx, katana, naabu, nuclei, gau and ffuf output, or connector facts.

## Synopsis

```
azhaq ingest FILE… | -in FILE | - [-db FILE]
```

## Examples

```
# Add the output of two tools to one database
azhaq ingest httpx.jsonl katana.jsonl -db example.db

# Read from a pipe
subfinder -d example.com -json | azhaq ingest - -db example.db

# Ingest, then hand the web services to the next tool
httpx -l hosts.txt -json | azhaq ingest -in - -db example.db && azhaq export -db example.db -format targets
```

## What it does

1. Reads each file you give, or standard input for `-`.
2. Turns the lines into facts and adds them to the database `-db`. Without `-db` it makes a new file.
3. Prints its summary.

Files are arguments (`azhaq ingest a.jsonl b.jsonl`). `-` is stdin, and `-in FILE` still works. The formats it reads are listed under `-in` in Flags. How an httpx, katana or ffuf answer is recorded is in the [connector protocol](../CONNECTOR.md#loading-other-tools-output-with-azhaq-ingest).

## Output

`ingest` prints no rows, only its summary. What it added is in the database: look at the map with `azhaq query` or `azhaq export`.

| Summary field | Meaning |
| --- | --- |
| `results` | The facts read, of every file given. |
| `counts` | The lines read, per format. |
| `notes` | The first 5 lines it could not read and skipped, when there were any. |
| `next` | Commands to look at the result: `azhaq query`, and `azhaq dns` for names taken in without addresses. |

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
