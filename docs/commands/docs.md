# azhaq docs

Print the documentation: a page for each command, output fields, exit codes, connectors, MCP.

## Synopsis

```
azhaq docs [TOPIC | COMMAND] | -flags COMMAND | -flags-into DIR
```

## Examples

```
azhaq docs output
azhaq docs ports
azhaq docs -flags ports
azhaq docs -flags-into docs/commands
```

## Output

Markdown; -flags prints one command's flag table, -flags-into rewrites the flag tables of the pages in DIR.

## Summary and exit codes

The summary and the exit codes are the shared ones: see [OUTPUT.md](../OUTPUT.md#exit-codes).

## Flags

<!-- flags:begin docs -->
| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-flags` | string |  | print the Markdown table of the flags of this command, made from the data help -json lists |
| `-flags-into` | string |  | rewrite the flag table of each NAME.md page in this directory, between its flags:begin and flags:end markers (go run ./cmd/azhaq docs -flags-into docs/commands) |
<!-- flags:end -->
