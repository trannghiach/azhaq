# azhaq docs

Print the documentation: a page for each command, output fields, exit codes, connectors, MCP.

## Synopsis

```
azhaq docs [TOPIC | COMMAND] | -flags COMMAND | -flags-into DIR
```

## Examples

```
# A topic
azhaq docs output

# The page of a command
azhaq docs ports

# The flag table of one command
azhaq docs -flags ports

# Rewrite the flag tables of the command pages in a directory
azhaq docs -flags-into docs/commands
```

## What it does

- With no argument, `docs` prints an overview and the list of topics.
- `azhaq docs TOPIC` prints one topic: `readme`, `migrating`, `recipes`, `concepts`, `troubleshooting`, `output`, `mcp`, `connector` or `architecture`.
- `azhaq docs COMMAND` prints the page of a command. `mcp` is also a topic, and the topic comes first: `azhaq docs commands/mcp` prints the page.
- `-flags` and `-flags-into` take no topic and are not used together. A name that is no topic or command is a usage error, exit 2.

## Output

Markdown. `-flags` prints one command's flag table. `-flags-into` rewrites the flag tables of the pages in DIR.

## Summary and exit codes

The summary and the exit codes are the shared ones: see [OUTPUT.md](../OUTPUT.md#exit-codes).

## Flags

<!-- flags:begin docs -->
| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-flags` | string |  | print the Markdown table of the flags of this command, made from the data help -json lists |
| `-flags-into` | string |  | rewrite the flag table of each NAME.md page in this directory, between its flags:begin and flags:end markers (go run ./cmd/azhaq docs -flags-into docs/commands) |
<!-- flags:end -->
