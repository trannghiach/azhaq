# azhaq mcp

Serve azhaq to MCP clients over stdio, with the scope and the request budget fixed at start.

## Synopsis

```
azhaq mcp [-scope FILE|PLATFORM -program P] [-allow D] [-deny D] [-max-requests N] [-rate N] [-dir DIR]
```

## Examples

```
# Hold every tool to a HackerOne program, with a budget and a pace
azhaq mcp -scope hackerone -program security -max-requests 20000 -rate 5

# Add the server to Claude Code, limited to one domain
claude mcp add azhaq -- azhaq mcp -allow example.com -max-requests 5000
```

## What it does

1. Starts a Model Context Protocol server that talks JSON-RPC on stdin and stdout.
2. Holds every tool to the scope given by `-scope`, `-allow` and `-deny`. All tool calls together share the `-max-requests` budget and the `-rate` pace.
3. Writes the workspaces the tools make into `-dir`.

The tools and their arguments are listed in [MCP.md](../MCP.md).

## Output

JSON-RPC (Model Context Protocol) on stdin and stdout.

## Summary and exit codes

The summary and the exit codes are the shared ones: see [OUTPUT.md](../OUTPUT.md#exit-codes). The server runs until its input closes or a signal comes. A signal ends it with exit 0, after the commands in flight stop.

## Flags

<!-- flags:begin mcp -->
| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-allow` | string, repeatable |  | a domain or host the tools may touch (repeatable); with -scope, added to it |
| `-deny` | string, repeatable |  | a domain or host the tools must not touch |
| `-dir` | string | `azhaq-mcp` | directory for the workspaces the tools write |
| `-max-requests` | int |  | requests to targets all tool calls together may send (0: no cap) |
| `-program` | string |  | the program to take from -scope |
| `-rate` | float |  | requests per second to targets in every tool call (0: no pace) |
| `-scope` | string |  | a program's scope every tool is held to: a file, or hackerone, bugcrowd, intigriti, yeswehack with -program |
| `-unlocked` | bool |  | serve without a scope: any target a tool is given may be touched (port scans stay refused) |
<!-- flags:end -->
