# azhaq mcp

Serve Azhaq to MCP clients over stdio, the scope and request budget fixed at start.

## Synopsis

```
azhaq mcp [-scope FILE|PLATFORM -program P] [-allow D] [-deny D] [-max-requests N] [-rate N] [-dir DIR]
```

## Examples

```
azhaq mcp -scope hackerone -program security -max-requests 20000 -rate 5
claude mcp add azhaq -- azhaq mcp -allow example.com -max-requests 5000
```

## Output

JSON-RPC (Model Context Protocol) on stdin and stdout.

## Summary and exit codes

The summary and the exit codes are the shared ones: see [OUTPUT.md](../OUTPUT.md#exit-codes).

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
