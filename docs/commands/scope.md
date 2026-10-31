# azhaq scope

Read a program's scope: what a run would take, exclude and skip.

## Synopsis

```
azhaq scope -scope FILE|hackerone|bugcrowd|intigriti|yeswehack [-program NAME] [-json]
```

## Examples

```
# A program from a platform
azhaq scope -scope bugcrowd -program tesla

# A scope file
azhaq scope -scope scope.csv
```

## What it does

1. Reads the scope from a file or from a platform: `hackerone`, `bugcrowd`, `intigriti` or `yeswehack`. A file can be a HackerOne CSV, bounty-targets JSON, Burp options or lines of rules.
2. When the source lists several programs, `-program` takes one.
3. Prints how a run would read it: the allow and deny rules, the domains to enumerate, the targets to probe, and the entries that cannot be used.

## Output

Plain output starts with one line of counts, then one line for each rule or entry:

```
NAME: N rules in, N out; N domains to enumerate, N targets to probe as given; N entries a run cannot use
  in    RULE
  out   RULE
  skip  ENTRY
```

`-json` prints one object:

| Field | Meaning |
| --- | --- |
| `program` | The program the scope came from. |
| `allow` | The rules a run may touch. |
| `deny` | The rules a run must not touch. |
| `domains` | The domains to enumerate. |
| `targets` | The targets to probe, as given. |
| `skipped` | The entries that cannot be used. |

## Summary and exit codes

The summary and the exit codes are the shared ones: see [OUTPUT.md](../OUTPUT.md#exit-codes). Without `-scope`, the command exits 2.

## Flags

<!-- flags:begin scope -->
| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-json` | bool |  | one JSON object: program, allow, deny, domains, targets, skipped |
| `-program` | string |  | the program to take from a list |
| `-scope` | string |  | a file or hackerone, bugcrowd, intigriti, yeswehack |
<!-- flags:end -->
