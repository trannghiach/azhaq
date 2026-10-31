# azhaq scope

Read a program's scope: what a run would take, exclude and skip.

## Synopsis

```
azhaq scope -scope FILE|hackerone|bugcrowd|intigriti|yeswehack [-program NAME] [-json]
```

## Examples

```
azhaq scope -scope bugcrowd -program tesla
azhaq scope -scope scope.csv
```

## Output

The allow and deny rules, domains to enumerate, targets to probe, and the entries that cannot be used.

## Summary and exit codes

The summary and the exit codes are the shared ones: see [OUTPUT.md](../OUTPUT.md#exit-codes).

## Flags

<!-- flags:begin scope -->
| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-json` | bool |  | one JSON object: program, allow, deny, domains, targets, skipped |
| `-program` | string |  | the program to take from a list |
| `-scope` | string |  | a file or hackerone, bugcrowd, intigriti, yeswehack |
<!-- flags:end -->
