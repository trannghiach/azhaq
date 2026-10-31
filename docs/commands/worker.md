# azhaq worker

Take work from a run started with -serve.

## Synopsis

```
azhaq worker -server URL [-token T]
```

## Examples

```
AZHAQ_WORKER_TOKEN=… azhaq worker -server http://10.0.0.5:7777
```

## Output

Progress on stderr.

## Summary and exit codes

The summary and the exit codes are the shared ones: see [OUTPUT.md](../OUTPUT.md#exit-codes).

## Flags

<!-- flags:begin worker -->
| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-server` | string |  | the run's address (azhaq run -serve) |
| `-slots` | int | `8` | tasks run at once |
| `-token` | string |  | the run's worker token (default $AZHAQ_WORKER_TOKEN) |
<!-- flags:end -->
