# azhaq resume

Continue a run that was interrupted or stopped by a limit.

## Synopsis

```
azhaq resume -db FILE [run flags to add, such as -cookie or -max-requests]
```

## Examples

```
azhaq resume -db app.db -max-requests 2000
```

## Output

As run; a run that ports started prints the open ports it finds, as ports does (-json: objects; -quiet: the summary only), not the ones an earlier run printed.

## Summary and exit codes

The summary and the exit codes are the shared ones: see [OUTPUT.md](../OUTPUT.md#exit-codes).

## Flags

<!-- flags:begin resume -->
`resume` takes the flags of [`run`](run.md#flags): the run's flags are read back from the database; flags given here are added and win.
<!-- flags:end -->
