# azhaq resume

Continue a run that was interrupted or stopped by a limit.

## Synopsis

```
azhaq resume -db FILE [run flags to add, such as -cookie or -max-requests]
```

## Examples

```
# Continue a run, with more requests allowed
azhaq resume -db app.db -max-requests 2000
```

## What it does

1. Opens the workspace given with `-db`, which is required.
2. Finds the run that has work left. If every run finished, it says so and exits 1.
3. Reads the run's flags back from the database. Flags given here are added and win.
4. Continues the targets the run started with. A `-list` given here replaces them.
5. Continues a stopped `fuzz` run with its own command, and a stopped port scan with the ports it has not asked.
6. Prints a line on stderr: `azhaq: resuming run ID of DB, N tasks known and not done`. `-json` leaves it out.

## Output

As `run`. A run that `ports` started prints the open ports it finds, as `ports` does, and not the ones an earlier run printed. `-json` prints objects. `-quiet` prints only the summary.

## Summary and exit codes

The summary and the exit codes are the shared ones: see [the summary](../OUTPUT.md#the-summary) and [exit codes](../OUTPUT.md#exit-codes).

## Flags

<!-- flags:begin resume -->
`resume` takes the flags of [`run`](run.md#flags): the run's flags are read back from the database; flags given here are added and win.
<!-- flags:end -->
