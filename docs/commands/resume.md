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
5. Continues a stopped `fuzz` run with its own command, a stopped port scan with the ports it has not asked, and a stopped `dirs` sweep with its words.
6. After a run that was killed (SIGKILL, a crash: its ledger has no seal at the end), reads the ledger lines after the last seal. Reads that had no stored answer are asked again. Writes are never sent again: each is held back, listed under `skipped`, and the summary says so. See [Workspaces, runs and resuming](../CONCEPTS.md#workspaces-runs-and-resuming).
7. Prints a line on stderr: `azhaq: resuming run ID of DB, N tasks known and not done`. `-json` leaves it out.

## Output

As the command that started the run. A run that `ports` started prints the open ports it finds, as `ports` does, and one that `dirs` started prints the paths it finds, as `dirs` does (the summary's `command` is `ports` or `dirs`, `results` the rows this run printed). Rows an earlier run printed are not printed again, so the rows of the runs add up to one run's. A run that `probe`, `crawl`, `params`, `shots`, `urls`, `subs` or any other command started names that command in the summary's `command` and prints the rows of the map, as `run` does, not that command's own rows; a note says so, and `azhaq query -db FILE` lists what the run found. A run started with `run` prints as `run`. `-json` prints objects. `-quiet` prints only the summary.

## Summary and exit codes

The summary and the exit codes are the shared ones: see [the summary](../OUTPUT.md#the-summary) and [exit codes](../OUTPUT.md#exit-codes).

## Details

### Which flags come back

- The run's flags are stored without its secrets: `-cookie`, `-login-pass`, `-worker-token`, and a `-header` whose name holds `auth`, `cookie`, `token`, `key`, `session`, `secret`, `csrf` or `xsrf`. Give them again after `-db`.
- Files and directories are stored as full paths, so `resume` works from another directory.
- A `-list` file is also copied into the workspace. If the file is gone or changed, the run continues the copy, and a note says so.
- `-all-gets` and `-get-words` are dropped from a run an older azhaq stored, with a note: every GET found in scope is requested now.

## Flags

<!-- flags:begin resume -->
`resume` takes the flags of [`run`](run.md#flags): the run's flags are read back from the database; flags given here are added and win.
<!-- flags:end -->
