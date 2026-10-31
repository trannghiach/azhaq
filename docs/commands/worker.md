# azhaq worker

Take work from a run started with -serve.

## Synopsis

```
azhaq worker -server URL [-token T]
```

## Examples

```
# Join a run that listens at 10.0.0.5:7777
AZHAQ_WORKER_TOKEN=… azhaq worker -server http://10.0.0.5:7777
```

## What it does

1. The run is started with `azhaq run -serve ADDRESS`. It checks a worker token: `-worker-token`, else `$AZHAQ_WORKER_TOKEN`, else a new one.
2. `worker` joins the run at `-server` with that token: `-token`, or `$AZHAQ_WORKER_TOKEN`.
3. It takes the run's flags, its `-deny-path` rules, the session headers and the files the run sends along. A URL a `-deny-path` rule keeps out is never sent, and the run lists it as not requested.
4. It claims tasks from the run and runs them, `-slots` at once (8 by default), until the run is over.
5. In a signed-in run it reports a 401, a redirect to the sign-in page or a cleared session cookie. The run makes the session check and signs in again (`-login`), and the worker takes the new headers with its next task. A session given with `-cookie` or `-header` cannot be renewed: the run ends its signed-in work with a failure, exit 3.
6. It keeps its own files in a temporary directory and removes it when it ends.

## Output

Progress on stderr.

## Summary and exit codes

The summary and the exit codes are the shared ones: see [the summary](../OUTPUT.md#the-summary) and [exit codes](../OUTPUT.md#exit-codes).

## Flags

<!-- flags:begin worker -->
| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-server` | string |  | the run's address (azhaq run -serve) |
| `-token` | string |  | the run's worker token (default $AZHAQ_WORKER_TOKEN) |
| `-slots` | int | `8` | tasks run at once |
<!-- flags:end -->
