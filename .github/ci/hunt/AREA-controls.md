## Your area: controls (folder AREA = controls)

Engagement controls and integration: ledger (`ledger -verify`, seal), `-max-requests`, kill file, `resume`, `-timeout` while waiting for `-rate`, scope refusals (including a `Host` header naming a denied host, on the command line and in MCP `headers`), `-proxy` (every request of `run`, `roles` replay, `params`), the MCP server (`mcp`, stdio JSON-RPC: lock, budget, scope, argument refusal, calls made at once, lifecycle requests), `roles` (sign-in, read replay, write replay, HAR import), `hunt`, `report`, `export` / `ingest` (including naabu's JSON for an address), `watch` / `diff` / `notify` (use `-notify-cmd 'cat >> FILE'` or a local webhook receiver you start), and `run` on VAmPI, DVWA (`-login`), Juice Shop, DVGA (`-graphql`). CHANGELOG sections: Fixed, Notifications, Docs, and the newest release's; MIGRATING: notify.

- Every run through countproxy: the summary's requests, the ledger's non-seal lines and the proxy log must agree exactly, unpaced, `-rate 10` and `-rate 2`, also with `-browser`.
- Kill file and SIGKILL mid-run, `-max-requests` then `resume` (twice), `-timeout` at `-rate 2`: exit codes, ledger seal, nothing sent after the stop.
- Write replay on VAmPI: does each verdict match what the server did (2xx, 4xx refusal, 5xx error)?
- A webhook URL or token must never appear in any output or error (try an unreachable webhook host and a 500-answering receiver).
- Run every three-command block of docs/MIGRATING.md that targets the labs (skip public ones beyond the allowed list): none may be a usage error, each must do what its reference tool line does.
