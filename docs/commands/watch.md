# azhaq watch

Run again and again into a workspace and report what appeared, changed or disappeared.

## Synopsis

```
azhaq watch -db WORKSPACE.db [-every 24h] [-notify WEBHOOK|@FILE] [-notify-config PROVIDER-CONFIG.yaml] [-notify-cmd CMD] [-json] -- RUN FLAGS
```

## Examples

```
azhaq watch -db acme.db -every 24h -notify https://hooks.slack.com/… -- -scope hackerone -program acme
```

## Output

The change set after each run (-json: one JSON object); a notification that did not arrive is named on stderr and the exit code is 3.

`azhaq watch -db FILE -- RUN FLAGS` runs the run options into the workspace and compares its last two runs, in the terms a person watching a target cares about. The text names each kind of change that happened, with at most 20 lines each (`… and N more`), and says `no change` when nothing did. The first run of a workspace is the baseline: everything in it is new, and it lists no routes. The baseline is printed but not sent to `-notify` or `-notify-cmd` (`-always` sends it, and every run after it).

```
azhaq watch app.db: 2026-10-29 23:29:48 against 2026-10-29 23:29:48
~ 4 API routes
    + POST /api/v2/export {format, userId}  (main.js)
    ~ /api/orders/{id}: +DELETE  (main.js)
    ~ PUT /api/profile: +role  (main.js)
    - /api/legacy/report  (main.js)
```

The sections are `+ hostnames that resolve`, `+ web services`, `+ URLs`, `~ API routes`, `~ hosts whose open ports changed`, `~ pages that answer differently` and `- hostnames gone`, `- web services gone`, `- URLs gone`. A frontend deploy that adds a route adds attack surface, and the first report is the one that pays, so the `API routes` section ties each change to the script that calls the route:

- `+ METHODS /route {names}`: a new route, its methods and the names it sends (query and body). The names are read from `fetch`, `XMLHttpRequest` (`send`), axios and jQuery calls whether the body is written in the call or kept in a variable, `JSON.stringify(…)`, `URLSearchParams` or a `FormData` built with `append`. A route that a script only names in a string, with no call and no description, has no method on its line (`+ /api/ping`): azhaq says no GET it did not see.
- `~ /route: +DELETE`: a method added to a known route (or `-GET`, removed).
- `~ PUT /route: +role`: a name the route's call now sends (or the name with a `-` in front, removed).
- `- /route`: a route the previous run's scripts or API description named and no source names in this run.

A route only found by guessing or in an archive is never reported gone, and one a crawl or a guess finds is not reported new: routes are compared where a script or an API description names them. Placeholder names (`{id}` or `{orderId}`), identifiers, ordering and case are not changes, so the same app mapped twice reports no route change; a placeholder renamed is no `URLs` or `URLs gone` line either. The start of a path a script joins more to (`"/api/admin/users/" + id + "/reset"` names `/api/admin/users/{id}/reset`, not `/api/admin/users`) is no route and is never reported. A route that answers differently (status, title, item count) stays under "pages that answer differently". A route reported as new or gone is not repeated under "URLs".

Notifications. `-notify URL` posts the text to a webhook: Slack and Discord incoming webhooks and Telegram's `sendMessage` (with `?chat_id=`) get it in their own shape, any other URL gets `{"text": …, "data": the change set}`. `-notify @FILE` reads the URLs from a file, one a line (`#` comments), and `$AZHAQ_NOTIFY` holds more, comma-separated; neither puts a URL on the command line. `-notify-config FILE` sends to the providers of a [notify](notify.md) `provider-config.yaml` instead (`-notify-provider` and `-notify-id` pick entries). The text lists up to `-notify-lines` lines (default 100) of each kind of change and counts the rest; the terminal shows 20. A message longer than the service takes (Discord 2,000 characters, Telegram 4,096, Slack 40,000) goes out in parts labelled `(1/3)`, cut at a line or a space. `-notify-format` sets the message with notify's variables (`{{data}}`, `{{date}}`, `{{time}}`, `{{datetime}}`, `{{count}}`), `-notify-rate` paces the requests (default 1 a second) and `-notify-proxy` sets a proxy. A URL's query sets what the service lets a message carry: `username` and `icon_emoji` for Slack, `username` and `avatar_url` for Discord, `parse_mode`, `thread` and `preview=yes` for Telegram. A 429 or a 5xx, or a connection that failed, is tried again (three tries, waiting for `Retry-After` up to a minute); any other 4xx is not. A delivery that failed is printed on stderr as `azhaq watch: POST https://host/…: reason`, never with the URL, and the exit code is 3 (the run's own 3 or 4 wins). With `-json` (and for `-notify-cmd` and generic hooks) the change set is one JSON object: `db`, `run`, `previous`, `baseline`, `hosts`, `services`, `urls`, `ports`, `changed`, `gone_hosts`, `gone_services`, `gone_urls` and `routes`. A `routes` entry is:

```json
"routes": [
  {"kind": "new", "host": "app.example.com", "route": "/api/v2/export",
   "methods_added": ["POST"], "fields_added": ["format", "userId"],
   "script": "https://app.example.com/main.js"},
  {"kind": "methods", "route": "/api/orders/{id}", "methods_added": ["DELETE"], …},
  {"kind": "fields", "route": "/api/profile", "method": "PUT", "fields_added": ["role"], …},
  {"kind": "gone", "route": "/api/legacy/report", "methods_removed": ["GET"], …}
]
```

`kind` is `new`, `methods`, `fields` or `gone`; `script` is the first script that names the route; `methods_removed` and `fields_removed` are set when something was taken away.

## Summary and exit codes

`watch` exits with the code of its run (one run, without `-every`).

The summary and the exit codes are the shared ones: see [OUTPUT.md](../OUTPUT.md#exit-codes).

## Flags

<!-- flags:begin watch -->
| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-always` | bool |  | notify after every run, the first (the baseline) included, not only when something changed |
| `-db` | string |  | workspace database (required) |
| `-every` | duration |  | run again after this long (default: run once, for cron) |
| `-json` | bool |  | print the change set as JSON |
| `-notify` | string, repeatable |  | webhook for changes: Slack, Discord, Telegram (…/sendMessage?chat_id=…) or any JSON endpoint (repeatable); @FILE reads URLs from a file, one a line, and $AZHAQ_NOTIFY holds more (comma-separated), so a token need not stand on the command line where ps shows it |
| `-notify-cmd` | string |  | command that gets the change set as JSON on stdin |
| `-notify-config` | string |  | notify's provider-config.yaml: send the changes to the providers it lists (Slack, Discord, Telegram, Teams, Google Chat, Pushover, Gotify, SMTP, custom) |
| `-notify-format` | string |  | format of each message: {{data}}, {{date}}, {{time}}, {{datetime}}, {{count}} |
| `-notify-id` | string, repeatable |  | with -notify-config, only the entries with these ids (repeatable or comma-separated) |
| `-notify-lines` | int | `100` | lines per kind of change in a message, the rest counted (0: all); a message longer than the service takes is sent in parts |
| `-notify-provider` | string, repeatable |  | with -notify-config, only these providers (repeatable or comma-separated) |
| `-notify-proxy` | string |  | proxy URL for the notification requests (default: the environment's) |
| `-notify-rate` | float | `1` | requests per second to the webhooks and providers (0: no limit) |
<!-- flags:end -->
