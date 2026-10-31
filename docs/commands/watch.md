# azhaq watch

Run again and again into a workspace and report what appeared, changed or disappeared.

## Synopsis

```
azhaq watch -db WORKSPACE.db [-every 24h] [-notify WEBHOOK|@FILE] [-notify-config PROVIDER-CONFIG.yaml] [-notify-cmd CMD] [-json] -- RUN FLAGS
```

## Examples

```
# Run once and print what changed since the last run (for cron)
azhaq watch -db acme.db -- -scope hackerone -program acme

# Run every 24 hours and post the changes to a Slack webhook
azhaq watch -db acme.db -every 24h -notify https://hooks.slack.com/… -- -scope hackerone -program acme

# Read the webhook URLs from a file, so none stands on the command line
azhaq watch -db acme.db -every 24h -notify @webhooks.txt -- -scope hackerone -program acme

# Send to the providers of a notify provider-config.yaml
azhaq watch -db h1.db -every 24h -notify-config provider-config.yaml -- -scope hackerone -program acme

# Give the change set as JSON to a command
azhaq watch -db acme.db -notify-cmd ./on-change.sh -- -scope hackerone -program acme
```

## What it does

1. Runs the flags after `--` into the workspace `-db`, as [run](run.md) does.
2. Compares the last two runs of the workspace, in the terms a person watching a target cares about.
3. Prints the change set: as text, or as one JSON object with `-json`.
4. Sends the change set to every `-notify` URL, `-notify-config` provider and `-notify-cmd`, when something changed (`-always`: after every run).
5. Runs again after `-every`. Without `-every` it runs once, for cron.

A frontend deploy that adds a route adds attack surface, and the first report is the one that pays. So the report ties each API route change to the script that calls the route.

## Output

After each run `watch` prints the change set.

The text names each kind of change that happened, with at most 20 lines each (`… and N more`). It says `no change` when nothing changed.

```
azhaq watch app.db: 2026-10-29 23:29:48 against 2026-10-29 23:29:48
~ 4 API routes
    + POST /api/v2/export {format, userId}  (main.js)
    ~ /api/orders/{id}: +DELETE  (main.js)
    ~ PUT /api/profile: +role  (main.js)
    - /api/legacy/report  (main.js)
```

The first run of a workspace is the baseline. Everything in it is new, and it lists no routes. The baseline is printed but not sent to `-notify` or `-notify-cmd`. `-always` sends it, and every run after it.

### Sections of the text

| Section | Meaning |
| --- | --- |
| `+ hostnames that resolve` | Names that resolve now and did not in the previous run. |
| `+ web services` | Front pages that answer now and did not before. |
| `+ URLs` | URLs found now that were not before. |
| `~ API routes` | New, changed or removed routes, each tied to its script. See below. |
| `~ hosts whose open ports changed` | Hosts whose open ports differ from the previous run's. |
| `~ pages that answer differently` | Pages whose status, title or item count changed. |
| `- hostnames gone` | Names that resolved in the previous run and do not now. |
| `- web services gone` | Front pages that answered in the previous run and do not now. |
| `- URLs gone` | URLs of the previous run that were not found this time. |

### Lines of the API routes section

| Line | Meaning |
| --- | --- |
| `+ METHODS /route {names}` | A new route: its methods and the names it sends, from the query and the body. |
| `~ /route: +DELETE` | A method added to a known route, or `-GET` for one removed. |
| `~ PUT /route: +role` | A name the route's call now sends, or the name with a `-` in front for one removed. |
| `- /route` | A route the previous run's scripts or API description named and no source names in this run. |

A route that a script only names in a string has no method on its line (`+ /api/ping`). That means no call and no description. azhaq says no GET it did not see.

### The JSON change set

`-json`, `-notify-cmd` and generic webhooks get the change set as one JSON object. Its fields are `db`, `run`, `previous`, `baseline`, `hosts`, `services`, `urls`, `ports`, `changed`, `gone_hosts`, `gone_services`, `gone_urls` and `routes`.

A `routes` entry is:

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

- `kind` is `new`, `methods`, `fields` or `gone`.
- `script` is the first script that names the route.
- `methods_removed` and `fields_removed` are set when something was taken away.

The route lines also go, as text, to Slack, Discord and Telegram.

## Summary and exit codes

Without `-every`, `watch` runs once and exits with the code of its run.

A notification that did not arrive is named on stderr, and the exit code is 3. The run's own 3 or 4 wins.

The summary and the other exit codes are the shared ones: see [OUTPUT.md](../OUTPUT.md#exit-codes).

## Details

### Which routes are compared

- Routes are compared where a script or an API description names them.
- A route found only by guessing or in an archive is never reported gone.
- A route that only a crawl or a guess finds is not reported new.
- Placeholder names (`{id}` or `{orderId}`), identifiers, ordering and case are not changes. The same app mapped twice reports no route change.
- A placeholder that was renamed is no `URLs` or `URLs gone` line either.
- The start of a path that a script joins more to is no route and is never reported. `"/api/admin/users/" + id + "/reset"` names `/api/admin/users/{id}/reset`, not `/api/admin/users`.
- A route that answers differently (status, title, item count) stays under "pages that answer differently".
- A route reported as new or gone is not repeated under "URLs".

### Where route names are read from

The names are read from `fetch`, `XMLHttpRequest` (`send`), axios and jQuery calls. They count whether the body is written in the call or kept in a variable. They are also read from `JSON.stringify(…)`, `URLSearchParams` and a `FormData` built with `append`.

### Notifications

- `-notify URL` posts the text to a webhook. Slack and Discord incoming webhooks and Telegram's `sendMessage` (with `?chat_id=`) get it in their own shape. Any other URL gets `{"text": …, "data": the change set}`.
- `-notify @FILE` reads the URLs from a file, one a line (`#` comments). `$AZHAQ_NOTIFY` holds more, comma-separated. Neither puts a URL on the command line.
- `-notify-config FILE` sends to the providers of a [notify](notify.md) `provider-config.yaml` instead. `-notify-provider` and `-notify-id` pick entries.
- The text lists up to `-notify-lines` lines (default 100) of each kind of change and counts the rest. The terminal shows 20.
- A message longer than the service takes goes out in parts labelled `(1/3)`, cut at a line or a space. The limits are 2,000 characters for Discord, 4,096 for Telegram and 40,000 for Slack.
- `-notify-format` sets the message with notify's [variables](notify.md#message-format).
- `-notify-rate` paces the requests (default 1 a second) and `-notify-proxy` sets a proxy.
- A URL's query sets what the service lets a message carry:
  - Slack: `username` and `icon_emoji`.
  - Discord: `username` and `avatar_url`.
  - Telegram: `parse_mode`, `thread` and `preview=yes`.
- Failed deliveries are tried again as [notify](notify.md#delivery-and-retries) does.
- A delivery that failed is printed on stderr as `azhaq watch: POST https://host/…: reason`, never with the URL. See [notify](notify.md#secrets).

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
