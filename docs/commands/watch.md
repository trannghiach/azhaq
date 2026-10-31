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

## Summary and exit codes

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
