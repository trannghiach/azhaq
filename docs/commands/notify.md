# azhaq notify

Send text from a pipe or a file to Slack, Discord, Telegram, Teams, Google Chat, Pushover, Gotify, SMTP or any URL; notify's flags and provider-config.yaml. Replaces notify (see [Migrating](../MIGRATING.md#notify-azhaq-notify)).

## Synopsis

```
azhaq notify [-i FILE | stdin]  [-pc provider-config.yaml] [-p PROVIDER] [-id ID] [-bulk] [-cl 4000] [-mf FORMAT] [-rl 1] [-d SECONDS] [-proxy URL] [-v] [-silent] [-json]
```

## Examples

```
azhaq subs -d example.com -live | azhaq notify -bulk -pc provider-config.yaml
azhaq notify -i report.txt -p slack,discord -id recon -mf 'recon {{date}}: {{data}}'
azhaq ports -host 127.0.0.1 -json | azhaq notify -p custom -rl 2
```

## Output

Each message as it was sent, one per line (-json: {"message","sent","failed"}); the summary on stderr names every provider entry a message did not reach and the exit code is 3 then, where notify exits 0.

## Summary and exit codes

The summary and the exit codes are the shared ones: see [OUTPUT.md](../OUTPUT.md#exit-codes).

## Flags

<!-- flags:begin notify -->
| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-bulk` | bool |  | pack lines into messages of up to -char-limit characters instead of one message per line |
| `-char-limit` | int | `4000` | max character limit per message: a longer line goes out in pieces that end in ... |
| `-cl` | int | `4000` | short for -char-limit |
| `-config` | string |  | notify configuration file: YAML of these flags, by their long names ($HOME/.config/notify/config.yaml when it exists); a flag given here wins |
| `-d` | float |  | short for -delay |
| `-data` | string |  | input file to send for notify (default: standard input) |
| `-delay` | float |  | delay in seconds before each message |
| `-disable-update-check` | bool |  | accepted and ignored: azhaq never checks for updates |
| `-duc` | bool |  | short for -disable-update-check |
| `-i` | string |  | short for -data |
| `-id` | string, repeatable |  | send only to the configured entries with this id (repeatable or comma-separated) |
| `-json` | bool |  | one JSON object per message on standard output, the summary as JSON on standard error |
| `-mf` | string |  | short for -msg-format |
| `-msg-format` | string |  | format of each message: {{data}}, {{date}}, {{time}}, {{datetime}}, {{count}}; wins over the provider's *_format |
| `-nc` | bool |  | short for -no-color |
| `-no-color` | bool |  | accepted and ignored: azhaq prints no colour |
| `-p` | string, repeatable |  | short for -provider |
| `-pc` | string |  | short for -provider-config |
| `-provider` | string, repeatable |  | provider to send the notification to: slack, discord, pushover, googlechat, smtp, teams, telegram, custom, gotify (repeatable or comma-separated) |
| `-provider-config` | string |  | provider config path (default: $HOME/.config/azhaq/notify.yaml, else notify's $HOME/.config/notify/provider-config.yaml); notify's schema, words starting with $ replaced by that variable |
| `-proxy` | string |  | HTTP or SOCKS5 proxy URL for the notification requests (default: the environment's); certificates are verified |
| `-rate-limit` | int | `1` | maximum number of requests to send per second (0: no limit) |
| `-rl` | int | `1` | short for -rate-limit |
| `-silent` | bool |  | no summary unless something failed |
| `-v` | bool |  | short for -verbose |
| `-verbose` | bool |  | log each delivery and each retry |
| `-version` | bool |  | print the version |
<!-- flags:end -->
