# azhaq notify

Send text from a pipe or a file to Slack, Discord, Telegram, Teams, Google Chat, Pushover, Gotify, SMTP or any URL. Replaces notify (see [Migrating](../MIGRATING.md#notify-azhaq-notify)).

## Synopsis

```
azhaq notify [-i FILE | stdin]  [-pc provider-config.yaml] [-p PROVIDER] [-id ID] [-bulk] [-cl 4000] [-mf FORMAT] [-rl 1] [-d SECONDS] [-proxy URL] [-v] [-silent] [-json]
```

## Examples

```
# Send every live subdomain, packed into as few messages as fit
azhaq subs -d example.com -live | azhaq notify -bulk -pc provider-config.yaml

# Send a file to two providers, only to the entries with the id recon
azhaq notify -i report.txt -p slack,discord -id recon -pc provider-config.yaml -mf 'recon {{date}}: {{data}}'

# Send a port scan to the custom entries, at most 2 requests a second
azhaq ports -host 127.0.0.1 -json | azhaq notify -p custom -rl 2 -pc provider-config.yaml
```

Every example names its provider config with `-pc`: see [The provider config](#the-provider-config).

## What it does

1. Reads text from standard input or `-i FILE`.
2. Cuts it into messages: one per line, or with `-bulk` as many lines as fit in `-cl` characters.
3. Sends each message to the providers of a `provider-config.yaml`.
4. Prints each message as it was sent, and a summary that names every entry a message did not reach.

`azhaq notify` is [notify](https://github.com/projectdiscovery/notify): its flags and its config file are notify's. `watch -notify-config` sends a change set through the same providers: see [watch](watch.md#notifications).

## Output

Plain output is the message text as sent, one message per line. With `-json` it is one JSON object per message on standard output, and the summary as JSON on standard error:

| Field | Meaning |
| --- | --- |
| `message` | The text as sent, before the format is applied. |
| `sent` | The entries it reached: `provider` and `id` of each. |
| `failed` | The entries it did not reach: `provider`, `id` and `error`. |

The summary on stderr names every provider entry that a message did not reach. `counts` has `delivered` and, when any message needed more tries, `retried`.

## Summary and exit codes

A delivery that did not arrive is named in the summary, and the exit code is 3. Where notify prints a line and exits 0, `azhaq notify` and `azhaq watch` do not exit 0 over a lost message.

Exit 2 and nothing sent when:

- there is no provider config
- the config has a key the schema does not have
- `-p` names something that is no provider
- `-p` or `-id` is a filter that matches nothing

The summary and the other exit codes are the shared ones: see [the summary](../OUTPUT.md#the-summary) and [exit codes](../OUTPUT.md#exit-codes).

## Details

### The provider config

- The config is notify's schema, key for key. It is read from `-pc`, else `~/.config/azhaq/notify.yaml`, else `~/.config/notify/provider-config.yaml`.
- Without a config, `azhaq notify` and `watch -notify-config` stop with exit 2 and send nothing. [MIGRATING.md](../MIGRATING.md#notify-azhaq-notify) has a sample config.
- A word that starts with `$` is replaced by that environment variable when it is set.
- A key the schema does not have is an error (exit 2). A mistyped `slack_webhok_url` is not a silent hole.
- `-config FILE` holds the flags by their long names. It defaults to `~/.config/notify/config.yaml`, when that exists. A flag on the command line wins.

### notify's flags

- The flags are notify's, long and short: see [Flags](#flags) and the table in [MIGRATING.md](../MIGRATING.md#notify-azhaq-notify).
- `-no-color` and `-disable-update-check` are accepted and do nothing.

### How messages are cut and sent

- Without `-bulk`, a line is a message. With `-bulk`, a message holds as many lines as fit in `-cl` characters (default 4000).
- A line over the limit goes out in pieces of `-cl` minus 3 that end in `...`. None is cut inside a character.
- An empty line is no message.
- `-d` waits that many seconds before each message.
- `-rl` (default 1) is the most requests a second, for every provider. 0 means no limit.
- Colour codes are removed.
- Each message goes to every entry of every provider, in this order: slack, discord, pushover, googlechat, smtp, teams, telegram, custom, gotify.
- `-p` and `-id` narrow the entries.

### Message format

`-mf` (or the entry's `*_format`) sets the message. The variables are:

| Variable | Value |
| --- | --- |
| `{{data}}` | The text. |
| `{{date}}` | The date, as `01-02-2006`. |
| `{{time}}` | The time, as `15:04:05-0700`. |
| `{{datetime}}` | Both. |
| `{{count}}` | The number of messages the provider has sent. notify's Discord and custom providers leave it at 0. azhaq counts. |

### Providers

| Provider | What is sent |
| --- | --- |
| `slack` | Webhook (`slack_webhook_url`, must start `https://hooks.slack.com/services/`): `{"text", "username"?, "icon_emoji"?}`. With `slack_threads`: see below. |
| `discord` | `https://discord.com/api/webhooks/ID/TOKEN`: `{"embeds":[{"description","color"}], "username"?, "avatar_url"?}`. With `discord_threads`: see below. |
| `telegram` | `https://api.telegram.org/botTOKEN/sendMessage`: `{"text","chat_id","message_thread_id"?,"parse_mode"?,"disable_web_page_preview","disable_notification","reply_to_message_id"}`. |
| `pushover` | `POST https://api.pushover.net/1/messages.json`, form-encoded `device`, `user`, `token`, `message`, `priority=0`. |
| `googlechat` | `POST https://chat.googleapis.com/v1/spaces/SPACE/messages?key=…&token=…`: `{"text"}`. |
| `teams` | An Office 365 connector or a Power Automate workflow. See below. |
| `smtp` | One mail to each address of `smtp_cc`, in one session. See below. |
| `gotify` | `POST /message` with `X-Gotify-Key`: `{"message","title"?}`. See below. |
| `custom` | `custom_method` to `custom_webhook_url`, with `custom_headers`. See below. |

Limits for one message or post:

- Discord: 2,000 characters to an embed, at most three embeds to a post, more posts for more text.
- Telegram: 4,096 characters. A longer text goes in parts. notify refuses it.
- Pushover: 1,024 characters to a message.
- Google Chat: 4,096 characters to a message.

Provider details:

- **slack**: with `slack_threads`, the request is `POST https://slack.com/api/chat.postMessage` with `Authorization: Bearer slack_token` and `{"channel", "text", "thread_ts"?}`. The first answer's `ts` is the thread of the messages after it. A failed `ok` is an error.
- **discord**: with `discord_threads`, the body is `{"content","username"?,"avatar_url"?}`, sent to the URL with `?thread_id=`.
- **telegram**: `telegram_chat_id` may be `chat:thread` or a comma list.
- **teams**: an Office 365 connector (`…/webhookb2/…`) gets a `MessageCard`, one section a line, and answers 200. A Power Automate workflow (`…/workflows/…`) gets `{"text"}` with HTML escaping and `<br>`, and answers 202.
- **smtp**:
  - STARTTLS is used when the server offers it and `smtp_disable_starttls` is not set.
  - Authentication is PLAIN with `smtp_username`.
  - Port 465 uses implicit TLS.
  - `smtp_server` is `host` or `host:port`.
  - With `smtp_html` the mail has a plain and an HTML part.
- **gotify**:
  - A token of the old shape (15 characters, starting with `A`) goes in the query, with notify's default title and `priority`.
  - The scheme is `http` with `gotify_disabletls`, `https` otherwise, with the certificate checked.
- **custom**:
  - `custom_method` is GET when empty, as in notify.
  - The body is the message, or the `custom_format` with `{{dataJsonString}}` (the message as a JSON string).
  - Or it is a `custom_sprig` template over the message read as a JSON object, such as `{{ .url | upper }}`. [Sprig](https://masterminds.github.io/sprig/) functions work.
  - An answer of 300 or more is a failure. notify does not look.

### Delivery and retries

These rules hold for every message azhaq sends, `azhaq watch`'s included.

- Every request has 30 seconds.
- A 429, a 5xx or a failed connection is tried again, up to three times. The wait is `Retry-After` (seconds or a date, up to a minute) or 1 and 2 seconds. A longer `Retry-After` is reported, not waited out.
- Any other 4xx is not tried again. A redirect to another host is not followed.
- A message longer than a service takes is sent in parts, not cut.
- Failures are never silent. The summary lists each provider and the ids of its entries that did not get a message, with the reason.

```
custom failed: POST http://host/…: 500 … (after 3 tries) ×4 (id ops)
```

### Secrets

- A webhook URL is a secret. azhaq never prints it.
- No error holds a URL's path or query, or a token, key, password or header value of the config, even if the server repeats it. An error from a hook names the host and what went wrong.
- A provider config keeps its tokens in the file. A word that starts with `$` in it is replaced by that environment variable.
- `watch` keeps URLs off the command line too, where `ps` shows them to every user: `-notify @FILE` and `AZHAQ_NOTIFY` (see [watch](watch.md#notifications)).

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
