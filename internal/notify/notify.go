// Package notify posts a short text, and for generic webhooks the full
// change set, to Slack, Discord, Telegram or any URL that takes JSON, and
// holds the providers of projectdiscovery/notify's provider-config.yaml.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// Limits of the services a webhook URL is recognised by, in characters.
const (
	slackLimit    = 40000
	discordLimit  = 2000
	telegramLimit = 4096
)

// Send posts text to hook with a default client. See Client.Send.
func Send(ctx context.Context, hook, text string, data any) error {
	return (&Client{}).Send(ctx, hook, text, data)
}

// HookLimit is the longest text, in characters, the service behind hook
// takes in one message; 0 when there is none (a generic JSON endpoint).
func HookLimit(hook string) int {
	u, err := url.Parse(hook)
	if err != nil {
		return 0
	}
	switch {
	case strings.HasSuffix(u.Host, "hooks.slack.com"):
		return slackLimit
	case strings.HasSuffix(u.Host, "discord.com") || strings.HasSuffix(u.Host, "discordapp.com"):
		return discordLimit
	case u.Host == "api.telegram.org":
		return telegramLimit
	case u.Host == "chat.googleapis.com":
		return googleChatLimit
	case strings.Contains(u.Path, "/workflows/") || strings.Contains(u.Path, "/webhookb2/"):
		return teamsLimit
	}
	return 0
}

// Send posts text to hook, in as many messages as the service takes (each
// labelled "(2/3)"). Slack and Discord incoming webhooks and Telegram's
// sendMessage (with chat_id in the URL) get the text in their own shape;
// any other URL gets {"text": …, "data": data}. Query parameters of the
// URL set what the service lets a message carry: Slack username and
// icon_emoji, Discord username and avatar_url, Telegram parse_mode,
// message_thread_id (or thread) and preview=yes.
func (c *Client) Send(ctx context.Context, hook, text string, data any) error {
	u, err := url.Parse(hook)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") {
		return fmt.Errorf("webhook %s is not an http(s) URL", redact(hook))
	}
	c.AddSecrets(u.Path, u.RawQuery)
	for _, part := range Split(text, HookLimit(hook)) {
		if err := c.post(ctx, u, part, data); err != nil {
			return err
		}
	}
	return nil
}

func (c *Client) post(ctx context.Context, hook *url.URL, text string, data any) error {
	u := *hook
	q := u.Query()
	take := func(names ...string) string {
		var v string
		for _, n := range names {
			if x := q.Get(n); x != "" && v == "" {
				v = x
			}
			q.Del(n)
		}
		return v
	}
	var body any
	var accept func(int) bool
	switch {
	case strings.HasSuffix(u.Host, "hooks.slack.com"):
		m := map[string]string{"text": text}
		if v := take("username"); v != "" {
			m["username"] = v
		}
		if v := take("icon_emoji"); v != "" {
			m["icon_emoji"] = v
		}
		body = m
	case strings.HasSuffix(u.Host, "discord.com") || strings.HasSuffix(u.Host, "discordapp.com"):
		m := map[string]string{"content": text}
		if v := take("username"); v != "" {
			m["username"] = v
		}
		if v := take("avatar_url"); v != "" {
			m["avatar_url"] = v
		}
		body = m
	case u.Host == "api.telegram.org":
		chat := take("chat_id")
		if chat == "" {
			return fmt.Errorf("a Telegram webhook needs ?chat_id= in the URL")
		}
		m := map[string]any{"chat_id": chat, "text": text, "disable_web_page_preview": take("preview") != "yes"}
		if v := take("parse_mode"); v != "" {
			m["parse_mode"] = v
		}
		if v := take("message_thread_id", "thread"); v != "" {
			if n, err := strconv.Atoi(v); err == nil {
				m["message_thread_id"] = n
			} else {
				m["message_thread_id"] = v
			}
		}
		body = m
	case u.Host == "chat.googleapis.com":
		body = map[string]string{"text": text} // keeps key and token in the query
		q = hook.Query()
	case strings.Contains(u.Path, "/workflows/"):
		// A Power Automate workflow takes HTML text and answers 202.
		body = map[string]string{"text": strings.ReplaceAll(html.EscapeString(text), "\n", "<br>")}
		accept = func(s int) bool { return s == http.StatusAccepted }
	case strings.Contains(u.Path, "/webhookb2/"):
		body = map[string]string{"text": text}
	default:
		body = map[string]any{"text": text, "data": data}
	}
	u.RawQuery = q.Encode()
	raw, _ := json.Marshal(body)
	_, err := c.Do(ctx, func() (*http.Request, error) {
		req, err := http.NewRequest(http.MethodPost, u.String(), bytes.NewReader(raw))
		if err != nil {
			return nil, fmt.Errorf("the webhook URL is not usable")
		}
		req.Header.Set("Content-Type", "application/json")
		return req, nil
	}, accept)
	return err
}

// redact keeps tokens out of error messages: webhook URLs carry secrets.
func redact(hook string) string {
	u, err := url.Parse(hook)
	if err != nil || u.Host == "" {
		return "(webhook)"
	}
	return u.Scheme + "://" + u.Host + "/…"
}
