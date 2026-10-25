// Package notify posts a short text, and for generic webhooks the full
// change set, to Slack, Discord, Telegram or any URL that takes JSON.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Send posts text to hook. Slack and Discord incoming webhooks and
// Telegram's sendMessage (with chat_id in the URL) get the text in their
// own shape; any other URL gets {"text": …, "data": data}.
func Send(ctx context.Context, hook, text string, data any) error {
	u, err := url.Parse(hook)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") {
		return fmt.Errorf("webhook %q is not an http(s) URL", redact(hook))
	}
	var body any
	switch {
	case strings.HasSuffix(u.Host, "hooks.slack.com"):
		body = map[string]string{"text": text}
	case strings.HasSuffix(u.Host, "discord.com") || strings.HasSuffix(u.Host, "discordapp.com"):
		body = map[string]string{"content": clip(text, 1900)}
	case u.Host == "api.telegram.org":
		chat := u.Query().Get("chat_id")
		if chat == "" {
			return fmt.Errorf("a Telegram webhook needs ?chat_id= in the URL")
		}
		q := u.Query()
		q.Del("chat_id")
		u.RawQuery = q.Encode()
		hook = u.String()
		body = map[string]any{"chat_id": chat, "text": clip(text, 4000), "disable_web_page_preview": true}
	default:
		body = map[string]any{"text": text, "data": data}
	}
	raw, _ := json.Marshal(body)
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, hook, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("webhook %s: %w", redact(hook), err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("webhook %s: %s %s", redact(hook), resp.Status, strings.TrimSpace(string(msg)))
	}
	return nil
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "\n…"
}

// redact keeps tokens out of error messages: webhook URLs carry secrets.
func redact(hook string) string {
	u, err := url.Parse(hook)
	if err != nil {
		return "(webhook)"
	}
	return u.Scheme + "://" + u.Host + "/…"
}
