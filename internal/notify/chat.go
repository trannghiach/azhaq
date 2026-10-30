package notify

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

// ---- Slack

// SlackOptions are notify's slack entry.
type SlackOptions struct {
	ID              string `yaml:"id"`
	SlackWebHookURL string `yaml:"slack_webhook_url"`
	SlackUsername   string `yaml:"slack_username"`
	SlackChannel    string `yaml:"slack_channel"`
	SlackThreads    bool   `yaml:"slack_threads"`
	SlackThreadTS   string `yaml:"slack_thread_ts"`
	SlackToken      string `yaml:"slack_token"`
	SlackFormat     string `yaml:"slack_format"`
	SlackIconEmoji  string `yaml:"slack_icon_emoji"`
}

type slack struct {
	env *Env
	counter
	opts []*SlackOptions
}

func newSlack(o []*SlackOptions, ids []string, env *Env) *slack {
	s := &slack{env: env, opts: pick(o, func(x *SlackOptions) string { return x.ID }, ids)}
	for _, x := range s.opts {
		env.Client.AddSecrets(x.SlackWebHookURL, x.SlackToken)
	}
	return s
}

func (s *slack) Name() string { return "slack" }
func (s *slack) entries() int { return len(s.opts) }

const slackPostMessageAPI = "https://slack.com/api/chat.postMessage"

func (s *slack) Send(ctx context.Context, msg, cli string) []Delivery {
	n := s.next()
	var out []Delivery
	for _, o := range s.opts {
		d := Delivery{Provider: "slack", ID: entryID(o.ID)}
		text := FormatMessage(msg, SelectFormat(cli, o.SlackFormat), n, s.env.now())
		parts := Split(text, slackLimit)
		d.Parts = len(parts)
		for _, part := range parts {
			if d.Err = s.one(ctx, o, part); d.Err != nil {
				break
			}
		}
		d.Tries = s.env.Client.Attempts() - 1
		out = append(out, d)
	}
	return out
}

func (s *slack) one(ctx context.Context, o *SlackOptions, text string) error {
	if o.SlackThreads {
		if o.SlackToken == "" {
			return fmt.Errorf("slack_token value is required to start a thread")
		}
		if o.SlackChannel == "" {
			return fmt.Errorf("slack_channel value is required to start a thread")
		}
		body := map[string]string{"channel": o.SlackChannel, "text": text}
		if o.SlackThreadTS != "" {
			body["thread_ts"] = o.SlackThreadTS
		}
		res, err := s.env.postJSON(ctx, slackPostMessageAPI, body, map[string]string{"Authorization": "Bearer " + o.SlackToken}, nil)
		if err != nil {
			return err
		}
		var r struct {
			Ok    bool   `json:"ok"`
			TS    string `json:"ts"`
			Error string `json:"error"`
		}
		if json.Unmarshal(res.Body, &r) != nil {
			return fmt.Errorf("slack answered something that is not JSON")
		}
		if !r.Ok {
			return fmt.Errorf("error while sending slack message: %s", r.Error)
		}
		if o.SlackThreadTS == "" {
			o.SlackThreadTS = r.TS // the first message starts the thread
		}
		return nil
	}
	if !strings.HasPrefix(o.SlackWebHookURL, "https://hooks.slack.com/services/") {
		return fmt.Errorf("invalid slack webhook URL")
	}
	body := map[string]any{"text": text}
	if o.SlackUsername != "" {
		body["username"] = o.SlackUsername
	}
	if o.SlackIconEmoji != "" {
		body["icon_emoji"] = o.SlackIconEmoji
	}
	_, err := s.env.postJSON(ctx, o.SlackWebHookURL, body, nil, nil)
	return err
}

// ---- Discord

// DiscordOptions are notify's discord entry.
type DiscordOptions struct {
	ID                      string `yaml:"id"`
	DiscordWebHookURL       string `yaml:"discord_webhook_url"`
	DiscordWebHookUsername  string `yaml:"discord_username"`
	DiscordWebHookAvatarURL string `yaml:"discord_avatar"`
	DiscordThreads          bool   `yaml:"discord_threads"`
	DiscordThreadID         string `yaml:"discord_thread_id"`
	DiscordFormat           string `yaml:"discord_format"`
}

type discord struct {
	env *Env
	counter
	opts []*DiscordOptions
}

func newDiscord(o []*DiscordOptions, ids []string, env *Env) *discord {
	d := &discord{env: env, opts: pick(o, func(x *DiscordOptions) string { return x.ID }, ids)}
	for _, x := range d.opts {
		env.Client.AddSecrets(x.DiscordWebHookURL)
	}
	return d
}

func (d *discord) Name() string { return "discord" }
func (d *discord) entries() int { return len(d.opts) }

var reDiscordWebhook = regexp.MustCompile(`(https?)://((?:ptb\.|canary\.)?discord(?:app)?\.com)/api/?(v\d{1,2})?/webhooks/(\d{17,19})/([\w\-]{68})`)

// Discord's limits for the embeds of one webhook message (shoutrrr's).
const (
	discordChunk = 2000
	discordTotal = 6000
	discordCount = 10
)

func (d *discord) Send(ctx context.Context, msg, cli string) []Delivery {
	n := d.next()
	var out []Delivery
	for _, o := range d.opts {
		dl := Delivery{Provider: "discord", ID: entryID(o.ID)}
		text := FormatMessage(msg, SelectFormat(cli, o.DiscordFormat), n, d.env.now())
		if o.DiscordThreads {
			if o.DiscordThreadID == "" {
				dl.Err = fmt.Errorf("thread_id value is required when discord_threads is set to true. check your configuration")
			} else {
				parts := Split(text, discordChunk)
				dl.Parts = len(parts)
				for _, part := range parts {
					body := map[string]string{"content": part}
					if o.DiscordWebHookAvatarURL != "" {
						body["avatar_url"] = o.DiscordWebHookAvatarURL
					}
					if o.DiscordWebHookUsername != "" {
						body["username"] = o.DiscordWebHookUsername
					}
					if _, dl.Err = d.env.postJSON(ctx, o.DiscordWebHookURL+"?thread_id="+url.QueryEscape(o.DiscordThreadID), body, nil, nil); dl.Err != nil {
						break
					}
				}
			}
		} else if m := reDiscordWebhook.FindStringSubmatch(o.DiscordWebHookURL); m == nil {
			dl.Err = fmt.Errorf("incorrect discord configuration")
		} else {
			dl.Parts, dl.Err = d.webhook(ctx, o, m[4], m[5], text)
		}
		dl.Tries = d.env.Client.Attempts() - 1
		out = append(out, dl)
	}
	return out
}

// webhook sends text the way shoutrrr does: as embeds, 2,000 characters
// each, at most three to a message (6,000 characters), a message per batch.
func (d *discord) webhook(ctx context.Context, o *DiscordOptions, id, token, text string) (int, error) {
	type embed struct {
		Description string `json:"description,omitempty"`
		Color       uint   `json:"color,omitempty"`
	}
	type payload struct {
		Embeds    []embed `json:"embeds"`
		Username  string  `json:"username,omitempty"`
		AvatarURL string  `json:"avatar_url,omitempty"`
	}
	posts := 0
	for {
		chunks, omitted := partition(text, 100)
		p := payload{Username: o.DiscordWebHookUsername, AvatarURL: o.DiscordWebHookAvatarURL}
		for _, c := range chunks {
			p.Embeds = append(p.Embeds, embed{Description: c, Color: 0x50D9ff})
		}
		if len(chunks) == 0 {
			return posts, fmt.Errorf("message is empty")
		}
		posts++
		if _, err := d.env.postJSON(ctx, "https://discord.com/api/webhooks/"+id+"/"+token, p, nil, nil); err != nil {
			return posts, err
		}
		if omitted == 0 {
			return posts, nil
		}
		r := []rune(text)
		text = string(r[len(r)-omitted:])
	}
}

// partition is shoutrrr's PartitionMessage (MIT) with Discord's limits:
// chunks of at most 2,000 characters, cut at a space or a newline found
// within the last distance characters, until 6,000 characters or ten
// chunks are used. omitted is how many characters did not fit.
func partition(input string, distance int) (items []string, omitted int) {
	runes := []rune(input)
	offset := 0
	maxTotal := min(len(runes), discordTotal)
	maxCount := discordCount - 1
	if len(input) == 0 {
		return nil, 0
	}
	for i := 0; i < maxCount; i++ {
		end := offset + discordChunk
		next := end
		if end >= maxTotal {
			end, next = maxTotal, maxTotal
		} else {
			for r := 0; r < distance; r++ {
				rp := end - r
				if runes[rp] == '\n' || runes[rp] == ' ' {
					end, next = rp, rp+1
					break
				}
			}
		}
		items = append(items, string(runes[offset:end]))
		offset = next
		if offset >= maxTotal {
			break
		}
	}
	return items, len(runes) - offset
}

// ---- Telegram

// TelegramOptions are notify's telegram entry.
type TelegramOptions struct {
	ID                string `yaml:"id"`
	TelegramAPIKey    string `yaml:"telegram_api_key"`
	TelegramChatID    string `yaml:"telegram_chat_id"`
	TelegramThreadID  string `yaml:"telegram_thread_id"`
	TelegramFormat    string `yaml:"telegram_format"`
	TelegramParseMode string `yaml:"telegram_parsemode"`
	TelegramPreview   bool   `yaml:"telegram_preview"`
}

type telegram struct {
	env *Env
	counter
	opts []*TelegramOptions
}

func newTelegram(o []*TelegramOptions, ids []string, env *Env) *telegram {
	t := &telegram{env: env, opts: pick(o, func(x *TelegramOptions) string { return x.ID }, ids)}
	for _, x := range t.opts {
		env.Client.AddSecrets(x.TelegramAPIKey)
	}
	return t
}

func (t *telegram) Name() string { return "telegram" }
func (t *telegram) entries() int { return len(t.opts) }

var reTelegramToken = regexp.MustCompile(`^[0-9]+:[a-zA-Z0-9_-]+$`)

func (t *telegram) Send(ctx context.Context, msg, cli string) []Delivery {
	n := t.next()
	var out []Delivery
	for _, o := range t.opts {
		d := Delivery{Provider: "telegram", ID: entryID(o.ID)}
		text := FormatMessage(msg, SelectFormat(cli, o.TelegramFormat), n, t.env.now())
		d.Err = t.one(ctx, o, text, &d)
		d.Tries = t.env.Client.Attempts() - 1
		out = append(out, d)
	}
	return out
}

func (t *telegram) one(ctx context.Context, o *TelegramOptions, text string, d *Delivery) error {
	if !reTelegramToken.MatchString(o.TelegramAPIKey) {
		return fmt.Errorf("invalid telegram token")
	}
	mode := o.TelegramParseMode
	switch strings.ToLower(mode) {
	case "", "none":
		mode = ""
	case "markdown":
		mode = "Markdown"
	case "html":
		mode = "HTML"
	case "markdownv2":
		mode = "MarkdownV2"
	default:
		return fmt.Errorf("telegram_parsemode %q is not None, Markdown, MarkdownV2 or HTML", o.TelegramParseMode)
	}
	channel := o.TelegramChatID
	if o.TelegramThreadID != "" && !strings.Contains(o.TelegramChatID, ":") {
		channel = o.TelegramChatID + ":" + o.TelegramThreadID
	}
	if channel == "" {
		return fmt.Errorf("no channels defined: telegram_chat_id is empty")
	}
	for _, ch := range strings.Split(channel, ",") {
		chat, thread, hasThread := strings.Cut(ch, ":")
		parts := Split(text, telegramLimit)
		d.Parts += len(parts)
		for _, part := range parts {
			body := map[string]any{
				"text":                     part,
				"chat_id":                  chat,
				"disable_web_page_preview": !o.TelegramPreview,
				"disable_notification":     false,
				"reply_to_message_id":      0,
			}
			if hasThread {
				if id, err := strconv.Atoi(thread); err == nil {
					body["message_thread_id"] = id
				}
			}
			if mode != "" {
				body["parse_mode"] = mode
			}
			if _, err := t.env.postJSON(ctx, "https://api.telegram.org/bot"+o.TelegramAPIKey+"/sendMessage", body, nil, nil); err != nil {
				return err
			}
		}
	}
	return nil
}

// ---- Google Chat

// GoogleChatOptions are notify's googlechat entry.
type GoogleChatOptions struct {
	ID               string `yaml:"id"`
	Space            string `yaml:"space"`
	Key              string `yaml:"key"`
	Token            string `yaml:"token"`
	GoogleChatFormat string `yaml:"google_chat_format"`
}

type googleChat struct {
	env *Env
	counter
	opts []*GoogleChatOptions
}

func newGoogleChat(o []*GoogleChatOptions, ids []string, env *Env) *googleChat {
	g := &googleChat{env: env, opts: pick(o, func(x *GoogleChatOptions) string { return x.ID }, ids)}
	for _, x := range g.opts {
		env.Client.AddSecrets(x.Key, x.Token)
	}
	return g
}

func (g *googleChat) Name() string { return "googlechat" }
func (g *googleChat) entries() int { return len(g.opts) }

// googleChatLimit is the longest text Google Chat takes in a message.
const googleChatLimit = 4096

func (g *googleChat) Send(ctx context.Context, msg, cli string) []Delivery {
	n := g.next()
	var out []Delivery
	for _, o := range g.opts {
		d := Delivery{Provider: "googlechat", ID: entryID(o.ID)}
		text := FormatMessage(msg, SelectFormat(cli, o.GoogleChatFormat), n, g.env.now())
		if o.Key == "" {
			d.Err = fmt.Errorf("missing field 'key'")
		} else {
			q := url.Values{}
			q.Set("key", o.Key)
			q.Set("token", o.Token)
			target := "https://chat.googleapis.com/v1/spaces/" + o.Space + "/messages?" + q.Encode()
			parts := Split(text, googleChatLimit)
			d.Parts = len(parts)
			for _, part := range parts {
				if _, d.Err = g.env.postJSON(ctx, target, map[string]string{"text": part}, nil, nil); d.Err != nil {
					break
				}
			}
		}
		d.Tries = g.env.Client.Attempts() - 1
		out = append(out, d)
	}
	return out
}

// ---- Microsoft Teams

// TeamsOptions are notify's teams entry.
type TeamsOptions struct {
	ID              string `yaml:"id"`
	TeamsWebHookURL string `yaml:"teams_webhook_url"`
	TeamsFormat     string `yaml:"teams_format"`
}

type teams struct {
	env *Env
	counter
	opts []*TeamsOptions
}

func newTeams(o []*TeamsOptions, ids []string, env *Env) *teams {
	t := &teams{env: env, opts: pick(o, func(x *TeamsOptions) string { return x.ID }, ids)}
	for _, x := range t.opts {
		env.Client.AddSecrets(x.TeamsWebHookURL)
	}
	return t
}

func (t *teams) Name() string { return "teams" }
func (t *teams) entries() int { return len(t.opts) }

// teamsLimit keeps a message under the 28 KB a Teams webhook takes.
const teamsLimit = 15000

var (
	reUUID4 = regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}`)
	reHash  = regexp.MustCompile(`[A-Za-z0-9]{32}`)
)

func (t *teams) Send(ctx context.Context, msg, cli string) []Delivery {
	n := t.next()
	var out []Delivery
	for _, o := range t.opts {
		d := Delivery{Provider: "teams", ID: entryID(o.ID)}
		text := FormatMessage(msg, SelectFormat(cli, o.TeamsFormat), n, t.env.now())
		parts := Split(text, teamsLimit)
		d.Parts = len(parts)
		for _, part := range parts {
			if d.Err = t.one(ctx, o, part); d.Err != nil {
				break
			}
		}
		d.Tries = t.env.Client.Attempts() - 1
		out = append(out, d)
	}
	return out
}

func (t *teams) one(ctx context.Context, o *TeamsOptions, text string) error {
	u, err := url.Parse(o.TeamsWebHookURL)
	if err != nil || u.Host == "" || u.Path == "" {
		return fmt.Errorf("teams: invalid webhook url")
	}
	switch {
	case strings.Contains(u.Path, "/webhookb2/"):
		return t.connector(ctx, o.TeamsWebHookURL, text)
	case strings.Contains(u.Path, "/workflows/"):
		// A Power Automate workflow: HTML text, answered with 202.
		body := map[string]string{"text": strings.ReplaceAll(html.EscapeString(text), "\n", "<br>")}
		_, err := t.env.postJSON(ctx, o.TeamsWebHookURL, body, nil, func(s int) bool { return s == http.StatusAccepted })
		return err
	}
	return fmt.Errorf("teams: unsupported webhook url")
}

// connector sends the MessageCard shoutrrr builds to an Office 365
// connector webhook: https://HOST/webhookb2/GROUP@TENANT/IncomingWebhook/ALT/OWNER.
func (t *teams) connector(ctx context.Context, hook, text string) error {
	before, tokens, _ := strings.Cut(hook, "/webhookb2/")
	host := strings.TrimPrefix(before, "https://")
	tokens = strings.ReplaceAll(tokens, "IncomingWebhook/", "")
	group, rest, _ := strings.Cut(tokens, "@")
	tenant, rest, _ := strings.Cut(rest, "/")
	alt, owner, _ := strings.Cut(rest, "/")
	if !reUUID4.MatchString(group) || !reUUID4.MatchString(tenant) || !reHash.MatchString(alt) || !reUUID4.MatchString(owner) {
		return fmt.Errorf("teams: invalid URL format: a token part is not valid")
	}
	path := "webhookb2"
	if host == "outlook.office.com" {
		path = "webhook"
	}
	type section struct {
		Text       string `json:"text,omitempty"`
		StartGroup bool   `json:"startGroup"`
	}
	var sections []section
	for _, line := range strings.Split(text, "\n") {
		sections = append(sections, section{Text: line})
	}
	summary := sections[0].Text
	if len(summary) > 20 {
		cut := 21
		for cut > 0 && cut < len(summary) && !utf8.RuneStart(summary[cut]) {
			cut--
		}
		summary = summary[:cut]
	}
	card := struct {
		Type     string    `json:"@type"`
		Context  string    `json:"@context"`
		Markdown bool      `json:"markdown"`
		Summary  string    `json:"summary,omitempty"`
		Sections []section `json:"sections,omitempty"`
	}{"MessageCard", "http://schema.org/extensions", true, summary, sections}
	target := fmt.Sprintf("https://%s/%s/%s@%s/IncomingWebhook/%s/%s", host, path, group, tenant, alt, owner)
	_, err := t.env.postJSON(ctx, target, card, nil, func(s int) bool { return s == http.StatusOK })
	return err
}
