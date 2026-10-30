package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"text/template"

	"github.com/Masterminds/sprig/v3"
)

// ---- Pushover

// PushoverOptions are notify's pushover entry.
type PushoverOptions struct {
	ID               string   `yaml:"id"`
	PushoverApiToken string   `yaml:"pushover_api_token"`
	UserKey          string   `yaml:"pushover_user_key"`
	PushoverDevices  []string `yaml:"pushover_devices"`
	PushoverFormat   string   `yaml:"pushover_format"`
}

type pushover struct {
	env *Env
	counter
	opts []*PushoverOptions
}

func newPushover(o []*PushoverOptions, ids []string, env *Env) *pushover {
	p := &pushover{env: env, opts: pick(o, func(x *PushoverOptions) string { return x.ID }, ids)}
	for _, x := range p.opts {
		env.Client.AddSecrets(x.PushoverApiToken, x.UserKey)
	}
	return p
}

func (p *pushover) Name() string { return "pushover" }
func (p *pushover) entries() int { return len(p.opts) }

// pushoverLimit is the longest message Pushover takes.
const pushoverLimit = 1024

func (p *pushover) Send(ctx context.Context, msg, cli string) []Delivery {
	n := p.next()
	var out []Delivery
	for _, o := range p.opts {
		d := Delivery{Provider: "pushover", ID: entryID(o.ID)}
		text := FormatMessage(msg, SelectFormat(cli, o.PushoverFormat), n, p.env.now())
		parts := Split(text, pushoverLimit)
		d.Parts = len(parts)
		for _, part := range parts {
			form := url.Values{}
			form.Set("device", strings.Join(o.PushoverDevices, ","))
			form.Set("user", o.UserKey)
			form.Set("token", o.PushoverApiToken)
			form.Set("message", part)
			form.Set("priority", "0")
			_, d.Err = p.env.post(ctx, http.MethodPost, "https://api.pushover.net/1/messages.json", []byte(form.Encode()),
				map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, func(s int) bool { return s == http.StatusOK })
			if d.Err != nil {
				break
			}
		}
		d.Tries = p.env.Client.Attempts() - 1
		out = append(out, d)
	}
	return out
}

// ---- Gotify

// GotifyOptions are notify's gotify entry.
type GotifyOptions struct {
	ID               string `yaml:"id"`
	GotifyHost       string `yaml:"gotify_host"`
	GotifyPort       string `yaml:"gotify_port"`
	GotifyToken      string `yaml:"gotify_token"`
	GotifyFormat     string `yaml:"gotify_format"`
	GotifyDisableTLS bool   `yaml:"gotify_disabletls"`
	GotifyTitle      string `yaml:"gotify_title"`
}

type gotify struct {
	env *Env
	counter
	opts []*GotifyOptions
}

func newGotify(o []*GotifyOptions, ids []string, env *Env) *gotify {
	g := &gotify{env: env, opts: pick(o, func(x *GotifyOptions) string { return x.ID }, ids)}
	for _, x := range g.opts {
		env.Client.AddSecrets(x.GotifyToken)
	}
	return g
}

func (g *gotify) Name() string { return "gotify" }
func (g *gotify) entries() int { return len(g.opts) }

// legacyGotifyToken: 15 characters starting with A, the old token shape.
func legacyGotifyToken(t string) bool {
	if len(t) != 15 || t[0] != 'A' {
		return false
	}
	return strings.Trim(t, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_") == ""
}

func (g *gotify) Send(ctx context.Context, msg, cli string) []Delivery {
	n := g.next()
	var out []Delivery
	for _, o := range g.opts {
		d := Delivery{Provider: "gotify", ID: entryID(o.ID)}
		text := FormatMessage(msg, SelectFormat(cli, o.GotifyFormat), n, g.env.now())
		d.Parts = 1
		d.Err = g.one(ctx, o, text)
		d.Tries = g.env.Client.Attempts() - 1
		out = append(out, d)
	}
	return out
}

// one sends to Gotify's REST API. A token of the old shape travels in the
// query, as shoutrrr sends it (with its default title and a priority);
// any other in the X-Gotify-Key header, as notify's direct path does.
func (g *gotify) one(ctx context.Context, o *GotifyOptions, text string) error {
	scheme := "https"
	if o.GotifyDisableTLS {
		scheme = "http"
	}
	hostPort := o.GotifyHost
	if o.GotifyPort != "" {
		hostPort = net.JoinHostPort(o.GotifyHost, o.GotifyPort)
	}
	endpoint := fmt.Sprintf("%s://%s/message", scheme, hostPort)
	if legacyGotifyToken(o.GotifyToken) {
		title := o.GotifyTitle
		if title == "" {
			title = "Shoutrrr notification"
		}
		body := map[string]any{"message": text, "title": title, "priority": 0}
		_, err := g.env.postJSON(ctx, endpoint+"?token="+o.GotifyToken, body, nil, nil)
		return err
	}
	body := map[string]any{"message": text}
	if o.GotifyTitle != "" {
		body["title"] = o.GotifyTitle
	}
	_, err := g.env.postJSON(ctx, endpoint, body, map[string]string{"X-Gotify-Key": o.GotifyToken}, nil)
	return err
}

// ---- custom

// CustomOptions are notify's custom entry.
type CustomOptions struct {
	ID               string            `yaml:"id"`
	CustomWebhookURL string            `yaml:"custom_webhook_url"`
	CustomMethod     string            `yaml:"custom_method"`
	CustomHeaders    map[string]string `yaml:"custom_headers"`
	CustomFormat     string            `yaml:"custom_format"`
	CustomSprig      string            `yaml:"custom_sprig"`
}

type custom struct {
	env *Env
	counter
	opts []*CustomOptions
}

func newCustom(o []*CustomOptions, ids []string, env *Env) *custom {
	c := &custom{env: env, opts: pick(o, func(x *CustomOptions) string { return x.ID }, ids)}
	for _, x := range c.opts {
		env.Client.AddSecrets(x.CustomWebhookURL)
		for _, v := range x.CustomHeaders {
			env.Client.AddSecrets(v)
		}
	}
	return c
}

func (c *custom) Name() string { return "custom" }
func (c *custom) entries() int { return len(c.opts) }

func (c *custom) Send(ctx context.Context, msg, cli string) []Delivery {
	n := c.next()
	var out []Delivery
	for _, o := range c.opts {
		d := Delivery{Provider: "custom", ID: entryID(o.ID), Parts: 1}
		body, err := c.render(o, msg, cli, n)
		if err != nil {
			d.Err = err
		} else {
			// An empty method is a GET, as in notify.
			_, d.Err = c.env.post(ctx, o.CustomMethod, o.CustomWebhookURL, []byte(body), o.CustomHeaders, nil)
		}
		d.Tries = c.env.Client.Attempts() - 1
		out = append(out, d)
	}
	return out
}

// render builds the body: a sprig template over the message read as a JSON
// object, the format with {{dataJsonString}} (the message as a JSON string)
// and the message variables, or the formatted message.
func (c *custom) render(o *CustomOptions, msg, cli string, n int) (string, error) {
	switch {
	case o.CustomSprig != "":
		data := map[string]any{}
		if err := json.Unmarshal([]byte(msg), &data); err != nil {
			return "", fmt.Errorf("the message is not a JSON object for custom_sprig: %v", err)
		}
		tmpl, err := template.New("sprig").Funcs(sprig.TxtFuncMap()).Parse(o.CustomSprig)
		if err != nil {
			return "", fmt.Errorf("custom_sprig does not parse: %v", err)
		}
		var buf bytes.Buffer
		if err := tmpl.Execute(&buf, data); err != nil {
			return "", fmt.Errorf("custom_sprig failed: %v", err)
		}
		return buf.String(), nil
	case strings.Contains(o.CustomFormat, "{{dataJsonString}}"):
		raw, _ := json.Marshal(msg)
		now := c.env.now()
		return strings.NewReplacer(
			"{{dataJsonString}}", string(raw),
			"{{datetime}}", FormatMessage("", "{{datetime}}", n, now),
			"{{date}}", FormatMessage("", "{{date}}", n, now),
			"{{time}}", FormatMessage("", "{{time}}", n, now),
			"{{count}}", fmt.Sprint(n),
		).Replace(o.CustomFormat), nil
	}
	return FormatMessage(msg, SelectFormat(cli, o.CustomFormat), n, c.env.now()), nil
}
