package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

// The provider configuration is projectdiscovery/notify's provider-config.yaml
// (MIT), key for key: a file written for notify works here. The requests
// are the ones notify (and shoutrrr, behind most of its providers) builds.

// ProviderConfig is the file: a list of entries per provider.
type ProviderConfig struct {
	Slack      []*SlackOptions      `yaml:"slack"`
	Discord    []*DiscordOptions    `yaml:"discord"`
	Pushover   []*PushoverOptions   `yaml:"pushover"`
	SMTP       []*SMTPOptions       `yaml:"smtp"`
	Teams      []*TeamsOptions      `yaml:"teams"`
	Telegram   []*TelegramOptions   `yaml:"telegram"`
	GoogleChat []*GoogleChatOptions `yaml:"googlechat"`
	Custom     []*CustomOptions     `yaml:"custom"`
	Gotify     []*GotifyOptions     `yaml:"gotify"`
}

// ProviderNames in notify's order, which is the order messages go out in.
var ProviderNames = []string{"slack", "discord", "pushover", "googlechat", "smtp", "teams", "telegram", "custom", "gotify"}

// Delivery is the outcome of one message to one configured entry.
type Delivery struct {
	Provider string
	ID       string
	Parts    int // requests or mails it took
	Tries    int // extra tries a 429, a 5xx or a failed connection cost
	Err      error
}

// Provider sends a message to each of its configured entries.
type Provider interface {
	Name() string
	Send(ctx context.Context, msg, cliFormat string) []Delivery
}

// Env is what every provider shares.
type Env struct {
	Client *Client
	Now    func() time.Time // nil: time.Now
}

func (e *Env) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

// post sends one request through the client, building it again for each try.
func (e *Env) post(ctx context.Context, method, url string, body []byte, header map[string]string, accept func(int) bool) (Result, error) {
	return e.Client.Do(ctx, func() (*http.Request, error) {
		req, err := http.NewRequest(method, url, bytes.NewReader(body))
		if err != nil {
			return nil, errors.New("the URL is not usable")
		}
		for k, v := range header {
			req.Header.Set(k, v)
		}
		return req, nil
	}, accept)
}

// postJSON posts a JSON body.
func (e *Env) postJSON(ctx context.Context, url string, v any, header map[string]string, accept func(int) bool) (Result, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return Result{}, err
	}
	h := map[string]string{"Content-Type": "application/json"}
	for k, x := range header {
		h[k] = x
	}
	return e.post(ctx, http.MethodPost, url, raw, h, accept)
}

// counter numbers the messages a provider sends, for {{count}}.
type counter struct{ n int }

func (c *counter) next() int { c.n++; return c.n }

func pick[T any](opts []*T, id func(*T) string, ids []string) []*T {
	var out []*T
	for _, o := range opts {
		if len(ids) == 0 || contains(ids, id(o)) {
			out = append(out, o)
		}
	}
	return out
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

func entryID(id string) string {
	if id == "" {
		return "(no id)"
	}
	return id
}

// Set is the providers a run sends to.
type Set struct {
	providers []Provider
	cliFormat string
	strip     bool
}

// NewSet builds the providers of cfg that names (empty: all) and ids
// (empty: all) select, in notify's order. A name that is not a provider is
// an error.
func NewSet(cfg *ProviderConfig, names, ids []string, cliFormat string, env *Env) (*Set, error) {
	for _, n := range names {
		if !contains(ProviderNames, n) {
			return nil, fmt.Errorf("%q is not a provider (%s)", n, strings.Join(ProviderNames, ", "))
		}
	}
	want := func(name string, n int) bool {
		return n > 0 && (len(names) == 0 || contains(names, name))
	}
	s := &Set{cliFormat: cliFormat, strip: true}
	add := func(p Provider) { s.providers = append(s.providers, p) }
	if want("slack", len(cfg.Slack)) {
		add(newSlack(cfg.Slack, ids, env))
	}
	if want("discord", len(cfg.Discord)) {
		add(newDiscord(cfg.Discord, ids, env))
	}
	if want("pushover", len(cfg.Pushover)) {
		add(newPushover(cfg.Pushover, ids, env))
	}
	if want("googlechat", len(cfg.GoogleChat)) {
		add(newGoogleChat(cfg.GoogleChat, ids, env))
	}
	if want("smtp", len(cfg.SMTP)) {
		add(newSMTP(cfg.SMTP, ids, env))
	}
	if want("teams", len(cfg.Teams)) {
		add(newTeams(cfg.Teams, ids, env))
	}
	if want("telegram", len(cfg.Telegram)) {
		add(newTelegram(cfg.Telegram, ids, env))
	}
	if want("custom", len(cfg.Custom)) {
		add(newCustom(cfg.Custom, ids, env))
	}
	if want("gotify", len(cfg.Gotify)) {
		add(newGotify(cfg.Gotify, ids, env))
	}
	return s, nil
}

// Entries is how many configured entries messages go to.
func (s *Set) Entries() int {
	n := 0
	for _, p := range s.providers {
		if c, ok := p.(interface{ entries() int }); ok {
			n += c.entries()
		}
	}
	return n
}

// Send sends msg to every entry. Colour codes are removed first, as notify does.
func (s *Set) Send(ctx context.Context, msg string) []Delivery {
	if s.strip {
		msg = ansi.ReplaceAllString(msg, "")
	}
	var out []Delivery
	for _, p := range s.providers {
		out = append(out, p.Send(ctx, msg, s.cliFormat)...)
	}
	return out
}

var ansi = regexp.MustCompile("[\u001B\u009B][[\\]()#;?]*(?:(?:(?:[a-zA-Z\\d]*(?:;[a-zA-Z\\d]*)*)?\u0007)|(?:(?:\\d{1,4}(?:;\\d{0,4})*)?[\\dA-PRZcf-ntqry=><~]))")

// LoadConfig reads a provider-config.yaml. Words that start with $ are
// replaced by the environment variable of that name when it is set, as
// notify does; keys the file has and the schema does not are an error, so
// a mistyped key is not a silent hole in the notification.
func LoadConfig(path string) (*ProviderConfig, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var lines []string
	for _, l := range strings.Split(string(raw), "\n") {
		lines = append(lines, substituteEnv(l))
	}
	return ParseConfig(strings.NewReader(strings.Join(lines, "\n")), path)
}

// ParseConfig decodes the YAML in r.
func ParseConfig(r io.Reader, name string) (*ProviderConfig, error) {
	var cfg ProviderConfig
	dec := yaml.NewDecoder(r)
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%s: %s", name, strings.TrimPrefix(err.Error(), "yaml: "))
	}
	return &cfg, nil
}

// substituteEnv is projectdiscovery/utils' (MIT): a whitespace-separated
// word, quotes trimmed, that starts with $ is replaced by that variable
// when it is not empty. ${NAME} works too.
func substituteEnv(line string) string {
	for _, word := range strings.Fields(line) {
		word = strings.Trim(word, `"`)
		if !strings.HasPrefix(word, "$") {
			continue
		}
		key := strings.TrimPrefix(word, "$")
		key = strings.TrimSuffix(strings.TrimPrefix(key, "{"), "}")
		if v := os.Getenv(key); v != "" {
			line = strings.Replace(line, word, v, 1)
		}
	}
	return line
}
