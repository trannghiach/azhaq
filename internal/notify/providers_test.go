package notify

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
	"time"
)

var fixedNow = time.Date(2026, 10, 30, 14, 5, 9, 0, time.FixedZone("", 7*3600))

// run sends msg to the providers cfg (YAML) holds, through the stub.
func run(t *testing.T, s *stub, cfg, cli string, names, ids []string, msgs ...string) []Delivery {
	t.Helper()
	pc, err := ParseConfig(strings.NewReader(cfg), "test.yaml")
	if err != nil {
		t.Fatal(err)
	}
	set, err := NewSet(pc, names, ids, cli, &Env{Client: s.client(), Now: func() time.Time { return fixedNow }})
	if err != nil {
		t.Fatal(err)
	}
	var out []Delivery
	for _, m := range msgs {
		out = append(out, set.Send(context.Background(), m)...)
	}
	for _, d := range out {
		if d.Err != nil {
			t.Errorf("%s %s: %v", d.Provider, d.ID, d.Err)
		}
	}
	return out
}

func jsonOf(t *testing.T, s string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatalf("%v: %q", err, s)
	}
	return m
}

func one(t *testing.T, s *stub) seen {
	t.Helper()
	g := s.got()
	if len(g) != 1 {
		t.Fatalf("%d requests, want 1: %+v", len(g), g)
	}
	return g[0]
}

func TestSlackWebhook(t *testing.T) {
	s := newStub(t)
	run(t, s, `
slack:
  - id: recon
    slack_webhook_url: https://hooks.slack.com/services/T000/B000/XXXX
    slack_username: azhaq
    slack_icon_emoji: ":mag:"
    slack_channel: "#ignored-on-webhooks"
    slack_format: "{{data}} ({{count}})"
`, "", nil, nil, "hello")
	r := one(t, s)
	if r.Method != "POST" || r.Host != "hooks.slack.com" || r.Path != "/services/T000/B000/XXXX" || r.Header.Get("Content-Type") != "application/json" {
		t.Errorf("%+v", r)
	}
	m := jsonOf(t, r.Body)
	if len(m) != 3 || m["text"] != "hello (1)" || m["username"] != "azhaq" || m["icon_emoji"] != ":mag:" {
		t.Errorf("body %v (notify sends text, username and icon_emoji, no channel)", m)
	}
}

func TestSlackThreadReusesTheFirstTimestamp(t *testing.T) {
	s := newStub(t)
	s.reply = func(n int, r *seen) (int, map[string]string, string) {
		return 200, nil, `{"ok":true,"ts":"1700000000.000100"}`
	}
	run(t, s, `
slack:
  - id: thr
    slack_threads: true
    slack_token: xoxb-123456
    slack_channel: C0123
`, "", nil, nil, "one", "two")
	g := s.got()
	if len(g) != 2 {
		t.Fatalf("%d requests", len(g))
	}
	for _, r := range g {
		if r.Host != "slack.com" || r.Path != "/api/chat.postMessage" || r.Header.Get("Authorization") != "Bearer xoxb-123456" || r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("%+v", r)
		}
	}
	if m := jsonOf(t, g[0].Body); m["channel"] != "C0123" || m["text"] != "one" || m["thread_ts"] != nil {
		t.Errorf("first %v", m)
	}
	if m := jsonOf(t, g[1].Body); m["thread_ts"] != "1700000000.000100" || m["text"] != "two" {
		t.Errorf("second %v", m)
	}
}

func TestSlackThreadErrorsAreReported(t *testing.T) {
	s := newStub(t)
	s.reply = func(int, *seen) (int, map[string]string, string) {
		return 200, nil, `{"ok":false,"error":"channel_not_found"}`
	}
	pc, _ := ParseConfig(strings.NewReader("slack:\n  - id: x\n    slack_threads: true\n    slack_token: xoxb-1\n    slack_channel: C1\n  - id: y\n    slack_threads: true\n    slack_channel: C1\n"), "t")
	set, _ := NewSet(pc, nil, nil, "", &Env{Client: s.client()})
	d := set.Send(context.Background(), "x")
	if len(d) != 2 || d[0].Err == nil || !strings.Contains(d[0].Err.Error(), "channel_not_found") || d[1].Err == nil || !strings.Contains(d[1].Err.Error(), "slack_token") {
		t.Errorf("%+v", d)
	}
}

func TestDiscordWebhookSendsEmbeds(t *testing.T) {
	s := newStub(t)
	id, tok := "123456789012345678", strings.Repeat("a", 68)
	run(t, s, `
discord:
  - id: d
    discord_webhook_url: https://discord.com/api/webhooks/`+id+`/`+tok+`
    discord_username: azhaq
    discord_avatar: https://x.test/a.png
`, "", nil, nil, "hello")
	r := one(t, s)
	if r.Host != "discord.com" || r.Path != "/api/webhooks/"+id+"/"+tok || r.Query != "" {
		t.Errorf("%+v", r)
	}
	m := jsonOf(t, r.Body)
	emb := m["embeds"].([]any)
	if len(emb) != 1 || emb[0].(map[string]any)["description"] != "hello" || emb[0].(map[string]any)["color"] != float64(0x50D9ff) || m["username"] != "azhaq" || m["avatar_url"] != "https://x.test/a.png" || m["content"] != nil {
		t.Errorf("body %v", m)
	}
}

// 2,000 characters to an embed, three to a message: shoutrrr's limits.
func TestDiscordLongMessagePartitions(t *testing.T) {
	s := newStub(t)
	id, tok := "123456789012345678", strings.Repeat("a", 68)
	long := strings.Repeat("word ", 2400) // 12,000 characters
	run(t, s, "discord:\n  - discord_webhook_url: https://discord.com/api/webhooks/"+id+"/"+tok+"\n", "", nil, nil, long)
	g := s.got()
	if len(g) != 2 {
		t.Fatalf("%d posts for 12,000 characters, want 2 (three embeds of 2,000 each, then the rest)", len(g))
	}
	total := 0
	for _, r := range g {
		emb := jsonOf(t, r.Body)["embeds"].([]any)
		for _, e := range emb {
			n := len([]rune(e.(map[string]any)["description"].(string)))
			if n > 2000 {
				t.Errorf("embed of %d characters", n)
			}
			total += n
		}
	}
	if total < 11000 {
		t.Errorf("%d characters sent of 12,000", total)
	}
}

func TestDiscordThread(t *testing.T) {
	s := newStub(t)
	run(t, s, `
discord:
  - discord_webhook_url: https://discord.com/api/webhooks/1/x
    discord_threads: true
    discord_thread_id: "987"
    discord_username: u
`, "", nil, nil, "hi")
	r := one(t, s)
	if r.Path != "/api/webhooks/1/x" || r.Query != "thread_id=987" {
		t.Errorf("%+v", r)
	}
	if m := jsonOf(t, r.Body); m["content"] != "hi" || m["username"] != "u" || m["avatar_url"] != nil || m["embeds"] != nil {
		t.Errorf("%v", m)
	}
}

func TestTelegram(t *testing.T) {
	s := newStub(t)
	run(t, s, `
telegram:
  - telegram_api_key: "123456:ABC-def"
    telegram_chat_id: "-1001234"
    telegram_thread_id: "42"
    telegram_parsemode: html
`, "", nil, nil, "<b>hi</b>")
	r := one(t, s)
	if r.Host != "api.telegram.org" || r.Path != "/bot123456:ABC-def/sendMessage" || r.Header.Get("Content-Type") != "application/json" {
		t.Errorf("%+v", r)
	}
	m := jsonOf(t, r.Body)
	want := map[string]any{"text": "<b>hi</b>", "chat_id": "-1001234", "message_thread_id": float64(42), "parse_mode": "HTML",
		"disable_web_page_preview": true, "disable_notification": false, "reply_to_message_id": float64(0)}
	if len(m) != len(want) {
		t.Errorf("body %v", m)
	}
	for k, v := range want {
		if m[k] != v {
			t.Errorf("%s: %v, want %v", k, m[k], v)
		}
	}
}

func TestTelegramPreviewAndChatThreadSyntax(t *testing.T) {
	s := newStub(t)
	run(t, s, "telegram:\n  - telegram_api_key: \"1:a\"\n    telegram_chat_id: \"-5:9\"\n    telegram_thread_id: \"77\"\n    telegram_preview: true\n", "", nil, nil, "x")
	m := jsonOf(t, one(t, s).Body)
	if m["chat_id"] != "-5" || m["message_thread_id"] != float64(9) || m["disable_web_page_preview"] != false || m["parse_mode"] != nil {
		t.Errorf("%v", m)
	}
}

func TestTelegramRefusesABadToken(t *testing.T) {
	s := newStub(t)
	pc, _ := ParseConfig(strings.NewReader("telegram:\n  - telegram_api_key: nope\n    telegram_chat_id: \"1\"\n"), "t")
	set, _ := NewSet(pc, nil, nil, "", &Env{Client: s.client()})
	if d := set.Send(context.Background(), "x"); d[0].Err == nil || len(s.got()) != 0 {
		t.Errorf("%+v", d)
	}
}

func TestTelegramSplitsWhatShoutrrrRefuses(t *testing.T) {
	s := newStub(t)
	run(t, s, "telegram:\n  - telegram_api_key: \"1:a\"\n    telegram_chat_id: \"1\"\n", "", nil, nil, strings.Repeat("ab ", 3000))
	g := s.got()
	if len(g) != 3 {
		t.Fatalf("%d posts for 9,000 characters", len(g))
	}
	if txt := jsonOf(t, g[0].Body)["text"].(string); !strings.HasPrefix(txt, "(1/3) ") || len([]rune(txt)) > 4096 {
		t.Errorf("%d characters, starts %q", len([]rune(txt)), txt[:10])
	}
}

func TestPushover(t *testing.T) {
	s := newStub(t)
	run(t, s, `
pushover:
  - id: p
    pushover_user_key: UKEY123
    pushover_api_token: ATOKEN456
    pushover_devices: [phone, tablet]
`, "", nil, nil, "hello there")
	r := one(t, s)
	if r.Host != "api.pushover.net" || r.Path != "/1/messages.json" || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
		t.Errorf("%+v", r)
	}
	v, _ := url.ParseQuery(r.Body)
	want := url.Values{"device": {"phone,tablet"}, "user": {"UKEY123"}, "token": {"ATOKEN456"}, "message": {"hello there"}, "priority": {"0"}}
	if len(v) != len(want) {
		t.Errorf("form %v", v)
	}
	for k := range want {
		if v.Get(k) != want.Get(k) {
			t.Errorf("%s = %q, want %q", k, v.Get(k), want.Get(k))
		}
	}
}

func TestGoogleChat(t *testing.T) {
	s := newStub(t)
	run(t, s, "googlechat:\n  - space: AAA\n    key: K1\n    token: T=2\n", "", nil, nil, "hi")
	r := one(t, s)
	if r.Host != "chat.googleapis.com" || r.Path != "/v1/spaces/AAA/messages" || r.Query != "key=K1&token=T%3D2" || r.Body != `{"text":"hi"}` {
		t.Errorf("%+v", r)
	}
}

func TestTeamsWorkflowAndConnector(t *testing.T) {
	s := newStub(t)
	s.reply = func(n int, r *seen) (int, map[string]string, string) {
		if strings.Contains(r.Path, "workflows") {
			return 202, nil, ""
		}
		return 200, nil, "1"
	}
	g1, g2, owner := "11111111-2222-4333-8444-555555555555", "66666666-7777-4888-9999-000000000000", "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
	alt := strings.Repeat("a1", 16)
	run(t, s, `
teams:
  - id: wf
    teams_webhook_url: https://prod.westus.logic.azure.com:443/workflows/abc/triggers/manual/paths/invoke?sig=SECRETSIG
  - id: conn
    teams_webhook_url: https://contoso.webhook.office.com/webhookb2/`+g1+`@`+g2+`/IncomingWebhook/`+alt+`/`+owner+`
`, "", nil, nil, "a <b> & c\nsecond line")
	g := s.got()
	if len(g) != 2 {
		t.Fatalf("%d posts", len(g))
	}
	if g[0].Host != "prod.westus.logic.azure.com:443" || g[0].Query != "sig=SECRETSIG" || jsonOf(t, g[0].Body)["text"] != "a &lt;b&gt; &amp; c<br>second line" {
		t.Errorf("workflow %+v", g[0])
	}
	if g[1].Host != "contoso.webhook.office.com" || g[1].Path != "/webhookb2/"+g1+"@"+g2+"/IncomingWebhook/"+alt+"/"+owner {
		t.Errorf("connector %+v", g[1])
	}
	m := jsonOf(t, g[1].Body)
	secs := m["sections"].([]any)
	if m["@type"] != "MessageCard" || m["@context"] != "http://schema.org/extensions" || m["markdown"] != true || len(secs) != 2 ||
		secs[0].(map[string]any)["text"] != "a <b> & c" || secs[1].(map[string]any)["text"] != "second line" || secs[1].(map[string]any)["startGroup"] != false {
		t.Errorf("card %v", m)
	}
	// "a <b> & c" is under 20 characters: the summary is the first line.
	if m["summary"] != "a <b> & c" {
		t.Errorf("summary %q", m["summary"])
	}
}

func TestTeamsWorkflowNeeds202(t *testing.T) {
	s := newStub(t)
	pc, _ := ParseConfig(strings.NewReader("teams:\n  - teams_webhook_url: https://x.test/workflows/abc\n"), "t")
	set, _ := NewSet(pc, nil, nil, "", &Env{Client: s.client()})
	if d := set.Send(context.Background(), "x"); d[0].Err == nil || !strings.Contains(d[0].Err.Error(), "200") {
		t.Errorf("a 200 from a workflow is not accepted: %+v", d)
	}
}

func TestGotify(t *testing.T) {
	s := newStub(t)
	run(t, s, `
gotify:
  - id: modern
    gotify_host: gotify.test
    gotify_port: "8080"
    gotify_token: gtfyaMODERNTOKEN
    gotify_disabletls: true
    gotify_title: recon
  - id: legacy
    gotify_host: gotify.test
    gotify_token: ALegacyToken123
`, "", nil, nil, "hi")
	g := s.got()
	if len(g) != 2 {
		t.Fatalf("%d posts", len(g))
	}
	if g[0].Host != "gotify.test:8080" || g[0].Path != "/message" || g[0].Query != "" || g[0].Header.Get("X-Gotify-Key") != "gtfyaMODERNTOKEN" || g[0].Body != `{"message":"hi","title":"recon"}` {
		t.Errorf("modern %+v", g[0])
	}
	if g[1].Host != "gotify.test" || g[1].Query != "token=ALegacyToken123" || g[1].Body != `{"message":"hi","priority":0,"title":"Shoutrrr notification"}` {
		t.Errorf("legacy %+v", g[1])
	}
}

func TestCustom(t *testing.T) {
	s := newStub(t)
	run(t, s, `
custom:
  - id: plain
    custom_webhook_url: http://hook.test/in
    custom_method: POST
    custom_headers:
      Authorization: Bearer abc
      X-Source: azhaq
  - id: json
    custom_webhook_url: http://hook.test/json
    custom_method: PUT
    custom_format: '{"text": {{dataJsonString}}, "n": "{{count}}"}'
  - id: fmt
    custom_webhook_url: http://hook.test/fmt
    custom_method: POST
    custom_format: "{{datetime}} | {{date}} | {{time}} | {{data}}"
`, "", nil, nil, "say \"hi\"\nnow")
	g := s.got()
	if len(g) != 3 {
		t.Fatalf("%d posts", len(g))
	}
	if g[0].Method != "POST" || g[0].Body != "say \"hi\"\nnow" || g[0].Header.Get("Authorization") != "Bearer abc" || g[0].Header.Get("X-Source") != "azhaq" {
		t.Errorf("plain %+v", g[0])
	}
	if g[1].Method != "PUT" || g[1].Body != `{"text": "say \"hi\"\nnow", "n": "1"}` {
		t.Errorf("json %+v", g[1])
	}
	if g[2].Body != "10-30-2026 14:05:09+0700 | 10-30-2026 | 14:05:09+0700 | say \"hi\"\nnow" {
		t.Errorf("format %q", g[2].Body)
	}
}

func TestCustomSprig(t *testing.T) {
	s := newStub(t)
	d := run(t, s, `
custom:
  - id: s
    custom_webhook_url: http://hook.test/s
    custom_method: POST
    custom_sprig: '{"host": "{{ .url | upper }}", "tags": "{{ join "," .tags }}"}'
`, "", nil, nil, `{"url":"a.test","tags":["x","y"]}`)
	_ = d
	g := s.got()
	if len(g) != 1 || g[0].Body != `{"host": "A.TEST", "tags": "x,y"}` {
		t.Errorf("%+v", g)
	}
}

func TestSprigNeedsJSON(t *testing.T) {
	s := newStub(t)
	pc, _ := ParseConfig(strings.NewReader("custom:\n  - custom_webhook_url: http://h.test/\n    custom_method: POST\n    custom_sprig: '{{ .a }}'\n"), "t")
	set, _ := NewSet(pc, nil, nil, "", &Env{Client: s.client()})
	if d := set.Send(context.Background(), "plain text"); d[0].Err == nil || len(s.got()) != 0 {
		t.Errorf("%+v", d)
	}
}

func TestProviderAndIDFilters(t *testing.T) {
	s := newStub(t)
	cfg := `
custom:
  - id: a
    custom_webhook_url: http://hook.test/a
    custom_method: POST
  - id: b
    custom_webhook_url: http://hook.test/b
    custom_method: POST
googlechat:
  - id: a
    space: S
    key: K
    token: T
`
	run(t, s, cfg, "", []string{"custom"}, []string{"b"}, "x")
	if g := s.got(); len(g) != 1 || g[0].Path != "/b" {
		t.Errorf("%+v", g)
	}
	pc, _ := ParseConfig(strings.NewReader(cfg), "t")
	if _, err := NewSet(pc, []string{"nope"}, nil, "", &Env{Client: s.client()}); err == nil {
		t.Error("an unknown provider name is a mistake")
	}
}

func TestCLIFormatBeatsProviderFormat(t *testing.T) {
	s := newStub(t)
	run(t, s, "custom:\n  - custom_webhook_url: http://h.test/\n    custom_method: POST\n    custom_format: \"provider {{data}}\"\n", "cli {{data}} #{{count}}", nil, nil, "a", "b")
	g := s.got()
	if len(g) != 2 || g[0].Body != "cli a #1" || g[1].Body != "cli b #2" {
		t.Errorf("%+v", g)
	}
}

func TestStripsColourCodes(t *testing.T) {
	s := newStub(t)
	run(t, s, "custom:\n  - custom_webhook_url: http://h.test/\n    custom_method: POST\n", "", nil, nil, "\x1b[31mred\x1b[0m text")
	if g := one(t, s); g.Body != "red text" {
		t.Errorf("%q", g.Body)
	}
}

func TestConfigReportsUnknownKeysAndSubstitutesEnv(t *testing.T) {
	if _, err := ParseConfig(strings.NewReader("slack:\n  - slack_webhok_url: x\n"), "pc.yaml"); err == nil || !strings.Contains(err.Error(), "slack_webhok_url") {
		t.Errorf("a mistyped key: %v", err)
	}
	t.Setenv("AZQ_TEST_HOOK", "https://hooks.slack.com/services/T/B/ENVTOKEN")
	dir := t.TempDir()
	p := dir + "/pc.yaml"
	if err := writeFile(p, "slack:\n  - id: e\n    slack_webhook_url: \"$AZQ_TEST_HOOK\"\n    slack_username: $AZQ_UNSET\n"); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(p)
	if err != nil || cfg.Slack[0].SlackWebHookURL != "https://hooks.slack.com/services/T/B/ENVTOKEN" || cfg.Slack[0].SlackUsername != "$AZQ_UNSET" {
		t.Errorf("%+v %v", cfg, err)
	}
}

// The text of a failed delivery never carries a secret of the config.
func TestProviderErrorsKeepSecrets(t *testing.T) {
	s := newStub(t)
	s.reply = func(n int, r *seen) (int, map[string]string, string) {
		return 400, nil, "bad: " + r.Path + " " + r.Query + " " + r.Body + " " + r.Header.Get("X-Gotify-Key")
	}
	pc, _ := ParseConfig(strings.NewReader(`
slack:
  - slack_webhook_url: https://hooks.slack.com/services/T/B/SLACKSECRET
telegram:
  - telegram_api_key: "1:TELEGRAMSECRET"
    telegram_chat_id: "1"
pushover:
  - pushover_user_key: PUSHUSERSECRET
    pushover_api_token: PUSHTOKENSECRET
googlechat:
  - space: S
    key: GCHATKEYSECRET
    token: GCHATTOKENSECRET
gotify:
  - gotify_host: g.test
    gotify_token: GOTIFYSECRET
    gotify_disabletls: true
`), "t")
	set, _ := NewSet(pc, nil, nil, "", &Env{Client: s.client()})
	for _, d := range set.Send(context.Background(), "x") {
		if d.Err == nil {
			t.Errorf("%s: a 400 is a failure", d.Provider)
			continue
		}
		if strings.Contains(strings.ToUpper(d.Err.Error()), "SECRET") {
			t.Errorf("%s: %v", d.Provider, d.Err)
		}
	}
}
