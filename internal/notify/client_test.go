package notify

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const token = "SECRETTOKEN-9f3a1c"

// No path of failure prints the secret in a webhook URL: not a refused
// connection, not a server that echoes the URL, not a timeout, not a
// rate limit that never lifts.
func TestNoErrorPathPrintsTheToken(t *testing.T) {
	echo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/echo/" + token:
			http.Error(w, "bad request for "+r.URL.String()+" host "+r.Host+r.URL.Path, 500)
		case "/rl/" + token:
			w.Header().Set("Retry-After", "0")
			http.Error(w, "slow down "+r.URL.Path, 429)
		case "/slow/" + token:
			time.Sleep(300 * time.Millisecond)
		}
	}))
	defer echo.Close()
	dead := httptest.NewServer(nil)
	deadURL := dead.URL
	dead.Close()
	cases := map[string]string{
		"refused": deadURL + "/hooks/" + token + "?key=" + token,
		"echo":    echo.URL + "/echo/" + token,
		"limited": echo.URL + "/rl/" + token,
		"timeout": echo.URL + "/slow/" + token,
		"badurl":  "http://127.0.0.1:1/" + token + "/%zz",
		"scheme":  "ftp://x/" + token,
	}
	for name, hook := range cases {
		c := &Client{Backoff: time.Millisecond, Timeout: 100 * time.Millisecond, Tries: 2}
		err := c.Send(context.Background(), hook, "hi", nil)
		if err == nil {
			t.Errorf("%s: no error", name)
			continue
		}
		if strings.Contains(err.Error(), token) || strings.Contains(err.Error(), "9f3a1c") {
			t.Errorf("%s: the error prints the token: %v", name, err)
		}
		t.Logf("%s: %v", name, err)
	}
}

func TestRetryRateLimitThenSucceed(t *testing.T) {
	s := newStub(t)
	s.reply = func(n int, r *seen) (int, map[string]string, string) {
		if n == 1 {
			return 429, map[string]string{"Retry-After": "1"}, "slow"
		}
		return 200, nil, "ok"
	}
	c := s.client()
	start := time.Now()
	if err := c.Send(context.Background(), "https://hooks.slack.com/services/T/B/"+token, "hi", nil); err != nil {
		t.Fatal(err)
	}
	if got := s.got(); len(got) != 2 {
		t.Fatalf("%d posts for a 429 that lifted, want 2", len(got))
	}
	if d := time.Since(start); d < time.Second {
		t.Errorf("Retry-After: 1 waited %v", d)
	}
	// The same message each try.
	if g := s.got(); g[0].Body != g[1].Body || g[0].Body != `{"text":"hi"}` {
		t.Errorf("bodies %q", []string{g[0].Body, g[1].Body})
	}
}

func TestRetryServerErrorThenGiveUp(t *testing.T) {
	s := newStub(t)
	s.reply = func(int, *seen) (int, map[string]string, string) { return 500, nil, "boom" }
	err := s.client().Send(context.Background(), "https://example.test/hook", "hi", nil)
	if len(s.got()) != 3 || err == nil || !strings.Contains(err.Error(), "after 3 tries") || !strings.Contains(err.Error(), "500") {
		t.Fatalf("%d posts, error %v", len(s.got()), err)
	}
}

func TestNoRetryOnClientError(t *testing.T) {
	s := newStub(t)
	s.reply = func(int, *seen) (int, map[string]string, string) { return 400, nil, "no" }
	if err := s.client().Send(context.Background(), "https://example.test/hook", "hi", nil); err == nil {
		t.Fatal("a 400 is a failure")
	}
	if len(s.got()) != 1 {
		t.Errorf("%d posts for a 400, want 1", len(s.got()))
	}
}

func TestRetryAfterLongerThanTheWaitIsSaid(t *testing.T) {
	s := newStub(t)
	s.reply = func(int, *seen) (int, map[string]string, string) {
		return 429, map[string]string{"Retry-After": "3600"}, "wait"
	}
	err := s.client().Send(context.Background(), "https://example.test/hook", "hi", nil)
	if len(s.got()) != 1 || err == nil || !strings.Contains(err.Error(), "Retry-After") {
		t.Fatalf("%d posts, %v", len(s.got()), err)
	}
}

func TestRetryAfterDate(t *testing.T) {
	if d := parseRetryAfter(time.Now().Add(3 * time.Second).UTC().Format(http.TimeFormat)); d < time.Second || d > 4*time.Second {
		t.Errorf("an HTTP date gave %v", d)
	}
	if parseRetryAfter("2") != 2*time.Second || parseRetryAfter("x") != 0 {
		t.Error("Retry-After seconds")
	}
}

// A paced client posts no faster than its rate.
func TestPace(t *testing.T) {
	s := newStub(t)
	c := s.client()
	c2, _ := NewClient(10, "")
	c.Rate = c2.Rate
	start := time.Now()
	for i := 0; i < 4; i++ {
		if err := c.Send(context.Background(), "https://example.test/hook", "hi", nil); err != nil {
			t.Fatal(err)
		}
	}
	if d := time.Since(start); d < 280*time.Millisecond {
		t.Errorf("4 posts at 10 a second took %v", d)
	}
}

func TestSendShapesAndChunks(t *testing.T) {
	s := newStub(t)
	c := s.client()
	long := strings.Repeat("line of a change set\n", 300) // ~6,300 characters
	if err := c.Send(context.Background(), "https://discord.com/api/webhooks/1/x?username=azhaq", long, nil); err != nil {
		t.Fatal(err)
	}
	var joined []string
	for i, r := range s.got() {
		var m map[string]string
		if err := json.Unmarshal([]byte(r.Body), &m); err != nil {
			t.Fatal(err)
		}
		if n := len([]rune(m["content"])); n > 2000 {
			t.Errorf("part %d has %d characters", i, n)
		}
		if m["username"] != "azhaq" || r.Query != "" {
			t.Errorf("username %q query %q", m["username"], r.Query)
		}
		joined = append(joined, m["content"])
	}
	if len(joined) < 4 {
		t.Fatalf("%d parts for 6,300 characters", len(joined))
	}
	if got, want := joinParts(joined), strings.TrimRight(long, "\n"); strings.Join(strings.Fields(got), "") != strings.Join(strings.Fields(want), "") {
		// Split drops the space or newline it cuts at: nothing else.
		t.Errorf("the parts do not hold the message")
	}
	// Generic hooks get one post with the data.
	s2 := newStub(t)
	if err := s2.client().Send(context.Background(), "https://example.test/h", long, map[string]int{"a": 1}); err != nil {
		t.Fatal(err)
	}
	if g := s2.got(); len(g) != 1 || !strings.Contains(g[0].Body, `"data":{"a":1}`) {
		t.Errorf("generic hook: %d posts", len(g))
	}
}

func TestTelegramURLParameters(t *testing.T) {
	s := newStub(t)
	hook := "https://api.telegram.org/bot123:ABC/sendMessage?chat_id=-100&parse_mode=HTML&thread=7&preview=yes"
	if err := s.client().Send(context.Background(), hook, "hi", nil); err != nil {
		t.Fatal(err)
	}
	r := s.got()[0]
	var m map[string]any
	_ = json.Unmarshal([]byte(r.Body), &m)
	if r.Path != "/bot123:ABC/sendMessage" || r.Query != "" || m["chat_id"] != "-100" || m["parse_mode"] != "HTML" || m["message_thread_id"] != float64(7) || m["disable_web_page_preview"] != false {
		t.Errorf("%+v %v", r, m)
	}
}

func TestHookNeedsHTTP(t *testing.T) {
	err := (&Client{}).Send(context.Background(), "file:///etc/passwd", "x", nil)
	if err == nil || !errors.Is(err, err) {
		t.Fatal("a file URL is not a webhook")
	}
}

func TestHookShapesForTeamsAndGoogleChat(t *testing.T) {
	s := newStub(t)
	s.reply = func(n int, r *seen) (int, map[string]string, string) {
		if strings.Contains(r.Path, "workflows") {
			return 202, nil, ""
		}
		return 200, nil, "ok"
	}
	c := s.client()
	for _, h := range []string{
		"https://chat.googleapis.com/v1/spaces/S/messages?key=K&token=T",
		"https://x.logic.azure.com/workflows/abc/run?sig=SIG",
		"https://contoso.webhook.office.com/webhookb2/g@t/IncomingWebhook/a/b",
	} {
		if err := c.Send(context.Background(), h, "a & b\nc", map[string]int{"n": 1}); err != nil {
			t.Fatalf("%s: %v", h, err)
		}
	}
	g := s.got()
	if len(g) != 3 {
		t.Fatalf("%d posts", len(g))
	}
	if g[0].Query != "key=K&token=T" || g[0].Body != `{"text":"a & b\nc"}` && jsonOf(t, g[0].Body)["text"] != "a & b\nc" {
		t.Errorf("google chat %+v", g[0])
	}
	if jsonOf(t, g[1].Body)["text"] != "a &amp; b<br>c" || g[1].Query != "sig=SIG" {
		t.Errorf("workflow %+v", g[1])
	}
	if m := jsonOf(t, g[2].Body); m["text"] != "a & b\nc" || m["data"] != nil {
		t.Errorf("connector %+v", g[2])
	}
}

// What a server answers a failed send with is not printed, an error code
// aside: it may echo anything, secrets included.
func TestFailedAnswerKeepsOnlyACode(t *testing.T) {
	for body, want := range map[string]string{"channel_not_found": "channel_not_found", "echoed SECRET_ECHO_TOKEN": ""} {
		s := newStub(t)
		s.reply = func(int, *seen) (int, map[string]string, string) { return 404, nil, body }
		err := s.client().Send(context.Background(), "https://example.test/hook", "hi", nil)
		if err == nil || strings.Contains(err.Error(), "SECRET") || (want != "" && !strings.Contains(err.Error(), want)) {
			t.Errorf("%q: %v", body, err)
		}
	}
}
