package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// notifyRow compares `azhaq notify` with ProjectDiscovery's notify against
// a stub the bench serves on 127.0.0.1: the same input and provider config,
// the requests the stub records, and that no webhook token reaches any
// output.
type notifyRow struct {
	Profile    string  `json:"profile,omitempty"`
	Messages   int     `json:"messages"`
	AzhaqOK    int     `json:"azhaq_confirmed"`
	NotifyOK   int     `json:"notify_confirmed"`
	AzhaqSecs  float64 `json:"azhaq_seconds"`
	NotifySecs float64 `json:"notify_seconds"`
	SameBodies bool    `json:"same_bodies"`
	TokenLeak  bool    `json:"token_leak"`
}

type stubReq struct {
	Path, Type, Body string
}

type stub struct {
	mu   sync.Mutex
	reqs []stubReq
	srv  *http.Server
	base string
}

func newStub() *stub {
	s := &stub{}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	must(err)
	s.base = "http://" + ln.Addr().String()
	s.srv = &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		s.mu.Lock()
		s.reqs = append(s.reqs, stubReq{r.URL.Path, r.Header.Get("Content-Type"), string(b)})
		s.mu.Unlock()
		fmt.Fprint(w, "ok")
	})}
	go s.srv.Serve(ln)
	return s
}

func (s *stub) forPath(prefix string) []stubReq {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []stubReq
	for _, r := range s.reqs {
		if strings.HasPrefix(r.Path, prefix) {
			out = append(out, r)
		}
	}
	return out
}

func (s *stub) reset() {
	s.mu.Lock()
	s.reqs = nil
	s.mu.Unlock()
}

// notifyConfig is notify's provider-config.yaml: a Slack webhook and a
// custom webhook, both to the stub under path.
func notifyConfig(base, path string) string {
	return fmt.Sprintf(`slack:
  - id: "slack1"
    slack_webhook_url: "%[1]s%[2]s/slack"
    slack_format: "{{data}}"
custom:
  - id: "hook1"
    custom_webhook_url: "%[1]s%[2]s/custom"
    custom_method: "POST"
    custom_format: '{"text":"{{data}}"}'
    custom_headers:
      Content-Type: application/json
`, base, path)
}

func benchNotify() *notifyRow {
	st := newStub()
	defer st.srv.Close()
	dir, _ := filepath.Abs(filepath.Join(work, "notify"))
	must(os.MkdirAll(dir, 0o755))
	var msgs []string
	for i := 1; i <= 6; i++ {
		msgs = append(msgs, fmt.Sprintf("new host app%d.example.com live", i))
	}
	in := filepath.Join(dir, "input.txt")
	must(os.WriteFile(in, []byte(strings.Join(msgs, "\n")+"\n"), 0o644))
	row := &notifyRow{Profile: prof, Messages: len(msgs)}
	rl := pick([]string(nil), []string{"-rl", politeHTTP})

	cfgA, cfgN := filepath.Join(dir, "azhaq.yaml"), filepath.Join(dir, "notify.yaml")
	must(os.WriteFile(cfgA, []byte(notifyConfig(st.base, "/azhaq")), 0o644))
	must(os.WriteFile(cfgN, []byte(notifyConfig(st.base, "/notify")), 0o644))
	aa := append([]string{"notify", "-i", in, "-provider-config", cfgA, "-silent"}, rl...)
	na := append([]string{"-i", in, "-provider-config", cfgN, "-silent", "-duc"}, rl...)
	// notify reads $HOME/.config/notify for its own state: a scratch HOME.
	home := filepath.Join(dir, "home")
	must(os.MkdirAll(home, 0o755))
	old := os.Getenv("HOME")
	must(os.Setenv("HOME", home))
	defer os.Setenv("HOME", old)

	count := func(path string) (int, []string) {
		got := st.forPath(path)
		n := 0
		var bodies []string
		for _, m := range msgs {
			for _, kind := range []string{"/slack", "/custom"} {
				for _, r := range st.forPath(path + kind) {
					if strings.Contains(r.Body, m) {
						n++
						break
					}
				}
			}
		}
		for _, r := range got {
			bodies = append(bodies, strings.TrimPrefix(r.Path, path)+" "+r.Type+" "+r.Body)
		}
		sort.Strings(bodies)
		return n, bodies
	}
	var azBodies, nBodies []string
	_, am := timedArgs("notify", 10*time.Minute, dir, azhaq, func(i int) []string {
		if i == 0 {
			st.reset()
		}
		return aa
	})
	row.AzhaqSecs = am.Seconds
	row.AzhaqOK, azBodies = count("/azhaq")
	_, nm := timedArgs("notify", 10*time.Minute, dir, ref("notify"), func(int) []string { return na })
	row.NotifySecs = nm.Seconds
	row.NotifyOK, nBodies = count("/notify")
	// The first run of each is what the stub holds (the repetitions send again).
	azBodies, nBodies = uniq(azBodies), uniq(nBodies)
	row.SameBodies = len(azBodies) > 0 && strings.Join(azBodies, "\n") == strings.Join(nBodies, "\n")
	cmds := cmdLine(azhaq, aa...) + " vs " + cmdLine("notify", na...)
	barOne("notify", row.AzhaqOK, row.NotifyOK, row.AzhaqSecs, row.NotifySecs, "the stub's own log (a request with the message in its body, per provider)", cmds,
		fmt.Sprintf("%d messages to 2 providers; distinct requests at the stub: azhaq %d, notify %d %s", row.Messages, len(azBodies), len(nBodies), azErr(am)))
	if !polite() {
		addCheck("notify: the same requests as notify's (bodies and content types), per the stub", row.SameBodies,
			"azhaq %s | notify %s", clip(strings.Join(azBodies, " ; "), 300), clip(strings.Join(nBodies, " ; "), 300))
		row.TokenLeak = tokenLeak(dir)
	}
	return row
}

// uniq drops repeats of a sorted list: the timing repetitions send again.
func uniq(xs []string) []string {
	var out []string
	for i, x := range xs {
		if i == 0 || x != xs[i-1] {
			out = append(out, x)
		}
	}
	return out
}

// tokenLeak runs `watch -notify` to a webhook that cannot be reached and
// looks for its secret in everything the run printed and wrote.
func tokenLeak(dir string) bool {
	const token = "TOKENzq9XyAbCdEf0123456789"
	closed := freePorts(1)[0]
	hook := fmt.Sprintf("http://127.0.0.1:%d/services/T000/B000/%s", closed, token)
	ws := filepath.Join(dir, "leak.db")
	hosts, stop := fleet(1)
	defer stop()
	r := azRun("notify", 3*time.Minute, dir, "watch", "-db", ws, "-always", "-notify", hook, "--", "-url", "http://"+hosts[0]+"/")
	leaked := strings.Contains(r.stdout+r.stderr, token)
	if !leaked {
		files, _ := filepath.Glob(ws + "*")
		for _, f := range files {
			if b, err := os.ReadFile(f); err == nil && strings.Contains(string(b), token) {
				leaked = true
			}
		}
	}
	addCheck("notify: a webhook token reaches no output when the webhook cannot be reached", !leaked,
		"azhaq watch -always -notify http://127.0.0.1:CLOSED/services/…/TOKEN: exit %d, token printed: %v", r.exit, leaked)
	return leaked
}
