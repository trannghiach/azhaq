package browser

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/trannghiach/azhaq/internal/fetch"
)

// recorder is a server that keeps the paths it was asked for.
type recorder struct {
	*httptest.Server
	mu    sync.Mutex
	paths []string
}

func newRecorder(h func(w http.ResponseWriter, r *http.Request)) *recorder {
	rec := &recorder{}
	rec.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.mu.Lock()
		rec.paths = append(rec.paths, r.URL.Path)
		rec.mu.Unlock()
		h(w, r)
	}))
	return rec
}

func (r *recorder) got() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.paths...)
}

// startChrome is a browser for a test, or a skip where Chrome cannot run.
func startChrome(t *testing.T) *Browser {
	t.Helper()
	if _, err := Find(); err != nil {
		t.Skip(err)
	}
	b := &Browser{}
	if err := b.Start(); errors.Is(err, ErrNoSandbox) {
		t.Skip(err)
	} else if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Close)
	return b
}

// A page in the scope (127.0.0.1) that asks a second server, named
// localhost, for everything a page can: none of it may reach that server,
// and what the page asks its own server for still does.
func TestScope(t *testing.T) {
	b := startChrome(t)
	t.Cleanup(fetch.Reset)
	other := newRecorder(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		fmt.Fprint(w, "x")
	})
	defer other.Close()
	u, _ := url.Parse(other.URL)
	o := "http://localhost:" + u.Port()
	page := `<html><head><link rel=preconnect href="` + o + `"><link rel=stylesheet href="` + o + `/style.css"></head><body>
<img src="` + o + `/pixel.png?u=secret"><script src="` + o + `/ext.js"></script>
<iframe src="` + o + `/frame"></iframe>
<script src="/own.js"></script>
<script>
fetch('` + o + `/api/fetch', {method: 'POST', body: 'x'}).catch(() => {});
const x = new XMLHttpRequest(); x.open('GET', '` + o + `/api/xhr'); x.send();
try { new WebSocket('ws://localhost:` + u.Port() + `/ws'); } catch (e) {}
try { new WebSocket('ws://' + location.host + '/ownws'); } catch (e) {}
new Worker('/worker.js');
navigator.sendBeacon('` + o + `/beacon', 'x');
</script></body></html>`
	own := newRecorder(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/own.js":
			w.Header().Set("Content-Type", "text/javascript")
			fmt.Fprint(w, `fetch('/api/own');`)
		case "/worker.js":
			w.Header().Set("Content-Type", "text/javascript")
			fmt.Fprint(w, `fetch('`+o+`/from-worker').catch(() => {});`)
		case "/away":
			http.Redirect(w, r, o+"/landing", http.StatusFound)
		default:
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, page)
		}
	})
	defer own.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	for _, scoped := range []bool{true, false} {
		name := "no scope"
		if scoped {
			name = "scope"
		}
		t.Run(name, func(t *testing.T) {
			fetch.Reset()
			if scoped {
				fetch.Allow = func(h string) bool { return h == "127.0.0.1" }
			}
			before := len(own.got())
			refusedBefore, _, _ := b.Refused()
			if err := fetch.Spend(ctx); err != nil { // the page, as the collectors count it
				t.Fatal(err)
			}
			p, err := b.Load(ctx, own.URL+"/", false)
			if err != nil {
				t.Fatal(err)
			}
			if n, _, _ := b.Refused(); n-refusedBefore < 7 {
				t.Errorf("%d requests refused", n-refusedBefore)
			}
			time.Sleep(500 * time.Millisecond)
			if got := other.got(); len(got) > 0 {
				t.Fatalf("the server outside the scope was asked for %q", got)
			}
			mine := own.got()[before:]
			for _, want := range []string{"/", "/own.js", "/api/own", "/worker.js", "/ownws"} {
				if !slices.Contains(mine, want) {
					t.Errorf("own server: %q missing from %q", want, mine)
				}
			}
			// Listed once in a run: the second load's are counted only.
			for _, want := range []string{o + "/ext.js", o + "/pixel.png", o + "/api/xhr", o + "/api/fetch", o + "/frame", o + "/from-worker", "ws://localhost:" + u.Port() + "/ws"} {
				if slices.Contains(p.Blocked, want) != scoped {
					t.Errorf("%s listed %v: %q", want, !scoped, p.Blocked)
				}
			}
			for _, l := range p.Blocked {
				if strings.Contains(l, "secret") {
					t.Errorf("a blocked URL is listed with its query: %s", l)
				}
			}
			if p.Left != "" || p.Capped {
				t.Errorf("left %q, capped %v", p.Left, p.Capped)
			}
			// Every request that left was counted, the page once.
			if n := fetch.Sent(); n != int64(len(own.got())-before) {
				t.Errorf("counted %d requests, the server got %d: %q", n, len(own.got())-before, own.got()[before:])
			}
			want := "outside the scope (Chrome)"
			if !scoped {
				want = "outside the site (Chrome)"
			}
			if Reason() != want {
				t.Errorf("reason %q", Reason())
			}
		})
	}

	t.Run("redirect out", func(t *testing.T) {
		fetch.Reset()
		fetch.Allow = func(h string) bool { return h == "127.0.0.1" }
		p, _ := b.Load(ctx, own.URL+"/away", false)
		if p.Left != o+"/landing" {
			t.Errorf("left %q", p.Left)
		}
		if got := other.got(); len(got) > 0 {
			t.Errorf("the server outside the scope was asked for %q", got)
		}
	})

	t.Run("budget", func(t *testing.T) {
		fetch.Reset()
		fetch.Allow = func(h string) bool { return h == "127.0.0.1" }
		fetch.MaxRequests = 2 // the page and one more
		before := len(own.got())
		if err := fetch.Spend(ctx); err != nil {
			t.Fatal(err)
		}
		p, _ := b.Load(ctx, own.URL+"/", false)
		if !p.Capped {
			t.Error("not capped")
		}
		// A WebSocket's handshake is counted, not refused: the Fetch
		// domain does not pause it.
		sent := slices.DeleteFunc(own.got()[before:], func(p string) bool { return p == "/ownws" })
		if len(sent) > 2 {
			t.Errorf("%d requests sent under a budget of 2: %q", len(sent), sent)
		}
	})

	// The run's summary lists them once, at most maxListed, and counts the rest.
	n, listed, _ := b.Refused()
	if n < listed || listed == 0 {
		t.Errorf("refused %d, listed %d", n, listed)
	}
}

// A sign-in that goes to an identity provider outside the scope fails,
// and says where it went.
func TestLoginOutsideScope(t *testing.T) {
	b := startChrome(t)
	t.Cleanup(fetch.Reset)
	sso := newRecorder(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, loginPage) })
	defer sso.Close()
	u, _ := url.Parse(sso.URL)
	idp := "http://localhost:" + u.Port()
	app := newRecorder(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, idp+"/authorize?client=app", http.StatusFound)
	})
	defer app.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	fetch.Reset()
	fetch.Allow = func(h string) bool { return h == "127.0.0.1" }
	_, err := b.Login(ctx, app.URL+"/login", "member@x.test", "s3cret")
	if err == nil || !strings.Contains(err.Error(), "the sign-in went to localhost, outside the scope: add it with -allow localhost") {
		t.Errorf("error %v", err)
	}
	if got := sso.got(); len(got) > 0 {
		t.Errorf("the identity provider outside the scope was asked for %q", got)
	}
}
