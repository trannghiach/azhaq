package browser

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/cdp/jsonv2"
	"github.com/chromedp/chromedp"

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
// The run's settings are reset once it is closed.
func startChrome(t *testing.T) *Browser {
	t.Helper()
	if _, err := Find(); err != nil {
		t.Skip(err)
	}
	b := &Browser{}
	t.Cleanup(fetch.Reset)
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
		// A WebSocket's handshake too: the guard refuses it.
		if sent := own.got()[before:]; len(sent) > 2 {
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

// A window a page opens (window.open, a link to _blank) is closed as it
// opens: it would outlive the page and keep sending requests.
func TestPopupClosed(t *testing.T) {
	b := startChrome(t)
	own := newRecorder(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		switch r.URL.Path {
		case "/poll":
			fmt.Fprint(w, `<html><body><script>setInterval(() => fetch('/api/poll').catch(() => {}), 200);</script></body></html>`)
		case "/api/poll":
			fmt.Fprint(w, "{}")
		default:
			fmt.Fprint(w, `<html><body><a id=a href="/poll?a" target=_blank>a</a><script>window.open('/poll'); document.getElementById('a').click();</script></body></html>`)
		}
	})
	defer own.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	fetch.Reset()
	fetch.Allow = func(h string) bool { return h == "127.0.0.1" }
	_ = fetch.Spend(ctx)
	if _, err := b.Load(ctx, own.URL+"/", false); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Second)
	if got := slices.DeleteFunc(own.got(), func(p string) bool { return p == "/" || p == "/favicon.ico" }); len(got) > 0 {
		t.Errorf("windows the page opened sent %q", got)
	}
	if n := fetch.Sent(); n != int64(len(own.got())) {
		t.Errorf("counted %d requests, the server got %d", n, len(own.got()))
	}
	targets, err := chromedp.Targets(b.root)
	if err != nil {
		t.Fatal(err)
	}
	for _, info := range targets {
		if info.OpenerID != "" {
			t.Errorf("a window the page opened is still there: %s", info.URL)
		}
	}
}

// Refusals no page claims do not pile up: a page already read has its
// late ones (beacons sent as the tab closes) once per URL, and a page
// still gets its own, Left and Capped, however many are held.
func TestHeldBounded(t *testing.T) {
	b := startChrome(t)
	other := newRecorder(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "x") })
	defer other.Close()
	u, _ := url.Parse(other.URL)
	o := "http://localhost:" + u.Port()
	own := newRecorder(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/away":
			http.Redirect(w, r, o+"/landing", http.StatusFound)
		default:
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><body>hi<img src="/a.png"><img src="/b.png"><script>addEventListener('pagehide', () => navigator.sendBeacon('`+o+`/bye', 'x'));
addEventListener('visibilitychange', () => navigator.sendBeacon('`+o+`/vis', 'x'));</script></body></html>`)
		}
	})
	defer own.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	fetch.Reset()
	fetch.Allow = func(h string) bool { return h == "127.0.0.1" }

	held := func() int { b.refMu.Lock(); defer b.refMu.Unlock(); return len(b.held) }
	for i := 0; i < 5; i++ {
		_ = fetch.Spend(ctx)
		if _, err := b.Load(ctx, fmt.Sprintf("%s/p%d", own.URL, i), false); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(500 * time.Millisecond)
	if n := held(); n > 2 {
		t.Errorf("%d refusals held after 5 pages that each said goodbye twice", n)
	}

	// A long run: refusals of no page up to the limit.
	for i := held(); i < maxHeld; i++ {
		b.refuse(nil, refusal{url: fmt.Sprintf("%s/sw%d", o, i), host: "localhost", frame: cdp.FrameID(fmt.Sprintf("SW%d", i))})
	}
	_ = fetch.Spend(ctx)
	p, _ := b.Load(ctx, own.URL+"/away", false)
	if p.Left != o+"/landing" || !slices.Contains(p.Blocked, o+"/landing") {
		t.Errorf("with %d refusals held, a redirect out gives Left %q, Blocked %q", held(), p.Left, p.Blocked)
	}
	fetch.MaxRequests = fetch.Sent() + 2 // the page and one image (fetched for a screenshot)
	_ = fetch.Spend(ctx)
	if p, _ := b.Load(ctx, own.URL+"/p9", true); !p.Capped {
		t.Errorf("with %d refusals held, a page the budget cut is not capped", held())
	}
	if n := held(); n > maxHeld {
		t.Errorf("%d refusals held", n)
	}
}

// What a capped page was refused is not lost: its caller drops the page,
// to load it again after azhaq resume, and the run lists them.
func TestCappedLeftover(t *testing.T) {
	b := startChrome(t)
	other := newRecorder(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "x") })
	defer other.Close()
	u, _ := url.Parse(other.URL)
	o := "http://localhost:" + u.Port()
	own := newRecorder(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body><img src="`+o+`/pixel.png"><img src="/a.png"><img src="/b.png"></body></html>`)
	})
	defer own.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	fetch.Reset()
	fetch.Allow = func(h string) bool { return h == "127.0.0.1" }
	fetch.MaxRequests = 2
	_ = fetch.Spend(ctx)
	p, _ := b.Load(ctx, own.URL+"/", true) // a screenshot: the images are fetched
	if !p.Capped || len(p.Blocked) > 0 {
		t.Errorf("capped %v, blocked %q", p.Capped, p.Blocked)
	}
	if left := b.Leftover(); !slices.Contains(left, o+"/pixel.png") {
		t.Errorf("leftover %q", left)
	}
}

// Chrome's requests are paced as the run's own are (-rate).
func TestPaced(t *testing.T) {
	b := startChrome(t)
	var mu sync.Mutex
	var at []time.Time
	own := newRecorder(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><body><img src="/i.png?0"><img src="/i.png?1"><img src="/i.png?2"><img src="/i.png?3"><img src="/i.png?4"><img src="/i.png?5"></body></html>`)
			return
		}
		mu.Lock()
		at = append(at, time.Now())
		mu.Unlock()
	})
	defer own.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	fetch.Reset()
	fetch.Allow = func(h string) bool { return h == "127.0.0.1" }
	fetch.SetRate(4)
	_ = fetch.Spend(ctx)
	if _, err := b.Load(ctx, own.URL+"/", true); err != nil { // a screenshot: the images are fetched
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(at) < 6 {
		t.Fatalf("%d images asked for", len(at))
	}
	// Six requests at four a second, after the page's own: over a second.
	if d := at[len(at)-1].Sub(at[0]); d < time.Second {
		t.Errorf("six images in %v at four requests a second", d)
	}
}

// A navigation out of the scope decided as the page is read is still the
// page's: claiming waits for what is being decided.
func TestSettleWaits(t *testing.T) {
	b := startChrome(t)
	tb := b.open(b.root, "MAIN", false, false)
	if b.begin("MAIN") != tb {
		t.Fatal("the frame is not the tab's")
	}
	go func() {
		time.Sleep(300 * time.Millisecond)
		b.refuse(tb, refusal{url: "http://elsewhere.test/", host: "elsewhere.test", frame: "MAIN", doc: true})
		b.done(tb)
	}()
	b.settle(tb)
	if rs := b.claim(tb); len(rs) != 1 || !rs[0].doc {
		t.Errorf("claimed %+v", rs)
	}
	// Later ones are not the page's, and held once per URL.
	b.refuse(nil, refusal{url: "http://elsewhere.test/bye", host: "elsewhere.test", frame: "MAIN"})
	b.refuse(nil, refusal{url: "http://elsewhere.test/bye", host: "elsewhere.test", frame: "MAIN", sends: true})
	if left := b.Leftover(); !slices.Equal(left, []string{"http://elsewhere.test/bye"}) {
		t.Errorf("leftover %q", left)
	}
}

// An event Chrome sends that does not decode does not end the answering:
// Chrome would hold every later request.
func TestAnswerSurvivesBadEvents(t *testing.T) {
	b := startChrome(t)
	ch := make(chan jsonv2.Value)
	done := make(chan struct{})
	go func() {
		b.answer(b.root, ch)
		close(done)
	}()
	for _, raw := range []string{`{"requestId":"interception-job-1.0","request":5}`, `not json`, `{"frameId":7}`, `{"requestId":"interception-job-2.0","request":{"url":"http://127.0.0.1/"}}`} {
		select {
		case ch <- jsonv2.Value(raw):
		case <-time.After(5 * time.Second):
			t.Fatalf("no longer answering after %s", raw)
		}
	}
	close(ch)
	<-done
	if !b.lost.Load() {
		t.Error("an ended answering is not noted")
	}
	if _, err := b.Load(context.Background(), "http://127.0.0.1/", false); err == nil {
		t.Error("a page loaded with its requests no longer held")
	}
}

// WebRTC sends no UDP outside the proxy: not to a STUN server outside the
// scope.
func TestWebRTCEscape(t *testing.T) {
	b := startChrome(t)
	udp, err := net.ListenPacket("udp", "127.0.0.2:0")
	if err != nil {
		t.Skip(err)
	}
	defer udp.Close()
	var got atomic.Int64
	go func() {
		buf := make([]byte, 2048)
		for {
			if _, _, err := udp.ReadFrom(buf); err != nil {
				return
			}
			got.Add(1)
		}
	}()
	_, port, _ := net.SplitHostPort(udp.LocalAddr().String())
	page := `<html><body><script>
const pc = new RTCPeerConnection({iceServers: [{urls: 'stun:127.0.0.2:` + port + `'}]});
pc.createDataChannel('x');
pc.createOffer().then(o => pc.setLocalDescription(o));
</script></body></html>`
	own := newRecorder(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, page)
	})
	defer own.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	fetch.Reset()
	fetch.Allow = func(h string) bool { return h == "127.0.0.1" }
	_ = fetch.Spend(ctx)
	if _, err := b.Load(ctx, own.URL+"/", false); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Second)
	if n := got.Load(); n > 0 {
		t.Errorf("WebRTC sent %d UDP datagrams outside the scope", n)
	}
}
