package rendercol

import (
	"context"
	"encoding/json"
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

	"github.com/trannghiach/azhaq/engine"
	"github.com/trannghiach/azhaq/internal/browser"
	"github.com/trannghiach/azhaq/internal/egress"
	"github.com/trannghiach/azhaq/internal/fetch"
	"github.com/trannghiach/azhaq/types"
)

// A page in the scope that loads a script, an image and an API call from
// another host (localhost, the scope being 127.0.0.1): rendering it sends
// none of them, lists them as skipped, and still records the page's own
// API call.
func TestRenderHeldToScope(t *testing.T) {
	if _, err := browser.Find(); err != nil {
		t.Skip(err)
	}
	var mu sync.Mutex
	var asked []string
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		asked = append(asked, r.URL.Path)
		mu.Unlock()
		w.Header().Set("Access-Control-Allow-Origin", "*")
		fmt.Fprint(w, "x")
	}))
	defer other.Close()
	u, _ := url.Parse(other.URL)
	o := "http://localhost:" + u.Port()
	var served int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		served++
		mu.Unlock()
		switch r.URL.Path {
		case "/app.js":
			w.Header().Set("Content-Type", "text/javascript")
			fmt.Fprint(w, `fetch('/api/items?page=1'); fetch('`+o+`/api/xhr').catch(() => {});`)
		case "/api/items":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `[]`)
		default:
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><body><script src="`+o+`/ext.js"></script><img src="`+o+`/pixel.png"><script src="/app.js"></script></body></html>`)
		}
	}))
	defer srv.Close()

	fetch.Reset()
	defer fetch.Reset()
	egress.SetScope(func(h string) bool { return h == "127.0.0.1" })
	b := &browser.Browser{}
	defer b.Close()
	if err := b.Start(); errors.Is(err, browser.ErrNoSandbox) {
		t.Skip(err)
	} else if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	var obs []types.StoredObservation
	c := &Collector{Browser: b}
	seed := types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": srv.URL + "/"}}
	if _, err := c.Run(ctx, seed, func(ob types.Observation) error {
		obs = append(obs, types.StoredObservation{EntityID: "page", Observation: ob})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	if len(asked) > 0 {
		t.Errorf("the host outside the scope was asked for %q", asked)
	}
	mu.Unlock()
	var urls []string
	for _, ob := range obs {
		var p struct{ URL string }
		if ob.Kind == "url" && json.Unmarshal(ob.Payload, &p) == nil {
			urls = append(urls, p.URL)
		}
	}
	if !slices.Contains(urls, srv.URL+"/api/items?page=1") {
		t.Errorf("the page's own API call is missing: %q", urls)
	}
	// The summary lists what Chrome was refused.
	skips := engine.Skips([]types.Entity{{ID: "page", Type: types.TypeURL, Key: srv.URL + "/"}}, obs)
	for _, want := range []string{o + "/ext.js", o + "/pixel.png", o + "/api/xhr"} {
		if !slices.Contains(skips, engine.Skip{Target: want, Reason: "outside the scope (Chrome)"}) {
			t.Errorf("%s not skipped: %+v", want, skips)
		}
	}
	// Counted: every request that left, the page once.
	b.Close()
	mu.Lock()
	defer mu.Unlock()
	if n := egress.Sent(); n != int64(served) {
		t.Errorf("%d requests counted, %d sent", n, served)
	}
}

// An app that routes after a #: /basket is rendered as /#/basket, whose
// document is the front page. A form there with no action submits to /,
// not to /basket.
func TestRenderHashRouteForm(t *testing.T) {
	if _, err := browser.Find(); err != nil {
		t.Skip(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body><script>if (!location.hash) location.hash = '#/';</script><form method="post"><input name="q"></form></body></html>`)
	}))
	defer srv.Close()

	fetch.Reset()
	defer fetch.Reset()
	b := &browser.Browser{}
	defer b.Close()
	if err := b.Start(); errors.Is(err, browser.ErrNoSandbox) {
		t.Skip(err)
	} else if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	c := &Collector{Browser: b}
	var actions []string
	for _, path := range []string{"/", "/basket"} {
		actions = nil
		seed := types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": srv.URL + path}}
		if _, err := c.Run(ctx, seed, func(ob types.Observation) error {
			var f struct{ Action string }
			if ob.Kind == "form" && json.Unmarshal(ob.Payload, &f) == nil {
				actions = append(actions, f.Action)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	if !slices.Equal(actions, []string{srv.URL + "/"}) {
		t.Errorf("the form on /#/basket submits to %q, want %s/", actions, srv.URL)
	}
}

// A page whose script sends, as it loads, a POST, a DELETE, a PUT of a
// form, a beacon and a form posted, besides a GET: rendering sends only
// the GETs, and maps the writes with their methods and the names they
// carry, never the values, as a script's calls are (hints, op source
// browser); the summary lists them as left alone. With -browser-writes
// they are sent, mapped alike and not listed.
func TestRenderWrites(t *testing.T) {
	if _, err := browser.Find(); err != nil {
		t.Skip(err)
	}
	var mu sync.Mutex
	var got []string // METHOD /path
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got = append(got, r.Method+" "+r.URL.Path)
		mu.Unlock()
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><body><form id=f method=post action="/api/subscribe"><input name=email value="a@b.test"><input name=plan value=pro></form>
<script>
const fd = new FormData(); fd.append('title', 'secret-title');
Promise.allSettled([
  fetch('/api/items?page=2'),
  fetch('/api/track?src=home', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({event: 'view', user: 'secret-user'})}),
  fetch('/api/items/7', {method: 'DELETE'}),
  fetch('/api/upload', {method: 'PUT', body: fd}),
  Promise.resolve(navigator.sendBeacon('/api/beacon', new URLSearchParams({sid: 'secret-sid', t: '1'}))),
]).then(() => setTimeout(() => document.getElementById('f').submit(), 100));
</script></body></html>`)
		default:
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{}`)
		}
	}))
	defer srv.Close()
	wantWrites := []string{"POST /api/track", "DELETE /api/items/7", "PUT /api/upload", "POST /api/beacon", "POST /api/subscribe"}

	for _, writes := range []bool{false, true} {
		t.Run(fmt.Sprintf("writes %v", writes), func(t *testing.T) {
			fetch.Reset()
			defer fetch.Reset()
			egress.SetScope(func(h string) bool { return h == "127.0.0.1" })
			b := &browser.Browser{Writes: writes}
			defer b.Close()
			if err := b.Start(); errors.Is(err, browser.ErrNoSandbox) {
				t.Skip(err)
			} else if err != nil {
				t.Fatal(err)
			}
			mu.Lock()
			got = nil
			mu.Unlock()
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			var obs []types.StoredObservation
			c := &Collector{Browser: b}
			page := srv.URL + "/"
			if _, err := c.Run(ctx, types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": page}}, func(ob types.Observation) error {
				obs = append(obs, types.StoredObservation{EntityID: "page", Observation: ob})
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			time.Sleep(300 * time.Millisecond)
			b.Close()

			mu.Lock()
			sent := append([]string(nil), got...)
			mu.Unlock()
			if !slices.Contains(sent, "GET /api/items") {
				t.Errorf("the page's GET was not sent: %q", sent)
			}
			for _, w := range wantWrites {
				if slices.Contains(sent, w) != writes {
					t.Errorf("%s sent %v: %q", w, !writes, sent)
				}
			}
			if !writes {
				for _, s := range sent {
					if m, _, _ := strings.Cut(s, " "); m != "GET" && m != "HEAD" && m != "OPTIONS" {
						t.Errorf("Chrome sent %s", s)
					}
				}
			}
			form := false
			for _, ob := range obs {
				if strings.Contains(string(ob.Payload), "secret") || strings.Contains(string(ob.Payload), "a@b.test") {
					t.Errorf("a value sent is kept: %s", ob.Payload)
				}
				form = form || ob.Kind == "form" && strings.Contains(string(ob.Payload), `"action":"`+srv.URL+`/api/subscribe"`)
			}
			if !writes && !form {
				// The form post refused, the page stays as it was: its
				// form is read, not Chrome's error page.
				t.Errorf("the page's form is not read: %d facts", len(obs))
			}

			// The map: each route a hint with the method and names sent.
			ents := []types.Entity{{ID: "page", Type: types.TypeURL, Key: page}}
			for _, w := range wantWrites {
				_, path, _ := strings.Cut(w, " ")
				ents = append(ents, types.Entity{ID: path, Type: types.TypeURL, Key: srv.URL + path})
			}
			rows := map[string]engine.MapEntry{}
			for _, r := range engine.BuildMap(ents, []types.Seed{{Type: types.TypeURL, Keys: map[string]string{"url": page}}}, obs, nil, false) {
				rows[r.Entity.Key] = r
			}
			for path, want := range map[string]engine.Op{
				"/api/track":     {Method: "POST", Query: []string{"src"}, Body: []string{"event", "user"}, BodyType: "application/json"},
				"/api/items/7":   {Method: "DELETE"},
				"/api/upload":    {Method: "PUT", Body: []string{"title"}, BodyType: "multipart/form-data"},
				"/api/beacon":    {Method: "POST", Body: []string{"sid", "t"}, BodyType: "application/x-www-form-urlencoded"},
				"/api/subscribe": {Method: "POST", Body: []string{"email", "plan"}, BodyType: "application/x-www-form-urlencoded"},
			} {
				r := rows[srv.URL+path]
				want.Source = "browser"
				if r.Coverage != "hint" || len(r.Ops) != 1 || fmt.Sprint(r.Ops[0]) != fmt.Sprint(want) || !slices.Equal(r.Methods, []string{want.Method}) {
					t.Errorf("%s: coverage %q, methods %q, ops %+v; want a hint with %+v", path, r.Coverage, r.Methods, r.Ops, want)
				}
			}

			// The summary: what was not sent, left alone.
			var listed []string
			for _, s := range engine.Skips(ents, obs) {
				if s.Reason == browser.WriteReason {
					listed = append(listed, s.Target)
				}
			}
			for _, w := range wantWrites {
				method, path, _ := strings.Cut(w, " ")
				if slices.Contains(listed, method+" "+srv.URL+path) == writes {
					t.Errorf("%s listed %v: %q", w, !writes, listed)
				}
			}
			if left := b.LeftoverWrites(); len(left) > 0 {
				t.Errorf("writes no page listed: %q", left)
			}
		})
	}
}

// socket.io's polling transport POSTs to the socket's path as the page
// loads: that is the socket's row (azhaq-js lists it), not an API route
// of the page's.
func TestWriteFactsSkipSocketPolling(t *testing.T) {
	page := "http://127.0.0.1:3001/"
	obs := WriteFacts(Name, page, []browser.Write{
		{Method: "POST", URL: "http://127.0.0.1:3001/socket.io", Query: []string{"EIO", "sid", "t", "transport"}, Sent: true},
		{Method: "POST", URL: "http://127.0.0.1:3001/rest/user/login", Body: []string{"email", "password"}, BodyType: "application/json"},
	})
	var rows []string
	for _, o := range obs {
		if o.Kind != "url" {
			continue
		}
		var p struct {
			URL string `json:"url"`
		}
		_ = json.Unmarshal(o.Payload, &p)
		rows = append(rows, p.URL)
	}
	if !slices.Equal(rows, []string{"http://127.0.0.1:3001/rest/user/login"}) {
		t.Errorf("rows %v", rows)
	}
}
