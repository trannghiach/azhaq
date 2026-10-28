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
	"sync"
	"testing"
	"time"

	"github.com/trannghiach/azhaq/engine"
	"github.com/trannghiach/azhaq/internal/browser"
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
	fetch.Allow = func(h string) bool { return h == "127.0.0.1" }
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
	if n := fetch.Sent(); n != int64(served) {
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
