package main

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/trannghiach/azhaq/internal/browser"
)

// countingProxy is a proxy that counts the requests it is asked for and
// sends them on to the site: a reverse proxy in front of site (every request
// goes to it, whatever address it names), or a forward proxy relaying the
// absolute address it is asked for.
func countingProxy(site *httptest.Server, reverse bool, delay time.Duration) (*httptest.Server, func() []string) {
	var mu sync.Mutex
	var seen []string
	note := func(r *http.Request) {
		time.Sleep(delay) // a proxy that takes its time, as one under load does
		mu.Lock()
		seen = append(seen, r.Method+" "+r.URL.Path)
		mu.Unlock()
	}
	var h http.Handler
	if reverse {
		u, _ := url.Parse(site.URL)
		rp := httputil.NewSingleHostReverseProxy(u)
		h = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { note(r); rp.ServeHTTP(w, r) })
	} else {
		tr := &http.Transport{Proxy: nil}
		h = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Host == "" || r.Method == http.MethodConnect {
				http.Error(w, "this proxy relays plain requests", http.StatusBadRequest)
				return
			}
			note(r)
			out, _ := http.NewRequestWithContext(r.Context(), r.Method, r.URL.String(), r.Body)
			out.Header = r.Header.Clone()
			resp, err := tr.RoundTrip(out)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadGateway)
				return
			}
			defer resp.Body.Close()
			for k, vs := range resp.Header {
				w.Header()[k] = vs
			}
			w.WriteHeader(resp.StatusCode)
			_, _ = io.Copy(w, resp.Body)
		})
	}
	return httptest.NewServer(h), func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), seen...)
	}
}

// -browser -interact behind -proxy maps what it maps without one, and more
// of what the proxy is asked for: the rendered page's routes, what the
// clicks bring, and the -interact note.
func TestInteractBehindAProxyMapsWhatItMapsWithoutOne(t *testing.T) {
	if _, err := browser.Find(); err != nil {
		t.Skip(err)
	}
	for _, reverse := range []bool{false, true} {
		t.Run(fmt.Sprintf("reverse=%v", reverse), func(t *testing.T) {
			srv := offsiteLinkServer()
			defer srv.Close()
			prox, asked := countingProxy(srv, reverse, 0)
			defer prox.Close()
			t.Chdir(t.TempDir())
			rows := func(extra ...string) (map[string]bool, string) {
				args := append([]string{"crawl", "-u", srv.URL + "/", "-d", "1", "-browser", "-interact", "-interact-clicks", "4", "-allow", "127.0.0.1", "-json", "-db", fmt.Sprintf("c%d.db", len(extra))}, extra...)
				out, errOut, code := cli(t, args...)
				if code != exitOK {
					t.Fatalf("%v: exit %d\n%s", extra, code, errOut)
				}
				got := map[string]bool{}
				for _, r := range jsonRows(t, out) {
					got[r["url"].(string)] = true
				}
				return got, errOut
			}
			plain, _ := rows()
			via, errOut := rows("-proxy", prox.URL)
			t.Logf("without %d rows, with %d; proxy asked %v\n%s", len(plain), len(via), asked(), errOut)
			for u := range plain {
				if !via[u] {
					t.Errorf("-proxy lost %s, which the crawl without it has", u)
				}
			}
			for _, route := range []string{"/api/loaded", "/api/clicked"} {
				if !via[srv.URL+route] {
					t.Errorf("%s is not among the rows behind the proxy", route)
				}
			}
			if !strings.Contains(errOut, "-interact:") {
				t.Errorf("the summary has no -interact note:\n%s", errOut)
			}
		})
	}
}

// slowAppServer is a single-page app that draws its menu only after four
// calls in a row have been answered, one after the other, once the page has
// loaded: on a path with latency it is up long after the load event.
func slowAppServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><title>shop</title><body><div id=app></div><script src="/app.js"></script></body></html>`)
		case "/app.js":
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprint(w, `fetch('/rest/boot/' + ['co','nfig'].join('')).then(() => fetch('/rest/boot/' + ['me','nu'].join(''))).
  then(() => fetch('/rest/boot/' + ['sta','te'].join(''))).then(() => fetch('/rest/boot/' + ['us','er'].join(''))).
  then(() => { document.getElementById('app').innerHTML = '<button id=b>Basket</button> <a href="#/search">Search</a>';
    document.getElementById('b').onclick = () => fetch('/api/' + ['cli','cked'].join('')); });`)
		default:
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"ok":true}`)
		}
	}))
}

// Behind a proxy that is slow to answer, the app is up later: the crawl
// waits for the page to settle, clicks what it drew, and says what the
// clicks did, so the map holds what it holds without the proxy and more.
func TestInteractWaitsForAnAppBehindASlowProxy(t *testing.T) {
	if _, err := browser.Find(); err != nil {
		t.Skip(err)
	}
	for _, reverse := range []bool{false, true} {
		t.Run(fmt.Sprintf("reverse=%v", reverse), func(t *testing.T) {
			srv := slowAppServer()
			defer srv.Close()
			prox, _ := countingProxy(srv, reverse, 600*time.Millisecond)
			defer prox.Close()
			t.Chdir(t.TempDir())
			out, errOut, code := cli(t, "crawl", "-u", srv.URL+"/", "-d", "1", "-browser", "-interact", "-interact-clicks", "3",
				"-allow", "127.0.0.1", "-proxy", prox.URL, "-json", "-db", "c.db")
			if code != exitOK {
				t.Fatalf("exit %d\n%s", code, errOut)
			}
			got := map[string]bool{}
			for _, r := range jsonRows(t, out) {
				got[r["url"].(string)] = true
			}
			for _, route := range []string{"/rest/boot/config", "/rest/boot/user", "/api/clicked"} {
				if !got[srv.URL+route] {
					t.Errorf("%s is not among the rows behind the proxy: %v", route, got)
				}
			}
			if !strings.Contains(errOut, "-interact: ") {
				t.Errorf("the summary has no -interact note:\n%s", errOut)
			}
		})
	}
}
