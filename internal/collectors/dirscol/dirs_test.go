package dirscol

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/trannghiach/azhaq/internal/fetch"
	"github.com/trannghiach/azhaq/internal/fuzz"
	"github.com/trannghiach/azhaq/types"
)

// spa answers every unknown path with its index page, like Juice Shop,
// and has a few real paths.
func spa(t *testing.T) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin":
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("forbidden"))
		case "/backup.bak":
			w.Write([]byte("-- dump of the users table, many rows follow"))
		case "/files":
			http.Redirect(w, r, "/files/", http.StatusMovedPermanently)
		case "/files/report":
			w.Write([]byte("quarterly numbers"))
		case "/logout":
			w.Write([]byte("bye"))
		default:
			w.Write([]byte("<html><title>App</title><body>the same shell for every route</body></html>"))
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func sweepOf(t *testing.T, c *Collector, base string) ([]string, map[string]any) {
	t.Helper()
	return sweepSeed(t, c, types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": base}}, base)
}

func sweepSeed(t *testing.T, c *Collector, seed types.Seed, base string) ([]string, map[string]any) {
	t.Helper()
	var got []string
	var summary map[string]any
	_, err := c.Run(context.Background(), seed, func(o types.Observation) error {
		var m map[string]any
		_ = json.Unmarshal(o.Payload, &m)
		switch o.Kind {
		case "dirs":
			summary = m
		case "skipped": // guesses held back, listed in the summary
		default:
			got = append(got, strings.TrimPrefix(m["url"].(string), strings.TrimSuffix(base, "/")))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(got)
	return got, summary
}

func TestSweepCalibratesAndRecurses(t *testing.T) {
	fetch.Reset()
	srv := spa(t)
	c := New(srv.Client(), Options{Words: []string{"admin", "backup", "files", "report", "login", "index", "logout"}, Extensions: []string{"bak"}, Depth: 2, Rate: 1000})
	got, summary := sweepOf(t, c, srv.URL+"/")
	want := []string{"/admin", "/backup.bak", "/files", "/files/report", "/logout"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("hits %v, want %v", got, want)
	}
	if summary["filtered"].(float64) == 0 {
		t.Errorf("the catch-all answers were not filtered: %v", summary)
	}
	if !c.Skip(types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": srv.URL + "/admin"}}) {
		t.Error("a sweep starts at the front page")
	}
}

func TestSweepKeepsSessionAlive(t *testing.T) {
	fetch.Reset()
	defer fetch.Reset()
	fetch.Extra = http.Header{"Cookie": {"session=1"}}
	srv := spa(t)
	c := New(srv.Client(), Options{Words: []string{"logout", "admin"}, Rate: 1000})
	got, _ := sweepOf(t, c, srv.URL+"/")
	if strings.Join(got, " ") != "/admin" {
		t.Errorf("with a session, logout must not be requested: %v", got)
	}
}

// A catch-all page cut off mid-body (the server going down) was a hit of
// length 0: calibration had seen the whole page.
func TestSweepDropsCutOffAnswers(t *testing.T) {
	fetch.Reset()
	shell := strings.Repeat("<p>the same shell for every route</p>", 50)
	tries := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tries[r.URL.Path]++
		switch {
		case r.URL.Path == "/flaky" && tries["/flaky"] == 1, r.URL.Path == "/zh-cn":
			w.Header().Set("Content-Length", "1850")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(shell[:100]))
			conn, _, _ := w.(http.Hijacker).Hijack()
			conn.Close()
		case r.URL.Path == "/admin":
			w.WriteHeader(http.StatusForbidden)
		default:
			w.Write([]byte(shell))
		}
	}))
	t.Cleanup(srv.Close)
	c := New(srv.Client(), Options{Words: []string{"admin", "flaky", "zh-cn"}, Rate: 1000, Threads: 1})
	got, summary := sweepOf(t, c, srv.URL+"/")
	if strings.Join(got, " ") != "/admin" {
		t.Errorf("hits %v, want only /admin", got)
	}
	if tries["/flaky"] != 2 || tries["/zh-cn"] != 2 {
		t.Errorf("a cut-off answer is asked once more: tries %v", tries)
	}
	if summary["failed"].(float64) != 1 {
		t.Errorf("failed %v, want 1 (zh-cn, cut off twice)", summary["failed"])
	}
}

// A URL with a path is swept from that path; one sweep per directory the
// user gave.
func TestSweepStartsAtTheGivenPath(t *testing.T) {
	fetch.Reset()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/sub/secret":
			w.Write([]byte("sub secret"))
		case "/rootonly":
			w.Write([]byte("root page"))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	c := New(srv.Client(), Options{Words: []string{"secret", "rootonly", "nope"}, Rate: 1000})
	seed := types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": srv.URL + "/sub", types.StartKey: "1"}}
	if c.Skip(seed) {
		t.Fatal("a URL the user gave is swept")
	}
	if !c.Skip(types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": srv.URL + "/sub/secret"}}) {
		t.Error("a URL found by another collector is not swept")
	}
	got, _ := sweepSeed(t, c, seed, srv.URL+"/sub")
	// Paths are shown relative to the start: /sub/secret, not /rootonly.
	if len(got) != 1 || got[0] != "/secret" {
		t.Errorf("hits %v, want /sub/secret only", got)
	}
}

// Lines are newlines+1 of the whole body, as ffuf counts them; a status
// ffuf's range holds (250) is matched; -fs hides a size.
func TestCountsMatchersAndFilters(t *testing.T) {
	fetch.Reset()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/trail":
			w.Write([]byte("a b c\n\n\n"))
		case "/s250":
			w.WriteHeader(250)
			w.Write([]byte("two fifty"))
		case "/big":
			w.Write([]byte(strings.Repeat("x", 4242)))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	words := []string{"trail", "s250", "big", "none"}
	rows := func(set *fuzz.Set) map[string]hit {
		c := New(srv.Client(), Options{Words: words, Rate: 1000, Set: set})
		out := map[string]hit{}
		var seen []types.Observation
		_, err := c.Run(context.Background(), types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": srv.URL + "/"}}, func(o types.Observation) error { seen = append(seen, o); return nil })
		if err != nil {
			t.Fatal(err)
		}
		for _, o := range seen {
			var h hit
			if o.Kind == "url" && json.Unmarshal(o.Payload, &h) == nil {
				out[strings.TrimPrefix(h.URL, srv.URL+"/")] = h
			}
		}
		return out
	}
	got := rows(nil)
	if h := got["trail"]; h.Lines != 4 || h.Words != 3 {
		t.Errorf("trail: lines %d words %d, want 4 and 3", h.Lines, h.Words)
	}
	if got["s250"].Status != 250 {
		t.Errorf("a 250 is in ffuf's default range: %v", got)
	}
	set := NewSet()
	if err := set.AddFilter("size", "4242"); err != nil {
		t.Fatal(err)
	}
	if got := rows(set); got["big"].URL != "" || got["trail"].URL == "" {
		t.Errorf("-fs 4242 hides big only: %v", got)
	}
	only := fuzz.NewSet(nil)
	if err := only.AddMatcher("line", "4"); err != nil {
		t.Fatal(err)
	}
	if got := rows(only); len(got) != 1 || got["trail"].URL == "" {
		t.Errorf("-ml 4 keeps trail only: %v", got)
	}
}

// Soft 404s that echo the path (in the body, in a redirect) are explained;
// real pages of nearly the same size are kept.
func TestSoftNotFoundKeepsRealPages(t *testing.T) {
	fetch.Reset()
	pad := strings.Repeat("lorem ipsum dolor sit amet ", 20)
	real := map[string]bool{"admin": true, "backup": true, "config": true}
	echo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.Trim(r.URL.Path, "/")
		if real[p] {
			fmt.Fprintf(w, "<title>%s</title>%s Welcome to the %s area.", p, pad, p)
			return
		}
		fmt.Fprintf(w, "<title>Not found: %s</title>%s The page %s does not exist.", p, pad, p)
	}))
	t.Cleanup(echo.Close)
	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.Trim(r.URL.Path, "/")
		switch {
		case p == "login":
			w.Write([]byte(pad + " sign in"))
		case real[p]:
			w.WriteHeader(403)
			w.Write([]byte(pad + " forbidden " + p))
		default:
			http.Redirect(w, r, "/login?next=/"+p, http.StatusFound)
		}
	}))
	t.Cleanup(redir.Close)
	words := []string{"admin", "backup", "config", "alpha", "beta", "gamma-long-name", "x", "delta", "login"}
	for name, srv := range map[string]*httptest.Server{"echo": echo, "redirect": redir} {
		c := New(srv.Client(), Options{Words: words, Rate: 1000})
		got, _ := sweepOf(t, c, srv.URL+"/")
		want := []string{"/admin", "/backup", "/config"}
		if name == "redirect" {
			want = append(want, "/login")
		}
		sort.Strings(want)
		if strings.Join(got, " ") != strings.Join(want, " ") {
			t.Errorf("%s: hits %v, want %v", name, got, want)
		}
	}
}

// A sweep keeps a connection per thread, not a new one for every third
// request; many hits are all reported.
func TestSweepReusesConnectionsAndReportsEveryHit(t *testing.T) {
	fetch.Reset()
	var conns atomic.Int64
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/hit") {
			fmt.Fprintf(w, "unique page %s %s", r.URL.Path, strings.Repeat("y", len(r.URL.Path)*7))
			return
		}
		http.NotFound(w, r)
	}))
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			conns.Add(1)
		}
	}
	srv.Start()
	t.Cleanup(srv.Close)
	var words []string
	for i := 0; i < 3000; i++ {
		words = append(words, fmt.Sprintf("hit%d", i), fmt.Sprintf("miss%d", i))
	}
	c := New(srv.Client(), Options{Words: words, Rate: 1e5, Threads: 16})
	got, summary := sweepOf(t, c, srv.URL+"/")
	if len(got) != 3000 || summary["hits"].(float64) != 3000 {
		t.Errorf("hits %d (summary %v), want 3000", len(got), summary["hits"])
	}
	if n := conns.Load(); n > 16+10 {
		t.Errorf("%d connections for 6000 requests at 16 threads", n)
	}
}

// A "?" in a word starts the query, as in ffuf (common.txt has
// dns-query?name=…): the path is /dns-query, the query follows.
func TestWordWithQuery(t *testing.T) {
	fetch.Reset()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/dns-query" && r.URL.Query().Get("name") == "a b" {
			w.Write([]byte("resolver answer"))
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	c := New(srv.Client(), Options{Words: []string{"dns-query?name=a b", "dns-query"}, Rate: 1000})
	got, _ := sweepOf(t, c, srv.URL+"/")
	if len(got) != 1 || got[0] != "/dns-query?name=a%20b" {
		t.Errorf("hits %v", got)
	}
}

// A sweep asks as ffuf does: no Accept, so a server that picks its answer
// by it (Express's redirect) answers with the body ffuf counts, and -fs
// copied from ffuf filters the same hit.
func TestSweepAsksWithoutAcceptLikeFfuf(t *testing.T) {
	fetch.Reset()
	const plain = "Found. Redirecting to /app/" // what a request with no Accept gets
	var accepts atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/app" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Accept") != "" {
			accepts.Add(1)
		}
		w.Header().Set("Location", "/app/")
		w.WriteHeader(http.StatusMovedPermanently)
		if strings.Contains(r.Header.Get("Accept"), "text/html") {
			w.Write([]byte("<p>Found. Redirecting to <a href=\"/app/\">/app/</a></p>"))
			return
		}
		w.Write([]byte(plain))
	}))
	defer srv.Close()
	words := []string{"app", "nothing"}
	var length float64
	c := New(srv.Client(), Options{Words: words, Rate: 1000})
	_, err := c.Run(context.Background(), types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": srv.URL + "/"}}, func(o types.Observation) error {
		var m map[string]any
		_ = json.Unmarshal(o.Payload, &m)
		if o.Kind == "url" {
			length, _ = m["length"].(float64)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if length != float64(len(plain)) || accepts.Load() != 0 {
		t.Errorf("/app is %v bytes (a request with no Accept gets %d), %d requests sent an Accept", length, len(plain), accepts.Load())
	}
	// A header the user gives wins.
	fetch.Extra = http.Header{"Accept": {"text/html"}}
	defer fetch.Reset()
	c = New(srv.Client(), Options{Words: words, Rate: 1000})
	_, _ = c.Run(context.Background(), types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": srv.URL + "/"}}, func(o types.Observation) error {
		var m map[string]any
		_ = json.Unmarshal(o.Payload, &m)
		if o.Kind == "url" {
			length, _ = m["length"].(float64)
		}
		return nil
	})
	if length == float64(len(plain)) {
		t.Errorf("-H Accept did not reach the server: /app is %v bytes", length)
	}
}

// Calibration asks its guesses together: a sweep of 27 words on a slow
// service waited four round trips for it, one at a time, before the sweep.
func TestCalibrationAsksItsGuessesTogether(t *testing.T) {
	for _, tc := range []struct {
		threads, want int
	}{{40, 5}, {1, 1}} {
		fetch.Reset()
		var inFlight, widest atomic.Int64
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			n := inFlight.Add(1)
			defer inFlight.Add(-1)
			for {
				old := widest.Load()
				if n <= old || widest.CompareAndSwap(old, n) {
					break
				}
			}
			// Each guess waits for the others (the four shapes and the
			// extension's) or a moment, so a sequential calibration shows.
			for i := 0; i < 12 && inFlight.Load() < 5; i++ {
				time.Sleep(5 * time.Millisecond)
			}
			http.NotFound(w, r)
		}))
		c := New(srv.Client(), Options{Words: []string{"admin"}, Extensions: []string{"php"}, Threads: tc.threads, Rate: 1000})
		c.calibrate(context.Background(), srv.URL+"/", schemeHost(srv.URL+"/"))
		srv.Close()
		if widest.Load() != int64(tc.want) {
			t.Errorf("-t %d: %d guesses in flight at most, want %d", tc.threads, widest.Load(), tc.want)
		}
	}
}
