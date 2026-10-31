package engine_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/trannghiach/azhaq/catalog"
	"github.com/trannghiach/azhaq/engine"
	"github.com/trannghiach/azhaq/internal/collectors/crawlcol"
	"github.com/trannghiach/azhaq/internal/collectors/httpcol"
	"github.com/trannghiach/azhaq/internal/fetch"
	"github.com/trannghiach/azhaq/internal/neterr"
	"github.com/trannghiach/azhaq/store"
	"github.com/trannghiach/azhaq/types"
)

// sessionApp is a signed-in site: its pages answer 200 to a live session
// and a redirect to /login to anyone else, and /logout ends the session
// the way a real one does, clearing the cookie.
type sessionApp struct {
	mu    sync.Mutex
	live  map[string]bool
	asked []string // path and whether the request carried a live session
	srv   *httptest.Server
}

func newSessionApp(t *testing.T) *sessionApp {
	a := &sessionApp{live: map[string]bool{"s1": true}}
	a.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, _ := r.Cookie("sid")
		a.mu.Lock()
		ok := c != nil && a.live[c.Value]
		a.asked = append(a.asked, fmt.Sprintf("%s %v", r.URL.Path, ok))
		if r.URL.Path == "/logout" && ok {
			delete(a.live, c.Value)
		}
		a.mu.Unlock()
		switch {
		case r.URL.Path == "/logout":
			http.SetCookie(w, &http.Cookie{Name: "sid", Value: "", MaxAge: -1, Path: "/"})
			http.Redirect(w, r, "/login", http.StatusFound)
		case r.URL.Path == "/login":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<title>Sign in</title>`))
		case !ok:
			http.Redirect(w, r, "/login", http.StatusFound)
		case r.URL.Path == "/":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<title>Home</title><a href="/a">a</a> <a href="/logout">out</a> <a href="/b">b</a> <a href="/c">c</a>`))
		default:
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("<title>" + r.URL.Path + "</title>" + strings.Repeat("<p>"+r.URL.Path+"</p>", 7*len(r.URL.Path))))
		}
	}))
	t.Cleanup(a.srv.Close)
	return a
}

// signedInAsked is the paths the app answered to a live session.
func (a *sessionApp) signedInAsked() map[string]bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := map[string]bool{}
	for _, l := range a.asked {
		if p, v, _ := strings.Cut(l, " "); v == "true" {
			out[p] = true
		}
	}
	return out
}

func runSession(t *testing.T, srv *httptest.Server, s fetch.Session) (map[string]string, []string) {
	t.Helper()
	fetch.Reset()
	t.Cleanup(fetch.Reset)
	fetch.SetExtra(http.Header{"Cookie": {"sid=s1"}})
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	cat := catalog.New()
	httpcol.Register(cat, srv.Client())
	crawlcol.Register(cat, srv.Client())
	eng := &engine.Engine{Cat: cat, Store: st}
	seed := types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": srv.URL + "/"}}
	fetch.WatchSession(s)
	if err := eng.RunLocal(context.Background(), []types.Seed{seed}, engine.Budgets{MaxDepth: 3, MaxItems: 64, Parallel: 1}); err != nil {
		t.Fatal(err)
	}
	ents, _ := st.Entities()
	obs, _ := st.Observations()
	status := map[string]string{}
	for _, r := range engine.BuildMap(ents, []types.Seed{seed}, obs, nil, false) {
		status[strings.TrimPrefix(r.Entity.Key, srv.URL)] = r.Coverage + " " + r.Proof
	}
	return status, fetch.Notes()
}

// The map requests /logout like any link; the session check notices the
// session is gone, signs in again, and the pages after it are asked, and
// stored, signed in.
func TestMapSignsInAgainWhenALinkEndsTheSession(t *testing.T) {
	a := newSessionApp(t)
	renewed := 0
	check := a.srv.URL + "/"
	s := fetch.Session{
		Check: check, Want: fetch.Print{Status: 200}, Every: 1000, SignIn: a.srv.URL + "/login",
		Renew: func(context.Context) error {
			renewed++
			a.mu.Lock()
			a.live["s2"] = true
			a.mu.Unlock()
			fetch.SetExtra(http.Header{"Cookie": {"sid=s2"}})
			return nil
		},
	}
	status, notes := runSession(t, a.srv, s)
	if renewed != 1 {
		t.Fatalf("signed in again %d times, want 1", renewed)
	}
	asked := a.signedInAsked()
	for _, p := range []string{"/", "/a", "/b", "/c"} {
		if !asked[p] {
			t.Errorf("%s was never asked with a live session: %v", p, a.asked)
		}
		if !strings.HasPrefix(status[p], "visited") || !strings.Contains(status[p], "status=200") {
			t.Errorf("%s is stored as %q, want the signed-in answer", p, status[p])
		}
	}
	found := false
	for _, n := range notes {
		if strings.HasPrefix(n, "the session ended after /logout was requested") && strings.Contains(n, "signed in again; ") && strings.Contains(n, " asked again") {
			found = true
		}
	}
	if !found {
		t.Errorf("notes %q", notes)
	}
	if fetch.SessionLost() != nil {
		t.Errorf("lost: %v", fetch.SessionLost())
	}
}

// A session given by cookie cannot be signed in again: the run says it
// ended and refuses what follows, never going on anonymous.
func TestMapStopsWhenACookieSessionEnds(t *testing.T) {
	a := newSessionApp(t)
	s := fetch.Session{Check: a.srv.URL + "/", Want: fetch.Print{Status: 200}, Every: 1000, SignIn: a.srv.URL + "/login",
		Why: "the session was given with -cookie or -header"}
	_, notes := runSession(t, a.srv, s)
	err := fetch.SessionLost()
	if err == nil || !strings.Contains(err.Error(), "the session ended: after /logout was requested") || !strings.Contains(err.Error(), "-cookie") {
		t.Fatalf("lost: %v", err)
	}
	if _, _, got := fetch.Do(context.Background(), a.srv.Client(), a.srv.URL+"/b"); got == nil || !errorsIs(got, neterr.ErrSessionLost) {
		t.Errorf("a request after the loss: %v", got)
	}
	if len(notes) == 0 || !strings.Contains(strings.Join(notes, "\n"), "the session ended") {
		t.Errorf("notes %q", notes)
	}
	// What came after /logout was never sent as an anonymous visitor.
	asked := strings.Join(a.asked, ",")
	if strings.Contains(asked, "/b false") || strings.Contains(asked, "/c false") {
		t.Errorf("asked anonymous after the session ended: %s", asked)
	}
}

func errorsIs(err, target error) bool { return strings.Contains(err.Error(), target.Error()) }

// silentApp ends the session on /logout without a word (no cookie is
// cleared) and answers a dead session 401, the way an API does. Its pages
// answer a live session and a dead one alike until the home page links to
// them, so the run has no page to check the session by when it starts.
type silentApp struct {
	mu      sync.Mutex
	live    map[string]bool
	served  []string // path and whether the session was live
	renewed int
	srv     *httptest.Server
}

func newSilentApp(t *testing.T) *silentApp {
	a := &silentApp{live: map[string]bool{"s1": true}}
	a.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, _ := r.Cookie("sid")
		a.mu.Lock()
		ok := c != nil && a.live[c.Value]
		a.served = append(a.served, fmt.Sprintf("%s %v", r.URL.Path, ok))
		if r.URL.Path == "/logout" && ok {
			delete(a.live, c.Value)
		}
		a.mu.Unlock()
		w.Header().Set("Content-Type", "text/html")
		switch {
		case r.URL.Path == "/":
			_, _ = w.Write([]byte(`<title>Home</title><a href="/a">a</a> <a href="/logout">out</a> <a href="/b">b</a> <a href="/c">c</a> <a href="/d">d</a>`))
		case r.URL.Path == "/logout":
			http.Redirect(w, r, "/", http.StatusFound)
		case !ok:
			http.Error(w, "sign in", http.StatusUnauthorized)
		default:
			_, _ = w.Write([]byte("<title>" + r.URL.Path + "</title>" + strings.Repeat("<p>"+r.URL.Path+"</p>", 7*len(r.URL.Path))))
		}
	}))
	t.Cleanup(a.srv.Close)
	return a
}

func (a *silentApp) liveCount(path string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := 0
	for _, l := range a.served {
		if l == path+" true" {
			n++
		}
	}
	return n
}

// A logout that says nothing, and no page that tells a live session from a
// dead one at the start: the first 401 is tested by signing in again, the
// run goes on signed in, and the link that ends the session is found when
// asking again would end the new one too, and not asked a third time.
func TestMapSurvivesASilentLogout(t *testing.T) {
	a := newSilentApp(t)
	renewals := 0
	sid := "s1"
	s := fetch.Session{
		Every: 1000, SignIn: a.srv.URL + "/login",
		Renew: func(context.Context) error {
			a.mu.Lock()
			renewals++
			sid = fmt.Sprintf("s%d", renewals+1)
			a.live[sid] = true
			a.mu.Unlock()
			fetch.SetExtra(http.Header{"Cookie": {"sid=" + sid}})
			return nil
		},
	}
	status, notes := runSession(t, a.srv, s)
	for _, p := range []string{"/", "/a", "/b", "/c", "/d"} {
		if !strings.HasPrefix(status[p], "visited") || !strings.Contains(status[p], "status=200") {
			t.Errorf("%s is stored as %q, want the signed-in answer\n%v", p, status[p], a.served)
		}
		if a.liveCount(p) == 0 {
			t.Errorf("%s was never asked with a live session", p)
		}
	}
	a.mu.Lock()
	finalLive := a.live[sid]
	a.mu.Unlock()
	if !finalLive {
		t.Errorf("the run ended with a dead session %s: %v", sid, a.served)
	}
	if n := a.liveCount("/logout"); n != 3 {
		t.Errorf("/logout was asked %d times with a live session, want 3 (the map, asked again, the search for what ended the session)", n)
	}
	joined := strings.Join(notes, "\n")
	if !strings.Contains(joined, "/logout ended the new session when asked again") {
		t.Errorf("notes %q", notes)
	}
	if fetch.SessionLost() != nil {
		t.Errorf("lost: %v", fetch.SessionLost())
	}
}
