package fetch

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A response ends the session when it expires a cookie the run sends, and
// only then: another cookie, or one set to a value, does not.
func TestClearsSession(t *testing.T) {
	Reset()
	defer Reset()
	Extra = http.Header{"Cookie": {"sid=abc; theme=dark"}}
	for set, want := range map[string]bool{
		"sid=; Max-Age=0; Path=/":                      true,
		"sid=x; Expires=Thu, 01 Jan 1970 00:00:00 GMT": true,
		"sid=; Path=/":                                 true,
		"sid=newvalue; Path=/":                         false,
		"other=; Max-Age=0":                            false,
		"theme=light":                                  false,
	} {
		if got := clearsSession(http.Header{"Set-Cookie": {set}}); got != want {
			t.Errorf("%q: %v, want %v", set, got, want)
		}
	}
	Extra = http.Header{"Authorization": {"Bearer x"}}
	if clearsSession(http.Header{"Set-Cookie": {"sid=; Max-Age=0"}}) {
		t.Error("a run with no cookie has none to lose")
	}
}

func sessionSite(t *testing.T) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok":
			_, _ = w.Write([]byte("ok"))
		case "/401":
			w.WriteHeader(http.StatusUnauthorized)
		case "/to-login":
			http.Redirect(w, r, "/login", http.StatusFound)
		case "/logout":
			http.SetCookie(w, &http.Cookie{Name: "sid", Value: "", MaxAge: -1, Path: "/"})
			_, _ = w.Write([]byte("bye"))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// A worker keeps no check of its own: it tells the run which GETs it sent
// and whether an answer looked like the end of the session.
func TestRemoteGuardReportsWhatItSaw(t *testing.T) {
	srv := sessionSite(t)
	for path, want := range map[string]SessionReport{
		"/ok":       {},
		"/401":      {Due: true},
		"/to-login": {Due: true},
		"/logout":   {Due: true, EndedBy: "/logout"},
	} {
		Reset()
		Extra = http.Header{"Cookie": {"sid=abc"}}
		WatchRemote(srv.URL+"/login", nil)
		if _, _, err := Do(context.Background(), srv.Client(), srv.URL+path); err != nil {
			t.Fatal(err)
		}
		got := TakeReport()
		if got == nil || len(got.Asked) != 1 || got.Due != want.Due || got.EndedBy != "" && got.EndedBy != srv.URL+want.EndedBy {
			t.Errorf("%s: report %+v, want %+v", path, got, want)
		}
		if TakeReport() != nil {
			t.Errorf("%s: a report is told once", path)
		}
	}
	Reset()
}

// The run counts a worker's requests toward its check, makes the check when
// an answer asked for it, signs in again, and asks again what the workers
// asked since the last good check, and what tasks lent before it asked.
func TestRunChecksForItsWorkers(t *testing.T) {
	srv := sessionSite(t)
	Reset()
	defer Reset()
	Extra = http.Header{"Cookie": {"sid=abc"}}
	renewed := 0
	// /ok answers 200 with the session; the check is asked without moving.
	WatchSession(Session{Check: srv.URL + "/ok", Want: Print{Status: 200}, Every: 3, Renew: func(context.Context) error {
		renewed++
		SetExtra(http.Header{"Cookie": {"sid=new"}})
		return nil
	}})
	if SessionGen() != 0 {
		t.Fatal("no renewal yet")
	}
	// Two requests are fewer than 3 and nothing asked: no check.
	AbsorbReport(&SessionReport{Asked: []string{"/a"}}, 2, true)
	if err := CheckDue(context.Background()); err != nil || renewed != 0 || SessionGen() != 0 {
		t.Fatalf("early check: %v %d", err, renewed)
	}
	// The check passes (/ok answers 200): nothing is renewed, the stretch is closed.
	AbsorbReport(&SessionReport{Asked: []string{"/b"}}, 1, true)
	if err := CheckDue(context.Background()); err != nil || renewed != 0 || TakeRedo() != nil {
		t.Fatalf("passing check: %v %d", err, renewed)
	}
	// A check that fails signs in again, and the stretch's GETs are asked again.
	WatchSession(Session{Check: srv.URL + "/401", Want: Print{Status: 200}, Every: 100, Renew: func(context.Context) error {
		renewed++
		return nil
	}})
	AbsorbReport(&SessionReport{Asked: []string{srv.URL + "/p", srv.URL + "/q"}, Due: true, EndedBy: srv.URL + "/q"}, 2, true)
	if err := CheckDue(context.Background()); err == nil {
		// the check page still answers 401 after signing in: the run stops
		t.Fatal("a session that does not come back is a failure")
	}
	if renewed != 1 || SessionLost() == nil {
		t.Fatalf("renewed %d, lost %v", renewed, SessionLost())
	}
	// Tasks lent before a renewal are asked again whole.
	Reset()
	Extra = http.Header{"Cookie": {"sid=abc"}}
	WatchSession(Session{Check: srv.URL + "/ok", Want: Print{Status: 200}, Renew: func(context.Context) error { return nil }})
	AbsorbReport(&SessionReport{Asked: []string{srv.URL + "/old"}}, 1, false)
	if redo := TakeRedo(); len(redo) != 1 || redo[0] != srv.URL+"/old" {
		t.Errorf("redo %v", redo)
	}
}

// A renewal is counted, so a worker knows to fetch the new headers.
func TestSessionGenCountsRenewals(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("sid"); err != nil || c.Value != "good" {
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	t.Cleanup(srv.Close)
	Reset()
	defer Reset()
	Extra = http.Header{"Cookie": {"sid=stale"}}
	n := 0
	WatchSession(Session{Check: srv.URL + "/me", Want: Print{Status: 200}, Every: 1, Renew: func(context.Context) error {
		n++
		SetExtra(http.Header{"Cookie": {"sid=good"}})
		return nil
	}})
	AbsorbReport(&SessionReport{Asked: []string{srv.URL + "/x"}, Due: true}, 1, true)
	if err := CheckDue(context.Background()); err != nil || n != 1 || SessionGen() != 1 {
		t.Fatalf("check %v, renewed %d, gen %d", err, n, SessionGen())
	}
	if redo := TakeRedo(); len(redo) != 1 || redo[0] != srv.URL+"/x" {
		t.Errorf("redo %v", redo)
	}
	if got := strings.Join(ExtraLines(), "|"); got != "Cookie: sid=good" {
		t.Errorf("lines %q", got)
	}
	SetExtraLines([]string{"Cookie: sid=zzz", "X-Token: t"})
	if got := strings.Join(ExtraLines(), "|"); !strings.Contains(got, "Cookie: sid=zzz") || !strings.Contains(got, "X-Token: t") {
		t.Errorf("lines %q", got)
	}
}
