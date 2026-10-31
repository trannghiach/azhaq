package main

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
)

// pathLog is a server that records the paths it is asked for.
func pathLog(t *testing.T, page string) (*httptest.Server, func() []string) {
	var mu sync.Mutex
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.URL.Path)
		mu.Unlock()
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, page)
		case "/ok", "/open", "/admin/users", "/logout", "/secret":
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprint(w, "found "+r.URL.Path)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), seen...)
	}
}

func skippedFor(rep report, reason string) []string {
	var out []string
	for _, s := range rep.Skipped {
		if s.Reason == reason {
			out = append(out, s.Target)
		}
	}
	return out
}

// The user's own rule keeps a path out of every command that sends: the
// map never requests it and lists it as not requested with the rule,
// while the link named /logout, which no rule covers, is requested.
func TestDenyPathHoldsInRunDirsAndFuzz(t *testing.T) {
	const rule = `^/(secret|admin/)`
	reason := "-deny-path " + rule

	t.Run("run", func(t *testing.T) {
		srv, seen := pathLog(t, `<a href="/ok">ok</a> <a href="/secret">s</a> <a href="/admin/users">a</a> <a href="/logout">out</a>`)
		_, errOut, err := captureBoth(t, func() error {
			return run([]string{"run", "-url", srv.URL + "/", "-no-paths", "-quiet", "-json", "-ledger", "off", "-db", filepath.Join(t.TempDir(), "w.db"), "-deny-path", rule})
		})
		if err != nil {
			t.Fatalf("%v\n%s", err, errOut)
		}
		got := seen()
		if slices.Contains(got, "/secret") || slices.Contains(got, "/admin/users") || !slices.Contains(got, "/logout") || !slices.Contains(got, "/ok") {
			t.Errorf("requested %v", got)
		}
		rep := lastReport(t, errOut)
		listed := skippedFor(rep, reason)
		slices.Sort(listed)
		want := []string{srv.URL + "/admin/users", srv.URL + "/secret"}
		if !slices.Equal(listed, want) {
			t.Errorf("not requested, %s: %v, want %v\n%s", reason, listed, want, errOut)
		}
		if len(rep.Skipped) != 2 {
			t.Errorf("skipped %v: a URL is listed for the rule only", rep.Skipped)
		}
	})

	t.Run("dirs", func(t *testing.T) {
		srv, seen := pathLog(t, "")
		wl := wlist(t, "secret", "open", "logout")
		_, errOut, err := captureBoth(t, func() error {
			return cmdDirs([]string{"-u", srv.URL + "/", "-w", wl, "-mc", "200", "-json", "-ledger", "off", "-deny-path", rule})
		})
		if err != nil {
			t.Fatalf("%v\n%s", err, errOut)
		}
		got := seen()
		if slices.Contains(got, "/secret") || !slices.Contains(got, "/open") || !slices.Contains(got, "/logout") {
			t.Errorf("requested %v", got)
		}
		rep := lastReport(t, errOut)
		if l := skippedFor(rep, reason); len(l) != 1 || l[0] != srv.URL+"/secret" {
			t.Errorf("not requested: %v\n%s", rep.Skipped, errOut)
		}
	})

	t.Run("fuzz", func(t *testing.T) {
		srv, seen := pathLog(t, "")
		wl := wlist(t, "secret", "open", "logout")
		_, errOut, err := captureBoth(t, func() error {
			return cmdFuzz([]string{"-u", srv.URL + "/FUZZ", "-w", wl, "-ac=false", "-mc", "200", "-json", "-deny-path", rule})
		})
		if err != nil {
			t.Fatalf("%v\n%s", err, errOut)
		}
		got := seen()
		if slices.Contains(got, "/secret") || !slices.Contains(got, "/open") || !slices.Contains(got, "/logout") {
			t.Errorf("requested %v", got)
		}
		rep := lastReport(t, errOut)
		if len(rep.Skipped) != 1 || rep.Skipped[0].Reason != reason || !strings.Contains(rep.Skipped[0].Target, "1 inputs") {
			t.Errorf("skipped %v", rep.Skipped)
		}
	})
}

// A rule that is not a regular expression is a usage error before anything
// is sent, on every command that takes it.
func TestDenyPathMustBeARegexp(t *testing.T) {
	srv, seen := pathLog(t, "")
	wl := wlist(t, "a")
	for name, fn := range map[string]func() error{
		"run": func() error {
			return run([]string{"run", "-url", srv.URL + "/", "-deny-path", "(", "-ledger", "off", "-db", filepath.Join(t.TempDir(), "w.db")})
		},
		"dirs": func() error {
			return cmdDirs([]string{"-u", srv.URL + "/", "-w", wl, "-deny-path", "(", "-ledger", "off"})
		},
		"fuzz": func() error { return cmdFuzz([]string{"-u", srv.URL + "/FUZZ", "-w", wl, "-deny-path", "("}) },
	} {
		_, _, err := captureBoth(t, fn)
		var ue usageErr
		if !errors.As(err, &ue) || !strings.Contains(err.Error(), "-deny-path") || exitCode(err) != 2 {
			t.Errorf("%s: %v (exit %d)", name, err, exitCode(err))
		}
	}
	if got := seen(); len(got) != 0 {
		t.Errorf("requested %v", got)
	}
}
