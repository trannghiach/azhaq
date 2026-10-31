package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/trannghiach/azhaq/internal/fetch"
	"github.com/trannghiach/azhaq/internal/fuzz"
	"github.com/trannghiach/azhaq/scope"
)

// hostSeen is a server that counts the requests that reach it and those
// that name secret.lab in a header, and keeps the Host each one named.
func hostSeen(t *testing.T) (srv *httptest.Server, n, named *atomic.Int64, hosts func() []string) {
	t.Helper()
	n, named = new(atomic.Int64), new(atomic.Int64)
	var mu sync.Mutex
	var seen []string
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		mu.Lock()
		seen = append(seen, r.Host)
		mu.Unlock()
		for _, h := range append([]string{r.Host}, r.Header.Values("X-Forwarded-Host")...) {
			if strings.Contains(h, "secret.lab") {
				named.Add(1)
			}
		}
		if strings.Contains(r.Header.Get("X-Host")+r.Header.Get("X-Original-Host"), "secret.lab") {
			named.Add(1)
		}
		w.WriteHeader(404)
	}))
	t.Cleanup(srv.Close)
	return srv, n, named, func() []string { mu.Lock(); defer mu.Unlock(); return append([]string(nil), seen...) }
}

// A header that names a host the scope leaves out is refused by every
// command that sends headers: exit 2, before the first request. With no
// -allow the host of the target is the scope.
func TestHostHeaderOutsideScopeIsRefusedByEveryCommand(t *testing.T) {
	srv, n, named, _ := hostSeen(t)
	words := wlist(t, "a", "b")
	lock := []string{"-allow", "127.0.0.1", "-deny", "secret.lab"}
	rawReq := filepath.Join(t.TempDir(), "r.req")
	os.WriteFile(rawReq, []byte("GET / HTTP/1.1\nHost: "+strings.TrimPrefix(srv.URL, "http://")+"\nX-Forwarded-Host: secret.lab\n\n"), 0o644)
	vi := filepath.Join(t.TempDir(), "vi.txt")
	os.WriteFile(vi, []byte("secret.lab,127.0.0.1\n"), 0o644)
	probeRaw := filepath.Join(t.TempDir(), "p.req")
	os.WriteFile(probeRaw, []byte("GET / HTTP/1.1\nX-Original-Host: secret.lab\n\n"), 0o644)
	mk := func(a ...string) []string { return a }
	cases := []struct {
		name string
		run  func([]string) error
		args []string
	}{
		{"fuzz scope given", cmdFuzz, append(mk("-u", srv.URL+"/FUZZ", "-H", "Host: secret.lab", "-w", words, "-ac=false"), lock...)},
		{"fuzz default scope", cmdFuzz, mk("-u", srv.URL+"/FUZZ", "-H", "Host: secret.lab", "-w", words, "-ac=false")},
		{"fuzz X-Forwarded-Host", cmdFuzz, append(mk("-u", srv.URL+"/FUZZ", "-H", "X-Forwarded-Host: secret.lab", "-w", words), lock...)},
		{"fuzz lower case name", cmdFuzz, append(mk("-u", srv.URL+"/FUZZ", "-H", "x-host: secret.lab:8080", "-w", words), lock...)},
		{"fuzz request file", cmdFuzz, mk("-request", rawReq, "-request-proto", "http", "-u", srv.URL+"/FUZZ", "-w", words)},
		{"dirs scope given", cmdDirs, append(mk("-u", srv.URL+"/", "-H", "Host: secret.lab", "-w", words), lock...)},
		{"dirs default scope", cmdDirs, mk("-u", srv.URL+"/", "-H", "Host: secret.lab", "-w", words)},
		{"params scope given", cmdParams, append(mk("-u", srv.URL+"/", "-H", "X-Host: secret.lab", "-w", words), lock...)},
		{"params default scope", cmdParams, mk("-u", srv.URL+"/", "-H", "Host: secret.lab", "-w", words)},
		{"params imported request", cmdParams, mk("-i", rawReq, "-w", words)},
		{"probe scope given", cmdProbe, append(mk("-u", srv.URL+"/", "-H", "Host: secret.lab"), lock...)},
		{"probe request file", cmdProbe, append(mk("-u", srv.URL+"/", "-rr", probeRaw), lock...)},
		{"probe virtual host line", cmdProbe, append(mk("-vi", "-l", vi), lock...)},
		{"crawl scope given", cmdCrawl, append(mk("-u", srv.URL+"/", "-H", "X-Forwarded-Host: secret.lab"), lock...)},
		{"roles -role", cmdRoles, append(mk("-dir", t.TempDir(), "-role", "anon", "-role", "bob=Host: secret.lab", "--", "-url", srv.URL+"/"), lock...)},
		{"roles default scope", cmdRoles, mk("-dir", t.TempDir(), "-role", "anon", "-role", "bob=X-Forwarded-Host: secret.lab", "--", "-url", srv.URL+"/")},
		{"roles -role-cmd", cmdRoles, append(mk("-dir", t.TempDir(), "-role", "anon", "-role-cmd", "bob=echo 'X-Host: secret.lab'", "--", "-url", srv.URL+"/"), lock...)},
		{"watch run options", cmdWatch, append(mk("-db", filepath.Join(t.TempDir(), "w.db"), "--", "-url", srv.URL+"/", "-header", "Host: secret.lab"), lock...)},
	}
	for _, c := range cases {
		fetch.Reset()
		n.Store(0)
		named.Store(0)
		_, _, err := captureBoth(t, func() error { return c.run(c.args) })
		if exitCode(err) != exitUsage || err == nil || !strings.Contains(err.Error(), "secret.lab") {
			t.Errorf("%s: exit %d, %v", c.name, exitCode(err), err)
		}
		if got := n.Load(); got != 0 && c.name != "roles -role-cmd" || named.Load() != 0 { // a command's header is known once it has run: the roles before it were sent
			t.Errorf("%s: %d requests reached the server, %d named secret.lab", c.name, got, named.Load())
		}
	}
	fetch.Reset()
}

// A host inside the scope is sent as the Host of the request.
func TestHostHeaderInsideScopeIsSent(t *testing.T) {
	srv, n, _, seen := hostSeen(t)
	fetch.Reset()
	t.Cleanup(fetch.Reset)
	_, _, err := captureBoth(t, func() error {
		return cmdFuzz([]string{"-u", srv.URL + "/FUZZ", "-H", "Host: ok.lab", "-w", wlist(t, "a"), "-ac=false", "-allow", "127.0.0.1", "-allow", "ok.lab", "-json"})
	})
	if err != nil || n.Load() != 1 || seen()[0] != "ok.lab" {
		t.Errorf("err %v, %d requests, hosts %v", err, n.Load(), seen())
	}
}

// A Host that comes from a wordlist is held to the scope for each word: the
// words that name a host outside it are counted and not sent.
func TestFuzzHostFromWordlistIsHeldToTheScope(t *testing.T) {
	srv, n, _, seen := hostSeen(t)
	fetch.Reset()
	t.Cleanup(fetch.Reset)
	rows, rep, err := fuzzRows(t, "-u", srv.URL+"/", "-H", "Host: FUZZ", "-w", wlist(t, "ok.lab", "secret.lab", "other.ok.lab"),
		"-mc", "all", "-ac=false", "-allow", "127.0.0.1", "-allow", "ok.lab", "-deny", "secret.lab")
	if err != nil {
		t.Fatal(err)
	}
	if n.Load() != 2 || len(rows) != 2 || rep.Requests != 2 || len(rep.Skipped) != 1 || !strings.Contains(rep.Skipped[0].Target, "1 inputs") {
		t.Errorf("%d requests, rows %q, summary %+v", n.Load(), rows, rep)
	}
	for _, h := range seen() {
		if h == "secret.lab" {
			t.Error("the denied host was sent")
		}
	}
}

// A literal Host header is checked before the run; one that holds the keyword
// and no -allow gives the scope its domain, as the URL's host does.
func TestFuzzScopeOfHostHeaders(t *testing.T) {
	kw := []string{"FUZZ"}
	tm, _ := fuzz.NewTemplate("", "http://10.0.0.5/", "", []string{"Host: FUZZ.example.com"}, nil)
	r, err := fuzzScope(tm, kw, "", "", nil, nil)
	if err != nil || !r.Allows("dev.example.com") || !r.Allows("10.0.0.5") || r.Allows("example.org") {
		t.Errorf("a virtual host sweep: %+v %v", r, err)
	}
	tm, _ = fuzz.NewTemplate("", "http://10.0.0.5/", "", []string{"Host: FUZZ"}, nil)
	if _, err := fuzzScope(tm, kw, "", "", nil, nil); exitCode(err) != exitUsage {
		t.Errorf("a whole host from a wordlist, no -allow: %v", err)
	}
	tm, _ = fuzz.NewTemplate("", "http://10.0.0.5/", "", []string{"Host: app.example.com"}, nil)
	if _, err := fuzzScope(tm, kw, "", "", nil, nil); exitCode(err) != exitUsage {
		t.Errorf("a literal Host the scope leaves out: %v", err)
	}
	if r, err := fuzzScope(tm, kw, "", "", []string{"10.0.0.5", "example.com"}, nil); err != nil || !r.Allows("app.example.com") {
		t.Errorf("a literal Host named by -allow: %+v %v", r, err)
	}
	tm, _ = fuzz.NewTemplate("", "http://10.0.0.5/", "", []string{"Host: 10.0.0.5:8080"}, nil)
	if _, err := fuzzScope(tm, kw, "", "", nil, nil); err != nil {
		t.Errorf("the target's own Host with a port: %v", err)
	}
}

// fuzz.InScope holds every host-naming header, in any case and in a list.
func TestFuzzInScopeReadsTheHeaders(t *testing.T) {
	allow := scope.Rules{Allow: []string{"127.0.0.1", "ok.lab"}, Deny: []string{"secret.lab"}}.Compile().Allows
	for _, c := range []struct {
		name, value string
		ok          bool
	}{
		{"Host", "ok.lab", true}, {"host", "secret.lab", false}, {"X-Forwarded-Host", "ok.lab, secret.lab", false},
		{"x-original-host", "other.test", false}, {"X-Forwarded-For", "other.test", true}, {"Host", "ok.lab:8443", true},
	} {
		req := &fuzz.Request{URL: "http://127.0.0.1/", Headers: []fuzz.Header{{Name: c.name, Value: c.value}}}
		if got := fuzz.InScope(allow, req); got != c.ok {
			t.Errorf("%s: %s: %v, want %v", c.name, c.value, got, c.ok)
		}
	}
}
