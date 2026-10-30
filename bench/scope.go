package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"
)

// scopeRow checks that a run with a program's scope never sends a request
// outside it, and that watching an unchanged target reports nothing.
type scopeRow struct {
	TrapRequests int64    `json:"trap_requests"`
	ChromeTrap   int64    `json:"chrome_trap_requests"`
	InScopeFound int      `json:"in_scope_found"`
	WatchRuns    int      `json:"watch_runs"`
	WatchNoise   []string `json:"watch_noise,omitempty"`
}

func benchScope(app string) *scopeRow {
	dir, _ := filepath.Abs(filepath.Join(work, "scope"))
	must(os.MkdirAll(dir, 0o755))
	row := &scopeRow{}

	// The trap listens on 127.0.0.2: every way a page can point there.
	var trapped atomic.Int64
	tl, err := net.Listen("tcp", "127.0.0.2:0")
	must(err)
	trap := "http://" + tl.Addr().String()
	go http.Serve(tl, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		trapped.Add(1)
		fmt.Fprint(w, "<html><title>trap</title></html>")
	}))
	defer tl.Close()
	sl, err := net.Listen("tcp", "127.0.0.1:0")
	must(err)
	site := "http://" + sl.Addr().String()
	go http.Serve(sl, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			fmt.Fprintf(w, `<html><title>in scope</title><script src="%[1]s/app.js"></script><script>fetch("%[1]s/api/v1/users")</script>
<a href="%[1]s/out">out</a><a href="/go">go</a><a href="/search?q=1">search</a><form action="%[1]s/submit"><input name="x"></form></html>`, trap)
		case "/login":
			fmt.Fprintf(w, `<html><title>sign in</title><script src="%[1]s/login.js"></script><img src="%[1]s/pixel.png"><form action="%[1]s/submit" method="post"><input name="user"><input type="password" name="pass"><button>Sign in</button></form><a href="%[1]s/after">after</a></html>`, trap)
		case "/go":
			http.Redirect(w, r, trap+"/landing", http.StatusFound)
		case "/robots.txt":
			fmt.Fprintf(w, "Sitemap: %s/sitemap.xml\n", trap)
		case "/search":
			fmt.Fprint(w, "<html>results</html>")
		default:
			http.NotFound(w, r)
		}
	}))
	defer sl.Close()

	scopeFile := filepath.Join(dir, "scope.txt")
	must(os.WriteFile(scopeFile, []byte("# the program\n"+strings.TrimPrefix(site, "http://")+"\n!127.0.0.2\n"), 0o644))
	words := filepath.Join(dir, "words.txt")
	must(os.WriteFile(words, []byte("admin\nlogin\nsearch\nq\nid\n"), 0o644))
	db := filepath.Join(dir, "scope-"+time.Now().Format("150405")+".db")
	run("scope", 5*time.Minute, dir, azhaq, "run", "-scope", scopeFile, "-dirs", words, "-params", words,
		"-ports", "80,"+strings.Split(site, ":")[2], "-graphql", "-db", db, "-quiet")
	row.TrapRequests = trapped.Load()
	out, _ := runOut(azhaq, "export", "-db", db, "-format", "urls")
	for _, u := range lines(out) {
		switch {
		case strings.HasPrefix(u, site):
			row.InScopeFound++
		}
	}
	addCheck("scope: no request leaves the program's scope", row.TrapRequests == 0 && row.InScopeFound >= 4,
		"%d requests to the out-of-scope host (links, scripts, a redirect, a form, robots.txt; path, parameter, port and GraphQL modules on); %d in-scope URLs mapped",
		row.TrapRequests, row.InScopeFound)

	// Chrome: -browser, -login and shots against the same page, with the trap
	// behind links, scripts, images, a redirect, a form post and the sign-in form.
	if _, err := exec.LookPath("google-chrome"); err != nil {
		if _, err = exec.LookPath("chromium"); err != nil {
			addCheck("scope: no request leaves the program's scope with Chrome (-browser, -login, shots)", false, "no Chrome in PATH")
		}
	}
	before := trapped.Load()
	cdb := filepath.Join(dir, "scope-chrome-"+time.Now().Format("150405")+".db")
	rb := azRun("scope", 5*time.Minute, dir, "run", "-scope", scopeFile, "-browser", "-db", cdb, "-quiet")
	rl := azRun("scope", 5*time.Minute, dir, "run", "-scope", scopeFile, "-login", site+"/login", "-login-user", "bench", "-login-pass", "bench", "-db", cdb+"-login.db", "-quiet")
	rs := azRun("scope", 5*time.Minute, dir, "shots", "-u", site+"/", "-u", site+"/login", "-scope", scopeFile, "-dir", filepath.Join(dir, "shots"), "-silent")
	rc := azRun("scope", 5*time.Minute, dir, "crawl", "-u", site+"/", "-browser", "-scope", scopeFile, "-silent")
	row.ChromeTrap = trapped.Load() - before
	addCheck("scope: no request leaves the program's scope with Chrome (-browser, -login, shots)", row.ChromeTrap == 0,
		"%d requests to the out-of-scope host from run -browser (exit %d), run -login (exit %d: the sign-in form posts to the trap, so it is refused), shots (exit %d) and crawl -browser (exit %d)", row.ChromeTrap, rb.exit, rl.exit, rs.exit, rc.exit)

	// Watching an unchanged app: after the first run, nothing to report.
	ws := filepath.Join(dir, "watch-"+time.Now().Format("150405")+".db")
	for i := 0; i < 3; i++ {
		out, _ := run("watch", 10*time.Minute, dir, azhaq, "watch", "-db", ws, "-json", "--", "-url", app)
		var ch map[string]any
		if json.Unmarshal(out, &ch) != nil {
			continue
		}
		row.WatchRuns++
		if i == 0 {
			continue
		}
		for _, k := range []string{"hosts", "services", "urls", "ports", "gone_hosts", "gone_services"} {
			if xs, ok := ch[k].([]any); ok {
				for _, x := range xs {
					row.WatchNoise = append(row.WatchNoise, fmt.Sprintf("run %d %s: %v", i+1, k, x))
				}
			}
		}
	}
	addCheck("watch: an unchanged app reports no change", row.WatchRuns == 3 && len(row.WatchNoise) == 0,
		"%d runs, %d reported changes %v", row.WatchRuns, len(row.WatchNoise), row.WatchNoise)
	return row
}
