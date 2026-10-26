package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// tenantsRow is azhaq roles on a multi-tenant app the bench serves: an
// anonymous visitor, a member and an owner of organisation 1, both signing
// in on a script-drawn login form. The access table is known.
type tenantsRow struct {
	Expected int      `json:"expected"`
	Matched  int      `json:"matched"`
	Extra    []string `json:"extra,omitempty"`   // rows not in the table
	Wrong    []string `json:"wrong,omitempty"`   // rows with other statuses
	Logouts  int64    `json:"signed_in_logouts"` // /logout requested with a session
	Seconds  float64  `json:"seconds"`
}

// tenantsTable is who may read what: anon, member, owner. Organisation 2
// belongs to nobody the bench signs in as.
var tenantsTable = map[string][3]int{
	"/api/me":              {401, 200, 200},
	"/api/orgs/1/members":  {401, 200, 200},
	"/api/orgs/1/settings": {401, 403, 200},
	"/api/orgs/1/billing":  {401, 403, 200},
	"/api/orgs/2/settings": {401, 403, 403},
	"/api/admin/users":     {401, 403, 403},
}

const tenantsLogin = `<html><title>Sign in</title><body><div id=app>Loading…</div><script>
setTimeout(() => {
  document.getElementById('app').innerHTML = '<form><input id=email type=email placeholder=Email>' +
    '<input id=pw type=password><button type=submit disabled>Sign in</button></form>';
  const f = document.querySelector('form'), b = f.querySelector('button');
  f.addEventListener('input', () => { b.disabled = !(email.value && pw.value); });
  f.addEventListener('submit', async e => {
    e.preventDefault();
    const r = await fetch('/api/login', {method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({email: email.value, password: pw.value})});
    if (!r.ok) return;
    localStorage.setItem('auth_token', (await r.json()).token);
    location.href = '/dashboard';
  });
}, 400);
</script></body></html>`

const tenantsApp = `const api = {
  me: () => fetch("/api/me"),
  members: org => fetch("/api/orgs/1/members"),
  settings: () => fetch("/api/orgs/1/settings"),
  billing: () => fetch("/api/orgs/1/billing"),
  other: () => fetch("/api/orgs/2/settings"),
  admin: () => fetch("/api/admin/users"),
  status: () => fetch("/api/public/status"),
};`

func benchTenants() *tenantsRow {
	row := &tenantsRow{Expected: len(tenantsTable)}
	dir, _ := filepath.Abs(filepath.Join(work, "tenants"))
	must(os.MkdirAll(dir, 0o755))
	users := map[string]string{"member@acme.test": "member", "owner@acme.test": "owner"}
	const password = "Bench-Passw0rd!"
	var mu sync.Mutex
	sessions := map[string]string{} // sid or token → role
	var logouts atomic.Int64
	who := func(r *http.Request) string {
		mu.Lock()
		defer mu.Unlock()
		if c, err := r.Cookie("sid"); err == nil && sessions[c.Value] != "" {
			return sessions[c.Value]
		}
		if t, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); ok {
			return sessions[t]
		}
		return ""
	}
	page := func(w http.ResponseWriter, title, body string) {
		fmt.Fprintf(w, `<html><title>%s</title><body><a href="/">Home</a> <a href="/login">Sign in</a> <a href="/dashboard">Dashboard</a> <a href="/logout">Sign out</a>%s<script src="/app.js"></script></body></html>`, title, body)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	must(err)
	defer ln.Close()
	site := "http://" + ln.Addr().String() + "/"
	go http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		role := who(r)
		need := func(ok ...string) bool {
			if role == "" {
				http.Error(w, `{"error":"sign in"}`, http.StatusUnauthorized)
				return false
			}
			for _, o := range ok {
				if role == o {
					return true
				}
			}
			http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
			return false
		}
		switch r.URL.Path {
		case "/":
			page(w, "Acme", "<h1>Acme workspaces</h1>")
		case "/dashboard":
			page(w, "Dashboard", "<div id=app></div>")
		case "/login":
			fmt.Fprint(w, tenantsLogin)
		case "/app.js":
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprint(w, tenantsApp)
		case "/logout":
			if role != "" {
				logouts.Add(1)
				mu.Lock()
				for k, v := range sessions {
					if v == role {
						delete(sessions, k)
					}
				}
				mu.Unlock()
			}
			http.Redirect(w, r, "/", http.StatusFound)
		case "/api/login":
			var body struct{ Email, Password string }
			if r.Method != http.MethodPost || json.NewDecoder(r.Body).Decode(&body) != nil || users[body.Email] == "" || body.Password != password {
				http.Error(w, `{"error":"bad credentials"}`, http.StatusUnauthorized)
				return
			}
			var b [12]byte
			_, _ = rand.Read(b[:])
			sid := hex.EncodeToString(b[:])
			_, _ = rand.Read(b[:])
			token := "eyJhbGciOiJIUzI1NiJ9.eyJ0ZW5hbnQiOiJhY21lIn0." + hex.EncodeToString(b[:])
			mu.Lock()
			sessions[sid], sessions[token] = users[body.Email], users[body.Email]
			mu.Unlock()
			http.SetCookie(w, &http.Cookie{Name: "sid", Value: sid, Path: "/", HttpOnly: true})
			fmt.Fprintf(w, `{"token":%q}`, token)
		case "/api/public/status":
			fmt.Fprint(w, `{"ok":true}`)
		case "/api/me":
			if need("member", "owner") {
				fmt.Fprintf(w, `{"role":%q}`, role)
			}
		case "/api/orgs/1/members":
			if need("member", "owner") {
				fmt.Fprint(w, `[{"email":"member@acme.test"},{"email":"owner@acme.test"}]`)
			}
		case "/api/orgs/1/settings", "/api/orgs/1/billing":
			if need("owner") {
				fmt.Fprint(w, `{"plan":"team"}`)
			}
		case "/api/orgs/2/settings", "/api/admin/users":
			need("admin")
		default:
			http.NotFound(w, r)
		}
	}))

	out, m := run("tenants", 10*time.Minute, dir, azhaq, "roles", "-dir", filepath.Join(dir, "tenants-"+time.Now().Format("150405")),
		"-jsonl", "-all", "-login", site+"login", "-role", "anon",
		"-role-login", "member=member@acme.test:"+password, "-role-login", "owner=owner@acme.test:"+password,
		"--", "-url", site)
	row.Seconds = m.Seconds
	row.Logouts = logouts.Load()
	origin := strings.TrimSuffix(site, "/")
	for _, l := range lines(out) {
		var r struct {
			URL     string         `json:"url"`
			Status  map[string]int `json:"status"`
			Verdict string         `json:"verdict"`
		}
		if json.Unmarshal([]byte(l), &r) != nil {
			continue
		}
		path := strings.TrimPrefix(r.URL, origin)
		got := [3]int{r.Status["anon"], r.Status["member"], r.Status["owner"]}
		want, ok := tenantsTable[path]
		switch {
		case !ok && (r.Verdict == "same for every role" || r.Verdict == "not answered" || r.Verdict == "different data per role"):
			// Pages everyone gets, and /logout, which only the anonymous
			// visitor may follow.
		case !ok:
			row.Extra = append(row.Extra, fmt.Sprintf("%s %v", path, got))
		case got != want:
			row.Wrong = append(row.Wrong, fmt.Sprintf("%s %v, want %v", path, got, want))
		default:
			row.Matched++
		}
	}
	sort.Strings(row.Extra)
	extraOK := len(row.Extra) == 0
	addCheck("roles: anon → member → owner on a multi-tenant app, signed in with Chrome",
		row.Matched == row.Expected && len(row.Wrong) == 0 && extraOK && row.Logouts == 0,
		"%d/%d rows as expected; wrong %v; extra %v; signed-in logouts %d %s", row.Matched, row.Expected, row.Wrong, row.Extra, row.Logouts, m.Error)
	return row
}
