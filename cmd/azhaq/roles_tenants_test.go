package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/trannghiach/azhaq/internal/browser"
)

const tenantsLoginPage = `<html><title>Sign in</title><body><div id=app>Loading…</div><script>
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
}, 100);
</script></body></html>`

// A multi-tenant app whose /logout ends every session of the visitor's role,
// and whose pages all link to it: the run's map asks it signed in. roles
// still answers for each role as itself.
func TestRolesSignedInWithChromeSurvivesLogoutLink(t *testing.T) {
	if _, err := browser.Find(); err != nil {
		t.Skip(err)
	}
	table := map[string][3]int{
		"/api/me":              {401, 200, 200},
		"/api/orgs/1/members":  {401, 200, 200},
		"/api/orgs/1/settings": {401, 403, 200},
		"/api/orgs/1/billing":  {401, 403, 200},
		"/api/orgs/2/settings": {401, 403, 403},
		"/api/admin/users":     {401, 403, 403},
	}
	users := map[string]string{"member@acme.test": "member", "owner@acme.test": "owner"}
	const password = "Bench-Passw0rd!"
	var mu sync.Mutex
	sessions := map[string]string{}
	var logouts atomic.Int64
	who := func(r *http.Request) string {
		mu.Lock()
		defer mu.Unlock()
		if c, err := r.Cookie("sid"); err == nil && sessions[c.Value] != "" {
			return sessions[c.Value]
		}
		if tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); ok {
			return sessions[tok]
		}
		return ""
	}
	page := func(w http.ResponseWriter, title, body string) {
		fmt.Fprintf(w, `<html><title>%s</title><body><a href="/">Home</a> <a href="/login">Sign in</a> <a href="/dashboard">Dashboard</a> <a href="/logout">Sign out</a>%s<script src="/app.js"></script></body></html>`, title, body)
	}
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
			fmt.Fprint(w, tenantsLoginPage)
		case "/app.js":
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprint(w, `const api = {me: () => fetch("/api/me"), members: org => fetch("/api/orgs/1/members"),
  settings: () => fetch("/api/orgs/1/settings"), billing: () => fetch("/api/orgs/1/billing"),
  other: () => fetch("/api/orgs/2/settings"), admin: () => fetch("/api/admin/users"), status: () => fetch("/api/public/status")};`)
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
	defer site.Close()

	out, errOut, err := captureBoth(t, func() error {
		return cmdRoles([]string{"-jsonl", "-all", "-dir", t.TempDir(), "-login", site.URL + "/login", "-role", "anon",
			"-role-login", "member=member@acme.test:" + password, "-role-login", "owner=owner@acme.test:" + password,
			"--", "-url", site.URL + "/"})
	})
	if err != nil {
		t.Fatalf("%v\n%s", err, errOut)
	}
	matched := 0
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		var r struct {
			URL    string         `json:"url"`
			Status map[string]int `json:"status"`
		}
		if json.Unmarshal([]byte(l), &r) != nil {
			continue
		}
		want, ok := table[strings.TrimPrefix(r.URL, site.URL)]
		if !ok {
			continue
		}
		if got := [3]int{r.Status["anon"], r.Status["member"], r.Status["owner"]}; got != want {
			t.Errorf("%s %v, want %v", r.URL, got, want)
		} else {
			matched++
		}
	}
	if matched != len(table) {
		t.Errorf("%d of %d rows as expected (/logout asked %d times)\n%s", matched, len(table), logouts.Load(), errOut)
	}
}
