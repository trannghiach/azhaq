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
	"testing"
	"time"

	"github.com/trannghiach/azhaq/internal/browser"
)

// An app that signs in like Juice Shop: the login answers a token, the API
// reads it as a bearer, an anonymous visitor gets 401, and a few routes
// answer 401 to the signed-in user too. The run reads those 401s as a
// possible end of the session and signs in again while it goes on; the
// answers it asks meanwhile are the user's, not an anonymous visitor's.
func TestRolesBearerSessionIsNotAnonymousWhileItSignsInAgain(t *testing.T) {
	if _, err := browser.Find(); err != nil {
		t.Skip(err)
	}
	const password = "Bench-Passw0rd!"
	const routes = 40
	var mu sync.Mutex
	tokens := map[string]bool{}
	anon := map[string]int{} // routes the server answered without a token
	signed := func(r *http.Request) bool {
		tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		mu.Lock()
		defer mu.Unlock()
		return ok && tokens[tok]
	}
	var links strings.Builder
	for i := 1; i <= 6; i++ {
		fmt.Fprintf(&links, `<a href="/api/public/%d">p%d</a> `, i, i)
	}
	links.WriteString(`<a href="/api/basket/9">basket</a> `)
	for i := 1; i <= routes; i++ {
		fmt.Fprintf(&links, `<a href="/api/data/%d">d%d</a> `, i, i)
	}
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch p := r.URL.Path; {
		case p == "/":
			fmt.Fprintf(w, `<html><title>Shop</title><body><a href="/login">Sign in</a> %s</body></html>`, links.String())
		case p == "/login":
			fmt.Fprint(w, tenantsLoginPage)
		case p == "/api/login":
			var body struct{ Email, Password string }
			if json.NewDecoder(r.Body).Decode(&body) != nil || body.Email != "user@shop.test" || body.Password != password {
				http.Error(w, `{"error":"bad credentials"}`, http.StatusUnauthorized)
				return
			}
			var b [12]byte
			_, _ = rand.Read(b[:])
			tok := "eyJhbGciOiJIUzI1NiJ9.eyJzaG9wIjoianVpY2UifQ." + hex.EncodeToString(b[:])
			mu.Lock()
			tokens[tok] = true
			mu.Unlock()
			fmt.Fprintf(w, `{"token":%q}`, tok)
		case strings.HasPrefix(p, "/api/public/"):
			fmt.Fprint(w, `{"ok":true}`)
		case p == "/api/basket/9": // someone else's: 401 even signed in
			http.Error(w, `{"error":"invalid basket"}`, http.StatusUnauthorized)
		case strings.HasPrefix(p, "/api/data/"):
			time.Sleep(150 * time.Millisecond)
			if !signed(r) {
				mu.Lock()
				anon[p]++
				mu.Unlock()
				http.Error(w, `{"error":"sign in"}`, http.StatusUnauthorized)
				return
			}
			fmt.Fprint(w, `{"rows":[]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer site.Close()

	out, errOut, err := captureBoth(t, func() error {
		return cmdRoles([]string{"-jsonl", "-all", "-dir", t.TempDir(), "-login", site.URL + "/login", "-role", "anon",
			"-role-login", "user=user@shop.test:" + password, "--", "-url", site.URL + "/"})
	})
	if err != nil {
		t.Fatalf("%v\n%s", err, errOut)
	}
	rows, wrong := 0, []string{}
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		var r struct {
			URL    string         `json:"url"`
			Status map[string]int `json:"status"`
		}
		if json.Unmarshal([]byte(l), &r) != nil || !strings.Contains(r.URL, "/api/data/") {
			continue
		}
		rows++
		if r.Status["anon"] != 401 || r.Status["user"] != 200 {
			wrong = append(wrong, fmt.Sprintf("%s anon %d user %d", strings.TrimPrefix(r.URL, site.URL), r.Status["anon"], r.Status["user"]))
		}
	}
	if rows != routes || len(wrong) > 0 {
		t.Errorf("%d of %d routes rows; not 401 → 200: %v\n%s", rows, routes, wrong, errOut)
	}
	// Only the anonymous role asks without the token: a request of the user's
	// run that went out stripped would be answered as a visitor.
	mu.Lock()
	defer mu.Unlock()
	for p, n := range anon {
		if n > 1 {
			t.Errorf("%s asked %d times without the token, want 1 (the anonymous role's)", p, n)
		}
	}
	if strings.Contains(errOut, "the session ended") {
		t.Errorf("a session that never ended was reported as ended\n%s", errOut)
	}
}
