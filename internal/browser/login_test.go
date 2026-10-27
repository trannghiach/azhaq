package browser

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestStoredToken(t *testing.T) {
	jwt := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.c2ln"
	tok, from := storedToken([]string{
		"localStorage.persist:root", `{"user":"{\"jwt\":\"eyJhbGciOiJub25lIn0.eyJzdWIiOiJvbGQifQ.\"}"}`,
		"localStorage.token", jwt,
		"sessionStorage.x", "plain",
	})
	if tok != jwt || from != "localStorage.token" {
		t.Errorf("got %q from %q", tok, from)
	}
	if tok, _ := storedToken([]string{"localStorage.lang", "en"}); tok != "" {
		t.Errorf("no token expected, got %q", tok)
	}
}

// A single-page login: the form is drawn by a script, the button stays
// disabled until both fields have values, and the answer is a cookie and a
// token the page stores.
const loginPage = `<html><body><div id=app></div><script>
setTimeout(() => {
  document.getElementById('app').innerHTML =
    '<div class=overlay style="position:fixed;inset:0;z-index:9"></div>' +
    '<form><label>Email <input id=email type=email></label>' +
    '<input id=pw type=password><button id=go type=submit disabled>Log in</button></form>';
  const f = document.querySelector('form'), b = document.getElementById('go');
  f.addEventListener('input', () => { b.disabled = !(email.value && pw.value); });
  f.addEventListener('submit', async e => {
    e.preventDefault();
    const r = await fetch('/api/login', {method: 'POST', body: JSON.stringify({email: email.value, password: pw.value})});
    if (!r.ok) { document.body.insertAdjacentHTML('beforeend', '<p>wrong</p>'); return; }
    const j = await r.json();
    localStorage.setItem('token', j.token);
    sessionStorage.setItem('bid', j.bid);
    history.pushState({}, '', '/dashboard');
    document.getElementById('app').innerHTML = '<h1>Welcome</h1>';
  });
}, 300);
</script></body></html>`

func TestLogin(t *testing.T) {
	if _, err := Find(); err != nil {
		t.Skip(err)
	}
	const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJtZW1iZXIifQ.c2lnbmVk"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/login":
			var body struct{ Email, Password string }
			if err := decodeJSON(r, &body); err != nil || body.Email != "member@x.test" || body.Password != "s3cret" {
				http.Error(w, "no", http.StatusUnauthorized)
				return
			}
			http.SetCookie(w, &http.Cookie{Name: "sid", Value: "abc123", Path: "/", HttpOnly: true})
			fmt.Fprintf(w, `{"token":%q,"bid":7}`, jwt)
		default:
			fmt.Fprint(w, loginPage)
		}
	}))
	defer srv.Close()
	b := &Browser{}
	defer b.Close()
	if err := b.Start(); errors.Is(err, ErrNoSandbox) {
		t.Skip(err)
	} else if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	var told []Session
	OnLogin = func(s Session) { told = append(told, s) }
	defer func() { OnLogin = nil }()
	s, err := b.Login(ctx, srv.URL+"/login", "member@x.test", "s3cret")
	if err != nil {
		t.Fatal(err)
	}
	// What the login answered and left in storage: who signed in.
	if len(told) != 1 || len(s.Answers) != 1 || string(s.Answers[0]) != fmt.Sprintf(`{"token":%q,"bid":7}`, jwt) {
		t.Errorf("told %d times, answers %q", len(told), s.Answers)
	}
	stored := map[string]string{}
	for i := 0; i+1 < len(s.Storage); i += 2 {
		stored[s.Storage[i]] = s.Storage[i+1]
	}
	if stored["sessionStorage.bid"] != "7" || stored["localStorage.token"] != jwt {
		t.Errorf("storage %v", stored)
	}
	if s.Bearer != jwt || s.From != "localStorage.token" {
		t.Errorf("token %q from %q", s.Bearer, s.From)
	}
	if len(s.Cookies) != 1 || s.Cookies[0] != "sid=abc123" {
		t.Errorf("cookies %v", s.Cookies)
	}
	if s.URL != srv.URL+"/dashboard" {
		t.Errorf("ended on %s", s.URL)
	}
	if _, err := b.Login(ctx, srv.URL+"/login", "member@x.test", "wrong"); !errors.Is(err, ErrLoginFailed) {
		t.Errorf("wrong password: %v", err)
	}
}

func decodeJSON(r *http.Request, v any) error { return json.NewDecoder(r.Body).Decode(v) }
