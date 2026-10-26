package browser

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
)

// Session is what signing in left in the browser.
type Session struct {
	URL     string   // the page the login ended on
	Cookies []string // name=value, the cookies the site sends
	Bearer  string   // a token the page keeps in localStorage or sessionStorage
	From    string   // where the token was, as storage.key
}

// Headers are the request headers that carry the session.
func (s Session) Headers() []string {
	var out []string
	if len(s.Cookies) > 0 {
		out = append(out, "Cookie: "+strings.Join(s.Cookies, "; "))
	}
	if s.Bearer != "" {
		out = append(out, "Authorization: Bearer "+s.Bearer)
	}
	return out
}

// ErrLoginFailed means the form was submitted and is still there.
var ErrLoginFailed = errors.New("the login form is still there after submitting it (wrong credentials, a CAPTCHA, or a second step)")

// markForm finds the visible password field, the text field before it in
// the same form and the form's submit button, and marks them.
const markForm = `(() => {
  const vis = e => e.getClientRects().length > 0 && getComputedStyle(e).visibility !== 'hidden';
  const pass = [...document.querySelectorAll('input[type=password]')].find(vis);
  if (!pass) return '';
  const scope = pass.form || document;
  const inputs = [...scope.querySelectorAll('input')].filter(vis);
  const user = inputs.slice(0, inputs.indexOf(pass)).reverse()
    .find(e => ['', 'text', 'email', 'tel'].includes((e.getAttribute('type') || '').toLowerCase()));
  const buttons = [...scope.querySelectorAll('button, input[type=submit], [role=button]')].filter(vis);
  const submit = buttons.find(b => (b.getAttribute('type') || '').toLowerCase() === 'submit')
    || buttons.find(b => /log\s*in|sign\s*in|submit|continue/i.test(b.innerText || b.value || ''));
  document.querySelectorAll('[data-azhaq]').forEach(e => e.removeAttribute('data-azhaq'));
  pass.setAttribute('data-azhaq', 'pass');
  if (user) user.setAttribute('data-azhaq', 'user');
  if (submit) submit.setAttribute('data-azhaq', 'submit');
  return 'pass' + (user ? ' user' : '') + (submit ? ' submit' : '');
})()`

// fillForm sets the values as typing would: through the input's own value
// setter, then the events frameworks listen to.
func fillForm(user, pass string) string {
	u, _ := json.Marshal(user)
	p, _ := json.Marshal(pass)
	return `(() => {
  const set = (el, v) => {
    if (!el) return;
    el.focus();
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(el, v);
    for (const t of ['input', 'change', 'blur']) el.dispatchEvent(new Event(t, {bubbles: true}));
  };
  set(document.querySelector('[data-azhaq=user]'), ` + string(u) + `);
  set(document.querySelector('[data-azhaq=pass]'), ` + string(p) + `);
  return true;
})()`
}

// submitForm clicks the submit button (directly, so an overlay cannot take
// the click), or submits the form; "enter" means neither was there.
const submitForm = `(() => {
  const b = document.querySelector('[data-azhaq=submit]');
  if (b && !b.disabled) { b.click(); return 'clicked'; }
  const p = document.querySelector('[data-azhaq=pass]');
  if (p && p.form) { p.form.requestSubmit ? p.form.requestSubmit() : p.form.submit(); return 'submitted'; }
  return 'enter';
})()`

// formState is the page's URL, and whether the password field is still shown.
const formState = `(() => {
  const p = [...document.querySelectorAll('input[type=password]')].find(e => e.getClientRects().length > 0);
  return location.href + '\n' + (p ? 'form' : '');
})()`

const readStorage = `(() => {
  const out = [];
  for (const [name, s] of [['localStorage', localStorage], ['sessionStorage', sessionStorage]]) {
    for (let i = 0; i < s.length; i++) { const k = s.key(i); out.push(name + '.' + k, s.getItem(k) || ''); }
  }
  return out;
})()`

var jwtRE = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*`)

// Login opens loginURL, fills the first visible password form with user and
// pass, submits it, and returns the session the site set: its cookies, and
// a JSON Web Token the page stored, if any. The browser keeps the session,
// so pages it renders afterwards are signed in.
func (b *Browser) Login(ctx context.Context, loginURL, user, pass string) (Session, error) {
	if err := b.start(); err != nil {
		return Session{}, err
	}
	tab, cancel := chromedp.NewContext(b.root)
	defer cancel()
	tab, cancelT := context.WithTimeout(tab, 90*time.Second)
	defer cancelT()
	stop := context.AfterFunc(ctx, cancelT)
	defer stop()
	// The tab opens with the context of its first action: open it here, so
	// the shorter navigation timeout below does not close it.
	if err := chromedp.Do(tab); err != nil {
		return Session{}, err
	}
	if len(b.Header) > 0 {
		if _, err := chromedp.Call(tab, network.SetExtraHTTPHeaders, network.SetExtraHTTPHeadersParams{Headers: network.Headers(b.Header)}); err != nil {
			return Session{}, err
		}
	}
	nav, cancelNav := context.WithTimeout(tab, 20*time.Second)
	err := chromedp.Do(nav, chromedp.Navigate(loginURL))
	cancelNav()
	if errors.Is(err, context.DeadlineExceeded) && tab.Err() == nil {
		err = nil
	}
	if err != nil {
		return Session{}, fmt.Errorf("opening %s: %w", loginURL, err)
	}

	// A single-page app draws its form after load.
	found := ""
	for i := 0; i < 30 && found == ""; i++ {
		if found, err = chromedp.Run(tab, chromedp.Evaluate[string](markForm)); err != nil {
			return Session{}, err
		}
		if found == "" {
			if err := chromedp.Do(tab, chromedp.Sleep(500*time.Millisecond)); err != nil {
				return Session{}, err
			}
		}
	}
	if found == "" {
		return Session{}, fmt.Errorf("no password field on %s", loginURL)
	}
	if !strings.Contains(found, "user") && user != "" {
		return Session{}, fmt.Errorf("a password field but no user name field on %s", loginURL)
	}
	before, _ := chromedp.Run(tab, chromedp.Location())
	if _, err := chromedp.Run(tab, chromedp.Evaluate[bool](fillForm(user, pass))); err != nil {
		return Session{}, err
	}
	// Frameworks enable the button once they have seen the values.
	if err := chromedp.Do(tab, chromedp.Sleep(400*time.Millisecond)); err != nil {
		return Session{}, err
	}
	how, err := chromedp.Run(tab, chromedp.Evaluate[string](submitForm))
	if err != nil {
		return Session{}, err
	}
	if how == "enter" {
		if err := chromedp.Do(tab, chromedp.SendKeys(chromedp.CSS(`[data-azhaq=pass]`), "\r")); err != nil {
			return Session{}, err
		}
	}

	// Signed in: the page moved on, or the form went away.
	left := false
	var after string
	for i := 0; i < 30 && !left; i++ {
		if err := chromedp.Do(tab, chromedp.Sleep(500*time.Millisecond)); err != nil {
			return Session{}, err
		}
		state, err := chromedp.Run(tab, chromedp.Evaluate[string](formState))
		if err != nil {
			continue // the page is navigating
		}
		at, form, _ := strings.Cut(state, "\n")
		after = at
		left = at != before || form == ""
	}
	if !left {
		return Session{URL: after}, ErrLoginFailed
	}
	// Tokens are often stored by the request the login sent, a moment later.
	if err := chromedp.Do(tab, chromedp.Sleep(1500*time.Millisecond)); err != nil {
		return Session{}, err
	}

	s := Session{URL: after}
	if s.URL == "" {
		s.URL, _ = chromedp.Run(tab, chromedp.Location())
	}
	jar, err := chromedp.Call(tab, network.GetCookies, network.GetCookiesParams{URLs: []string{loginURL, s.URL}})
	if err != nil {
		return s, err
	}
	for _, c := range jar.Cookies {
		s.Cookies = append(s.Cookies, c.Name+"="+c.Value)
	}
	sort.Strings(s.Cookies)
	kv, err := chromedp.Run(tab, chromedp.Evaluate[[]string](readStorage))
	if err != nil {
		return s, err
	}
	s.Bearer, s.From = storedToken(kv)
	// sessionStorage belongs to the tab: what the login put there (a
	// basket id, a tenant) goes into every tab opened afterwards.
	b.mu.Lock()
	for i := 0; i+1 < len(kv); i += 2 {
		if k, ok := strings.CutPrefix(kv[i], "sessionStorage."); ok {
			if b.session == nil {
				b.session = map[string]string{}
			}
			b.session[k] = kv[i+1]
		}
	}
	b.mu.Unlock()
	return s, nil
}

// storedToken picks a JSON Web Token out of storage entries (key, value,
// key, value…), preferring keys that name a token.
func storedToken(kv []string) (token, from string) {
	best := -1
	for i := 0; i+1 < len(kv); i += 2 {
		t := jwtRE.FindString(kv[i+1])
		if t == "" {
			continue
		}
		score := 0
		if k := strings.ToLower(kv[i]); strings.Contains(k, "token") || strings.Contains(k, "auth") || strings.Contains(k, "jwt") {
			score = 1
		}
		if score > best {
			best, token, from = score, t, kv[i]
		}
	}
	return token, from
}
