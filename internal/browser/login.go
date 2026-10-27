package browser

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"

	"github.com/trannghiach/azhaq/internal/fetch"
	"github.com/trannghiach/azhaq/internal/neterr"
)

// Session is what signing in left in the browser.
type Session struct {
	URL     string   // the page the login ended on
	Cookies []string // name=value, the cookies the site sends
	Bearer  string   // a token the page keeps in localStorage or sessionStorage
	From    string   // where the token was, as storage.key
	Storage []string // what localStorage and sessionStorage held: storage.key, value, storage.key, value…
	Answers [][]byte // the JSON answers to the requests submitting the form sent (the login's own answer)
	Blocked []string // URLs the sign-in asked for outside the scope, to list (Reason); not sent
}

// OnLogin, when set, is told of every session a login left: azhaq roles
// learns from it who each role is (a user id, a basket id).
var OnLogin func(Session)

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
func (b *Browser) Login(ctx context.Context, loginURL, user, pass string) (_ Session, err error) {
	if err := b.start(); err != nil {
		return Session{}, err
	}
	b.visit(loginURL)
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
	// What Chrome refused for the sign-in's frames: a sign-in that went to
	// an identity provider outside the scope fails, and says so.
	var framesMu sync.Mutex
	main := cdp.FrameID(chromedp.FromContext(tab).Target.TargetID)
	frames := map[cdp.FrameID]bool{main: true}
	all := chromedp.Events(tab, network.RequestWillBeSent)
	go func() {
		for ev, err := range all {
			if err != nil {
				return
			}
			framesMu.Lock()
			frames[ev.FrameID] = true
			framesMu.Unlock()
		}
	}()
	b.sockets(tab, main)
	var mine []refusal
	refused := func() []refusal {
		framesMu.Lock()
		mine = append(mine, b.claim(frames)...)
		framesMu.Unlock()
		return mine
	}
	defer func() {
		if err != nil {
			err = outside(loginURL, main, refused(), err)
		}
	}()
	if len(b.Header) > 0 {
		if _, err := chromedp.Call(tab, network.SetExtraHTTPHeaders, network.SetExtraHTTPHeadersParams{Headers: network.Headers(b.Header)}); err != nil {
			return Session{}, err
		}
	}
	nav, cancelNav := context.WithTimeout(tab, 20*time.Second)
	err = chromedp.Do(nav, chromedp.Navigate(loginURL))
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
	// The requests submitting sends, other than GETs: their answers say
	// who signed in.
	var sentMu sync.Mutex
	var sent []network.RequestID
	listen, stopListen := context.WithCancel(tab)
	defer stopListen()
	events := chromedp.Events(listen, network.RequestWillBeSent)
	go func() {
		for ev, err := range events {
			if err != nil {
				return
			}
			if ev.Request != nil && ev.Request.Method != "GET" && ev.Request.Method != "OPTIONS" {
				sentMu.Lock()
				if len(sent) < 8 {
					sent = append(sent, ev.RequestID)
				}
				sentMu.Unlock()
			}
		}
	}()
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
	s.Blocked = b.list(refused())
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
	s.Storage = kv
	stopListen()
	sentMu.Lock()
	ids := append([]network.RequestID(nil), sent...)
	sentMu.Unlock()
	for _, id := range ids {
		// A page that navigated away has dropped the body: nothing to read.
		res, err := chromedp.Call(tab, network.GetResponseBody, network.GetResponseBodyParams{RequestID: id})
		if body := bytes.TrimSpace(res.Body); err == nil && len(body) <= 1<<16 && json.Valid(body) && len(body) > 0 && (body[0] == '{' || body[0] == '[') {
			s.Answers = append(s.Answers, body)
		}
	}
	if OnLogin != nil {
		OnLogin(s)
	}
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

// outside explains a sign-in that failed where Chrome was refused. The
// page going to a host outside the scope (an identity provider) is the
// cause; a frame from there, or a call the page sent there, may be. The
// budget running out is said as such.
func outside(loginURL string, main cdp.FrameID, rs []refusal, err error) error {
	var went, other string
	for _, r := range rs {
		switch {
		case r.budget:
			return fmt.Errorf("%w (Chrome was refused requests while signing in)", neterr.ErrBudget)
		case r.doc && r.frame == main && went == "":
			went = r.host
		case (r.doc || r.sends) && other == "":
			other = r.host
		}
	}
	at := hostOf(loginURL)
	fix := func(host string) string {
		if fetch.Allow == nil {
			return fmt.Sprintf("outside the site of %s: name both with -allow %s -allow %s", at, fetch.Site(at), host)
		}
		return "outside the scope: add it with -allow " + host
	}
	switch {
	case went != "":
		return fmt.Errorf("the sign-in went to %s, %s", went, fix(went))
	case other != "":
		return fmt.Errorf("%w; Chrome was not let reach %s for it (%s, if the sign-in needs it)", err, other, fix(other))
	}
	return err
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
