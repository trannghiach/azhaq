package fetch

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/trannghiach/azhaq/internal/neterr"
)

// A signed-in run can lose its session without a word: any URL it requests
// may end it (a /logout link, an expiry), and what follows is answered as an
// anonymous visitor. Nothing is guessed from a name. The run keeps one check,
// a page that answers differently with its session and without it, asks it
// every Every requests and when an answer looks like the end of the session
// (a 401, a redirect to the sign-in page, a response that clears a session
// cookie), and when the check fails it signs in again or stops.

// Print is the part of an answer a session check compares: the status and
// the path the answer redirects to.
type Print struct {
	Status int
	Loc    string
}

// Session is what a run knows of its session.
type Session struct {
	// Check is a URL that answers differently with the session than without
	// it, and Want is its answer with it. Empty: the run found no such page,
	// and only a response that clears the session cookie tells it is over.
	Check string
	Want  Print
	// Every is how many requests pass between checks; 50 when zero.
	Every int
	// SignIn is the sign-in page of the run: an answer that redirects to it
	// asks for a check.
	SignIn string
	// Renew signs in again and sets the new session (SetExtra). Nil: the run
	// cannot, and says so when its session ends.
	Renew func(ctx context.Context) error
	// Why says, when Renew is nil, how the session was given.
	Why string
}

const (
	defaultEvery = 50
	maxAsked     = 4096 // GET URLs kept to be asked again
	maxRenewals  = 5
)

type sessionGuard struct {
	s Session

	gate     sync.RWMutex // held for writing while a check runs
	checking atomic.Bool
	since    atomic.Int64 // requests since the last good check
	due      atomic.Bool  // an answer looked like the end of the session

	renewing atomic.Bool // signing in again: its own requests pass

	mu       sync.Mutex
	asked    []string // GETs that came through Do since the last good check
	endedBy  string   // a URL whose answer cleared the session cookie
	lost     error
	redo     []string
	renewals int
}

var guardP atomic.Pointer[sessionGuard]

// extraMu holds Extra steady while a request reads it and a new session is set.
var extraMu sync.RWMutex

// SetExtra replaces the headers every request carries, as a new session does.
func SetExtra(h http.Header) {
	extraMu.Lock()
	Extra = h
	extraMu.Unlock()
}

// WatchSession starts the check; Reset ends it.
func WatchSession(s Session) {
	if s.Every <= 0 {
		s.Every = defaultEvery
	}
	guardP.Store(&sessionGuard{s: s})
}

func resetSession() { guardP.Store(nil) }

// SessionLost is the error of a run whose session ended and could not be
// brought back, nil otherwise. Every request after it is refused with it.
func SessionLost() error {
	if g := guardP.Load(); g != nil {
		g.mu.Lock()
		defer g.mu.Unlock()
		return g.lost
	}
	return nil
}

// TakeRedo is the URLs a new session makes worth asking again: the GETs sent
// since the last good check, now evicted from the cache. The scheduler asks
// their pages again.
func TakeRedo() []string {
	g := guardP.Load()
	if g == nil {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	out := g.redo
	g.redo = nil
	return out
}

// Measure asks raw with the run's session and without it, and gives both
// answers: a page worth checking the session by differs.
func Measure(ctx context.Context, raw string) (with, without Print, err error) {
	if with, err = askPrint(ctx, raw, true); err != nil {
		return
	}
	without, err = askPrint(ctx, raw, false)
	return
}

// askPrint requests raw once, not followed, and gives its print. It is
// counted in the budget and the ledger like any request, but not checked
// by the guard itself.
func askPrint(ctx context.Context, raw string, session bool) (Print, error) {
	if err := denied(raw); err != nil {
		return Print{}, err
	}
	if err := spendCount(ctx, true); err != nil {
		return Print{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		Refund()
		return Print{}, err
	}
	if session {
		ApplyHeaders(req)
		withJar(req)
	} else {
		req.Header.Set("User-Agent", UserAgent)
	}
	resp, err := noFollow(nil).Do(req)
	if err != nil {
		return Print{}, err
	}
	defer resp.Body.Close()
	p := Print{Status: resp.StatusCode}
	if loc, err := url.Parse(resp.Header.Get("Location")); err == nil {
		p.Loc = loc.Path
	}
	return p, nil
}

// EndCheck checks the session once more when requests were sent since the
// last check, so that the end of a run is not taken on trust.
func EndCheck(ctx context.Context) {
	if g := guardP.Load(); g != nil && g.since.Load() > 0 {
		_ = g.check(ctx)
	}
}

// tick counts a request about to be sent and, when a check is due, makes
// it. It returns the error that refuses the request.
func (g *sessionGuard) tick(ctx context.Context) error {
	if g.renewing.Load() {
		return nil
	}
	g.gate.RLock() // waits while a check or a new sign-in runs
	g.gate.RUnlock()
	g.mu.Lock()
	lost := g.lost
	g.mu.Unlock()
	if lost != nil {
		return lost
	}
	if n := g.since.Add(1); n < int64(g.s.Every) && !g.due.Load() {
		return nil
	}
	return g.check(ctx)
}

func (g *sessionGuard) alive(p Print) bool { return p == g.s.Want }

// check asks the check and, when the session is gone, signs in again or
// stops the run's signed-in work.
func (g *sessionGuard) check(ctx context.Context) error {
	if !g.checking.CompareAndSwap(false, true) {
		return nil
	}
	g.gate.Lock()
	defer func() {
		g.gate.Unlock()
		g.checking.Store(false)
	}()
	sent := g.since.Swap(0)
	g.due.Store(false)
	g.mu.Lock()
	endedBy := g.endedBy
	g.mu.Unlock()
	var got Print
	if g.s.Check != "" {
		p, err := askPrint(ctx, g.s.Check, true)
		if err != nil {
			return nil // not answered: nothing is judged from it
		}
		if g.alive(p) {
			g.mu.Lock()
			g.asked, g.endedBy = nil, ""
			g.mu.Unlock()
			return nil
		}
		got = p
	} else if endedBy == "" {
		return nil
	}
	return g.lose(ctx, got, endedBy, int(sent))
}

// lose handles a session that failed its check.
func (g *sessionGuard) lose(ctx context.Context, got Print, endedBy string, sent int) error {
	g.mu.Lock()
	n := len(g.asked)
	g.mu.Unlock()
	unrecorded := max(0, sent-n)
	how := "the check " + pathOf(g.s.Check) + " answered " + describe(got) + ", where it answered " + describe(g.s.Want) + " with the session"
	if g.s.Check == "" {
		how = "a response cleared the session cookie"
	}
	what := fmt.Sprintf("the session ended (%s)", how)
	if endedBy != "" {
		what = fmt.Sprintf("the session ended after %s was requested (%s)", pathOf(endedBy), how)
	}
	fail := func(why string) error {
		err := &neterr.SessionLost{Msg: fmt.Sprintf("the session ended: %s; %s; %d GETs sent since the last good check were answered without it, and so were %d other requests", strings.TrimPrefix(what, "the session ended "), why, n, unrecorded)}
		g.mu.Lock()
		g.lost = err
		g.mu.Unlock()
		Note(err.Error())
		return err
	}
	if g.s.Renew == nil {
		return fail("the run cannot sign in again (" + g.s.Why + ")")
	}
	g.mu.Lock()
	over := g.renewals >= maxRenewals
	g.renewals++
	g.mu.Unlock()
	if over {
		return fail(fmt.Sprintf("it ended %d times, and signing in again did not hold", maxRenewals))
	}
	g.renewing.Store(true)
	err := g.s.Renew(ctx)
	g.renewing.Store(false)
	if err != nil {
		return fail("signing in again failed: " + err.Error())
	}
	if p, err := askPrint(ctx, g.s.Check, true); g.s.Check != "" && (err != nil || !g.alive(p)) {
		return fail("signed in again, but the check still answers " + describe(p))
	}
	g.mu.Lock()
	// The request whose answer cleared the session is not asked again: its
	// answer, to a live session, is the one it gives.
	redo := slices.DeleteFunc(g.asked, func(u string) bool { return u == endedBy })
	g.asked, g.endedBy = nil, ""
	g.redo = append(g.redo, redo...)
	g.mu.Unlock()
	for _, u := range redo {
		evict(u)
	}
	msg := what + "; signed in again; " + plural(len(redo), "request") + " asked again"
	if unrecorded > 0 {
		msg += fmt.Sprintf(" (%s sent in the same stretch, path or parameter guesses, are not)", plural(unrecorded, "request"))
	}
	Note(msg)
	return nil
}

func describe(p Print) string {
	if p.Status == 0 {
		return "nothing"
	}
	s := fmt.Sprint(p.Status)
	if p.Loc != "" {
		s += " to " + p.Loc
	}
	return s
}

func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

func pathOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Path == "" {
		return raw
	}
	return u.Path
}

// evict forgets the answer to raw, so that asking again sends it.
func evict(raw string) {
	cacheMu.Lock()
	delete(cache, raw)
	cacheMu.Unlock()
	redoKeys.Store(raw, true)
}

// redoKeys are the URLs asked again: a kept answer of an earlier run is not
// read back for them.
var redoKeys sync.Map

// sessionSaw tells the guard a request was answered: it keeps the URL to ask
// again, and notices an answer that looks like the end of the session.
func sessionSaw(raw string, res Result) {
	g := guardP.Load()
	if g == nil {
		return
	}
	g.mu.Lock()
	if len(g.asked) < maxAsked {
		g.asked = append(g.asked, raw)
	}
	g.mu.Unlock()
	if clearsSession(res.Header) || clearsSession(res.FinalHeader) {
		g.mu.Lock()
		if g.endedBy == "" {
			g.endedBy = raw
		}
		g.mu.Unlock()
		g.due.Store(true)
		return
	}
	if res.Status == http.StatusUnauthorized || g.s.SignIn != "" && slices.ContainsFunc(res.Hops, func(h Hop) bool {
		return h.Location != "" && pathOf(h.Location) == pathOf(g.s.SignIn)
	}) {
		g.due.Store(true)
	}
}

// clearsSession says a response expires a cookie the run sends: a
// Set-Cookie with an empty value, a Max-Age of zero or an Expires in the past.
func clearsSession(h http.Header) bool {
	if len(h["Set-Cookie"]) == 0 {
		return false
	}
	extraMu.RLock()
	mine := (&http.Request{Header: http.Header{"Cookie": Extra.Values("Cookie")}}).Cookies()
	extraMu.RUnlock()
	if len(mine) == 0 {
		return false
	}
	for _, c := range (&http.Response{Header: h}).Cookies() {
		if c.MaxAge < 0 || c.Value == "" || !c.Expires.IsZero() && c.Expires.Before(time.Now()) {
			if slices.ContainsFunc(mine, func(m *http.Cookie) bool { return m.Name == c.Name }) {
				return true
			}
		}
	}
	return false
}

// sessionTick is called for each request about to be sent.
func sessionTick(ctx context.Context) error {
	if g := guardP.Load(); g != nil {
		return g.tick(ctx)
	}
	return nil
}
