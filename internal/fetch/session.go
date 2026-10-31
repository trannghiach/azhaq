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

	"github.com/trannghiach/azhaq/internal/egress"
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
	maxProbes    = 6 // answers measured to find a check page when the start gave none
	maxVerifies  = 3 // times a 401 is tested by signing in again when there is no check page
	maxEnders    = 8 // times the search for a request that ends the session may sign in again
)

type sessionGuard struct {
	s Session

	gate     sync.RWMutex // held for writing while a check runs
	checking atomic.Bool
	since    atomic.Int64 // requests since the last good check
	due      atomic.Bool  // an answer looked like the end of the session

	renewing atomic.Bool  // signing in again: its own requests pass
	probing  atomic.Bool  // a candidate for the check page is being measured
	good     atomic.Int64 // checks that held, and renewals: the stretch a request belongs to

	// remote: a worker's guard. It measures nothing and renews nothing: it
	// keeps what its requests were answered and tells the run (TakeReport).
	remote bool
	tell   func(SessionReport) // remote: tells the run at once, not with the task's outcome
	told   atomic.Bool         // remote: the run was told since the last TakeReport
	gen    atomic.Int64        // sessions the run has had after the first: workers fetch the new headers

	mu       sync.Mutex
	asked    []string // GETs that came through Do since the last good check
	endedBy  string   // a URL whose answer cleared the session cookie
	lost     error
	redo     []string
	renewals int
	probes   int             // candidates measured so far
	suspects []suspect       // answers that looked like the end of the session, no check page to say
	proven   map[string]bool // suspects that answered alike once signed in again
	verifies int
	enders   map[string]bool // requests that end the session whenever they are sent
	stretch  int64           // the oldest stretch a renewal made worth asking again, not taken yet
	stretchN bool
}

// suspect is a URL answered as if the session were over (a 401, a redirect to
// the sign-in page), with the answer.
type suspect struct {
	url string
	was Print
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
	guardP.Store(&sessionGuard{s: s, proven: map[string]bool{}})
}

func resetSession() { guardP.Store(nil) }

// WatchRemote gives a worker process the part of the session check that
// only needs its own answers: the GETs it sent, and whether an answer looked
// like the end of the session (a 401, a redirect to signIn, a cleared
// cookie). The run's process makes the check and signs in again; the worker
// sends TakeReport with each outcome.
//
// tell, when set, is called as soon as an answer looks like the end of the
// session (once until the next TakeReport), so that the run notices while
// the task is still running.
func WatchRemote(signIn string, tell func(SessionReport)) {
	guardP.Store(&sessionGuard{s: Session{SignIn: signIn}, remote: true, tell: tell})
}

// SessionReport is what a worker saw of the session while it ran a task.
type SessionReport struct {
	Asked   []string `json:"asked,omitempty"`    // GETs sent, answered with the session it had
	Due     bool     `json:"due,omitempty"`      // an answer looked like the end of the session
	EndedBy string   `json:"ended_by,omitempty"` // a URL whose answer cleared the session cookie
}

// TakeReport is what this worker's requests were answered since the last
// call, or nil when there is nothing to tell.
func TakeReport() *SessionReport {
	g := guardP.Load()
	if g == nil || !g.remote {
		return nil
	}
	g.mu.Lock()
	r := &SessionReport{Asked: g.asked, EndedBy: g.endedBy, Due: g.due.Swap(false)}
	g.asked, g.endedBy = nil, ""
	g.mu.Unlock()
	g.told.Store(false)
	if len(r.Asked) == 0 && !r.Due {
		return nil
	}
	return r
}

// AbsorbReport counts what a worker's task did into the run's session
// check: its requests, its GETs (asked again if the session ends) and what
// its answers looked like. current is false for a task lent before the
// session was last renewed: its answers may have come without the session,
// so its GETs are asked again.
func AbsorbReport(r *SessionReport, requests int, current bool) {
	g := guardP.Load()
	if g == nil || g.remote {
		return
	}
	if !current {
		if r != nil {
			g.mu.Lock()
			g.redo = append(g.redo, r.Asked...)
			g.mu.Unlock()
			for _, u := range r.Asked {
				evict(u)
			}
		}
		return
	}
	g.since.Add(int64(requests))
	if r == nil {
		return
	}
	g.mu.Lock()
	g.asked = append(g.asked, r.Asked[:min(len(r.Asked), max(0, maxAsked-len(g.asked)))]...)
	if r.EndedBy != "" && g.endedBy == "" {
		g.endedBy = r.EndedBy
	}
	g.mu.Unlock()
	if r.Due {
		g.due.Store(true)
	}
}

// CheckDue makes the session check when enough requests passed (also those
// of workers) or an answer asked for it. The run's own requests make it by
// themselves; this is for a run whose work is done by workers. The error is
// the one that ends signed-in work, nil while the session holds.
func CheckDue(ctx context.Context) error {
	g := guardP.Load()
	if g == nil || g.remote {
		return nil
	}
	if g.since.Load() >= int64(g.s.Every) || g.due.Load() {
		return g.check(ctx)
	}
	return SessionLost()
}

// SessionGen is how many times the session was renewed: a worker that
// holds an older one fetches the new headers before its next task.
func SessionGen() int {
	if g := guardP.Load(); g != nil {
		return int(g.gen.Load())
	}
	return 0
}

// ExtraLines are the run's session and other headers as "Name: value".
func ExtraLines() []string {
	extraMu.RLock()
	defer extraMu.RUnlock()
	var out []string
	for k, vs := range Extra {
		for _, v := range vs {
			out = append(out, k+": "+v)
		}
	}
	return out
}

// SetExtraLines replaces the headers every request carries with lines of
// "Name: value", and drops the answers kept under the old ones.
func SetExtraLines(lines []string) {
	h := http.Header{}
	for _, l := range lines {
		if k, v, ok := strings.Cut(l, ":"); ok {
			h.Add(strings.TrimSpace(k), strings.TrimSpace(v))
		}
	}
	SetExtra(h)
	cacheMu.Lock()
	cache = map[string]cacheEnt{}
	cacheMu.Unlock()
}

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

// GoodChecks counts the checks that held and the sessions renewed: a task
// that began and ended within one count asked nothing in a stretch that was
// lost.
func GoodChecks() int64 {
	if g := guardP.Load(); g != nil {
		return g.good.Load()
	}
	return 0
}

// TakeStretch is the count GoodChecks had while the stretch ran that a
// renewal made worth asking again, once: a task that was running at that
// count, or ended at it or after, sent requests with the session that ended.
func TakeStretch() (int64, bool) {
	g := guardP.Load()
	if g == nil {
		return 0, false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	from, ok := g.stretch, g.stretchN
	g.stretchN = false
	return from, ok
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
	if err := egress.CheckDenied(raw); err != nil {
		return Print{}, err
	}
	if err := egress.SpendCounted(ctx, true); err != nil {
		return Print{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		egress.Refund()
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
// last check, or an answer asked for one after it, so that the end of a run
// is not taken on trust.
func EndCheck(ctx context.Context) {
	if g := guardP.Load(); g != nil && !g.remote && (g.since.Load() > 0 || g.due.Load()) {
		_ = g.check(ctx)
	}
}

// tick counts a request about to be sent and, when a check is due, makes
// it. It returns the error that refuses the request.
func (g *sessionGuard) tick(ctx context.Context) error {
	if g.remote || g.renewing.Load() {
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

// page is the check page and its answer with the session; a probe may set
// it after the run began.
func (g *sessionGuard) page() (string, Print) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.s.Check, g.s.Want
}

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
	if page, want := g.page(); page != "" {
		p, err := askPrint(ctx, page, true)
		if err != nil {
			return nil // not answered: nothing is judged from it
		}
		if p == want {
			g.mu.Lock()
			g.asked, g.endedBy = nil, ""
			g.mu.Unlock()
			g.good.Add(1)
			return nil
		}
		got = p
	} else if endedBy == "" {
		return g.verify(ctx, int(sent))
	}
	return g.lose(ctx, got, endedBy, int(sent))
}

// lose handles a session that failed its check.
func (g *sessionGuard) lose(ctx context.Context, got Print, endedBy string, sent int) error {
	g.mu.Lock()
	n := len(g.asked)
	g.mu.Unlock()
	unrecorded := max(0, sent-n)
	page, want := g.page()
	how := "the check " + pathOf(page) + " answered " + describe(got) + ", where it answered " + describe(want) + " with the session"
	if page == "" {
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
	if err := g.renew(ctx); err != nil {
		return fail("signing in again failed: " + err.Error())
	}
	if p, err := askPrint(ctx, page, true); page != "" && (err != nil || p != want) {
		return fail("signed in again, but the check still answers " + describe(p))
	}
	g.resume(ctx, what, endedBy, unrecorded)
	return nil
}

// renew signs in again; its own requests pass the guard.
func (g *sessionGuard) renew(ctx context.Context) error {
	g.renewing.Store(true)
	defer g.renewing.Store(false)
	return g.s.Renew(ctx)
}

// resume asks again what was asked since the last good check, now that the
// session is back.
func (g *sessionGuard) resume(ctx context.Context, what, endedBy string, unrecorded int) {
	g.mu.Lock()
	second := g.renewals >= 2
	asked := slices.Clone(g.asked)
	g.mu.Unlock()
	// A request that ends the session every time it is sent would end the
	// new one too. The first loss cannot tell which it was; one that follows
	// a renewal can: the requests asked since are searched.
	var enders []string
	if second {
		enders = g.findEnders(ctx, asked)
	}
	g.mu.Lock()
	// The request whose answer cleared the session is not asked again: its
	// answer, to a live session, is the one it gives. Nor is one found to end it.
	redo := slices.DeleteFunc(g.asked, func(u string) bool { return u == endedBy || g.enders[u] })
	g.asked, g.endedBy = nil, ""
	g.redo = append(g.redo, redo...)
	if from := g.good.Add(1) - 1; !g.stretchN || from < g.stretch {
		g.stretch, g.stretchN = from, true
	}
	g.mu.Unlock()
	for _, u := range redo {
		evict(u)
	}
	g.gen.Add(1)
	msg := what + "; signed in again; " + plural(len(redo), "request") + " asked again"
	if len(enders) > 0 {
		paths := make([]string, len(enders))
		for i, u := range enders {
			paths[i] = pathOf(u)
		}
		msg += "; " + strings.Join(paths, ", ") + " ended the new session when asked again and is not asked again"
	}
	if unrecorded > 0 {
		msg += fmt.Sprintf(" (%s sent in the same stretch by sweeps and page tasks: those run again)", plural(unrecorded, "request"))
	}
	Note(msg)
}

// verify tests the answers that looked like the end of the session when no
// check page tells: it signs in again and asks them once more. One that now
// answers differently was the session ending, and becomes the check page;
// answers alike were the page's own, whatever the session.
func (g *sessionGuard) verify(ctx context.Context, sent int) error {
	g.mu.Lock()
	sus := g.suspects
	g.suspects = nil
	if g.s.Renew == nil || g.verifies >= maxVerifies || len(sus) == 0 {
		g.mu.Unlock()
		return nil
	}
	g.verifies++
	if len(sus) > 6 {
		sus = sus[len(sus)-6:] // the latest are the likeliest to follow the end
	}
	g.mu.Unlock()
	if g.renew(ctx) != nil {
		return nil // nothing is judged from a sign-in that failed
	}
	for _, sp := range sus {
		p, err := askPrint(ctx, sp.url, true)
		if err != nil {
			continue
		}
		if p == sp.was {
			g.mu.Lock()
			g.proven[sp.url] = true
			g.mu.Unlock()
			continue
		}
		g.mu.Lock()
		g.s.Check, g.s.Want = sp.url, p
		g.renewals++
		n := len(g.asked)
		g.mu.Unlock()
		what := fmt.Sprintf("the session ended (%s answered %s with the session, and %s once signed in again)", pathOf(sp.url), describe(sp.was), describe(p))
		g.resume(ctx, what, "", max(0, sent-n))
		return nil
	}
	return nil
}

// findEnders asks urls, which were sent since the session was last renewed,
// with the new session, checking it after every request (after every few
// when there are many, then one by one in the chunk that failed). A request
// after which the check fails ends the session: it is kept (enders), the run
// signs in again and goes on, and it is returned. The session is live on
// return unless signing in again failed or was needed more than maxEnders times.
func (g *sessionGuard) findEnders(ctx context.Context, urls []string) []string {
	page, want := g.page()
	if page == "" {
		return nil
	}
	urls = slices.DeleteFunc(slices.Compact(slices.Clone(urls)), func(u string) bool { return u == page })
	var found []string
	signIns := 0
	live := func() bool {
		p, err := askPrint(ctx, page, true)
		return err != nil || p == want
	}
	restore := func() bool {
		signIns++
		return signIns <= maxEnders && g.renew(ctx) == nil
	}
	send := func(us []string) {
		for _, u := range us {
			if ctx.Err() != nil {
				return
			}
			_, _ = askPrint(ctx, u, true)
		}
	}
	chunk := max(1, len(urls)/32)
	for i := 0; i < len(urls) && ctx.Err() == nil; i += chunk {
		part := urls[i:min(i+chunk, len(urls))]
		send(part)
		if live() {
			continue
		}
		if !restore() {
			return found
		}
		if len(part) > 1 { // one by one, now that the chunk is known to hold one
			for _, u := range part {
				send([]string{u})
				if live() {
					continue
				}
				found = append(found, u)
				if !restore() {
					break
				}
			}
		} else {
			found = append(found, part[0])
		}
	}
	g.mu.Lock()
	if g.enders == nil {
		g.enders = map[string]bool{}
	}
	for _, u := range found {
		g.enders[u] = true
	}
	g.mu.Unlock()
	return found
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
func sessionSaw(ctx context.Context, raw string, res Result) {
	g := guardP.Load()
	if g == nil {
		return
	}
	defer g.probe(ctx, raw, res)
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
		g.notify(raw)
		return
	}
	if res.Status == http.StatusUnauthorized || g.s.SignIn != "" && slices.ContainsFunc(res.Hops, func(h Hop) bool {
		return h.Location != "" && pathOf(h.Location) == pathOf(g.s.SignIn)
	}) {
		g.due.Store(true)
		g.suspect(raw, res)
		g.notify("")
	}
}

// probe looks for the check page when the start found none: a page that
// the run starts from answers alike with and without a session, an API
// route it finds later (/api/me) often does not. A JSON answer of 200 is
// measured with the session and without it, up to maxProbes times.
func (g *sessionGuard) probe(ctx context.Context, raw string, res Result) {
	if g.remote || res.Status != http.StatusOK || len(res.Hops) > 1 || len(res.Header["Set-Cookie"]) > 0 ||
		!strings.Contains(strings.ToLower(res.Header.Get("Content-Type")), "json") {
		return
	}
	if page, _ := g.page(); page != "" || g.renewing.Load() || g.checking.Load() || !g.probing.CompareAndSwap(false, true) {
		return
	}
	defer g.probing.Store(false)
	g.mu.Lock()
	if g.probes >= maxProbes || g.lost != nil {
		g.mu.Unlock()
		return
	}
	g.probes++
	g.mu.Unlock()
	with, without, err := Measure(ctx, raw)
	if err != nil || with == without || with.Status == 0 {
		return
	}
	g.mu.Lock()
	if g.s.Check == "" {
		g.s.Check, g.s.Want = raw, with
	}
	g.mu.Unlock()
}

// suspect keeps an answer that looked like the end of the session, to be
// tested when there is no check page.
func (g *sessionGuard) suspect(raw string, res Result) {
	if g.remote {
		return
	}
	p := Print{Status: res.Status}
	if len(res.Hops) > 0 {
		if loc, err := url.Parse(res.Hops[0].Location); err == nil {
			p.Loc = loc.Path
		}
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.s.Check != "" || g.proven[raw] || len(g.suspects) >= 64 || slices.ContainsFunc(g.suspects, func(s suspect) bool { return s.url == raw }) {
		return
	}
	g.suspects = append(g.suspects, suspect{raw, p})
}

// notify tells the run, from a worker, that an answer looked like the end
// of the session.
func (g *sessionGuard) notify(endedBy string) {
	if g.tell != nil && !g.told.Swap(true) {
		go g.tell(SessionReport{Due: true, EndedBy: endedBy})
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
