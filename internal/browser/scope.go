package browser

import (
	"context"
	"net/url"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/cdp/jsonv2"
	cdpfetch "github.com/chromedp/cdproto/fetch"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/cdproto/target"
	"github.com/chromedp/chromedp"

	"github.com/trannghiach/azhaq/internal/egress"
	"github.com/trannghiach/azhaq/internal/fetch"
	"github.com/trannghiach/azhaq/internal/ledger"
	"github.com/trannghiach/azhaq/internal/webextract"
)

// Chrome is held to where plain HTTP may go: every request a page, a frame
// or a worker sends is paused (the Fetch domain, for the whole browser) and
// sent only when its host is in the run's scope (the egress scope) or, without
// one, in the site (fetch.Site) of a page Chrome was pointed at, paced and
// counted as the run's own requests are. The rest fail before they leave
// the machine. What connects without a request the Fetch domain sees
// (WebSockets, preconnects, Chrome's own services) is refused by the guard.
// A window a page opens is closed as it opens: it would outlive its page.
// Only GET, HEAD and OPTIONS are sent, outside the sign-in (writes.go).

const (
	maxListed = 100     // refused URLs a run lists; the rest are counted
	maxHeld   = 4096    // refusals kept for one page, and for no open page
	maxGone   = 1 << 14 // frames of pages already read, whose late refusals are counted only
)

// refusal is a request Chrome was not let send.
type refusal struct {
	url    string // without its query: a third party's query carries the page's data
	host   string
	frame  cdp.FrameID
	doc    bool // a page's or a frame's document: a navigation
	sends  bool // a script's request with a body (a login's call)
	budget bool // refused for the request budget, not for where it went

	download bool   // refused for being a download, not for where it went (downloads.go)
	name     string // what Chrome would have saved it as
}

// tab is an open page's share of what Chrome refuses, by the frames it is
// known to have, until the page is read. Where the page went out of the
// scope, and whether the budget refused it anything, are kept whatever
// else it was refused.
type tab struct {
	main    cdp.FrameID     // its target's id, which is its main frame's
	ctx     context.Context // ends with the tab: its requests stop waiting for the pace
	frames  []cdp.FrameID
	rs      map[refusal]bool
	left    *refusal // the first navigation of its main frame refused
	capped  bool
	pending int  // requests of its frames being decided
	read    bool // claimed: what comes later is counted only
	signin  bool // the sign-in's: its writes are sent, and not kept
	lean    bool // read, not shot: its images, fonts and media are not fetched
	writes  []Write
	prog    *progress // when the page last moved (with a pace), or nil
	log     *pageLog  // what Chrome saw of the page, or nil
}

// decoration: a request that draws the page and names no route: an
// image, a font, a sound or a video. A page read for its requests and
// its document does without them; a screenshot needs them.
func decoration(rt network.ResourceType) bool {
	switch rt {
	case network.ResourceTypeImage, network.ResourceTypeFont, network.ResourceTypeMedia:
		return true
	}
	return false
}

// chatter: a request every tab repeats that names no route of its own:
// socket.io's polling (its socket is a row of the map already, from the
// script that opens it) and the tab's icon.
func chatter(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	return webextract.SocketPath(u.Path) || strings.HasSuffix(strings.ToLower(u.Path), "/favicon.ico")
}

// icon: the tab's icon, which no screenshot shows.
func icon(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && strings.HasSuffix(strings.ToLower(u.Path), "/favicon.ico")
}

func (t *tab) add(r refusal) {
	if r.budget {
		t.capped = true
		return
	}
	if r.doc && r.frame == t.main && t.left == nil {
		t.left = &r
	}
	if len(t.rs) < maxHeld {
		t.rs[r] = true
	}
}

// Reason is what a run lists Chrome's refused requests under.
func Reason() string {
	if !egress.HasScope() {
		return "outside the site (Chrome)"
	}
	return "outside the scope (Chrome)"
}

// visit adds the site of rawURL to those Chrome may reach without a scope.
func (b *Browser) visit(rawURL string) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Hostname() == "" {
		return
	}
	b.mu.Lock()
	if b.sites == nil {
		b.sites = map[string]bool{}
	}
	b.sites[fetch.Site(u.Hostname())] = true
	b.mu.Unlock()
}

// allowed says whether Chrome may request raw.
func (b *Browser) allowed(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	switch u.Scheme {
	case "http", "https", "ws", "wss":
		return b.allowedHost(u.Hostname())
	}
	return true // data:, blob:, about:, chrome: nothing leaves the machine
}

// local reports whether raw is served by Chrome itself (chrome-extension:,
// chrome:, data:, blob:, about:, file: ...): only http, https, ws, wss and
// ftp URLs go to a host.
func local(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" {
		return false
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https", "ws", "wss", "ftp":
		return false
	}
	return true
}

func (b *Browser) allowedHost(host string) bool {
	if host == "" {
		return false
	}
	if b.allow != nil {
		return b.allow(host)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.sites[fetch.Site(host)]
}

// intercept pauses every request of the browser and sends on what may go,
// and closes every window a page opens. It subscribes before enabling, so
// no request is paused unanswered. The events are read raw: one that does
// not decode is skipped, not the end of the loop, as Chrome would then
// hold every later request for ever.
func (b *Browser) intercept(root context.Context) error {
	br := chromedp.FromContext(root).Browser
	opened, stopOpened := br.Subscribe(target.TargetCreated.Method)
	context.AfterFunc(root, stopOpened)
	go func() {
		defer stopOpened()
		for raw := range opened {
			var ev target.EventTargetCreated
			if jsonv2.Unmarshal(raw, &ev) != nil || ev.TargetInfo == nil || ev.TargetInfo.OpenerID == "" || ev.TargetInfo.Type != "page" {
				continue
			}
			// Unpaced, uncounted and claimed by no page, it would keep
			// sending requests for the rest of the run.
			b.popup(cdp.FrameID(ev.TargetInfo.TargetID))
			go func() {
				_, _ = chromedp.CallBrowser(root, target.CloseTarget, target.CloseTargetParams{TargetID: ev.TargetInfo.TargetID})
			}()
		}
	}()

	paused, stop := br.Subscribe(cdpfetch.RequestPaused.Method)
	context.AfterFunc(root, stop)
	if _, err := chromedp.CallBrowser(root, cdpfetch.Enable, cdpfetch.EnableParams{
		Patterns: []*cdpfetch.RequestPattern{{URLPattern: "*", RequestStage: cdpfetch.RequestStageRequest}},
	}); err != nil {
		stop()
		return err
	}
	go func() {
		defer stop()
		b.answer(root, paused)
	}()
	return nil
}

// answer decides each paused request of the browser, until Chrome goes.
func (b *Browser) answer(root context.Context, paused <-chan jsonv2.Value) {
	for raw := range paused {
		var ev cdpfetch.EventRequestPaused
		if err := jsonv2.Unmarshal(raw, &ev); err != nil {
			var id struct {
				RequestID cdpfetch.RequestID `json:"requestId"`
			}
			if jsonv2.Unmarshal(raw, &id) == nil && id.RequestID != "" {
				b.busy(func() { b.fail(root, id.RequestID) })
			}
			continue
		}
		t := b.begin(ev.FrameID)
		if !b.busy(func() { b.decide(root, ev, t) }) {
			b.done(t)
		}
	}
	// Chrome is gone, or no longer tells which requests it holds: no page
	// is loaded without them held to the scope.
	b.lost.Store(true)
}

// busy runs f on its own unless Chrome is being closed; Close waits for it.
func (b *Browser) busy(f func()) bool {
	b.closeMu.Lock()
	defer b.closeMu.Unlock()
	if b.closing {
		return false
	}
	b.working.Add(1)
	go func() {
		defer b.working.Done()
		f()
	}()
	return true
}

func (b *Browser) fail(root context.Context, id cdpfetch.RequestID) {
	_, _ = chromedp.CallBrowser(root, cdpfetch.FailRequest, cdpfetch.FailRequestParams{RequestID: id, ErrorReason: network.ErrorReasonBlockedByClient})
}

// decide sends on or fails a paused request; t is the open page its frame
// was known to be of when it was paused, or nil.
func (b *Browser) decide(root context.Context, ev cdpfetch.EventRequestPaused, t *tab) {
	if ev.Request != nil && local(ev.Request.URL) {
		// Chrome's own pages (its PDF viewer loads chrome-extension: and
		// chrome: files) reach no target: not counted, not listed, not
		// refused.
		b.done(t)
		_, _ = chromedp.CallBrowser(root, cdpfetch.ContinueRequest, cdpfetch.ContinueRequestParams{RequestID: ev.RequestID})
		return
	}
	r := refusal{frame: ev.FrameID, doc: ev.ResourceType == network.ResourceTypeDocument}
	raw, write := "", false
	if ev.Request != nil {
		raw = ev.Request.URL
		if !reads(ev.Request.Method) {
			r.sends = ev.ResourceType == network.ResourceTypeXHR || ev.ResourceType == network.ResourceTypeFetch
			write = t == nil || !t.signin // the sign-in posts its form
		}
	}
	b.pausedAgain(ev.NetworkID, raw)
	refuse := true
	switch {
	case b.isPopup(ev.FrameID):
		b.done(t)
		b.fail(root, ev.RequestID) // a window a page opened, being closed
		return
	case raw != "" && egress.CheckDenied(raw) != nil:
		// The user's own -deny-path rule: never requested, and listed with
		// the rule by fetch (not as a refusal of the scope).
		b.done(t)
		b.fail(root, ev.RequestID)
		return
	case !b.allowed(raw):
		r.url, r.host = listable(raw) // an image on a third party's host is listed: its query may carry the page's data
	case t != nil && !write && (t.lean && (decoration(ev.ResourceType) || chatter(raw)) || !t.lean && icon(raw)):
		// Not sent, not counted, not listed: the page is read without
		// what only draws it, and without the socket's polling; a
		// screenshot is taken without the tab's icon, which it never shows.
		b.done(t)
		b.fail(root, ev.RequestID)
		return
	case write && (!b.Writes || ledger.Held(ev.Request.Method, raw)):
		// Not sent, nor counted: what it would have sent is mapped. A write
		// the run that was killed sent is not sent again.
		b.wrote(t, ev.FrameID, writeOf(ev.Request))
		b.done(t)
		if r.doc {
			// A form posted: stopped as a user stops it, the page stays
			// as it was. Blocked, Chrome would show its error instead,
			// to read and to screenshot as the page.
			_, _ = chromedp.CallBrowser(root, cdpfetch.FailRequest, cdpfetch.FailRequestParams{RequestID: ev.RequestID, ErrorReason: network.ErrorReasonAborted})
			return
		}
		b.fail(root, ev.RequestID)
		return
	case r.doc && b.paidFor(ev.FrameID):
		refuse = false // the page itself: its caller counted it (egress.SpendUnpaced); it waits for the pace as it is sent
	case egress.Take() != nil:
		r.budget = true
	default:
		refuse = false
	}
	if refuse {
		b.refuse(t, r)
		b.done(t)
		b.fail(root, ev.RequestID)
		return
	}
	if write {
		w := writeOf(ev.Request)
		w.Sent = true
		b.wrote(t, ev.FrameID, w)
	}
	b.done(t)
	{
		ctx := root
		if t != nil {
			ctx = t.ctx
		}
		if egress.Pace(ctx) != nil {
			egress.Refund() // never sent: the page closed while it waited
			b.fail(root, ev.RequestID)
			return
		}
	}
	if t != nil {
		t.prog.touch()
	}
	rctx := root
	if t != nil {
		rctx = t.ctx
	}
	b.sending(ev.NetworkID, letGo{ctx: rctx, method: ev.Request.Method, url: ev.Request.URL, at: time.Now(), t: t})
	_, _ = chromedp.CallBrowser(root, cdpfetch.ContinueRequest, cdpfetch.ContinueRequestParams{RequestID: ev.RequestID})
}

// watch follows the tab of ctx, t's page, until it closes, and returns a
// func that waits for that. The frames the page attaches, and those its
// requests come from (also sees each request), become the tab's, so that
// what Chrome refuses them is the page's. A WebSocket, whose handshake
// the Fetch domain does not pause, is the tab's refusal outside the scope
// (the guard refuses it); the guard counts the others, and refuses them
// once the budget is spent: the tab is then capped.
func (b *Browser) watch(ctx context.Context, t *tab, also func(*network.EventRequestWillBeSent)) (wait func()) {
	var wg sync.WaitGroup
	sent := chromedp.Events(ctx, network.RequestWillBeSent)
	wg.Go(func() {
		for ev, err := range sent {
			if err != nil {
				return
			}
			if also != nil {
				also(&ev)
			}
			if t.log != nil {
				t.log.requestSent(&ev)
			}
			b.addFrame(t, ev.FrameID)
		}
	})
	if t.log != nil {
		wg.Go(func() {
			for ev, err := range chromedp.Events(ctx, network.LoadingFinished) {
				if err != nil {
					return
				}
				t.log.finished(&ev)
			}
		})
		wg.Go(func() {
			for ev, err := range chromedp.Events(ctx, network.LoadingFailed) {
				if err != nil {
					return
				}
				t.log.failed(&ev)
			}
		})
		wg.Go(func() {
			for ev, err := range chromedp.Events(ctx, runtime.ConsoleAPICalled) {
				if err != nil {
					return
				}
				t.log.logged(&ev)
			}
		})
		wg.Go(func() {
			for ev, err := range chromedp.Events(ctx, runtime.ExceptionThrown) {
				if err != nil {
					return
				}
				t.log.thrown(&ev)
			}
		})
	}
	// A page that calls alert() on load would keep its tab until its time
	// is up: the dialog is accepted, as a visitor would, by a goroutine of
	// its own because the event loop must not wait on Chrome.
	wg.Go(func() {
		for _, err := range chromedp.Events(ctx, page.JavascriptDialogOpening) {
			if err != nil {
				return
			}
			go func() {
				_, _ = chromedp.Call(ctx, page.HandleJavaScriptDialog, page.HandleJavaScriptDialogParams{Accept: true})
			}()
		}
	})
	attached := chromedp.Events(ctx, page.FrameAttached)
	wg.Go(func() {
		for ev, err := range attached {
			if err != nil {
				return
			}
			b.addFrame(t, ev.FrameID)
		}
	})
	gone := chromedp.Events(ctx, network.RequestWillBeSentExtraInfo)
	wg.Go(func() {
		for ev, err := range gone {
			if err != nil {
				return
			}
			b.sentOff(ev.RequestID)
		}
	})
	hits := chromedp.Events(ctx, network.RequestServedFromCache)
	wg.Go(func() {
		for ev, err := range hits {
			if err != nil {
				return
			}
			b.fromCache(ev.RequestID)
		}
	})
	// A disk cache hit says so only in its response; requestServedFromCache
	// is for the memory cache.
	answered := chromedp.Events(ctx, network.ResponseReceived)
	wg.Go(func() {
		for ev, err := range answered {
			if err != nil {
				return
			}
			if t.log != nil {
				t.log.responded(&ev)
			}
			if r := ev.Response; r != nil && (r.FromDiskCache || r.FromPrefetchCache || r.FromServiceWorker) {
				b.fromCache(ev.RequestID)
			}
		}
	})
	sockets := chromedp.Events(ctx, network.WebSocketCreated)
	wg.Go(func() {
		for ev, err := range sockets {
			if err != nil {
				return
			}
			r := refusal{frame: t.main}
			switch {
			case !b.allowed(ev.URL):
				r.url, r.host = listable(ev.URL)
			case egress.Spent():
				r.budget = true
			default:
				continue
			}
			b.refuse(t, r)
		}
	})
	return func() {
		wg.Wait()
		b.unheard(t)
	}
}

// listable is raw as a refusal lists it: without its query and fragment.
func listable(raw string) (string, string) {
	u, err := url.Parse(raw)
	if err != nil {
		return raw, ""
	}
	u.RawQuery, u.ForceQuery, u.Fragment, u.RawFragment, u.User = "", false, "", "", nil
	return u.String(), strings.ToLower(u.Hostname())
}

func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

// paidFor takes the mark Load leaves on a tab whose page its caller
// counted: the first document request of that frame is not counted again.
func (b *Browser) paidFor(frame cdp.FrameID) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.paid[frame] {
		delete(b.paid, frame)
		return true
	}
	return false
}

func (b *Browser) prepay(frame cdp.FrameID, on bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !on {
		delete(b.paid, frame)
		return
	}
	if b.paid == nil {
		b.paid = map[cdp.FrameID]bool{}
	}
	b.paid[frame] = true
}

func (b *Browser) popup(id cdp.FrameID) {
	b.refMu.Lock()
	defer b.refMu.Unlock()
	if b.popups == nil || len(b.popups) >= maxGone {
		b.popups = map[cdp.FrameID]bool{}
	}
	b.popups[id] = true
}

func (b *Browser) isPopup(id cdp.FrameID) bool {
	b.refMu.Lock()
	defer b.refMu.Unlock()
	return b.popups[id]
}

// closePopups closes the windows the page of main opened that are still
// there. Chrome answers after every event it sent before.
func (b *Browser) closePopups(ctx context.Context, main cdp.FrameID) {
	res, err := chromedp.CallBrowser(ctx, target.GetTargets, target.GetTargetsParams{})
	if err != nil {
		return
	}
	for _, info := range res.TargetInfos {
		if info.Type == "page" && cdp.FrameID(info.OpenerID) == main {
			b.popup(cdp.FrameID(info.TargetID))
			_, _ = chromedp.CallBrowser(ctx, target.CloseTarget, target.CloseTargetParams{TargetID: info.TargetID})
		}
	}
}

// open makes main's page one whose refusals are kept for it; signin
// makes it the sign-in's, whose writes are sent; lean one read without
// its images, fonts and media.
func (b *Browser) open(ctx context.Context, main cdp.FrameID, signin, lean bool) *tab {
	return b.openTab(ctx, main, signin, lean, nil, nil)
}

// openTab is open for a page that is followed: its progress under a pace,
// and its record.
func (b *Browser) openTab(ctx context.Context, main cdp.FrameID, signin, lean bool, prog *progress, log *pageLog) *tab {
	t := &tab{main: main, ctx: ctx, rs: map[refusal]bool{}, signin: signin, lean: lean, prog: prog, log: log}
	b.addFrame(t, main)
	return t
}

// addFrame makes frame t's, with what was refused it before it was known.
func (b *Browser) addFrame(t *tab, frame cdp.FrameID) {
	if frame == "" {
		return
	}
	b.refMu.Lock()
	defer b.refMu.Unlock()
	if t.read || b.tabs[frame] == t {
		return
	}
	if b.tabs == nil {
		b.tabs = map[cdp.FrameID]*tab{}
	}
	b.tabs[frame] = t
	t.frames = append(t.frames, frame)
	for r := range b.held {
		if r.frame == frame {
			t.add(r)
			delete(b.held, r)
		}
	}
	if t.signin {
		return
	}
	b.heldW = slices.DeleteFunc(b.heldW, func(h heldWrite) bool {
		if h.frame == frame {
			t.addWrite(h.w)
		}
		return h.frame == frame
	})
}

// begin notes that a request of frame is being decided, and returns the
// open page the frame is of, if any.
func (b *Browser) begin(frame cdp.FrameID) *tab {
	b.refMu.Lock()
	defer b.refMu.Unlock()
	t := b.tabs[frame]
	if t != nil {
		t.pending++
	}
	return t
}

func (b *Browser) done(t *tab) {
	if t == nil {
		return
	}
	b.refMu.Lock()
	t.pending--
	b.refMu.Unlock()
}

// settle waits, briefly, for what Chrome paused of t's frames to be
// decided, so that a navigation out of the scope paused as the page was
// read is the page's (Left). Chrome's answer to a call comes after every
// event it sent before it; the events then reach decide within moments.
func (b *Browser) settle(t *tab) {
	ctx, cancel := context.WithTimeout(b.root, 2*time.Second)
	defer cancel()
	b.closePopups(ctx, t.main)
	for wait := 10 * time.Millisecond; ; wait = 5 * time.Millisecond {
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		b.refMu.Lock()
		n := t.pending
		b.refMu.Unlock()
		if n <= 0 {
			return
		}
	}
}

func (b *Browser) refuse(t *tab, r refusal) {
	b.refMu.Lock()
	defer b.refMu.Unlock()
	if !r.budget && !r.download {
		b.refused++
	}
	if t == nil {
		t = b.tabs[r.frame] // a frame its page made known meanwhile
	}
	switch {
	case t != nil && !t.read:
		t.add(r)
	case t != nil || b.gone[r.frame]:
		// Its page was read (a beacon sent as the tab closes): listed with
		// no page, a budget refusal counted only.
		if !r.budget {
			b.hold(refusal{url: r.url, host: r.host, download: r.download, name: r.name})
		}
	default:
		b.hold(r) // a worker's, or a frame no open page has made known yet
	}
}

// hold keeps a refusal no open page has; refMu is held. A budget refusal
// says only that its frame's page is capped.
func (b *Browser) hold(r refusal) {
	if r.budget {
		r = refusal{frame: r.frame, budget: true}
	}
	if b.held == nil {
		b.held = map[refusal]bool{}
	}
	if len(b.held) >= maxHeld && !b.held[r] {
		if !r.budget {
			b.unlisted = true
		}
		return
	}
	b.held[r] = true
}

// claim takes t's refusals, the first navigation of its main frame first,
// and makes later ones of its frames counted only.
func (b *Browser) claim(t *tab) []refusal {
	b.refMu.Lock()
	defer b.refMu.Unlock()
	if t.read {
		return nil
	}
	t.read = true
	if b.gone == nil || len(b.gone)+len(t.frames) > maxGone {
		b.gone = map[cdp.FrameID]bool{}
	}
	for _, f := range t.frames {
		delete(b.tabs, f)
		b.gone[f] = true
	}
	var out []refusal
	for r := range t.rs {
		if t.left == nil || r != *t.left {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].url < out[j].url })
	if t.left != nil {
		out = append([]refusal{*t.left}, out...)
	}
	if t.capped {
		out = append(out, refusal{frame: t.main, budget: true})
	}
	return out
}

// leave hands refusals no page will list to the run's leftovers.
func (b *Browser) leave(rs []refusal) {
	b.refMu.Lock()
	defer b.refMu.Unlock()
	for _, r := range rs {
		if !r.budget && r.url != "" {
			b.hold(refusal{url: r.url, host: r.host, download: r.download, name: r.name})
		}
	}
}

// list is the URLs of rs a run lists as refused for where they went: the
// first maxListed of the run. The downloads among them are listed apart
// (downloads).
func (b *Browser) list(rs []refusal) []string {
	b.refMu.Lock()
	defer b.refMu.Unlock()
	var out []string
	for _, r := range rs {
		if r.budget || r.download || r.url == "" || b.listed[r.url] {
			continue
		}
		if len(b.listed) >= maxListed {
			b.unlisted = true
			continue
		}
		if b.listed == nil {
			b.listed = map[string]bool{}
		}
		b.listed[r.url] = true
		out = append(out, r.url)
	}
	return out
}

// Leftover is the refused URLs no page listed: a service worker's
// requests, a beacon sent as a tab closed, a capped page's.
func (b *Browser) Leftover() []string {
	return b.list(b.takeHeld(false))
}

// takeHeld takes the refusals no page has that are downloads, or that are
// not, sorted by URL.
func (b *Browser) takeHeld(downloads bool) []refusal {
	b.refMu.Lock()
	var rs []refusal
	for r := range b.held {
		if r.download == downloads {
			rs = append(rs, r)
			delete(b.held, r)
		}
	}
	b.refMu.Unlock()
	sort.Slice(rs, func(i, j int) bool { return rs[i].url < rs[j].url })
	return rs
}

// Refused is how many requests Chrome was not let send for where they
// went, how many URLs the run lists, and whether others went unlisted.
func (b *Browser) Refused() (requests, listed int, more bool) {
	b.refMu.Lock()
	defer b.refMu.Unlock()
	return b.refused, len(b.listed), b.unlisted
}

// GuardDenied is how many connections Chrome itself opened to hosts outside
// the scope (a page's are refused earlier, as requests): its own services
// reaching out. All were refused; the hosts are sorted.
func (b *Browser) GuardDenied() (n int, hosts []string) {
	if b.guard == nil {
		return 0, nil
	}
	return b.guard.Denied()
}
