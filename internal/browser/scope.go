package browser

import (
	"context"
	"net/url"
	"sort"
	"strings"

	"github.com/chromedp/cdproto/cdp"
	cdpfetch "github.com/chromedp/cdproto/fetch"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"

	"github.com/trannghiach/azhaq/internal/fetch"
)

// Chrome is held to where plain HTTP may go: every request a page, a frame
// or a worker sends is paused (the Fetch domain, for the whole browser) and
// sent only when its host is in the run's scope (fetch.Allow) or, without
// one, in the site (fetch.Site) of a page Chrome was pointed at. The rest
// fail before they leave the machine. What connects without a request the
// Fetch domain sees (WebSockets, preconnects, Chrome's own services) is
// refused by the guard.

const (
	maxListed = 100  // refused URLs a run lists; the rest are counted
	maxHeld   = 4096 // refusals waiting for their tab to claim them
)

// refusal is a request Chrome was not let send.
type refusal struct {
	url    string // without its query: a third party's query carries the page's data
	host   string
	frame  cdp.FrameID
	doc    bool // a page's or a frame's document: a navigation
	sends  bool // a script's request with a body (a login's call)
	budget bool // refused for the request budget, not for where it went
}

// Reason is what a run lists Chrome's refused requests under.
func Reason() string {
	if fetch.Allow == nil {
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

func (b *Browser) allowedHost(host string) bool {
	if host == "" {
		return false
	}
	if allow := fetch.Allow; allow != nil {
		return allow(host)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.sites[fetch.Site(host)]
}

// intercept pauses every request of the browser and sends on what may go.
// It subscribes before enabling, so no request is paused unanswered.
func (b *Browser) intercept(root context.Context) error {
	events := chromedp.BrowserEvents(root, cdpfetch.RequestPaused)
	if _, err := chromedp.CallBrowser(root, cdpfetch.Enable, cdpfetch.EnableParams{
		Patterns: []*cdpfetch.RequestPattern{{URLPattern: "*", RequestStage: cdpfetch.RequestStageRequest}},
	}); err != nil {
		return err
	}
	go func() {
		for ev, err := range events {
			if err != nil {
				return
			}
			go b.decide(root, ev)
		}
	}()
	return nil
}

func (b *Browser) decide(root context.Context, ev cdpfetch.EventRequestPaused) {
	r := refusal{frame: ev.FrameID, doc: ev.ResourceType == network.ResourceTypeDocument}
	raw := ""
	if ev.Request != nil {
		raw = ev.Request.URL
		switch ev.Request.Method {
		case "GET", "HEAD", "OPTIONS":
		default:
			r.sends = ev.ResourceType == network.ResourceTypeXHR || ev.ResourceType == network.ResourceTypeFetch
		}
	}
	switch {
	case !b.allowed(raw):
		r.url, r.host = listable(raw)
	case r.doc && b.paidFor(ev.FrameID):
		r = refusal{} // the page itself: its caller counted it (fetch.Spend)
	case fetch.Take() != nil:
		r.url, r.host, r.budget = raw, hostOf(raw), true
	default:
		r = refusal{}
	}
	if r.url == "" {
		_, _ = chromedp.CallBrowser(root, cdpfetch.ContinueRequest, cdpfetch.ContinueRequestParams{RequestID: ev.RequestID})
		return
	}
	b.refuse(r)
	_, _ = chromedp.CallBrowser(root, cdpfetch.FailRequest, cdpfetch.FailRequestParams{RequestID: ev.RequestID, ErrorReason: network.ErrorReasonBlockedByClient})
}

// sockets watches the WebSockets a tab opens, whose handshakes the Fetch
// domain does not pause: one outside the scope (which the guard refuses)
// is the tab's refusal; one where it may go counts as a request, which the
// budget cannot refuse.
func (b *Browser) sockets(tab context.Context, main cdp.FrameID) {
	events := chromedp.Events(tab, network.WebSocketCreated)
	go func() {
		for ev, err := range events {
			if err != nil {
				return
			}
			if !b.allowed(ev.URL) {
				r := refusal{frame: main}
				r.url, r.host = listable(ev.URL)
				b.refuse(r)
			} else if fetch.Take() != nil {
				fetch.Count(1)
			}
		}
	}()
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

func (b *Browser) refuse(r refusal) {
	b.refMu.Lock()
	defer b.refMu.Unlock()
	if !r.budget {
		b.refused++
	}
	if b.held == nil {
		b.held = map[refusal]bool{}
	}
	if len(b.held) < maxHeld {
		b.held[r] = true
	}
}

// claim takes the refusals of a tab's frames.
func (b *Browser) claim(frames map[cdp.FrameID]bool) []refusal {
	b.refMu.Lock()
	defer b.refMu.Unlock()
	var out []refusal
	for r := range b.held {
		if frames == nil || frames[r.frame] {
			out = append(out, r)
			delete(b.held, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].url < out[j].url })
	return out
}

// list is the URLs of rs a run lists: the first maxListed of the run.
func (b *Browser) list(rs []refusal) []string {
	b.refMu.Lock()
	defer b.refMu.Unlock()
	var out []string
	for _, r := range rs {
		if r.budget || r.url == "" || b.listed[r.url] {
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

// Leftover is the refused URLs no page claimed, to list: a service
// worker's requests, requests sent after a page was read.
func (b *Browser) Leftover() []string { return b.list(b.claim(nil)) }

// Refused is how many requests Chrome was not let send for where they
// went, how many URLs the run lists, and whether others went unlisted.
func (b *Browser) Refused() (requests, listed int, more bool) {
	b.refMu.Lock()
	defer b.refMu.Unlock()
	return b.refused, len(b.listed), b.unlisted
}
