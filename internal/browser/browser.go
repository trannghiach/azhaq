// Package browser drives a Chrome already installed on the machine
// (headless, through the DevTools protocol): screenshots, and pages whose
// content only exists once their scripts run. Nothing is downloaded
// (downloads.go), and Chrome reaches only what the run may (scope.go).
package browser

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"

	"github.com/trannghiach/azhaq/internal/fetch"
	"github.com/trannghiach/azhaq/internal/webextract"
)

// ErrNoChrome means no Chrome or Chromium was found.
var ErrNoChrome = errors.New("no Chrome or Chromium found (install one, or set AZHAQ_CHROME to its path)")

// ErrNoSandbox means the system refused Chrome its sandbox.
var ErrNoSandbox = errors.New("Chrome could not start its sandbox (set AZHAQ_CHROME_NO_SANDBOX=1 to run it without one, knowing the pages are untrusted)")

// Start launches Chrome now rather than on the first page, so a run can
// report a Chrome that cannot start before it begins.
func (b *Browser) Start() error { return b.start() }

// Find returns the path of an installed Chrome or Chromium.
func Find() (string, error) {
	if p := os.Getenv("AZHAQ_CHROME"); p != "" {
		return p, nil
	}
	for _, name := range []string{"google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "chrome",
		"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", `C:\Program Files\Google\Chrome\Application\chrome.exe`} {
		if p, err := exec.LookPath(name); err == nil {
			return p, nil
		}
	}
	return "", ErrNoChrome
}

// Browser is one headless Chrome shared by a run.
type Browser struct {
	Width, Height int
	Tabs          int           // pages open at once; default 4
	Timeout       time.Duration // per page; default 30 s
	UserAgent     string
	Header        map[string]any // added to every request (-cookie, -header)
	// Writes lets pages and their scripts send what they send besides
	// GET, HEAD and OPTIONS, as a user's browser would (-browser-writes):
	// it changes data on the target. Otherwise only the sign-in does.
	Writes bool
	// Interact is how many clicks a loaded page gets (-interact): its
	// buttons, links and menus, to find what only a click brings. It
	// sends nothing a load does not (see interact.go).
	Interact int

	once   sync.Once
	err    error
	alloc  context.Context
	cancel context.CancelFunc
	root   context.Context
	sem    chan struct{}

	guard *guard
	lost  atomic.Bool // Chrome's paused requests are no longer heard of

	closeMu sync.Mutex
	closing bool
	working sync.WaitGroup // requests being decided

	sendMu sync.Mutex
	out    map[network.RequestID]letGo // let send, not yet seen leaving
	cached map[network.RequestID]letGo // let send, answered from Chrome's cache

	mu      sync.Mutex
	session map[string]string    // sessionStorage a login left, for every tab
	sites   map[string]bool      // without a scope: the sites of the pages Chrome was pointed at
	allow   func(string) bool    // the run's scope when Chrome started (fetch.Allow), or nil
	paid    map[cdp.FrameID]bool // tabs whose page their caller counted

	refMu    sync.Mutex
	tabs     map[cdp.FrameID]*tab // open pages, by each frame they are known to have
	gone     map[cdp.FrameID]bool // frames of pages already read
	popups   map[cdp.FrameID]bool // windows pages opened, closed as they open
	held     map[refusal]bool     // refused for no open page, to list at the end
	heldW    []heldWrite          // writes of no open page
	listed   map[string]bool      // refused URLs handed out to be listed
	refused  int                  // requests refused for where they went
	unlisted bool                 // more URLs were refused than are listed
}

func (b *Browser) start() error {
	b.once.Do(func() {
		path, err := Find()
		if err != nil {
			b.err = err
			return
		}
		if b.Width == 0 {
			b.Width, b.Height = 1440, 900
		}
		if b.Tabs <= 0 {
			b.Tabs = 4
		}
		if b.Timeout <= 0 {
			b.Timeout = 30 * time.Second
		}
		b.sem = make(chan struct{}, b.Tabs)
		// The scope this Chrome is held to, as the run set it when Chrome
		// started: a later fetch.Reset (a run ending, a test) does not move
		// it under requests still being decided.
		b.allow = fetch.Allow
		if b.guard, err = newGuard(b.allowedHost); err != nil {
			b.err = fmt.Errorf("starting Chrome: %w", err)
			return
		}
		opts := append(chromedp.DefaultExecAllocatorOptions[:],
			chromedp.ExecPath(path),
			chromedp.WindowSize(b.Width, b.Height),
			chromedp.Flag("ignore-certificate-errors", true),
			chromedp.Flag("disable-extensions", true),
			chromedp.Flag("mute-audio", true),
			// Every connection, loopback ones too, through the guard; and
			// no WebRTC packet outside it.
			chromedp.ProxyServer("socks5://"+b.guard.addr()),
			chromedp.Flag("proxy-bypass-list", "<-loopback>"),
			chromedp.Flag("webrtc-ip-handling-policy", "disable_non_proxied_udp"),
		)
		// The sandbox stays on: the pages are the targets'. Where the system
		// refuses it (AppArmor on recent Ubuntu, some containers), the user
		// may turn it off knowingly.
		if os.Getenv("AZHAQ_CHROME_NO_SANDBOX") == "1" {
			opts = append(opts, chromedp.NoSandbox)
		}
		if b.UserAgent != "" {
			opts = append(opts, chromedp.UserAgent(b.UserAgent))
		}
		b.alloc, b.cancel = chromedp.NewExecAllocator(context.Background(), opts...)
		// The guard lives as long as this Chrome, and relays for it alone.
		context.AfterFunc(b.alloc, b.guard.close)
		root, _ := chromedp.NewContext(b.alloc)
		if err := chromedp.Do(root); err != nil {
			b.err = fmt.Errorf("starting Chrome: %w", err)
			if strings.Contains(err.Error(), "sandbox") {
				b.err = fmt.Errorf("%w: %v", ErrNoSandbox, err)
			}
			b.cancel()
			return
		}
		if p := chromedp.FromContext(root).Browser.Process(); p != nil {
			b.guard.chrome(p.Pid)
		}
		// No page opens before every request is held to the scope, and
		// every download refused.
		if err := b.intercept(root); err != nil {
			b.err = fmt.Errorf("starting Chrome: holding its requests to the scope: %w", err)
			b.cancel()
			return
		}
		if err := b.denyDownloads(root); err != nil {
			b.err = fmt.Errorf("starting Chrome: refusing its downloads: %w", err)
			b.cancel()
			return
		}
		b.root = root
	})
	return b.err
}

// Close stops Chrome, and waits for what was handling its requests.
func (b *Browser) Close() {
	b.closeMu.Lock()
	b.closing = true
	b.closeMu.Unlock()
	if b.cancel != nil {
		b.cancel()
	}
	if b.guard != nil {
		b.guard.close()
	}
	b.working.Wait()
	b.unheard(nil)
}

// Page is what loading a URL gave.
type Page struct {
	URL         string // after redirects
	Title       string
	PNG         []byte
	HTML        string
	Asked       int         // how many requests the page made, images, fonts and media included: what its budget has to cover
	Requests    []string    // every URL the page asked for with GET, HEAD or OPTIONS while loading, sent or not; without its images, fonts and media
	Blocked     []string    // URLs it asked for outside the scope, to list (Reason); not sent
	Downloads   []string    // what it would have saved to disk, to list (DownloadReason); refused
	Writes      []Write     // what else it sent in the scope, or was refused (WriteReason) without Browser.Writes
	Left        string      // the page went there, outside the scope, and was stopped: what shows is Chrome's error
	Interaction Interaction // what clicking it found, with Browser.Interact
	Capped      bool        // the request budget refused some of its requests; what it was refused is then in Leftover and LeftoverWrites, not Blocked and Writes
}

// sessionScript restores the login's sessionStorage in a new tab before
// the page's own scripts run, or is "".
func (b *Browser) sessionScript() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.session) == 0 {
		return ""
	}
	raw, _ := json.Marshal(b.session)
	return `(() => { try { const s = ` + string(raw) + `; for (const k in s) if (sessionStorage.getItem(k) === null) sessionStorage.setItem(k, s[k]); } catch (e) {} })()`
}

// Load opens rawURL in a new tab, waits for the network to settle, and
// returns the page; shot adds a screenshot of the viewport, and has the
// page's images, fonts and media fetched, which a page read for its
// requests and its document does without. The caller has counted the
// page itself against the budget (fetch.Spend); every other request
// Chrome sends for it is counted here.
func (b *Browser) Load(ctx context.Context, rawURL string, shot bool) (Page, error) {
	if err := b.start(); err != nil {
		return Page{}, err
	}
	b.visit(rawURL)
	select {
	case b.sem <- struct{}{}:
	case <-ctx.Done():
		return Page{}, ctx.Err()
	}
	defer func() { <-b.sem }()
	if b.lost.Load() {
		return Page{}, errLost
	}
	watched := func() {}
	defer func() { watched() }() // once the tab is closed
	tab, cancel := chromedp.NewContext(b.root)
	defer cancel()
	tab, cancelT := context.WithTimeout(tab, b.Timeout+time.Duration(b.Interact)*2*time.Second)
	defer cancelT()
	stop := context.AfterFunc(ctx, cancelT)
	defer stop()
	var p Page
	if err := chromedp.Do(tab); err != nil { // opens the tab
		return p, err
	}

	// The page's requests, from the moment the tab opens, and the frames
	// they came from: what Chrome refuses those is this page's.
	main := cdp.FrameID(chromedp.FromContext(tab).Target.TargetID)
	t := b.open(tab, main, false, !shot)
	defer func() { // a page not read: its refusals listed with none
		b.leave(b.claim(t))
		b.leaveWrites(b.writesOf(t))
	}()
	var mu sync.Mutex
	var reqs []string
	var asked int
	watched = b.watch(tab, t, func(ev *network.EventRequestWillBeSent) {
		if ev.Request != nil && reads(ev.Request.Method) {
			mu.Lock()
			asked++
			mu.Unlock()
		}
		if ev.Request == nil || !reads(ev.Request.Method) || decoration(ev.Type) {
			return // a write: the request paused says more of it (Writes); a decoration names no route
		}
		mu.Lock()
		reqs = append(reqs, ev.Request.URL)
		mu.Unlock()
	})
	if _, err := chromedp.Call(tab, network.Enable, network.EnableParams{}); err != nil {
		return p, err
	}
	b.prepay(main, true)
	defer b.prepay(main, false)
	if len(b.Header) > 0 {
		if _, err := chromedp.Call(tab, network.SetExtraHTTPHeaders, network.SetExtraHTTPHeadersParams{Headers: network.Headers(b.Header)}); err != nil {
			return p, err
		}
	}
	if js := b.sessionScript(); js != "" {
		if _, err := chromedp.Call(tab, page.AddScriptToEvaluateOnNewDocument, page.AddScriptToEvaluateOnNewDocumentParams{Source: js}); err != nil {
			return p, err
		}
	}
	// A page whose load event never fires (a stalled tracker, a long poll)
	// is still captured as far as it got.
	nav, cancelNav := context.WithTimeout(tab, min(b.Timeout/2, 15*time.Second))
	err := chromedp.Do(nav, chromedp.Navigate(rawURL))
	cancelNav()
	if errors.Is(err, context.DeadlineExceeded) && tab.Err() == nil {
		err = nil
	}
	if err == nil {
		err = chromedp.Do(tab, chromedp.Sleep(1500*time.Millisecond)) // scripts that render after load
	}
	if err == nil {
		p.URL, _ = chromedp.Run(tab, chromedp.Location())
		p.Title, _ = chromedp.Run(tab, chromedp.Title())
		p.HTML, _ = chromedp.Run(tab, chromedp.OuterHTML(chromedp.CSS("html")))
		if shot {
			p.PNG, err = chromedp.Run(tab, chromedp.CaptureScreenshot())
		}
	}
	if err == nil && b.Interact > 0 {
		p.Interaction = b.interact(tab, p.URL, b.Interact, webextract.StateChanging)
	}
	b.settle(t)
	mu.Lock()
	p.Requests = append([]string(nil), reqs...)
	p.Asked = asked
	mu.Unlock()
	mine := b.claim(t)
	writes := b.writesOf(t)
	for _, r := range mine {
		p.Capped = p.Capped || r.budget
		if r.frame == main && r.doc && !r.budget && p.Left == "" {
			p.Left = r.url
		}
	}
	if p.Capped {
		// Its caller drops what a capped page gave, to load it again after
		// azhaq resume: the run lists its refusals.
		b.leave(mine)
		b.leaveWrites(writes)
	} else {
		p.Blocked = b.list(mine)
		p.Downloads = b.downloads(mine)
		p.Writes = writes
	}
	return p, err
}

var errLost = errors.New("Chrome no longer reports the requests it holds: its pages are not loaded")
