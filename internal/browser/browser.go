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
	"maps"
	"net/url"
	"os"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/runtime"
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

// chrome is the Chrome this browser runs.
func (b *Browser) chrome() (string, error) {
	if b.ChromePath != "" {
		return b.ChromePath, nil
	}
	return Find()
}

// restrictedPorts are the ports Chrome refuses to open by default
// (net::ERR_UNSAFE_PORT): ones whose protocols a page could be made to
// speak to. A target that serves HTTP on one is still a target.
const restrictedPorts = "1,7,9,11,13,15,17,19,20,21,22,23,25,37,42,43,53,69,77,79,87,95,101,102,103,104,109,110,111,113,115,117,119,123,135,137,139,143,161,179,389,427,465,512,513,514,515,526,530,531,532,540,548,554,556,563,587,601,636,989,990,993,995,1719,1720,1723,2049,3659,4045,4190,5060,5061,6000,6566,6665,6666,6667,6668,6669,6679,6697,10080"

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
	// What a screenshot is, and when it is taken.
	Format     string        // "png" (default) or "jpeg"
	Quality    int           // jpeg quality, 1 to 100; default 80
	FullPage   bool          // the whole page, not the viewport
	Wait       time.Duration // after the load event, for scripts that draw after it: 0 is 1.5 s, negative none
	Script     string        // run on the page before it is taken (-shot-js)
	Codes      []int         // take only pages that answered with one of these statuses; empty: any
	ChromePath string        // the Chrome to run; default AZHAQ_CHROME, else the first found
	ProfileDir string        // a user data directory to keep, signed in sessions and all; default a temporary one
	Proxy      string        // an http or socks5 proxy for Chrome's own connections; default the environment's
	AllowPorts bool          // let Chrome open the ports it refuses by default (6000, 10080, ...)
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
	gate   gate

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
		path, err := b.chrome()
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
		// The scope this Chrome is held to, as the run set it when Chrome
		// started: a later fetch.Reset (a run ending, a test) does not move
		// it under requests still being decided.
		b.allow = fetch.Allow
		if b.guard, err = newGuard(b.allowedHost); err != nil {
			b.err = fmt.Errorf("starting Chrome: %w", err)
			return
		}
		if b.Proxy != "" {
			pu, err := url.Parse(b.Proxy)
			if err != nil || pu.Host == "" {
				b.err = fmt.Errorf("starting Chrome: -chrome-proxy wants a URL such as http://127.0.0.1:8080 or socks5://127.0.0.1:9050, got %q", b.Proxy)
				b.guard.close()
				return
			}
			b.guard.via = pu
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
		if b.ProfileDir != "" {
			opts = append(opts, chromedp.UserDataDir(b.ProfileDir))
		}
		if b.AllowPorts {
			opts = append(opts, chromedp.Flag("explicitly-allowed-ports", restrictedPorts))
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
	Image       []byte // the screenshot, in Format
	Format      string // "png" or "jpeg"
	Skipped     string // why no screenshot was taken of a page that answered
	HTML        string
	Asked       int         // how many requests the page made, images, fonts and media included: what its budget has to cover
	Requests    []string    // every URL the page asked for with GET, HEAD or OPTIONS while loading, sent or not; without its images, fonts and media
	Blocked     []string    // URLs it asked for outside the scope, to list (Reason); not sent
	Downloads   []string    // what it would have saved to disk, to list (DownloadReason); refused
	Writes      []Write     // what else it sent in the scope, or was refused (WriteReason) without Browser.Writes
	Left        string      // the page went there, outside the scope, and was stopped: what shows is Chrome's error
	Interaction Interaction // what clicking it found, with Browser.Interact
	Capped      bool        // the request budget refused some of its requests; what it was refused is then in Leftover and LeftoverWrites, not Blocked and Writes
	// Unloaded is how many of the images, styles, scripts, fonts and media
	// the page asked for (of Resources) had not come back, or failed, when
	// the picture was taken: the screenshot is then Partial.
	Unloaded, Resources int
	Partial             bool
	Record              Record // what Chrome saw: answer, headers, TLS, requests, console
	// OffScope is how many requests of this page were refused for being
	// outside the scope (its stylesheets, scripts and images from a CDN,
	// a frame), whether or not an earlier page had them listed, and
	// OffScopeHosts the hosts they went to, sorted: the page is drawn
	// without them.
	OffScope      int
	OffScopeHosts []string
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
	if err := b.gate.enter(ctx, b.Tabs, b.Timeout); err != nil {
		return Page{}, err
	}
	weight := 0 // what the page asked for, once it is known, for the next page's admission
	defer func() { b.gate.leave(weight) }()
	if b.lost.Load() {
		return Page{}, errLost
	}
	watched := func() {}
	defer func() { watched() }() // once the tab is closed
	tab, cancel := chromedp.NewContext(b.root)
	defer cancel()
	// With a pace the page's deadlines run from when it last moved.
	var prog *progress
	if fetch.Rate() > 0 {
		prog = newProgress()
	}
	extra := time.Duration(b.Interact) * 2 * time.Second // the clicks of -interact
	tab, cancelT := deadline(tab, prog, b.Timeout+extra, 10*b.Timeout+extra)
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
	log := newPageLog(main, prog)
	t := b.openTab(tab, main, false, !shot, prog, log)
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
	prog.touch()
	nav, cancelNav := deadline(tab, prog, min(b.Timeout/2, 15*time.Second), 10*b.Timeout)
	err := chromedp.Do(nav, chromedp.Navigate(rawURL))
	navLate := nav.Err() != nil && tab.Err() == nil
	cancelNav()
	if (navLate || errors.Is(err, context.DeadlineExceeded)) && tab.Err() == nil {
		err = nil
	}
	if err == nil {
		if wait := b.wait(); wait > 0 {
			err = chromedp.Do(tab, chromedp.Sleep(wait)) // scripts that render after load
		}
	}
	waiting := 0
	if err == nil && shot {
		waiting = b.quiet(tab, t, log, prog)
	}
	if err == nil {
		p.URL, _ = chromedp.Run(tab, chromedp.Location())
		p.Title, _ = chromedp.Run(tab, chromedp.Title())
		p.HTML, _ = chromedp.Run(tab, chromedp.OuterHTML(chromedp.CSS("html")))
		if shot {
			rec, _, _ := log.snapshot()
			switch {
			case len(b.Codes) > 0 && !slices.Contains(b.Codes, rec.Status):
				p.Skipped = fmt.Sprintf("answered %d, not one of the statuses asked for (-shot-codes)", rec.Status)
			default:
				if b.Script != "" {
					await := true
					_, _ = chromedp.Call(tab, runtime.Evaluate, runtime.EvaluateParams{Expression: b.Script, AwaitPromise: &await})
				}
				p.Image, err = b.capture(tab)
				p.Format = b.format()
			}
		}
	}
	p.Record, p.Unloaded, p.Resources = log.snapshot()
	p.Unloaded, p.Resources = p.Unloaded+waiting, p.Resources+waiting // asked for, and still waiting for its turn
	p.Partial = p.Unloaded > 0
	if err == nil && b.Interact > 0 {
		p.Interaction = b.interact(tab, p.URL, b.Interact, webextract.StateChanging)
	}
	b.settle(t)
	mu.Lock()
	p.Requests = append([]string(nil), reqs...)
	p.Asked = asked
	mu.Unlock()
	if shot && !p.Partial {
		weight = p.Asked
	}
	if tab.Err() != nil && errors.Is(context.Cause(tab), context.DeadlineExceeded) && errors.Is(err, context.Canceled) {
		err = context.DeadlineExceeded // the page stopped moving: a timeout
	}
	mine := b.claim(t)
	writes := b.writesOf(t)
	hosts := map[string]bool{}
	for _, r := range mine {
		p.Capped = p.Capped || r.budget
		if r.frame == main && r.doc && !r.budget && p.Left == "" {
			p.Left = r.url
		}
		if !r.budget && !r.download && r.host != "" && !(r.frame == main && r.doc) {
			p.OffScope++
			hosts[r.host] = true
		}
	}
	p.OffScopeHosts = slices.Sorted(maps.Keys(hosts))
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

// wait is how long Load waits after the load event.
func (b *Browser) wait() time.Duration {
	switch {
	case b.Wait < 0:
		return 0
	case b.Wait == 0:
		return 1500 * time.Millisecond
	}
	return b.Wait
}

func (b *Browser) format() string {
	if strings.EqualFold(b.Format, "jpeg") || strings.EqualFold(b.Format, "jpg") {
		return "jpeg"
	}
	return "png"
}

// maxShotHeight bounds a full-page picture: a page that scrolls for ever
// would otherwise be an image of that size.
const maxShotHeight = 16384

// capture takes the screenshot, of the viewport or of the whole page.
func (b *Browser) capture(tab context.Context) ([]byte, error) {
	on := true
	params := page.CaptureScreenshotParams{FromSurface: &on}
	if b.format() == "jpeg" {
		q := int64(b.Quality)
		if q < 1 || q > 100 {
			q = 80
		}
		params.Format, params.Quality = page.CaptureScreenshotFormatJpeg, &q
	}
	if b.FullPage {
		m, err := chromedp.Call(tab, page.GetLayoutMetrics, cdp.Empty{})
		if err != nil {
			return nil, err
		}
		if c := m.CSSContentSize; c != nil && c.Width > 0 && c.Height > 0 {
			params.Clip = &page.Viewport{Width: c.Width, Height: min(c.Height, maxShotHeight), Scale: 1}
			params.CaptureBeyondViewport = &on
		}
	}
	r, err := chromedp.Call(tab, page.CaptureScreenshot, params)
	if err != nil {
		return nil, err
	}
	return r.Data, nil
}

var errLost = errors.New("Chrome no longer reports the requests it holds: its pages are not loaded")
