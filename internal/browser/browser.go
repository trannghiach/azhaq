// Package browser drives a Chrome already installed on the machine
// (headless, through the DevTools protocol): screenshots, and pages whose
// content only exists once their scripts run. Nothing is downloaded.
package browser

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
)

// ErrNoChrome means no Chrome or Chromium was found.
var ErrNoChrome = errors.New("no Chrome or Chromium found (install one, or set AZHAQ_CHROME to its path)")

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

	once   sync.Once
	err    error
	alloc  context.Context
	cancel context.CancelFunc
	root   context.Context
	sem    chan struct{}
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
		opts := append(chromedp.DefaultExecAllocatorOptions[:],
			chromedp.ExecPath(path),
			chromedp.WindowSize(b.Width, b.Height),
			chromedp.Flag("ignore-certificate-errors", true),
			chromedp.Flag("disable-extensions", true),
			chromedp.Flag("mute-audio", true),
		)
		if b.UserAgent != "" {
			opts = append(opts, chromedp.UserAgent(b.UserAgent))
		}
		b.alloc, b.cancel = chromedp.NewExecAllocator(context.Background(), opts...)
		root, _ := chromedp.NewContext(b.alloc)
		if err := chromedp.Do(root); err != nil {
			b.err = fmt.Errorf("starting Chrome: %w", err)
			return
		}
		b.root = root
	})
	return b.err
}

// Close stops Chrome.
func (b *Browser) Close() {
	if b.cancel != nil {
		b.cancel()
	}
}

// Page is what loading a URL gave.
type Page struct {
	URL      string // after redirects
	Title    string
	PNG      []byte
	HTML     string
	Requests []string // every URL the page asked for while loading
}

// Load opens rawURL in a new tab, waits for the network to settle, and
// returns the page; shot adds a screenshot of the viewport.
func (b *Browser) Load(ctx context.Context, rawURL string, shot bool) (Page, error) {
	if err := b.start(); err != nil {
		return Page{}, err
	}
	select {
	case b.sem <- struct{}{}:
	case <-ctx.Done():
		return Page{}, ctx.Err()
	}
	defer func() { <-b.sem }()
	tab, cancel := chromedp.NewContext(b.root)
	defer cancel()
	tab, cancelT := context.WithTimeout(tab, b.Timeout)
	defer cancelT()
	stop := context.AfterFunc(ctx, cancelT)
	defer stop()

	// The page's requests, from the moment the tab opens.
	var mu sync.Mutex
	var reqs []string
	events := chromedp.Events(tab, network.RequestWillBeSent)
	go func() {
		for ev, err := range events {
			if err != nil {
				return
			}
			mu.Lock()
			reqs = append(reqs, ev.Request.URL)
			mu.Unlock()
		}
	}()
	var p Page
	if _, err := chromedp.Call(tab, network.Enable, network.EnableParams{}); err != nil {
		return p, err
	}
	if len(b.Header) > 0 {
		if _, err := chromedp.Call(tab, network.SetExtraHTTPHeaders, network.SetExtraHTTPHeadersParams{Headers: network.Headers(b.Header)}); err != nil {
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
	mu.Lock()
	p.Requests = append([]string(nil), reqs...)
	mu.Unlock()
	return p, err
}
