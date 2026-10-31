package egress

import (
	"context"

	"github.com/chromedp/chromedp"
)

// LaunchChrome starts Chrome's allocator with every connection of it, the
// loopback ones too, made through g, and no WebRTC packet outside it. The
// guard dials for Chrome and holds each connection to the scope, the
// budget, the kill file and the ledger; it ends with the allocator.
func LaunchChrome(g *ChromeGuard, opts ...chromedp.ExecAllocatorOption) (context.Context, context.CancelFunc) {
	opts = append(opts,
		chromedp.ProxyServer("socks5://"+g.Addr()),
		chromedp.Flag("proxy-bypass-list", "<-loopback>"),
		chromedp.Flag("webrtc-ip-handling-policy", "disable_non_proxied_udp"),
	)
	alloc, cancel := chromedp.NewExecAllocator(context.Background(), opts...)
	// The guard lives as long as this Chrome, and relays for it alone.
	context.AfterFunc(alloc, g.Close)
	return alloc, cancel
}
