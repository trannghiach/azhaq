package browser

import (
	"context"

	cdpbrowser "github.com/chromedp/cdproto/browser"
	"github.com/chromedp/cdproto/cdp/jsonv2"
	"github.com/chromedp/chromedp"
)

// Chrome saves nothing to disk. A URL that is a file (an archive, a
// program, a key store), or a page that saves one as it loads (an <a
// download>, a Content-Disposition: attachment), would otherwise land it
// in the user's Downloads folder behind a run that maps: a target's file,
// named by the target. Every download is denied for the whole browser
// before its first tab opens; the request itself was sent (it is in the
// scope, paced and counted like any other), only what it answered is
// dropped. What was denied is listed as a refusal, like a request outside
// the scope, with the name Chrome would have saved it under.

// DownloadReason is what a run lists the downloads Chrome refused under.
const DownloadReason = "Chrome would download it"

// denyDownloads refuses every download of the browser, and keeps each one
// refused for the page whose frame asked for it. Chrome tells of a
// download as it begins, before it is denied.
func (b *Browser) denyDownloads(root context.Context) error {
	br := chromedp.FromContext(root).Browser
	began, stop := br.Subscribe(cdpbrowser.DownloadWillBegin.Method)
	context.AfterFunc(root, stop)
	events := true
	if _, err := chromedp.CallBrowser(root, cdpbrowser.SetDownloadBehavior, cdpbrowser.SetDownloadBehaviorParams{
		Behavior: cdpbrowser.SetDownloadBehaviorBehaviorDeny, EventsEnabled: &events,
	}); err != nil {
		stop()
		return err
	}
	go func() {
		defer stop()
		for raw := range began {
			var ev cdpbrowser.EventDownloadWillBegin
			if jsonv2.Unmarshal(raw, &ev) != nil || ev.URL == "" {
				continue
			}
			r := refusal{frame: ev.FrameID, download: true, name: ev.SuggestedFilename}
			r.url, r.host = listable(ev.URL)
			b.refuse(nil, r)
		}
	}()
	return nil
}

// target is how a run lists a refused download: its URL and the name
// Chrome would have saved it under. The URL itself was requested, and a
// summary lists nothing requested as left alone: the name keeps the
// refusal on the list.
func (r refusal) target() string {
	if !r.download || r.name == "" {
		return r.url
	}
	return r.url + " (" + r.name + ")"
}

// downloads is the downloads among rs a run lists, the first maxListed of
// the run.
func (b *Browser) downloads(rs []refusal) []string {
	b.refMu.Lock()
	defer b.refMu.Unlock()
	var out []string
	for _, r := range rs {
		t := r.target()
		if !r.download || b.listed[t] {
			continue
		}
		if len(b.listed) >= maxListed {
			b.unlisted = true
			continue
		}
		if b.listed == nil {
			b.listed = map[string]bool{}
		}
		b.listed[t] = true
		out = append(out, t)
	}
	return out
}

// LeftoverDownloads is the downloads Chrome refused that no page listed:
// a sign-in's, a capped page's, one begun as its tab closed.
func (b *Browser) LeftoverDownloads() []string {
	return b.downloads(b.takeHeld(true))
}
