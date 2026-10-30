package browser

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/chromedp/chromedp"
)

// Interaction: with Browser.Interact set, a page that has loaded has its
// buttons, links and menus clicked, up to that many clicks, to find the
// routes and requests only a click brings: the part of katana's headless
// mode that matters to a map. It sends nothing a page load does not: the
// writes a click would send are refused and mapped as before
// (Browser.Writes is not set by it), a click on something that looks like
// it ends a session or deletes is not made, and Chrome stays held to the
// scope and the budget.

const candidatesJS = `(() => {
  const sel = 'a[href], button, [role=button], [role=link], [role=tab], [role=menuitem], [onclick], [routerlink], [ng-click], [data-toggle], summary, input[type=button], input[type=submit]';
  const seen = new Set();
  const out = [];
  for (const e of document.querySelectorAll(sel)) {
    const r = e.getBoundingClientRect(), s = getComputedStyle(e);
    if (r.width <= 0 || r.height <= 0 || s.visibility === 'hidden' || e.disabled) continue;
    const a = e.closest('a');
    const href = a ? a.getAttribute('href') || '' : '';
    const text = (e.innerText || e.value || e.getAttribute('aria-label') || e.getAttribute('title') || '').trim().slice(0, 60);
    const key = e.tagName + '|' + text + '|' + href + '|' + (e.getAttribute('routerlink') || '');
    if (seen.has(key)) continue;
    seen.add(key);
    e.setAttribute('data-azq', String(out.length));
    out.push({i: out.length, key: key, tag: e.tagName.toLowerCase(), text: text, href: href, download: !!(a && a.hasAttribute('download')), type: e.type || ''});
  }
  return out;
})()`

type candidate struct {
	I        int    `json:"i"`
	Key      string `json:"key"`
	Tag      string `json:"tag"`
	Text     string `json:"text"`
	Href     string `json:"href"`
	Download bool   `json:"download"`
	Type     string `json:"type"`
}

// risky says whether a click is left alone: its words or its address say
// it ends the session, deletes or changes something.
var risky = regexp.MustCompile(`(?i)log\s?out|sign\s?out|delete|remove|erase|reset|unsubscribe|deactivate|close account|destroy|revoke|purge`)

func skipCandidate(c candidate, stateChanging func(string) string) bool {
	if c.Download || risky.MatchString(c.Text) || risky.MatchString(c.Href) {
		return true
	}
	h := strings.ToLower(strings.TrimSpace(c.Href))
	if strings.HasPrefix(h, "mailto:") || strings.HasPrefix(h, "tel:") || strings.HasPrefix(h, "javascript:") || strings.HasPrefix(h, "blob:") {
		return true
	}
	return stateChanging != nil && c.Href != "" && stateChanging(c.Href) != ""
}

// Interaction is what clicking a page found.
type Interaction struct {
	Clicks    int      // clicks made
	Skipped   int      // candidates left alone for what their words or address say
	Routes    []string // where the page's address went after a click (a route, a hash route), not the page's own
	Snapshots []string // the page's HTML after a click that changed it, up to 12
}

// interact clicks the page's candidates, one at a time, putting the page
// back where it was after each: by history, else by loading it again.
func (b *Browser) interact(tab context.Context, start string, max int, stateChanging func(string) string) Interaction {
	var in Interaction
	tried := map[string]bool{}
	sameURL := func(a, c string) bool { return a == c }
	for in.Clicks < max && tab.Err() == nil {
		if now, _ := chromedp.Run(tab, chromedp.Location()); now != start && in.Clicks > 0 {
			nav, cancel := context.WithTimeout(tab, 10*time.Second)
			_ = chromedp.Do(nav, chromedp.Navigate(start))
			cancel()
			_ = chromedp.Do(tab, chromedp.Sleep(700*time.Millisecond))
		}
		cands, err := chromedp.Run(tab, chromedp.Evaluate[[]candidate](candidatesJS))
		if err != nil {
			return in
		}
		var pick *candidate
		for i := range cands {
			c := &cands[i]
			if tried[c.Key] {
				continue
			}
			tried[c.Key] = true
			if skipCandidate(*c, stateChanging) {
				in.Skipped++
				continue
			}
			pick = c
			break
		}
		if pick == nil {
			return in
		}
		before, _ := chromedp.Run(tab, chromedp.Location())
		click := fmt.Sprintf(`(() => { const e = document.querySelector('[data-azq="%d"]'); if (!e) return false; e.click(); return true; })()`, pick.I)
		if ok, err := chromedp.Run(tab, chromedp.Evaluate[bool](click)); err != nil || !ok {
			continue
		}
		in.Clicks++
		_ = chromedp.Do(tab, chromedp.Sleep(700*time.Millisecond))
		after, _ := chromedp.Run(tab, chromedp.Location())
		if after != "" && !sameURL(after, before) {
			if r := withoutQuery(after); r != "" && !contains(in.Routes, r) && withoutQuery(start) != r {
				in.Routes = append(in.Routes, r)
			}
		}
		if len(in.Snapshots) < 12 {
			if html, err := chromedp.Run(tab, chromedp.OuterHTML(chromedp.CSS("html"))); err == nil {
				in.Snapshots = append(in.Snapshots, html)
			}
		}
		if after != "" && after != start {
			_, _ = chromedp.Run(tab, chromedp.Evaluate[any](`history.back()`))
			_ = chromedp.Do(tab, chromedp.Sleep(400*time.Millisecond))
			if now, _ := chromedp.Run(tab, chromedp.Location()); now != start {
				nav, cancel := context.WithTimeout(tab, 10*time.Second)
				_ = chromedp.Do(nav, chromedp.Navigate(start))
				cancel()
				_ = chromedp.Do(tab, chromedp.Sleep(700*time.Millisecond))
			}
		}
	}
	return in
}

func withoutQuery(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	u.RawQuery = ""
	return u.String()
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}
