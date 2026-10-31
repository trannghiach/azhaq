package browser

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/chromedp/chromedp"
)

// Interaction: with Browser.Interact set, a page that has loaded has its
// buttons, links and menus clicked, up to that many clicks, to find the
// routes and requests only a click brings: the part of katana's headless
// mode that matters to a map. A click is a click whatever its words say,
// as it is for katana: a link's GET is requested. It sends no write: the
// writes a click would send are refused by their method and mapped
// (Browser.Writes is not set by it), and Chrome stays held to the scope
// and the budget.

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

// skipCandidate says whether a click is left alone: a download, or an
// address that is not a page of the site (mail, a phone call, a script).
func skipCandidate(c candidate) bool {
	if c.Download {
		return true
	}
	h := strings.ToLower(strings.TrimSpace(c.Href))
	return strings.HasPrefix(h, "mailto:") || strings.HasPrefix(h, "tel:") || strings.HasPrefix(h, "javascript:") || strings.HasPrefix(h, "blob:")
}

// Interaction is what clicking a page found.
type Interaction struct {
	Clicks    int      // clicks made
	Skipped   int      // candidates left alone: downloads, mail and phone links
	Routes    []string // where the page's address went after a click (a route, a hash route), not the page's own
	Snapshots []string // the page's HTML after a click that changed it, up to 12
}

// interact clicks the page's candidates, one at a time, putting the page
// back where it was after each: by history, else by loading it again. It
// ends when spent says the budget refused the page something: the page is
// loaded again after azhaq resume, so more clicks are time for nothing.
// idle says whether the page has nothing out: a page with nothing to click
// yet is looked at again while it is still drawing.
func (b *Browser) interact(tab context.Context, start string, max int, spent func() bool, idle func() bool) Interaction {
	var in Interaction
	tried := map[string]bool{}
	sameURL := func(a, c string) bool { return a == c }
	for in.Clicks < max && tab.Err() == nil && !spent() {
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
		if in.Clicks == 0 && len(tried) == 0 {
			cands, err = b.drawn(tab, cands, spent, idle)
			if err != nil {
				return in
			}
		}
		var pick *candidate
		for i := range cands {
			c := &cands[i]
			if tried[c.Key] {
				continue
			}
			tried[c.Key] = true
			if skipCandidate(*c) {
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
			// Not a selector query: it polls for the node until the tab ends,
			// and a click that left the scope has left no page to find it in.
			if html, err := chromedp.Run(tab, chromedp.Evaluate[string](`document.documentElement ? document.documentElement.outerHTML : ''`)); err == nil && html != "" {
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

// drawn looks again, a few times, at a page that shows nothing to click: an
// app that is still drawing its menus (after a slow answer) shows them soon.
// It ends once something shows, or the page has been quiet and unchanged for
// two looks.
func (b *Browser) drawn(tab context.Context, cands []candidate, spent func() bool, idle func() bool) ([]candidate, error) {
	size := func() int {
		n, _ := chromedp.Run(tab, chromedp.Evaluate[int](`document.getElementsByTagName('*').length`))
		return n
	}
	last, still := size(), 0
	for look := 0; look < 8 && len(cands) == 0 && tab.Err() == nil && !spent(); look++ {
		_ = chromedp.Do(tab, chromedp.Sleep(300*time.Millisecond))
		var err error
		if cands, err = chromedp.Run(tab, chromedp.Evaluate[[]candidate](candidatesJS)); err != nil {
			return nil, err
		}
		if n := size(); n == last && idle() {
			if still++; still >= 2 {
				break
			}
		} else {
			last, still = n, 0
		}
	}
	return cands, nil
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
