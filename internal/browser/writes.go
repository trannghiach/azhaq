package browser

import (
	"encoding/json"
	"maps"
	"mime"
	"mime/multipart"
	"net/url"
	"slices"
	"sort"
	"strings"
	"unicode"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/network"
)

// Chrome sends GET, HEAD and OPTIONS (a CORS preflight) only. Whatever
// else a page or its scripts send, a POST, a DELETE, a beacon, a form
// posted as the page loads, is failed before it leaves, as a request
// outside the scope is (a form's post is stopped, so that the page stays
// as it was): a page that saves, tracks or deletes on load
// would otherwise change data on the target behind a run that maps. The
// sign-in's own tab is let send them (it posts the credentials), and so
// is every page with -browser-writes (Browser.Writes). What a page would
// have sent is kept as a Write: its method and the names its query and
// body carry, never their values, so that the route is mapped with that
// method, as a script's call is.

// WriteReason is what a run lists the writes Chrome did not send under.
const WriteReason = "a page's script would send a write"

const (
	maxWrites = 64      // writes kept for one page
	maxNames  = 64      // names kept of one write's query, and of its body
	maxBody   = 1 << 20 // body bytes read for its names
)

// Write is a request a page sent, or would have sent, with a method other
// than GET, HEAD and OPTIONS.
type Write struct {
	Method   string
	URL      string   // without its query
	Query    []string // the names in its query
	Body     []string // the names its body sends: a JSON object's keys, a form's fields
	BodyType string   // the body's media type, when it gave names
	Sent     bool     // -browser-writes let it go
}

// Target is how a run lists it: POST http://host/path.
func (w Write) Target() string { return w.Method + " " + w.URL }

// reads: a method that changes nothing on a server that keeps to HTTP.
func reads(method string) bool {
	switch method {
	case "GET", "HEAD", "OPTIONS":
		return true
	}
	return false
}

// writeOf is what req says of its route: the names, not the values.
func writeOf(req *network.Request) Write {
	w := Write{Method: req.Method}
	w.URL, _ = listable(req.URL)
	if u, err := url.Parse(req.URL); err == nil {
		w.Query = names(slices.Collect(maps.Keys(u.Query())))
	}
	var body []byte
	for _, e := range req.PostDataEntries {
		if e == nil || len(body)+len(e.Bytes) > maxBody {
			break // a large upload: its form names, if any, are in what came first
		}
		body = append(body, e.Bytes...)
	}
	w.Body, w.BodyType = bodyFields(body, header(req.Headers, "Content-Type"))
	return w
}

// bodyFields are the names a request body sends: a JSON object's keys,
// whatever the media type says (a beacon's string is text/plain), or a
// form's fields, urlencoded or multipart.
func bodyFields(body []byte, contentType string) ([]string, string) {
	media, params, _ := mime.ParseMediaType(contentType)
	var obj map[string]json.RawMessage
	switch {
	case len(strings.TrimSpace(string(body))) == 0:
	case json.Unmarshal(body, &obj) == nil && obj != nil:
		if media == "" {
			media = "application/json"
		}
		return names(slices.Collect(maps.Keys(obj))), media
	case media == "multipart/form-data" && params["boundary"] != "":
		var out []string
		r := multipart.NewReader(strings.NewReader(string(body)), params["boundary"])
		for {
			p, err := r.NextPart()
			if err != nil {
				break
			}
			if n := p.FormName(); n != "" && !slices.Contains(out, n) {
				out = append(out, n)
			}
		}
		if out = names(out); len(out) > 0 {
			return out, media
		}
	case (media == "" || media == "application/x-www-form-urlencoded") && strings.Contains(string(body), "="):
		if q, err := url.ParseQuery(strings.TrimSpace(string(body))); err == nil && len(q) > 0 {
			return names(slices.Collect(maps.Keys(q))), "application/x-www-form-urlencoded"
		}
	}
	return nil, ""
}

// names keeps the ones that read as names, sorted, at most maxNames: an
// object keyed by its data (an email, a long id) is not a list of fields.
func names(in []string) []string {
	var out []string
	for _, n := range in {
		if n == "" || len(n) > 64 || strings.LastIndexByte(n, '@') > 0 || strings.ContainsFunc(n, func(r rune) bool { return unicode.IsSpace(r) || !unicode.IsPrint(r) }) {
			continue
		}
		out = append(out, n)
	}
	sort.Strings(out)
	if len(out) > maxNames {
		out = out[:maxNames]
	}
	return out
}

func header(h network.Headers, name string) string {
	for k, v := range h {
		if strings.EqualFold(k, name) {
			s, _ := v.(string)
			return s
		}
	}
	return ""
}

// addWrite keeps w for the page, one per method and URL, with the names
// of every time it was sent; refMu is held.
func (t *tab) addWrite(w Write) {
	for i := range t.writes {
		if x := &t.writes[i]; x.Method == w.Method && x.URL == w.URL {
			x.Query = names(union(x.Query, w.Query))
			x.Body = names(union(x.Body, w.Body))
			if x.BodyType == "" {
				x.BodyType = w.BodyType
			}
			return
		}
	}
	if len(t.writes) < maxWrites {
		t.writes = append(t.writes, w)
	}
}

func union(a, b []string) []string {
	out := append([]string(nil), a...)
	for _, n := range b {
		if !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	return out
}

// heldWrite is a write no open page has yet: its frame's page may make
// the frame known, or none will (a worker's, a page already read).
type heldWrite struct {
	frame cdp.FrameID
	w     Write
}

// wrote keeps what a page sent, or was refused, of its writes: on the
// open page of frame, else held for the run to list.
func (b *Browser) wrote(t *tab, frame cdp.FrameID, w Write) {
	b.refMu.Lock()
	defer b.refMu.Unlock()
	if t == nil {
		t = b.tabs[frame] // a frame its page made known meanwhile
	}
	switch {
	case t != nil && !t.read:
		t.addWrite(w)
	case t != nil || b.gone[frame]:
		b.holdWrite("", w) // its page was read: a beacon as the tab closes
	default:
		b.holdWrite(frame, w)
	}
}

// holdWrite keeps a write no open page has; refMu is held.
func (b *Browser) holdWrite(frame cdp.FrameID, w Write) {
	for _, h := range b.heldW {
		if h.frame == frame && h.w.Method == w.Method && h.w.URL == w.URL {
			return
		}
	}
	if len(b.heldW) < maxHeld {
		b.heldW = append(b.heldW, heldWrite{frame, w})
	}
}

// writesOf takes the writes of t, a page read or given up on.
func (b *Browser) writesOf(t *tab) []Write {
	b.refMu.Lock()
	defer b.refMu.Unlock()
	ws := t.writes
	t.writes = nil
	sort.Slice(ws, func(i, j int) bool { return ws[i].Target() < ws[j].Target() })
	return ws
}

// leaveWrites hands writes no page will list to the run's leftovers.
func (b *Browser) leaveWrites(ws []Write) {
	b.refMu.Lock()
	defer b.refMu.Unlock()
	for _, w := range ws {
		b.holdWrite("", w)
	}
}

// LeftoverWrites is the writes Chrome refused that no page listed: a
// service worker's, a beacon sent as a tab closed, a capped page's, as
// Write.Target gives them.
func (b *Browser) LeftoverWrites() []string {
	b.refMu.Lock()
	defer b.refMu.Unlock()
	var out []string
	for _, h := range b.heldW {
		if t := h.w.Target(); !h.w.Sent && !slices.Contains(out, t) {
			out = append(out, t)
		}
	}
	b.heldW = nil
	sort.Strings(out)
	if len(out) > maxListed {
		out = out[:maxListed]
	}
	return out
}
