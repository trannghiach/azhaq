package crawlcol

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/trannghiach/azhaq/catalog"
	"github.com/trannghiach/azhaq/internal/crawlscope"
	"github.com/trannghiach/azhaq/internal/fetch"
	"github.com/trannghiach/azhaq/internal/neterr"
	"github.com/trannghiach/azhaq/internal/normalize"
	"github.com/trannghiach/azhaq/internal/webextract"
	"github.com/trannghiach/azhaq/types"
)

const Name = "azhaq-crawl"

type Collector struct {
	Client *http.Client
	// FillForms asks the action of a GET form with neutral values in its
	// fields (-fill-forms); SubmitForms also sends POST forms the same way
	// (-submit-forms), which changes data; Climb lists the parent
	// directories of every link (-path-climb).
	FillForms, SubmitForms, Climb bool

	submitted sync.Map // forms already sent: one submission each
	climbed   sync.Map
}

func New(client *http.Client) *Collector {
	return &Collector{Client: fetch.Client(client)}
}

func Register(cat *catalog.Catalog, client *http.Client) {
	cat.MustRegister(New(client))
}

func (c *Collector) Name() string { return Name }

// Info: this collector sends requests to the target.
func (c *Collector) Info() catalog.Info {
	return catalog.Info{Kind: catalog.Touch, After: "azhaq-http"}
}

func (c *Collector) Inputs() []types.SeedType { return []types.SeedType{types.TypeURL} }

func (c *Collector) Outputs() []string { return []string{"url"} }

// Skip declines scripts and static assets: there is nothing to crawl.
func (c *Collector) Skip(seed types.Seed) bool {
	switch webextract.ClassifyURL(seed.Keys["url"]) {
	case "script", "asset":
		return true
	}
	return false
}

func (c *Collector) Run(ctx context.Context, seed types.Seed, emit func(types.Observation) error) (types.RunMeta, error) {
	raw, err := normalize.URL(seed.Keys["url"])
	if err != nil {
		return types.RunMeta{Status: types.StatusError, Error: err.Error()}, err
	}
	res, _, err := fetch.Do(ctx, c.Client, raw)
	if err != nil {
		if neterr.Quiet(err) {
			return types.RunMeta{Status: types.StatusOK}, nil
		}
		return types.RunMeta{Status: types.StatusError, Error: err.Error()}, err
	}
	final := res.URL
	if final == "" {
		final = res.RequestURL
	}
	base, err := url.Parse(final)
	if err != nil {
		return types.RunMeta{Status: types.StatusOK}, nil
	}
	meta := types.RunMeta{Status: types.StatusOK}
	if n, err := normalize.URL(final); err == nil && n != raw {
		// Redirected: the page it landed on is visited and crawled itself;
		// the hops in between are URLs of the map too, as a crawler that
		// reads Location lists them.
		for _, h := range res.Hops {
			hop, err := normalize.URL(h.URL)
			if err != nil || hop == raw || hop == n || !crawlscope.Within(raw, hop) {
				continue
			}
			payload, _ := json.Marshal(map[string]string{"url": hop, "via": "redirect", "tag": "header", "attribute": "location"})
			if err := emit(types.Observation{Collector: Name, Source: raw, Kind: "url", Payload: payload, Confidence: 0.85, ObservedAt: time.Now().UTC()}); err != nil {
				return meta, err
			}
			meta.EmitCount++
		}
		return meta, nil
	}
	if fetch.ErrorPage(res) {
		// A site's 404 page links to its pages relative to a path that
		// does not exist: /swagger/v1/ + index.jsp is not a page. What it
		// names is kept as rejected, not read as links.
		return meta, c.rejectAll(raw, res.Body, base, webextract.ReasonErrorPage, emit, &meta)
	}
	ct := strings.ToLower(res.Header.Get("Content-Type"))
	switch {
	case strings.Contains(ct, "json"):
		return c.jsonLinks(raw, res.Body, base, emit)
	case ct != "" && !strings.Contains(ct, "html") && !strings.Contains(ct, "xml"):
		if strings.HasPrefix(ct, "text/") && !strings.Contains(ct, "javascript") {
			linked := map[string]bool{raw: true}
			return meta, c.textStrings(raw, string(res.Body), base, linked, "text", emit, &meta)
		}
		return meta, nil
	}
	if fetch.FinalCatchAll(ctx, c.Client, res) {
		// The generic page: its links were read from the real one.
		return meta, c.rejectAll(raw, res.Body, base, webextract.ReasonCatchAll, emit, &meta)
	}
	body := res.Body
	if gen := webextract.Generator(body); gen != "" {
		payload, _ := json.Marshal(map[string]string{"generator": gen, "url": raw})
		if err := emit(types.Observation{
			Collector: Name, Source: raw, Kind: "meta",
			Payload: payload, Confidence: 0.8, ObservedAt: time.Now().UTC(),
		}); err != nil {
			return meta, err
		}
		meta.EmitCount++
	}
	asked := map[string]bool{} // GET form actions asked filled in, not bare
	for _, f := range webextract.Forms(body, base) {
		row := map[string]any{
			"method": f.Method, "action": f.Action, "fields": f.Fields, "via": "html",
		}
		if f.ID != "" {
			row["id"] = f.ID
		}
		if f.Name != "" {
			row["name"] = f.Name
		}
		if f.Enctype != "" {
			row["enctype"] = f.Enctype
		}
		if len(f.Files) > 0 {
			row["files"] = f.Files
		}
		payload, _ := json.Marshal(row)
		if err := emit(types.Observation{
			Collector: Name, Source: raw, Kind: "form",
			Payload: payload, Confidence: 0.85, ObservedAt: time.Now().UTC(),
		}); err != nil {
			return meta, err
		}
		meta.EmitCount++
		if f.Action == "" || f.Action == raw || !crawlscope.Within(raw, f.Action) {
			continue
		}
		switch {
		case strings.EqualFold(f.Method, "GET"):
			if err := c.getForm(raw, f, emit, &meta); err != nil {
				return meta, err
			}
			if filled, ok := webextract.FilledGet(f); c.FillForms && ok && crawlscope.Within(raw, filled) {
				asked[f.Action] = true
			}
		case c.SubmitForms:
			if err := c.postForm(ctx, raw, f, emit, &meta); err != nil {
				return meta, err
			}
		}
	}
	// The query names in its links are the links' own: each link is a URL
	// of the map, and its row lists them.
	linked := map[string]bool{}
	refs := append(webextract.HeaderRefs(res.Header, base), webextract.LinkRefs(body, base)...)
	for _, ref := range refs {
		link := ref.URL
		linked[link] = true
		if !crawlscope.Within(raw, link) {
			c.offsite(raw, ref, emit, &meta)
			continue
		}
		if link == raw || webextract.ListingSort(link) {
			continue // the page itself, or a directory listing sorted another way
		}
		p := map[string]any{"url": link, "via": "html", "tag": ref.Tag, "attribute": ref.Attr}
		if ref.Method != "" {
			p["methods"] = []string{ref.Method}
		}
		payload, _ := json.Marshal(p)
		if err := emit(types.Observation{
			Collector:  Name,
			Source:     raw,
			Kind:       "url",
			Payload:    payload,
			Confidence: 0.85,
			ObservedAt: time.Now().UTC(),
		}); err != nil {
			return meta, err
		}
		meta.EmitCount++
		if c.Climb {
			if err := c.climbs(raw, link, emit, &meta); err != nil {
				return meta, err
			}
		}
		if ref.Method == "" && !asked[link] && webextract.Hintable(link) {
			meta.NextHints = append(meta.NextHints, types.Seed{
				Type: types.TypeURL,
				Keys: map[string]string{"url": link},
			})
		}
	}
	if err := c.textStrings(raw, string(body), base, linked, "html-text", emit, &meta); err != nil {
		return meta, err
	}
	// Links the page's scripts render from Markdown in its text, and what
	// it leaves to them, which the run's summary weighs for -browser.
	md, un := webextract.ReadUnrendered(body, base)
	if un.Any() {
		payload, _ := json.Marshal(map[string]any{"url": raw, "unrendered": un})
		if err := emit(types.Observation{
			Collector: Name, Source: raw, Kind: "meta",
			Payload: payload, Confidence: 0.8, ObservedAt: time.Now().UTC(),
		}); err != nil {
			return meta, err
		}
		meta.EmitCount++
	}
	for _, link := range md {
		if linked[link] || link == raw {
			continue
		}
		if !crawlscope.Within(raw, link) {
			c.offsite(raw, webextract.PageRef{URL: link, Tag: "markdown"}, emit, &meta)
			continue
		}
		payload, _ := json.Marshal(map[string]string{"url": link, "via": "markdown"})
		if err := emit(types.Observation{
			Collector: Name, Source: raw, Kind: "url",
			Payload: payload, Confidence: 0.8, ObservedAt: time.Now().UTC(),
		}); err != nil {
			return meta, err
		}
		meta.EmitCount++
		if webextract.Hintable(link) {
			meta.NextHints = append(meta.NextHints, types.Seed{
				Type: types.TypeURL, Keys: map[string]string{"url": link},
			})
		}
	}
	return meta, nil
}

// jsonLinks reads links out of a JSON response: HTML inside string values
// and values that are themselves a same-origin URL or path.
func (c *Collector) jsonLinks(raw string, body []byte, base *url.URL, emit func(types.Observation) error) (types.RunMeta, error) {
	meta := types.RunMeta{Status: types.StatusOK}
	linked := map[string]bool{raw: true}
	for _, link := range webextract.JSONLinks(body, base) {
		linked[link] = true
		if link == raw {
			continue
		}
		if !crawlscope.Within(raw, link) {
			c.offsite(raw, webextract.PageRef{URL: link, Tag: "json"}, emit, &meta)
			continue
		}
		payload, _ := json.Marshal(map[string]string{"url": link, "via": "json"})
		if err := emit(types.Observation{
			Collector: Name, Source: raw, Kind: "url",
			Payload: payload, Confidence: 0.7, ObservedAt: time.Now().UTC(),
		}); err != nil {
			return meta, err
		}
		meta.EmitCount++
		if webextract.Hintable(link) {
			meta.NextHints = append(meta.NextHints, types.Seed{
				Type: types.TypeURL, Keys: map[string]string{"url": link},
			})
		}
	}
	if err := c.textStrings(raw, string(body), base, linked, "json-text", emit, &meta); err != nil {
		return meta, err
	}
	return meta, nil
}

// offsite records a link the crawl's scope leaves alone, when the crawl may
// go beyond the page's origin: the summary counts them and -do lists them.
func (c *Collector) offsite(page string, ref webextract.PageRef, emit func(types.Observation) error, meta *types.RunMeta) {
	if !crawlscope.Wide() {
		return
	}
	payload, _ := json.Marshal(map[string]string{"url": ref.URL, "via": "html", "tag": ref.Tag, "attribute": ref.Attr})
	if emit(types.Observation{
		Collector: Name, Source: page, Kind: "offsite",
		Payload: payload, Confidence: 0.85, ObservedAt: time.Now().UTC(),
	}) == nil {
		meta.EmitCount++
	}
}

// textStrings reads the paths and file names in a page's text that its
// markup does not link, as katana's body regex does: a page of the app
// under a bare name is a URL, every other string is kept as rejected with
// why. linked holds the URLs the page already names.
func (c *Collector) textStrings(raw, text string, base *url.URL, linked map[string]bool, via string, emit func(types.Observation) error, meta *types.RunMeta) error {
	seen := map[string]bool{}
	for _, cd := range webextract.Candidates(text, base, base, false) {
		if cd.Link != "" && (linked[cd.Link] || cd.Link == raw) || cd.Resolved != "" && (linked[cd.Resolved] || cd.Resolved == raw) {
			continue
		}
		reason := cd.Reason
		switch {
		case reason == "" && !crawlscope.Within(raw, cd.Link):
			reason = webextract.ReasonOffsite
			if !crawlscope.Wide() {
				reason = webextract.ReasonOtherHost
			}
		case reason == "" && webextract.ListingSort(cd.Link):
			reason = webextract.ReasonJunk
		}
		if reason != "" {
			if k := cd.Text + "\x00" + reason; !seen[k] {
				seen[k] = true
				if err := emit(webextract.RejectedObs(Name, raw, cd.Text, reason, via, cd.Resolved)); err != nil {
					return err
				}
				meta.EmitCount++
			}
			continue
		}
		linked[cd.Link] = true
		payload, _ := json.Marshal(map[string]string{"url": cd.Link, "via": via})
		if err := emit(types.Observation{
			Collector: Name, Source: raw, Kind: "url",
			Payload: payload, Confidence: 0.6, ObservedAt: time.Now().UTC(),
		}); err != nil {
			return err
		}
		meta.EmitCount++
		if webextract.Hintable(cd.Link) {
			meta.NextHints = append(meta.NextHints, types.Seed{
				Type: types.TypeURL, Keys: map[string]string{"url": cd.Link},
			})
		}
	}
	return nil
}

// rejectAll keeps every string of a page that is not read as links.
func (c *Collector) rejectAll(raw string, body []byte, base *url.URL, reason string, emit func(types.Observation) error, meta *types.RunMeta) error {
	seen := map[string]bool{}
	for _, cd := range webextract.Candidates(string(body), base, base, false) {
		if seen[cd.Text] {
			continue
		}
		seen[cd.Text] = true
		if err := emit(webextract.RejectedObs(Name, raw, cd.Text, reason, "html-text", cd.Resolved)); err != nil {
			return err
		}
		meta.EmitCount++
	}
	return nil
}

// getForm lists a GET form's action and, with -fill-forms, asks it the way
// a browser would after the fields got neutral values: one request.
func (c *Collector) getForm(page string, f webextract.Form, emit func(types.Observation) error, meta *types.RunMeta) error {
	row := func(link string) error {
		payload, _ := json.Marshal(map[string]string{"url": link, "via": "form", "tag": "form", "attribute": "action"})
		meta.EmitCount++
		return emit(types.Observation{Collector: Name, Source: page, Kind: "url", Payload: payload, Confidence: 0.85, ObservedAt: time.Now().UTC()})
	}
	hint := func(link string) {
		if webextract.Hintable(link) {
			meta.NextHints = append(meta.NextHints, types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": link}})
		}
	}
	filled, ok := webextract.FilledGet(f)
	if !c.FillForms || !ok || !crawlscope.Within(page, filled) {
		hint(f.Action)
		return nil
	}
	if err := row(f.Action); err != nil {
		return err
	}
	if err := row(filled); err != nil {
		return err
	}
	hint(filled)
	return nil
}

// postForm sends a POST form with neutral values (-submit-forms) and lists
// the route with the method and the names it took.
func (c *Collector) postForm(ctx context.Context, page string, f webextract.Form, emit func(types.Observation) error, meta *types.RunMeta) error {
	q := webextract.FilledQuery(f)
	key := f.Action + "\x00" + q
	if len(f.Files) > 0 || q == "" || strings.Contains(f.Enctype, "multipart") {
		fetch.Note("a POST form to " + f.Action + " was not submitted: it uploads a file or has nothing to send")
		return nil
	}
	if w := webextract.StateChanging(f.Action); w != "" {
		fetch.Note("a POST form to " + f.Action + " was not submitted: its address looks like it would " + w + " something")
		return nil
	}
	if _, dup := c.submitted.LoadOrStore(key, true); dup {
		return nil
	}
	res, err := fetch.SubmitForm(ctx, c.Client, f.Action, q)
	if err != nil {
		if neterr.Quiet(err) || errors.Is(err, neterr.ErrBudget) {
			return nil
		}
		return err
	}
	op := map[string]any{"method": "POST", "body": f.Fields, "body_type": f.Enctype, "source": "form"}
	payload, _ := json.Marshal(map[string]any{
		"url": f.Action, "via": "form", "tag": "form", "attribute": "action", "methods": []string{"POST"},
		"body": f.Fields, "ops": []any{op}, "post_status": res.Status,
	})
	meta.EmitCount++
	return emit(types.Observation{Collector: Name, Source: page, Kind: "url", Payload: payload, Confidence: 0.85, ObservedAt: time.Now().UTC()})
}

// climbs lists the parent directories of link, once each.
func (c *Collector) climbs(page, link string, emit func(types.Observation) error, meta *types.RunMeta) error {
	u, err := url.Parse(link)
	if err != nil {
		return err
	}
	p := u.Path
	for {
		i := strings.LastIndex(strings.TrimSuffix(p, "/"), "/")
		if i <= 0 {
			return nil
		}
		p = p[:i+1]
		parent := *u
		parent.Path, parent.RawQuery, parent.Fragment = p, "", ""
		n, err := normalize.URL(parent.String())
		if err != nil || !crawlscope.Within(page, n) {
			return nil
		}
		if _, dup := c.climbed.LoadOrStore(n, true); dup {
			continue
		}
		payload, _ := json.Marshal(map[string]string{"url": n, "via": "climb", "tag": "path-climb"})
		meta.EmitCount++
		if err := emit(types.Observation{Collector: Name, Source: page, Kind: "url", Payload: payload, Confidence: 0.6, ObservedAt: time.Now().UTC()}); err != nil {
			return err
		}
		if webextract.Hintable(n) {
			meta.NextHints = append(meta.NextHints, types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": n}})
		}
	}
}
