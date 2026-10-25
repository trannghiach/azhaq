package jscol

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/trannghiach/azhaq/internal/catalog"
	"github.com/trannghiach/azhaq/internal/fetch"
	"github.com/trannghiach/azhaq/internal/neterr"
	"github.com/trannghiach/azhaq/internal/normalize"
	"github.com/trannghiach/azhaq/internal/types"
	"github.com/trannghiach/azhaq/internal/webextract"
)

const Name = "azhaq-js"

const (
	// maxEmit caps URLs from one page and the scripts it pulls in.
	maxEmit = 512
	// maxScripts caps scripts fetched for one page, chunks included.
	maxScripts = 64
)

// Collector reads the scripts of every page it is given: inline scripts,
// same-origin <script src>, and the chunks and modules those import. Each
// script URL is fetched and parsed once per run, however many pages use it.
type Collector struct {
	Client *http.Client
	parsed sync.Map // script URL → true
}

func looksLikeJS(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	p := strings.ToLower(u.Path)
	return strings.HasSuffix(p, ".js") || strings.HasSuffix(p, ".mjs") || strings.HasSuffix(p, ".cjs")
}

func New(client *http.Client) *Collector {
	return &Collector{Client: fetch.Client(client)}
}

func Register(cat *catalog.Catalog, client *http.Client) {
	cat.MustRegister(New(client))
}

func (c *Collector) Name() string { return Name }

// Info: this collector sends requests to the target.
func (c *Collector) Info() catalog.Info { return catalog.Info{Kind: catalog.Touch} }

func (c *Collector) Inputs() []types.SeedType { return []types.SeedType{types.TypeURL} }

func (c *Collector) Outputs() []string { return []string{"url"} }

// Skip declines API routes, assets other than scripts, and scripts already
// parsed, so they do not spend the run's item budget.
func (c *Collector) Skip(seed types.Seed) bool {
	raw, err := normalize.URL(seed.Keys["url"])
	if err != nil {
		return false
	}
	if looksLikeJS(raw) {
		_, done := c.parsed.Load(raw)
		return done
	}
	switch webextract.ClassifyURL(raw) {
	case "api", "asset":
		return true
	}
	return false
}

type script struct {
	url  *url.URL
	body string
}

func (c *Collector) Run(ctx context.Context, seed types.Seed, emit func(types.Observation) error) (types.RunMeta, error) {
	raw, err := normalize.URL(seed.Keys["url"])
	if err != nil {
		return types.RunMeta{Status: types.StatusError, Error: err.Error()}, err
	}
	if looksLikeJS(raw) {
		if _, done := c.parsed.LoadOrStore(raw, true); done {
			return types.RunMeta{Status: types.StatusOK}, nil
		}
	}
	res, _, err := fetch.Do(ctx, c.Client, raw)
	if err != nil {
		if neterr.UnknownHost(err) {
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
	if n, err := normalize.URL(final); err == nil && n != raw && !looksLikeJS(raw) {
		// Redirected: the page it landed on is visited and read itself.
		return types.RunMeta{Status: types.StatusOK}, nil
	}
	ct := strings.ToLower(res.Header.Get("Content-Type"))
	isJS := strings.Contains(ct, "javascript") || strings.Contains(ct, "ecmascript") || looksLikeJS(final)

	var queue []script
	var fetched []string
	switch {
	case isJS:
		c.parsed.Store(final, true)
		queue = append(queue, script{url: base, body: string(res.Body)})
	case strings.Contains(ct, "html") || ct == "":
		if fetch.FinalCatchAll(ctx, c.Client, res) {
			// The generic shell: its scripts were read from the real page.
			return types.RunMeta{Status: types.StatusOK}, nil
		}
		for _, body := range webextract.InlineScripts(res.Body) {
			queue = append(queue, script{url: base, body: body})
		}
		for _, src := range webextract.ScriptSrcs(res.Body, base) {
			queue = c.load(ctx, raw, src, false, queue, &fetched)
		}
	default:
		return types.RunMeta{Status: types.StatusOK}, nil
	}

	var found []string
	for i := 0; i < len(queue); i++ {
		if ctx.Err() != nil {
			return types.RunMeta{Status: types.StatusCancelled}, ctx.Err()
		}
		s := queue[i]
		for _, link := range webextract.JSURLs(s.body, s.url) {
			if webextract.SameOrigin(raw, link) && link != raw {
				found = append(found, link)
			}
		}
		for _, ref := range webextract.ScriptRefs(s.body, s.url) {
			queue = c.load(ctx, raw, ref, true, queue, &fetched)
		}
	}

	meta := types.RunMeta{Status: types.StatusOK}
	put := func(link, role string) error {
		row := map[string]any{"url": link, "via": "js", "role": role}
		if params := queryNames(link); len(params) > 0 {
			// "/rest/user/change-password?current=" is a prefix the app
			// completes at run time: keep the route, note the names.
			row["url"] = webextract.RouteKey(link)
			row["params"] = params
		} else if role != "script" {
			row["url"] = webextract.RouteKey(link)
		}
		payload, _ := json.Marshal(row)
		if err := emit(types.Observation{
			Collector:  Name,
			Source:     raw,
			Kind:       "url",
			Payload:    payload,
			Confidence: 0.7,
			ObservedAt: time.Now().UTC(),
		}); err != nil {
			return err
		}
		meta.EmitCount++
		return nil
	}
	for _, src := range fetched {
		if err := put(src, "script"); err != nil {
			return meta, err
		}
		meta.NextHints = append(meta.NextHints, types.Seed{
			Type: types.TypeURL, Keys: map[string]string{"url": src},
		})
	}
	for _, link := range webextract.CollapseURLs(found) {
		if meta.EmitCount >= maxEmit {
			break
		}
		role := webextract.ClassifyURL(link)
		if role == "asset" || role == "script" {
			continue // scripts that loaded are listed above
		}
		if err := put(link, role); err != nil {
			return meta, err
		}
		if webextract.Hintable(link) {
			meta.NextHints = append(meta.NextHints, types.Seed{
				Type: types.TypeURL,
				Keys: map[string]string{"url": webextract.RouteKey(link)},
			})
		}
	}
	return meta, nil
}

// load fetches a same-origin script the run has not parsed yet and queues it.
// Names found inside scripts must end in .js; <script src> need not.
func (c *Collector) load(ctx context.Context, page, src string, needExt bool, queue []script, fetched *[]string) []script {
	if len(*fetched) >= maxScripts || !webextract.SameOrigin(page, src) || (needExt && !looksLikeJS(src)) {
		return queue
	}
	if _, done := c.parsed.LoadOrStore(src, true); done {
		return queue
	}
	res, _, err := fetch.Do(ctx, c.Client, src)
	if err != nil || res.Status != http.StatusOK {
		return queue
	}
	ct := strings.ToLower(res.Header.Get("Content-Type"))
	if strings.Contains(ct, "html") {
		return queue // an SPA index served for a missing chunk
	}
	u, err := url.Parse(src)
	if err != nil {
		return queue
	}
	*fetched = append(*fetched, src)
	return append(queue, script{url: u, body: string(res.Body)})
}

func queryNames(raw string) []string {
	u, err := url.Parse(raw)
	if err != nil || u.RawQuery == "" {
		return nil
	}
	var out []string
	for k := range u.Query() {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
