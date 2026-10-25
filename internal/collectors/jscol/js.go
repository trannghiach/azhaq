package jscol

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/trannghiach/azhaq/catalog"
	"github.com/trannghiach/azhaq/internal/fetch"
	"github.com/trannghiach/azhaq/internal/neterr"
	"github.com/trannghiach/azhaq/internal/normalize"
	"github.com/trannghiach/azhaq/internal/webextract"
	"github.com/trannghiach/azhaq/types"
)

const Name = "azhaq-js"

const (
	// maxEmit caps URLs from one page and the scripts it pulls in.
	maxEmit = 512
	// maxScripts caps scripts fetched for one page, chunks included.
	maxScripts = 64
	// maxMaps caps source maps read for one page.
	maxMaps = 8
	// maxMapFiles caps the source file names kept per map.
	maxMapFiles = 200
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
func (c *Collector) Info() catalog.Info { return catalog.Info{Kind: catalog.Touch, After: "azhaq-http"} }

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
	url     *url.URL
	body    string
	fromMap bool // original source from a source map
}

// sourceMap is what a map says about the code behind a bundle.
type sourceMap struct {
	url   string
	files []string // the app's own source files, libraries left out
	count int      // all sources, libraries included
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
	var maps []sourceMap
	var ops []string
	opSeen := map[string]bool{}
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
		// Paths joined from constants are relative to the app's root,
		// where single-page apps send their requests from.
		for _, p := range webextract.Assembled(s.body) {
			if !strings.HasPrefix(p, "http") {
				p = base.Scheme + "://" + base.Host + "/" + strings.TrimPrefix(p, "/")
			}
			if link, err := normalize.URL(p); err == nil && webextract.SameOrigin(raw, link) && link != raw {
				found = append(found, link)
			}
		}
		for _, op := range webextract.GraphQLOps(s.body) {
			if !opSeen[op] {
				opSeen[op] = true
				ops = append(ops, op)
			}
		}
		for _, ref := range webextract.ScriptRefs(s.body, s.url) {
			queue = c.load(ctx, raw, ref, true, queue, &fetched)
		}
		// Chunks the loader names at run time (webpack chunk maps).
		for _, ch := range webextract.ChunkURLs(s.body) {
			if ref, err := s.url.Parse(ch); err == nil {
				queue = c.load(ctx, raw, ref.String(), true, queue, &fetched)
			}
		}
		if !s.fromMap && len(maps) < maxMaps {
			if m, sources := c.readMap(ctx, raw, webextract.SourceMapURL(s.body, s.url), s.url); m.url != "" {
				maps = append(maps, m)
				queue = append(queue, sources...)
			}
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
	if len(ops) > 0 {
		sort.Strings(ops)
		payload, _ := json.Marshal(map[string]any{"url": raw, "via": "js", "graphql_operations": ops})
		if err := emit(types.Observation{
			Collector: Name, Source: raw, Kind: "graphql",
			Payload: payload, Confidence: 0.7, ObservedAt: time.Now().UTC(),
		}); err != nil {
			return meta, err
		}
		meta.EmitCount++
	}
	for _, m := range maps {
		row := map[string]any{"url": m.url, "via": "js", "role": "sourcemap", "sources": m.count}
		if len(m.files) > 0 {
			row["files"] = m.files
		}
		payload, _ := json.Marshal(row)
		if err := emit(types.Observation{
			Collector: Name, Source: raw, Kind: "url",
			Payload: payload, Confidence: 0.9, ObservedAt: time.Now().UTC(),
		}); err != nil {
			return meta, err
		}
		meta.EmitCount++
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
		if webextract.Hintable(link) && !strings.Contains(link, "{") { // a template is mapped, not requested
			meta.NextHints = append(meta.NextHints, types.Seed{
				Type: types.TypeURL,
				Keys: map[string]string{"url": webextract.RouteKey(link)},
			})
		}
	}
	return meta, nil
}

// vendorScript matches well-known library builds served from the app's own
// origin (react-dom.development.js, jquery-3.6.0.min.js): they are large
// and hold no routes of the app.
var vendorScript = regexp.MustCompile(`(?i)(^|/)(react(-dom)?|jquery(-ui|-migrate)?|bootstrap(\.bundle)?|angular|vue|lodash|moment|popper|d3|three|chart|highcharts|swagger-ui-(bundle|standalone-preset)|polyfills?-legacy)([.-][\w.-]*)?\.js$`)

// load fetches a same-origin script the run has not parsed yet and queues it.
// Names found inside scripts must end in .js; <script src> need not.
func (c *Collector) load(ctx context.Context, page, src string, needExt bool, queue []script, fetched *[]string) []script {
	if len(*fetched) >= maxScripts || !webextract.SameOrigin(page, src) || (needExt && !looksLikeJS(src)) {
		return queue
	}
	if u, err := url.Parse(src); err == nil && vendorScript.MatchString(u.Path) {
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

// readMap fetches a same-origin source map and returns its app sources as
// scripts to read; library sources (node_modules, webpack runtime) are
// counted but not read.
func (c *Collector) readMap(ctx context.Context, page, mapURL string, scriptURL *url.URL) (sourceMap, []script) {
	if mapURL == "" {
		return sourceMap{}, nil
	}
	var body []byte
	if strings.HasPrefix(mapURL, "data:") {
		meta, data, ok := strings.Cut(strings.TrimPrefix(mapURL, "data:"), ",")
		if !ok || !strings.HasSuffix(meta, ";base64") {
			return sourceMap{}, nil
		}
		raw, err := base64.StdEncoding.DecodeString(data)
		if err != nil {
			return sourceMap{}, nil
		}
		body, mapURL = raw, scriptURL.String()+" (inline map)"
	} else {
		if !webextract.SameOrigin(page, mapURL) {
			return sourceMap{}, nil
		}
		if _, done := c.parsed.LoadOrStore(mapURL, true); done {
			return sourceMap{}, nil
		}
		res, _, err := fetch.Do(ctx, c.Client, mapURL)
		if err != nil || res.Status != http.StatusOK {
			return sourceMap{}, nil
		}
		body = res.Body
	}
	var sm struct {
		Sources        []string  `json:"sources"`
		SourcesContent []*string `json:"sourcesContent"`
	}
	if json.Unmarshal(body, &sm) != nil || len(sm.Sources) == 0 {
		return sourceMap{}, nil
	}
	m := sourceMap{url: mapURL, count: len(sm.Sources)}
	var out []script
	for i, name := range sm.Sources {
		if library(name) {
			continue
		}
		if len(m.files) < maxMapFiles {
			m.files = append(m.files, name)
		}
		if i < len(sm.SourcesContent) && sm.SourcesContent[i] != nil {
			out = append(out, script{url: scriptURL, body: *sm.SourcesContent[i], fromMap: true})
		}
	}
	return m, out
}

func library(source string) bool {
	return strings.Contains(source, "node_modules/") || strings.Contains(source, "webpack/") ||
		strings.Contains(source, "(webpack)") || strings.HasPrefix(source, "external ")
}
