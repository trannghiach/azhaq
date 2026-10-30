package jscol

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
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
	maxEmit = 4096
	// maxScripts caps scripts fetched for one page, chunks included.
	maxScripts = 256
	// maxMaps caps source maps read for one page.
	maxMaps = 8
	// maxMapFiles caps the source file names kept per map.
	maxMapFiles = 200
	// maxSites caps the places kept for where one route is named.
	maxSites = 3
	// maxGuessedMaps caps the source maps asked for by name (main.js.map
	// for main.js) on one origin, for scripts that name none.
	maxGuessedMaps = 10
	// maxManifests caps the build manifests read for one page.
	maxManifests = 8
)

// Collector reads the scripts of every page it is given: inline scripts,
// <script src> on the page's site, and the chunks and modules those
// import. A script on another host is read when the run may request that
// host: with a scope, when the scope allows it; without one, when it is
// on the page's registrable domain (fetch.SameSite), as Chrome loads a
// page's resources. Each script URL is fetched and parsed once per run,
// however many pages use it.
type Collector struct {
	Client *http.Client
	// NoMapGuess leaves out the source maps asked for by name next to a
	// bundle that names none (main.js.map); a map a script or a header
	// names is still read. crawl sets it: asking for a name is a guess,
	// not what a crawler sends.
	NoMapGuess bool
	parsed     sync.Map // script, map and manifest URL → true

	mu      sync.Mutex
	guessed map[string]int // origin → source maps asked for by name
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
func (c *Collector) Info() catalog.Info {
	return catalog.Info{Kind: catalog.Touch, After: "azhaq-http"}
}

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
	url       *url.URL
	body      string
	inline    bool   // in the page: relative paths are the page's
	fromMap   bool   // original source from a source map
	source    string // and the file it is
	line, col int    // where an inline script starts in the page
	mapRef    string // the map its SourceMap header names
}

// site is where in s the bytes start..end lie, as a reader finds them:
// an inline script's lines are the page's. A call is shown as written,
// anything else with the code around it.
func (s script) site(loc *webextract.Locator, start, end int, call bool) webextract.Site {
	var st webextract.Site
	if call {
		st = loc.CallSite(s.url.String(), start, end)
	} else {
		st = loc.Site(s.url.String(), start, end)
	}
	if s.inline {
		st.Inline = true
		if st.Line == 1 {
			st.Col += s.col - 1
		}
		st.Line += s.line - 1
	}
	if s.fromMap {
		st.Source = s.source
	}
	return st
}

// sites keeps a few places per route.
type sites map[string][]webextract.Site

// add keeps where start..end of s names route k, until k has maxSites:
// past that the place is not worked out at all.
func (m sites) add(k string, s script, loc *webextract.Locator, start, end int, call bool) {
	if len(m[k]) >= maxSites {
		return
	}
	st := s.site(loc, start, end, call)
	for _, x := range m[k] {
		if x.Script == st.Script && x.Source == st.Source && x.Line == st.Line && x.Col == st.Col {
			return
		}
	}
	m[k] = append(m[k], st)
}

// sourceMap is what a map says about the code behind a bundle.
type sourceMap struct {
	url     string
	files   []string // the app's own source files, libraries left out
	count   int      // all sources, libraries included
	guessed bool     // asked for by name: no comment or header named it
}

// buildManifest is a bundler's manifest that was read, and what it gave.
type buildManifest struct {
	url            string
	kind           string   // vite, cra, ngsw, nuxt
	files          []string // source files it names (Vite)
	scripts, pages int
}

// clientViews are the views the app's router draws, by path, in the order
// found.
type clientViews struct {
	order []string
	guard map[string]string
	at    sites
}

func (v *clientViews) add(path, guard string) {
	if g, ok := v.guard[path]; ok {
		if g == "" {
			v.guard[path] = guard
		}
		return
	}
	v.order = append(v.order, path)
	v.guard[path] = guard
}

// match is the view a link to path opens: the view of that path, or one
// that takes a parameter after it (/chatbot/conversation for
// /chatbot/conversation/{id}, as router.navigate([path, id]) builds it).
func (v *clientViews) match(path string) (string, bool) {
	if _, ok := v.guard[path]; ok {
		return path, true
	}
	for _, p := range v.order {
		if rest, ok := strings.CutPrefix(p, path+"/{"); ok && strings.HasSuffix(rest, "}") && !strings.Contains(rest, "/") {
			return p, true
		}
	}
	return "", false
}

// socket is a WebSocket endpoint as the map keys it: ws:// or wss://.
type socket struct {
	url                 string
	namespace           string
	socketIO, isDefault bool
	sites               []webextract.Site
}

// merge takes what another sighting of the same endpoint says: an app's
// own call over the library's default, a namespace once known.
func (k *socket) merge(o socket) {
	k.socketIO = k.socketIO || o.socketIO
	if !o.isDefault {
		k.isDefault = false
	}
	if k.namespace == "" {
		k.namespace = o.namespace
	}
}

// socketKey is where a socket connects, as ws:// or wss://: the page's
// host for a path, its scheme from the script when it says.
func socketKey(w webextract.Socket, page *url.URL) (socket, bool) {
	raw := w.URL
	if !strings.Contains(raw, "://") {
		scheme := w.Scheme
		if scheme == "" {
			scheme = map[bool]string{true: "wss", false: "ws"}[page.Scheme == "https"]
		}
		raw = scheme + "://" + page.Host + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return socket{}, false
	}
	switch u.Scheme {
	case "http":
		u.Scheme = "ws"
	case "https":
		u.Scheme = "wss"
	case "ws", "wss":
	default:
		return socket{}, false
	}
	if h := u.Hostname(); (h == "0.0.0.0" || h == "::") && portOf(u) == portOf(page) {
		// ws://0.0.0.0:5013/subscriptions, as a server's own template
		// writes its listening address: the page's server.
		u.Host = page.Host
	}
	u.RawQuery, u.Fragment = "", ""
	u.Path = strings.TrimSuffix(u.Path, "/")
	n, err := normalize.URL(u.String())
	if err != nil {
		return socket{}, false
	}
	return socket{url: n, namespace: w.Namespace, socketIO: w.SocketIO, isDefault: w.Default}, true
}

// portOf is u's port, its scheme's when it names none.
func portOf(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	if u.Scheme == "https" || u.Scheme == "wss" {
		return "443"
	}
	return "80"
}

// clientURL is the URL a browser shows for a view: after # when the app
// routes by the hash (http://host/#/administration), else its path.
func clientURL(root *url.URL, hash bool, path string) string {
	if hash {
		return root.String() + "#" + path
	}
	u := *root
	u.Path = strings.TrimSuffix(root.Path, "/") + path
	n, err := normalize.URL(u.String())
	if err != nil {
		return u.String()
	}
	return n
}

// viewOf is the router path a link on the app's own origin names, from
// the app's root: /accounting for http://host/accounting.
func viewOf(root *url.URL, link string) (string, bool) {
	u, err := url.Parse(link)
	if err != nil || u.Scheme != root.Scheme || u.Host != root.Host || u.RawQuery != "" || !strings.HasPrefix(u.Path, root.Path) {
		return "", false
	}
	p := "/" + strings.Trim(strings.TrimPrefix(u.Path, root.Path), "/")
	return p, p != "/"
}

// inRoutes says whether a string at i is a route table's path.
func inRoutes(rs []webextract.ClientRoute, i int) bool {
	for _, r := range rs {
		if i >= r.Start && i < r.End {
			return true
		}
	}
	return false
}

// keepString says whether a URL a script names is a row of the page's
// map: one on the page's origin, or an API route on another host the run
// may request (https://api.example.com/v1/users in a bundle of
// www.example.com). Other links to other hosts are left to their own
// pages.
func keepString(page, link string) bool {
	if partial(link) {
		return false
	}
	if webextract.SameOrigin(page, link) {
		return true
	}
	return webextract.ClassifyURL(link) == "api" && fetch.SameSite(page, link)
}

// setFrom names the script a route on another origin was found in: its
// FOUND link comes from that script, not from the page that loaded it.
func setFrom(row map[string]any, page string, at []webextract.Site) {
	link, _ := row["url"].(string)
	if s, ok := strings.CutPrefix(link, "ws"); ok && (strings.HasPrefix(s, "://") || strings.HasPrefix(s, "s://")) {
		link = "http" + s // a socket of the page's server is the page's
	}
	if len(at) == 0 || webextract.SameOrigin(page, link) || at[0].Script == "" || at[0].Script == page {
		return
	}
	row["from"] = at[0].Script
}

func addSites(xs, ys []webextract.Site) []webextract.Site {
	for _, y := range ys {
		dup := false
		for _, x := range xs {
			if x.Script == y.Script && x.Source == y.Source && x.Line == y.Line && x.Col == y.Col {
				dup = true
				break
			}
		}
		if !dup && len(xs) < maxSites {
			xs = append(xs, y)
		}
	}
	return xs
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
	var found []string
	tails := map[string]bool{} // named only joined to a base: this.host+`/orders`
	var mans []buildManifest
	var maps []sourceMap
	appRoot := &url.URL{Scheme: base.Scheme, Host: base.Host, Path: "/"} // where the app's router takes its paths from
	origin := base.Scheme + "://" + base.Host
	// readManifests reads the build manifests a page or a script points
	// to: a script one (Next.js) is read as a script; a JSON one has its
	// scripts queued, its maps read and its pages kept.
	var readManifests func(refs []string)
	readManifests = func(refs []string) {
		for _, ref := range refs {
			if looksLikeJS(ref) {
				queue = c.load(ctx, raw, ref, false, queue, &fetched)
				continue
			}
			if len(mans) >= maxManifests {
				return
			}
			m, ok := c.readManifest(ctx, raw, ref)
			if !ok {
				continue
			}
			if m.BuildID != "" {
				readManifests([]string{webextract.NuxtMeta(ref, m.BuildID)})
				continue
			}
			mb := manifestBase(ref)
			bm := buildManifest{url: ref, kind: m.Kind, files: m.Sources}
			for _, f := range m.Scripts {
				if u, err := mb.Parse(f); err == nil {
					bm.scripts++
					queue = c.load(ctx, raw, u.String(), true, queue, &fetched)
				}
			}
			// A map the manifest lists is asked for out of the origin's
			// budget for maps no script named: a build that left forty
			// .map entries behind and none of the files costs ten GETs.
			for _, f := range m.Maps {
				u, err := mb.Parse(f)
				if err != nil || len(maps) >= maxMaps {
					continue
				}
				if _, done := c.parsed.Load(u.String()); done {
					continue
				}
				js, err := url.Parse(strings.TrimSuffix(u.String(), ".map"))
				if err != nil || !c.mapTry(u.Scheme+"://"+u.Host) {
					continue
				}
				if sm, sources := c.readMap(ctx, raw, u.String(), js, false); sm.url != "" {
					maps = append(maps, sm)
					queue = append(queue, sources...)
				}
			}
			for _, p := range m.Pages {
				if u, err := appRoot.Parse(strings.TrimPrefix(p, "/")); err == nil {
					if n, err := normalize.URL(u.String()); err == nil {
						bm.pages++
						found = append(found, n)
					}
				}
			}
			mans = append(mans, bm)
		}
	}
	switch {
	case isJS:
		c.parsed.Store(final, true)
		queue = append(queue, script{url: base, body: string(res.Body), mapRef: headerMap(res.Header, base)})
	case strings.Contains(ct, "html") || ct == "":
		if fetch.ErrorPage(res) {
			return types.RunMeta{Status: types.StatusOK}, nil
		}
		if fetch.FinalCatchAll(ctx, c.Client, res) {
			// The generic shell: its scripts were read from the real page.
			return types.RunMeta{Status: types.StatusOK}, nil
		}
		appRoot = webextract.AppRoot(res.Body, base)
		for _, in := range webextract.InlineScriptsAt(res.Body) {
			queue = append(queue, script{url: base, body: in.Text, inline: true, line: in.Line, col: in.Col})
		}
		srcs := webextract.ScriptSrcs(res.Body, base)
		for _, src := range srcs {
			queue = c.load(ctx, raw, src, false, queue, &fetched)
		}
		readManifests(webextract.PageManifests(res.Body, base, srcs))
	default:
		return types.RunMeta{Status: types.StatusOK}, nil
	}

	var calls []webextract.Call
	var ops []string
	opSeen := map[string]bool{}
	var secrets []map[string]any
	secretSeen := map[string]bool{}
	named, called := sites{}, sites{} // route → where scripts name it, and call it
	views := clientViews{guard: map[string]string{}, at: sites{}}
	var cands []strCand
	var socks []socket
	sockAt := map[string]int{}
	hash := false
	for i := 0; i < len(queue); i++ {
		if ctx.Err() != nil {
			return types.RunMeta{Status: types.StatusCancelled}, ctx.Err()
		}
		s := queue[i]
		loc := webextract.NewLocator(s.body)
		routes := webextract.ClientRoutes(s.body)
		ws := webextract.WebSockets(s.body)
		for _, r := range routes {
			views.add(r.Path, r.Guard)
			views.at.add(r.Path, s, loc, r.Start, r.End, false)
		}
		hash = hash || webextract.HashRouting(s.body)
		for _, w := range ws {
			k, ok := socketKey(w, base)
			if !ok || !fetch.SameSite(raw, k.url) {
				continue // a third party's service (a chat widget, analytics)
			}
			j, seen := sockAt[k.url]
			if !seen {
				j = len(socks)
				sockAt[k.url] = j
				socks = append(socks, k)
			}
			socks[j].merge(k)
			if len(socks[j].sites) < maxSites {
				socks[j].sites = append(socks[j].sites, s.site(loc, w.Start, w.End, !w.Default))
			}
		}
		// A path in a script on another host is still one the page's
		// requests go to.
		refBase := s.url
		if !webextract.SameOrigin(raw, s.url.String()) {
			refBase = base
		}
		specStart, specEnd := webextract.EmbeddedSpec(s.body)
		for _, r := range webextract.JSURLRefs(s.body, refBase) {
			if r.URL == raw || inRoutes(routes, r.Start) || webextract.InSocket(ws, r.Start) || !keepString(raw, r.URL) {
				continue
			}
			if r.Start >= specStart && r.Start < specEnd && jsonKey(s.body, r.End) {
				continue // a path of the description ("/orders": {…}), under its servers: azhaq-openapi reads it
			}
			if _, seen := tails[r.URL]; !seen || !r.Joined {
				tails[r.URL] = r.Joined
			}
			found = append(found, r.URL)
			named.add(webextract.RouteKey(r.URL), s, loc, r.Start, r.End, false)
		}
		if !s.fromMap && !s.inline && strings.Contains(s.body, "<") {
			// Markup a script carries (an Angular template, a string of
			// HTML): its links are the app's; one built from an expression
			// (src="`+_(i[8])+`") is no URL.
			for _, ref := range webextract.LinkRefs([]byte(s.body), s.url) {
				if ref.Method != "" {
					continue
				}
				cands = append(cands, strCand{Cand: markupCand(ref, base), s: s, loc: loc})
			}
		}
		if !s.fromMap {
			for _, cd := range webextract.Candidates(s.body, base, s.url, !strings.HasSuffix(strings.ToLower(s.url.Path), ".css")) {
				cands = append(cands, strCand{cd, s, loc})
			}
		}
		// Paths joined from constants are relative to the app's root,
		// where single-page apps send their requests from.
		for _, r := range webextract.AssembledRefs(s.body) {
			p := r.URL
			if !strings.HasPrefix(p, "http") {
				p = origin + "/" + strings.TrimPrefix(p, "/")
			}
			if link, err := normalize.URL(p); err == nil && webextract.SameOrigin(raw, link) && link != raw {
				found = append(found, link)
				named.add(webextract.RouteKey(link), s, loc, r.Start, r.End, false)
			}
		}
		var cs []webextract.Call
		if s.inline {
			for _, c := range webextract.PageCalls(s.body) {
				if !strings.HasPrefix(c.Path, "/") && !strings.HasPrefix(c.Path, "http://") && !strings.HasPrefix(c.Path, "https://") {
					ref, err := s.url.Parse(c.Path)
					if err != nil {
						continue
					}
					c.Path = ref.String()
				}
				cs = append(cs, c)
			}
		} else {
			cs = webextract.Calls(s.body)
		}
		for _, c := range cs {
			if k, ok := callRoute(c, origin, raw); ok {
				called.add(k, s, loc, c.At, c.End, true)
			}
		}
		calls = append(calls, cs...)
		for _, sec := range webextract.Secrets(s.body) {
			if !secretSeen[sec.Value] && len(secrets) < 100 {
				secretSeen[sec.Value] = true
				row := map[string]any{"kind": sec.Kind, "severity": sec.Severity, "value": sec.Value, "script": s.url.String()}
				if sec.Name != "" {
					row["name"] = sec.Name
				}
				secrets = append(secrets, row)
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
		if !s.fromMap && !s.inline {
			readManifests(webextract.ScriptManifests(s.body, s.url, appRoot))
		}
		if !s.fromMap && len(maps) < maxMaps {
			ref, guessed := webextract.SourceMapURL(s.body, s.url), false
			if ref == "" {
				ref = s.mapRef
			}
			if ref == "" && !s.inline && !c.NoMapGuess {
				ref, guessed = c.guessMap(s.url), true
			}
			if m, sources := c.readMap(ctx, raw, ref, s.url, guessed); m.url != "" {
				maps = append(maps, m)
				queue = append(queue, sources...)
			}
		}
	}

	meta := types.RunMeta{Status: types.StatusOK}
	// The strings katana's patterns take from the scripts: a page the app
	// serves under a bare name (users.php, admin/) is a URL; the others are
	// kept as rejected, with why, and never requested.
	have := map[string]bool{}
	for _, l := range found {
		have[l] = true
	}
	for _, cl := range calls {
		if k, ok := callRoute(cl, origin, raw); ok {
			have[k] = true
		}
	}
	rejSeen := map[string]bool{}
	for _, cd := range cands {
		reason := cd.Reason
		switch {
		case cd.Link != "" && have[cd.Link]:
			continue
		case reason == "" && vendorScript.MatchString(cd.s.url.Path):
			reason = webextract.ReasonLibrary
		case reason == "" && !keepString(raw, cd.Link):
			reason = webextract.ReasonOtherHost
		case reason == "" && partial(cd.Link):
			reason = webextract.ReasonExpression
		}
		if reason == "" {
			have[cd.Link] = true
			found = append(found, cd.Link)
			named.add(webextract.RouteKey(cd.Link), cd.s, cd.loc, cd.Start, cd.End, false)
			if cd.Alt != "" && !have[cd.Alt] {
				if k := cd.Alt + "\x00alt"; !rejSeen[k] {
					rejSeen[k] = true
					if err := emit(webextract.RejectedObs(Name, raw, cd.Text, webextract.ReasonScriptRel, "js", cd.Alt)); err != nil {
						return meta, err
					}
					meta.EmitCount++
				}
			}
			continue
		}
		if cd.Link != "" || cd.Resolved != "" {
			if u := cd.Resolved; u != "" && have[u] {
				continue // the URL is one the page names another way
			}
		}
		if k := cd.Text + "\x00" + reason; !rejSeen[k] {
			rejSeen[k] = true
			if err := emit(webextract.RejectedObs(Name, raw, cd.Text, reason, "js", cd.Resolved)); err != nil {
				return meta, err
			}
			meta.EmitCount++
		}
		if cd.Alt != "" && !have[cd.Alt] {
			if k := cd.Alt + "\x00alt"; !rejSeen[k] {
				rejSeen[k] = true
				if err := emit(webextract.RejectedObs(Name, raw, cd.Text, webextract.ReasonScriptRel, "js", cd.Alt)); err != nil {
					return meta, err
				}
				meta.EmitCount++
			}
		}
	}
	emitRow := func(row map[string]any, conf float64) error {
		payload, _ := json.Marshal(row)
		if err := emit(types.Observation{Collector: Name, Source: raw, Kind: "url", Payload: payload, Confidence: conf, ObservedAt: time.Now().UTC()}); err != nil {
			return err
		}
		meta.EmitCount++
		return nil
	}
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
		if at := named[webextract.RouteKey(link)]; role != "script" && len(at) > 0 {
			row["found_in"] = at
			setFrom(row, raw, at)
		}
		return emitRow(row, 0.7)
	}
	if len(secrets) > 0 {
		payload, _ := json.Marshal(map[string]any{"url": raw, "via": "js", "secrets": secrets})
		if err := emit(types.Observation{
			Collector: Name, Source: raw, Kind: "secrets",
			Payload: payload, Confidence: 0.8, ObservedAt: time.Now().UTC(),
		}); err != nil {
			return meta, err
		}
		meta.EmitCount++
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
		if m.guessed {
			row["guessed"] = true
		}
		if err := emitRow(row, 0.9); err != nil {
			return meta, err
		}
	}
	for _, m := range mans {
		row := map[string]any{"url": m.url, "via": "js", "role": "manifest", "framework": m.kind, "scripts": m.scripts}
		if m.pages > 0 {
			row["pages"] = m.pages
		}
		if len(m.files) > 0 {
			row["files"] = m.files[:min(len(m.files), maxMapFiles)]
		}
		if err := emitRow(row, 0.9); err != nil {
			return meta, err
		}
	}
	// The views the app's router draws: rows of their own. A string that
	// names one is a link to it. A view after the hash is never requested
	// (the server answers each with the app's shell); one in the path is
	// asked for once, as the server may answer it itself (a sign-in, a
	// page it renders), and a shell answer leaves the row as it is.
	for _, p := range views.order {
		if meta.EmitCount >= maxEmit {
			break
		}
		view := clientURL(appRoot, hash, p)
		row := map[string]any{"url": view, "via": "js", "role": "client-route"}
		if g := views.guard[p]; g != "" {
			row["guard"] = g
		}
		at := views.at[p]
		for _, link := range found {
			if v, ok := viewOf(appRoot, link); ok {
				if m, ok := views.match(v); ok && m == p {
					at = addSites(at, named[webextract.RouteKey(link)])
				}
			}
		}
		if len(at) > 0 {
			row["found_in"] = at
		}
		if err := emitRow(row, 0.8); err != nil {
			return meta, err
		}
		if !hash && !strings.Contains(p, "{") && webextract.Hintable(view) {
			meta.NextHints = append(meta.NextHints, types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": view}})
		}
	}
	// WebSocket endpoints: not pages, never requested. socket.io's
	// default path counts when no call of the app's says otherwise.
	explicit := false
	for _, k := range socks {
		explicit = explicit || k.socketIO && !k.isDefault
	}
	for _, k := range socks {
		if meta.EmitCount >= maxEmit || k.isDefault && explicit {
			continue
		}
		row := map[string]any{"url": k.url, "via": "js", "role": "websocket"}
		if k.socketIO {
			row["protocol"] = "socket.io"
			if k.namespace != "" {
				row["namespace"] = k.namespace
			}
		}
		if len(k.sites) > 0 {
			row["found_in"] = k.sites
			setFrom(row, raw, k.sites)
		}
		if err := emitRow(row, 0.8); err != nil {
			return meta, err
		}
	}
	// Requests the scripts make: method, path and the names they send.
	// A route called with GET is fetched like any other found route; one
	// whose method only a run-time value gives is listed without one.
	callOps := map[string][]map[string]any{}
	var opOrder []string
	gets := map[string]bool{}
	params, body := map[string][]string{}, map[string][]string{} // route → names sent, whatever the method
	for _, c := range webextract.MergeCalls(calls) {
		k, ok := callRoute(c, origin, raw)
		if !ok {
			continue
		}
		if _, ok := callOps[k]; !ok {
			callOps[k] = nil
			opOrder = append(opOrder, k)
		}
		params[k] = addAll(params[k], c.Query...)
		body[k] = addAll(body[k], c.Body...)
		if c.Method == "" {
			continue
		}
		op := map[string]any{"method": c.Method}
		if len(c.Query) > 0 {
			op["query"] = c.Query
		}
		if len(c.Body) > 0 {
			op["body"] = c.Body
		}
		callOps[k] = append(callOps[k], op)
		if c.Method == "GET" {
			gets[k] = true
		}
	}
	for _, k := range opOrder {
		if meta.EmitCount >= maxEmit {
			break
		}
		var methods []string
		for _, op := range callOps[k] {
			methods = addAll(methods, op["method"].(string))
		}
		row := map[string]any{"url": k, "via": "js-call", "role": "api"}
		if len(methods) > 0 {
			row["methods"], row["ops"] = methods, callOps[k]
		}
		if len(params[k]) > 0 {
			row["params"] = params[k]
		}
		if len(body[k]) > 0 {
			row["body"] = body[k]
		}
		if len(called[k]) > 0 {
			row["found_in"] = called[k]
			setFrom(row, raw, called[k])
		}
		if err := emitRow(row, 0.8); err != nil {
			return meta, err
		}
		if gets[k] && !strings.Contains(k, "{") && webextract.Hintable(k) {
			meta.NextHints = append(meta.NextHints, types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": k}})
		}
	}
	if len(fetched) >= maxScripts || meta.EmitCount >= maxEmit {
		payload, _ := json.Marshal(map[string]any{"url": raw, "via": "js",
			"warning": fmt.Sprintf("the scripts of %s hold more than Azhaq reads from one page (%d scripts, %d routes): some were left unread", raw, maxScripts, maxEmit)})
		if err := emit(types.Observation{Collector: Name, Source: raw, Kind: "note", Payload: payload, Confidence: 1, ObservedAt: time.Now().UTC()}); err != nil {
			return meta, err
		}
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
		if tails[link] && tailOf(link, callOps) {
			continue // this.host+`/orders`: the call says where its base put it
		}
		if v, ok := viewOf(appRoot, link); ok {
			if _, ok := views.match(v); ok {
				continue // a link to one of the app's views: its row, and its hint, are above
			}
		}
		if u, err := url.Parse(link); err == nil && (webextract.SocketPath(u.Path) || webextract.NextInternal(u.Path)) {
			continue // socket.io's or Next.js's own, not a page
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

// markupCand judges a URL read from markup inside a script. A browser
// resolves it against the page; the reading against the script's own file,
// where it differs, is the Alt a crawler that resolves that way would ask.
func markupCand(ref webextract.PageRef, page *url.URL) webextract.Cand {
	c := webextract.Cand{Str: webextract.Str{Text: ref.Raw}, Resolved: ref.URL}
	if u, ok := webextract.ResolveRef(page, ref.Raw); ok {
		c.Resolved = u
		if u != ref.URL {
			c.Alt = ref.URL
		}
	}
	dec, err := url.PathUnescape(c.Resolved)
	switch {
	case err != nil || strings.ContainsAny(dec, "`()[]{}|+$\\<>'") || webextract.JunkURL(c.Resolved):
		c.Reason = webextract.ReasonExpression
	case ref.Attr == "handler":
		c.Reason = webextract.ReasonNotPath
	default:
		c.Link = c.Resolved
	}
	return c
}

// strCand is a string read from a script, and the script it is in.
type strCand struct {
	webextract.Cand
	s   script
	loc *webextract.Locator
}

// vendorScript matches well-known library builds served from the app's own
// origin (react-dom.development.js, jquery-3.6.0.min.js): they are large
// and hold no routes of the app.
var vendorScript = regexp.MustCompile(`(?i)(^|/)(react(-dom)?|jquery(-ui|-migrate)?|bootstrap(\.bundle)?|angular|vue|lodash|moment|popper|d3|three|chart|highcharts|swagger-ui-(bundle|standalone-preset)|polyfills?-legacy)([.-][\w.-]*)?\.js$`)

// load fetches a script on the page's site the run has not parsed yet and
// queues it. Names found inside scripts must end in .js; <script src>
// need not.
func (c *Collector) load(ctx context.Context, page, src string, needExt bool, queue []script, fetched *[]string) []script {
	if len(*fetched) >= maxScripts || !fetch.SameSite(page, src) || (needExt && !looksLikeJS(src)) {
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
	return append(queue, script{url: u, body: string(res.Body), mapRef: headerMap(res.Header, u)})
}

// headerMap is the source map a script's response names in its SourceMap
// header (X-SourceMap before it), or "".
func headerMap(h http.Header, scriptURL *url.URL) string {
	ref := h.Get("SourceMap")
	if ref == "" {
		ref = h.Get("X-SourceMap")
	}
	if ref = strings.TrimSpace(ref); ref == "" || scriptURL == nil {
		return ""
	}
	u, err := scriptURL.Parse(ref)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return ""
	}
	return u.String()
}

// guessMap is the source map a bundle that names none would have next to
// it (main.js.map for main.js), while its origin has guesses left; "".
func (c *Collector) guessMap(scriptURL *url.URL) string {
	u := *scriptURL
	u.RawQuery, u.Fragment = "", ""
	u.Path += ".map"
	ref := u.String()
	if _, done := c.parsed.Load(ref); done {
		return ""
	}
	if !c.mapTry(u.Scheme + "://" + u.Host) {
		return ""
	}
	return ref
}

// mapTry takes one of the maxGuessedMaps requests an origin has for maps
// no script of its own named: guessed by name, or listed by a manifest.
func (c *Collector) mapTry(origin string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.guessed == nil {
		c.guessed = map[string]int{}
	}
	if c.guessed[origin] >= maxGuessedMaps {
		return false
	}
	c.guessed[origin]++
	return true
}

// readManifest fetches a JSON build manifest on the page's site, once
// per run.
func (c *Collector) readManifest(ctx context.Context, page, ref string) (webextract.Manifest, bool) {
	if !fetch.SameSite(page, ref) {
		return webextract.Manifest{}, false
	}
	if _, done := c.parsed.LoadOrStore(ref, true); done {
		return webextract.Manifest{}, false
	}
	res, _, err := fetch.Do(ctx, c.Client, ref)
	if err != nil || res.Status != http.StatusOK || strings.Contains(strings.ToLower(res.Header.Get("Content-Type")), "html") {
		return webextract.Manifest{}, false
	}
	return webextract.ReadManifest(res.Body)
}

// manifestBase is what the files a manifest lists are relative to: its
// folder, or the build's root for Vite's .vite/manifest.json.
func manifestBase(ref string) *url.URL {
	u, err := url.Parse(ref)
	if err != nil {
		return &url.URL{}
	}
	u.RawQuery = ""
	u.Path = strings.TrimSuffix(u.Path[:strings.LastIndex(u.Path, "/")+1], ".vite/")
	return u
}

// callRoute is the route a call goes to, when it stays on the page's
// site: a call to another host the run may request is a route of that
// host's.
func callRoute(c webextract.Call, origin, page string) (string, bool) {
	link := c.Path
	if strings.HasPrefix(link, "/") {
		link = origin + link
	}
	if partial(link) {
		return "", false
	}
	n, err := normalize.URL(link)
	if err != nil || !fetch.SameSite(page, n) {
		return "", false
	}
	return webextract.RouteKey(n), true
}

// jsonKey says whether the string ending at i is a key of a JSON object.
func jsonKey(src string, i int) bool {
	for ; i < len(src) && strings.ContainsRune(" \t\r\n", rune(src[i])); i++ {
	}
	return i < len(src) && src[i] == ':'
}

// tailOf says whether link, a path a script joins to a base it does not
// spell out, is the tail of a route a call builds under a prefix
// (/rest/order-history/orders for `/orders`) and of no call at the root:
// a GET at the root would ask the catch-all page for it.
func tailOf(link string, calls map[string][]map[string]any) bool {
	u, err := url.Parse(link)
	if err != nil || u.Path == "" || u.Path == "/" {
		return false
	}
	origin := u.Scheme + "://" + u.Host
	if _, root := calls[link]; root {
		return false
	}
	for k := range calls {
		if strings.HasPrefix(k, origin+"/") && strings.HasSuffix(k, u.Path) && len(k) > len(origin)+len(u.Path) {
			return true
		}
	}
	return false
}

// partial says whether a URL a script builds was worked out only as far
// as its authority: 'http://127.0.0.1:' + port + '/x' with the port
// unknown reads "http://127.0.0.1:", a route of no host. An authority
// that ends in : or . is one, and so is a scheme with no host.
func partial(link string) bool {
	u, err := url.Parse(link)
	if err != nil || u.Scheme == "" {
		return false // a path: whatever it is, it is the page's
	}
	h := u.Host
	return h == "" || strings.HasSuffix(h, ":") || strings.HasSuffix(h, ".") || u.Hostname() == ""
}

func addAll(xs []string, ys ...string) []string {
	for _, y := range ys {
		dup := false
		for _, x := range xs {
			if x == y {
				dup = true
				break
			}
		}
		if !dup {
			xs = append(xs, y)
		}
	}
	return xs
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

// readMap fetches a source map on the page's site and returns its app
// sources as scripts to read; library sources (node_modules, webpack
// runtime) are counted but not read. A guessed map counts only when it
// is one: JSON with sources and mappings.
func (c *Collector) readMap(ctx context.Context, page, mapURL string, scriptURL *url.URL, guessed bool) (sourceMap, []script) {
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
		if !fetch.SameSite(page, mapURL) {
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
		Mappings       *string   `json:"mappings"`
	}
	if json.Unmarshal(body, &sm) != nil || len(sm.Sources) == 0 || guessed && sm.Mappings == nil {
		return sourceMap{}, nil
	}
	m := sourceMap{url: mapURL, count: len(sm.Sources), guessed: guessed}
	var out []script
	for i, name := range sm.Sources {
		if library(name) {
			continue
		}
		if len(m.files) < maxMapFiles {
			m.files = append(m.files, name)
		}
		if i < len(sm.SourcesContent) && sm.SourcesContent[i] != nil {
			out = append(out, script{url: scriptURL, body: *sm.SourcesContent[i], fromMap: true, source: name})
		}
	}
	return m, out
}

func library(source string) bool {
	return strings.Contains(source, "node_modules/") || strings.Contains(source, "webpack/") ||
		strings.Contains(source, "(webpack)") || strings.HasPrefix(source, "external ")
}
