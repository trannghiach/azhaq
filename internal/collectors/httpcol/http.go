package httpcol

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/time/rate"

	"github.com/trannghiach/azhaq/catalog"
	"github.com/trannghiach/azhaq/internal/fetch"
	"github.com/trannghiach/azhaq/internal/fingerprint"
	"github.com/trannghiach/azhaq/internal/neterr"
	"github.com/trannghiach/azhaq/internal/normalize"
	"github.com/trannghiach/azhaq/internal/takeover"
	"github.com/trannghiach/azhaq/internal/webextract"
	"github.com/trannghiach/azhaq/types"
)

const Name = "azhaq-http"

var titleRE = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

type Collector struct {
	Client *http.Client
	// Ports are the web ports tried on each hostname, HTTPS first (HTTP
	// first on 80). Empty: https://host/, falling back to http://host/.
	Ports []int
	// Only restricts the schemes tried on a name, an address or a host:port
	// to "http" or "https"; empty tries HTTPS, then HTTP. A URL given with
	// its scheme is fetched as given.
	Only string
	// NoFavicon skips the favicon request on root pages.
	NoFavicon bool
	// NoTech skips technology fingerprints (about 30 MB of memory).
	NoTech bool
	// Probe answers like httpx: one request per service, no catch-all
	// check (nothing is crawled from it).
	Probe bool
	// Spec is azhaq probe's own: httpx's flags. Nil answers as a run does.
	Spec *Spec

	emitted sync.Map // URLs already reported in this run
	ownURL  sync.Map // URLs reported by their own URL task

	turnOnce sync.Once
	turns    *rate.Limiter // Spec.TargetRate
}

// turn waits for a service's turn under -rl.
func (c *Collector) turn(ctx context.Context) error {
	if c.Spec == nil || c.Spec.TargetRate <= 0 {
		return nil
	}
	c.turnOnce.Do(func() { c.turns = rate.NewLimiter(rate.Limit(c.Spec.TargetRate), 1) })
	return c.turns.Wait(ctx)
}

func New(client *http.Client) *Collector {
	return &Collector{Client: fetch.Client(client)}
}

func Register(cat *catalog.Catalog, client *http.Client) {
	cat.MustRegister(New(client))
}

func (c *Collector) Name() string { return Name }

// Info: this collector sends requests to the target, and for a hostname
// waits for DNS so names that do not resolve are never probed.
func (c *Collector) Info() catalog.Info {
	return catalog.Info{Kind: catalog.Touch, After: "azhaq-dns"}
}

func (c *Collector) Inputs() []types.SeedType {
	return []types.SeedType{types.TypeURL, types.TypeHostname, types.TypeIPAddress}
}

// Skip: an address is probed when it came from a network (-asn, -cidr);
// the address behind a URL is probed through the URL.
func (c *Collector) Skip(seed types.Seed) bool {
	if c.Spec != nil && seed.Type == types.TypeHostname && !slices.Contains(c.Spec.Bare, strings.ToLower(seed.Keys["fqdn"])) {
		return true // probe: a name met in a URL given is not asked on ports nobody named
	}
	return seed.Type == types.TypeIPAddress && seed.Keys["from"] != "prefix"
}

func (c *Collector) Outputs() []string { return []string{"application"} }

func (c *Collector) Run(ctx context.Context, seed types.Seed, emit func(types.Observation) error) (types.RunMeta, error) {
	groups := c.targets(seed)
	if seed.Type == types.TypeURL && len(groups) == 0 {
		return types.RunMeta{Status: types.StatusError, Error: "invalid url"}, fmt.Errorf("invalid url")
	}
	meta := types.RunMeta{Status: types.StatusOK}
	var lastErr error
	answered := false
	answeredURL := ""
	// Each group is one service (a port); its URLs are tried in order and
	// the first that answers stands for it.
	variants := c.variants(groups0(groups))
	for _, group := range groups {
		if err := c.turn(ctx); err != nil {
			return types.RunMeta{Status: types.StatusCancelled}, err
		}
		for gi, raw := range group {
			if ctx.Err() != nil {
				return meta, ctx.Err()
			}
			if why := c.excluded(ctx, raw); why != "" {
				lastErr = fmt.Errorf("not requested: %s", why)
				continue
			}
			obs, hint, _, err := c.fetch(ctx, raw, variants[0])
			if err != nil {
				lastErr = err
				continue
			}
			if c.Spec != nil && gi == 0 && len(group) > 1 && strings.HasPrefix(raw, "http://") && statusOf(obs) == http.StatusBadRequest {
				// A plain request to a TLS port is answered 400: ask again over
				// TLS, as httpx does, and keep the 400 when that does not answer.
				if o2, h2, _, err := c.fetch(ctx, group[1], variants[0]); err == nil {
					raw, obs, hint = group[1], o2, h2
				}
			}
			answered = true
			answeredURL = raw
			// An answer is reported once per URL by a URL's own task, which
			// the map row of that URL reads; a name's task reports it when no
			// task has (one cached from a redirect hop, tesla.com →
			// www.tesla.com, never was), without keeping the URL's own task
			// from recording it on its URL.
			// Probe answers each input in a row of its own, so two inputs
			// that reach one URL (a name and its URL) both report it.
			once := c.Spec == nil
			if seed.Type == types.TypeURL {
				if _, dup := c.ownURL.LoadOrStore(obs.Source, true); dup && once {
					break
				}
				c.emitted.Store(obs.Source, true)
			} else if _, dup := c.emitted.LoadOrStore(obs.Source, true); dup && once {
				break
			}
			if err := emit(obs); err != nil {
				return meta, err
			}
			meta.EmitCount++
			if hint.Key() != "" && c.Spec == nil {
				meta.NextHints = append(meta.NextHints, hint)
			}
			for _, n := range TakeNames(obs.Source) {
				meta.NextHints = append(meta.NextHints, types.Seed{Type: types.TypeHostname, Keys: map[string]string{"fqdn": n}})
			}
			// Other methods of -x, and the other addresses of -pa, go to the URL
			// that answered, one request each.
			for _, rq := range c.more(ctx, raw, variants) {
				o, _, _, err := c.fetch(ctx, raw, rq)
				if err != nil {
					lastErr = err
					continue
				}
				if _, dup := c.emitted.LoadOrStore(o.Source, true); dup && once {
					continue
				}
				if err := emit(o); err != nil {
					return meta, err
				}
				meta.EmitCount++
			}
			break
		}
	}
	if seed.Type == types.TypeURL && seed.Keys[FallbackKey] != "" && len(groups) == 1 && c.Spec == nil {
		// Input like host:port: the scheme that answered goes on as its own
		// URL, and the guess is dropped so the other collectors read the
		// page that exists.
		if u, err := normalize.URL(seed.Keys["url"]); err == nil && answeredURL != "" && answeredURL != u {
			meta.Drop = true
			hint := types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": answeredURL, types.SameTargetKey: "1"}}
			if seed.Keys[types.StartKey] != "" {
				hint.Keys[types.StartKey] = "1" // a sweep goes on from the path the user gave
			}
			meta.NextHints = append(meta.NextHints, hint)
		}
	}
	if seed.Type == types.TypeURL && !answered {
		meta.Drop = true // nothing to crawl or read
	}
	if meta.EmitCount == 0 && !answered && lastErr != nil {
		if neterr.Quiet(lastErr) {
			return types.RunMeta{Status: types.StatusOK}, nil
		}
		meta.Status = types.StatusError
		meta.Error = lastErr.Error()
		return meta, lastErr
	}
	return meta, nil
}

// FallbackKey on a URL seed asks for the same URL over plain HTTP when the
// HTTPS request fails: input given as host:port or a bare IP.
const FallbackKey = "fallback"

// targets are the groups of URLs to try for a seed, narrowed to the one
// scheme asked for.
func (c *Collector) targets(seed types.Seed) [][]string {
	groups := c.baseTargets(seed)
	if c.Only != "" && !(seed.Type == types.TypeURL && seed.Keys[FallbackKey] == "") {
		// -no-http, -no-https: one scheme only.
		var only [][]string
		for _, g := range groups {
			var keep []string
			for _, u := range g {
				if strings.HasPrefix(u, c.Only+"://") {
					keep = append(keep, u)
				}
			}
			if len(keep) > 0 {
				only = append(only, keep)
			}
		}
		groups = only
	}
	if c.Spec == nil || len(groups) == 0 {
		return groups
	}
	if c.Spec.NoFallback {
		// Both schemes are asked and reported: each URL is a service.
		var split [][]string
		for _, g := range groups {
			for _, u := range g {
				split = append(split, []string{u})
			}
		}
		groups = split
	}
	paths := c.Spec.Paths
	if c.Spec.Raw != nil {
		paths = []string{c.Spec.Raw.Path}
	}
	if len(paths) == 0 {
		return groups
	}
	// -path asks each target for these paths in place of its own.
	var out [][]string
	for _, g := range groups {
		for _, p := range paths {
			var ng []string
			for _, u := range g {
				if v, ok := withPath(u, p); ok {
					ng = append(ng, v)
				}
			}
			if len(ng) > 0 {
				out = append(out, ng)
			}
		}
	}
	return out
}

// withPath is u with its path and query replaced by p.
func withPath(u, p string) (string, bool) {
	pu, err := url.Parse(u)
	if err != nil {
		return "", false
	}
	if p == "" {
		p = "/"
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	rel, err := url.Parse(p)
	if err != nil {
		return "", false
	}
	pu.Path, pu.RawPath, pu.RawQuery = rel.Path, rel.RawPath, rel.RawQuery
	n, err := normalize.URL(pu.String())
	return n, err == nil
}

// HTTPFirst says a bare host:port is asked over plain HTTP first, as httpx
// does: ports 80 and 8080, and any above 1024 (a TLS port there is
// answered 400, or closes the connection, and is asked again over TLS).
func HTTPFirst(port int) bool { return port == 80 || port == 8080 || port > 1024 }

func (c *Collector) baseTargets(seed types.Seed) [][]string {
	switch seed.Type {
	case types.TypeURL:
		u, err := normalize.URL(seed.Keys["url"])
		if err != nil {
			return nil
		}
		if p, err := url.Parse(u); err == nil && c.Spec != nil {
			if seed.Keys[FallbackKey] == "https" && p.Scheme == "http" {
				p.Scheme = "https"
				if p.Port() == "" {
					p.Host = net.JoinHostPort(p.Hostname(), "80")
				}
				if h, err := normalize.URL(p.String()); err == nil {
					return [][]string{{u, h}}
				}
			}
		}
		if seed.Keys[FallbackKey] == "http" && strings.HasPrefix(u, "https://") {
			if p, err := url.Parse(u); err == nil {
				if p.Port() == "" {
					p.Host = p.Hostname() // https default 443 becomes http default 80
				}
				p.Scheme = "http"
				if h, err := normalize.URL(p.String()); err == nil {
					return [][]string{{u, h}}
				}
			}
		}
		return [][]string{{u}}
	case types.TypeHostname, types.TypeIPAddress:
		h := normalize.Hostname(seed.Key())
		if h == "" || (seed.Type == types.TypeHostname && net.ParseIP(h) != nil) {
			return nil
		}
		if ip := net.ParseIP(h); ip != nil && ip.To4() == nil {
			h = "[" + h + "]"
		}
		if c.Spec != nil && len(c.Spec.Ports) > 0 {
			var out [][]string
			for _, ps := range c.Spec.Ports {
				out = append(out, portGroup(h, ps, true))
			}
			return out
		}
		if len(c.Ports) == 0 {
			return [][]string{{"https://" + h + "/", "http://" + h + "/"}}
		}
		var out [][]string
		for _, p := range c.Ports {
			out = append(out, portGroup(h, PortSpec{Port: p}, c.Spec != nil))
		}
		return out
	}
	return nil
}

// portGroup is the URLs of one web port of a host, in the order they are
// tried: the scheme given, or both, the likelier first.
func portGroup(h string, ps PortSpec, probe bool) []string {
	hp := net.JoinHostPort(strings.Trim(h, "[]"), strconv.Itoa(ps.Port))
	plain, secure := hp, hp
	switch ps.Port {
	case 80:
		plain = h
	case 443:
		secure = h
	}
	httpURL, httpsURL := "http://"+plain+"/", "https://"+secure+"/"
	switch ps.Scheme {
	case "http":
		return []string{httpURL}
	case "https":
		return []string{httpsURL}
	}
	if ps.Port == 80 || probe && ps.Port != 443 && HTTPFirst(ps.Port) {
		return []string{httpURL, "https://" + hp + "/"}
	}
	if ps.Port == 443 {
		return []string{httpsURL, "http://" + hp + "/"}
	}
	return []string{"https://" + hp + "/", "http://" + hp + "/"}
}

// variants are the requests sent to each URL that answers: one GET, or
// what -x, -body and -rr ask for.
func (c *Collector) variants(raw string) []*fetch.Req {
	s := c.Spec
	if s == nil {
		return []*fetch.Req{nil}
	}
	base := c.methodVariants()
	opt, ok := s.PerHost[strings.ToLower(normalize.HostFromURL(raw))]
	if !ok {
		return base
	}
	// A line gave a virtual host or an address for this host: every request
	// goes to that address, once for each virtual host.
	vhosts := opt.VHosts
	if len(vhosts) == 0 {
		vhosts = []string{""}
	}
	var out []*fetch.Req
	for _, vh := range vhosts {
		for _, v := range base {
			cp := &fetch.Req{IP: opt.IP}
			if v != nil {
				cp.Method, cp.Body = v.Method, v.Body
				cp.Header = v.Header.Clone()
			}
			if vh != "" {
				if cp.Header == nil {
					cp.Header = http.Header{}
				}
				cp.Header.Set("Host", vh)
			}
			out = append(out, cp)
		}
	}
	return out
}

func (c *Collector) methodVariants() []*fetch.Req {
	s := c.Spec
	if s.Raw != nil {
		return []*fetch.Req{{Method: s.Raw.Method, Body: s.Raw.Body, Header: s.Raw.Header}}
	}
	methods := s.Methods
	if len(methods) == 0 {
		methods = []string{http.MethodGet}
	}
	var out []*fetch.Req
	for _, m := range methods {
		rq := &fetch.Req{Method: m}
		if s.Body != "" {
			rq.Body = []byte(s.Body)
		}
		out = append(out, rq)
	}
	return out
}

// more are the requests after the first for a URL that answered: the other
// methods, and with -pa each of those to every address of the name.
func (c *Collector) more(ctx context.Context, raw string, variants []*fetch.Req) []*fetch.Req {
	if c.Spec == nil || !c.Spec.AllIPs {
		return variants[1:]
	}
	var ips []string
	if h := normalize.HostFromURL(raw); h != "" && net.ParseIP(h) == nil {
		ips = fetch.Resolve(ctx, h)
	}
	if len(ips) < 2 {
		return variants[1:]
	}
	var out []*fetch.Req
	for i, ip := range ips {
		for j, v := range variants {
			if i == 0 && j == 0 {
				continue
			}
			cp := &fetch.Req{IP: ip}
			if v != nil {
				cp.Method, cp.Body, cp.Header = v.Method, v.Body, v.Header
			}
			out = append(out, cp)
		}
	}
	return out
}

// excluded says why raw is not requested under -e, or "".
func (c *Collector) excluded(ctx context.Context, raw string) string {
	s := c.Spec
	if s == nil || len(s.Exclude)+len(s.ExcludePorts)+len(s.ExcludeNets)+len(s.excludeRe) == 0 {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	port := u.Port()
	if port == "" {
		port = map[string]string{"http": "80", "https": "443"}[u.Scheme]
	}
	n, _ := strconv.Atoi(port)
	if slices.Contains(s.ExcludePorts, n) {
		return "port " + port + " is excluded (-e)"
	}
	for _, re := range s.excludeRe {
		if re.MatchString(raw) {
			return "matches -e " + re.String()
		}
	}
	ips := []string{u.Hostname()}
	if net.ParseIP(u.Hostname()) == nil {
		ips = fetch.Resolve(ctx, u.Hostname())
	}
	for _, a := range ips {
		ip := net.ParseIP(a)
		if ip == nil {
			continue
		}
		for _, n := range s.ExcludeNets {
			if pf, err := netip.ParsePrefix(n); err == nil && pf.Contains(addrOf(ip)) {
				return "inside " + n + " (-e)"
			} else if a, err := netip.ParseAddr(n); err == nil && a == addrOf(ip) {
				return a.String() + " is excluded (-e)"
			}
		}
		if slices.Contains(s.Exclude, "private-ips") && (ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()) {
			return "a private address (-e private-ips)"
		}
		if slices.Contains(s.Exclude, "cdn") && port != "80" && port != "443" {
			if name, _ := fingerprint.Network(ip); name != "" {
				return "a CDN address answers on ports 80 and 443 only (-e cdn)"
			}
		}
	}
	return ""
}

func addrOf(ip net.IP) netip.Addr {
	a, _ := netip.AddrFromSlice(ip)
	return a.Unmap()
}

func statusOf(o types.Observation) int {
	var p struct {
		Status int `json:"status"`
	}
	_ = json.Unmarshal(o.Payload, &p)
	return p.Status
}

func (c *Collector) fetch(ctx context.Context, raw string, rq *fetch.Req) (types.Observation, types.Seed, bool, error) {
	res, cached, err := fetch.DoReq(ctx, c.Client, raw, rq)
	if err != nil {
		return types.Observation{}, types.Seed{}, cached, err
	}
	data := res.Body
	title := ""
	if c.Spec != nil {
		data = res.Body
		if !c.Spec.NoDecode {
			data = decode(res.Body, lastHeader(res))
		}
		if canHaveTitle(headerGet(lastHeader(res), "Content-Type")) {
			title = domTitle(data)
		}
	} else if m := titleRE.FindSubmatch(res.Body); len(m) == 2 {
		title = strings.Join(strings.Fields(html.UnescapeString(string(m[1]))), " ")
		if !utf8.ValidString(title) {
			title = ""
		}
	}
	reqURL := res.RequestURL
	if n, err := normalize.URL(raw); err == nil {
		reqURL = n
	}
	final := res.URL
	if n, err := normalize.URL(res.URL); err == nil {
		final = n
	}
	dres := res
	dres.Body = data
	row := describe(reqURL, final, dres, title, c.NoTech, c.Spec != nil)
	catchAll := !c.Probe && fetch.CatchAll(ctx, c.Client, res)
	if catchAll {
		// Same answer as a path that does not exist: not a page of its own.
		row["catchall"] = true
	}
	if !c.NoFavicon && !catchAll && (isRoot(reqURL) || isRoot(final)) {
		if hash, from, icon := c.favicon(ctx, final, res); hash != "" {
			row["favicon"] = hash
			row["favicon_url"] = from
			if c.Spec != nil {
				sum := md5.Sum(icon)
				row["favicon_md5"] = hex.EncodeToString(sum[:])
				row["favicon_path"] = iconHref(res.Body, final, from)
			}
		}
	}
	source := reqURL
	if c.Spec != nil {
		source = c.probeFields(ctx, row, raw, reqURL, final, res, data, rq)
	}
	payload, _ := json.Marshal(row)
	obs := types.Observation{
		Collector:  Name,
		Source:     source,
		Kind:       "application",
		Payload:    payload,
		Confidence: 0.9,
		ObservedAt: time.Now().UTC(),
	}
	var hint types.Seed
	if final != "" && final != reqURL && !catchAll && sameSite(reqURL, final) {
		// A redirect to another site (an open redirect, a login provider)
		// is recorded in the hops, not followed.
		hint = types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": final}}
	}
	return obs, hint, cached, nil
}

func lastHeader(res fetch.Result) http.Header {
	if res.FinalHeader != nil {
		return res.FinalHeader
	}
	return res.Header
}

func describe(reqURL, final string, res fetch.Result, title string, noTech, everyAnswer bool) map[string]any {
	sum := sha256.Sum256(res.Body)
	out := map[string]any{
		"url":          reqURL,
		"status":       res.Status,
		"final_url":    final,
		"content_type": headerGet(res.Header, "Content-Type"),
		"server":       headerGet(res.Header, "Server"),
		"title":        title,
		"location":     headerGet(res.Header, "Location"),
		"body_hash":    hex.EncodeToString(sum[:8]),
	}
	if gen := webextract.Generator(res.Body); gen != "" {
		out["generator"] = gen
	}
	if isRoot(reqURL) {
		// A hosting service's page for a name nobody claimed.
		if f, ok := takeover.ByPage(nil, res.Body[:min(len(res.Body), 64<<10)]); ok {
			out["takeover"] = f
		}
	}
	if n := len(res.Hops); n > 1 {
		out["final_status"] = res.Hops[n-1].Status
	}
	if res.Status >= 500 {
		// What a failed answer gives away (an SQL error, a stack trace, a
		// debug page): its kind, and the 100 bytes that say so.
		if kind, sample := webextract.ErrorText(res.Body); kind != "" {
			out["error_text"], out["error_sample"] = kind, sample
		}
	}
	last := res.FinalHeader
	if last == nil {
		last = res.Header
	}
	// Documents get the full fingerprint; a site's front page that is not
	// HTML (an API root) still gets its headers read (Server, cookies).
	if !noTech && (everyAnswer || page(last) || isRoot(reqURL) || isRoot(final)) {
		var body []byte
		if everyAnswer || page(last) {
			body = res.Body[:min(len(res.Body), maxTechBody)]
		}
		if tech := fingerprint.Tech(last, body); len(tech) > 0 {
			out["tech"] = tech
		}
	}
	length := len(res.Body)
	if n, err := strconv.Atoi(headerGet(last, "Content-Length")); err == nil && res.Truncated && n > length {
		length = n
	}
	words, lines := fingerprint.Stats(res.Body)
	out["length"], out["words"], out["lines"] = length, words, lines
	out["ms"] = res.Elapsed.Milliseconds()
	if res.IP != "" {
		out["ip"] = res.IP
	}
	if cookies := cookieNames(res.Header); len(cookies) > 0 {
		out["cookies"] = cookies
	}
	if xs := extraHeaders(res.Header); len(xs) > 0 {
		out["headers"] = xs
	}
	if res.Truncated {
		out["truncated"] = true
	} else if keys := JSONKeys(res.Body, headerGet(last, "Content-Type")); len(keys) > 0 {
		out["json_keys"] = keys
		if ids := JSONIDs(res.Body); len(ids) > 0 {
			out["json_ids"] = ids
		}
		if n, ok := JSONItems(res.Body); ok {
			out["json_items"] = n
		}
	}
	if len(res.Hops) > 0 {
		out["hops"] = res.Hops
	}
	if len(fetch.Extra) > 0 && fetch.Extra.Get("Cookie") != "" {
		out["auth"] = "cookie"
	}
	return out
}

func headerGet(h http.Header, k string) string {
	if h == nil {
		return ""
	}
	return h.Get(k)
}

func extraHeaders(h http.Header) map[string]string {
	if h == nil {
		return nil
	}
	out := map[string]string{}
	for k, vs := range h {
		if len(vs) == 0 {
			continue
		}
		lk := strings.ToLower(k)
		if strings.HasPrefix(lk, "x-") {
			out[lk] = vs[0]
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func cookieNames(h http.Header) []map[string]any {
	if h == nil {
		return nil
	}
	var out []map[string]any
	for _, line := range h.Values("Set-Cookie") {
		c, err := http.ParseSetCookie(line)
		if err != nil || c.Name == "" {
			continue
		}
		m := map[string]any{"name": c.Name}
		if c.HttpOnly {
			m["httponly"] = true
		}
		if c.Secure {
			m["secure"] = true
		}
		switch c.SameSite {
		case http.SameSiteLaxMode:
			m["samesite"] = "Lax"
		case http.SameSiteStrictMode:
			m["samesite"] = "Strict"
		case http.SameSiteNoneMode:
			m["samesite"] = "None"
		}
		out = append(out, m)
	}
	return out
}

// JSONItems is how many items a JSON listing holds: the length of a
// top-level array, or of the one array an envelope holds
// ({"data":[…]}, {"users":[…],"total":…}). A listing that grows or
// shrinks between runs is a change worth reporting; its bytes alone are
// not (timestamps, tokens).
func JSONItems(body []byte) (int, bool) {
	var v any
	if json.Unmarshal(body, &v) != nil {
		return 0, false
	}
	switch x := v.(type) {
	case []any:
		return len(x), true
	case map[string]any:
		n, found := 0, 0
		for _, f := range x {
			if xs, ok := f.([]any); ok {
				n, found = len(xs), found+1
			}
		}
		if found == 1 {
			return n, true
		}
	}
	return 0, false
}

// JSONKeys are the top-level fields of a JSON answer ("[]" and the fields
// of the first element for an array; one level into a small envelope
// such as {"status":…,"data":{…}}), so answers can be compared by shape.
func JSONKeys(body []byte, contentType string) []string {
	if !strings.Contains(strings.ToLower(contentType), "json") {
		return nil
	}
	var v any
	if json.Unmarshal(body, &v) != nil {
		return nil
	}
	prefix := ""
	if xs, ok := v.([]any); ok {
		prefix = "[]"
		if len(xs) == 0 {
			return []string{"[]"}
		}
		v = xs[0]
	}
	m, ok := v.(map[string]any)
	if !ok {
		return []string{prefix + "value"}
	}
	keys := make([]string, 0, len(m))
	for k, x := range m {
		if inner, ok := x.(map[string]any); ok && len(m) <= 3 {
			for ik := range inner {
				keys = append(keys, prefix+k+"."+ik)
			}
			continue
		}
		keys = append(keys, prefix+k)
	}
	sort.Strings(keys)
	if len(keys) > 64 {
		keys = keys[:64]
	}
	return keys
}

// idKey: a field that names an object others may ask for by that value.
var idKey = regexp.MustCompile(`(?i)^(id|uuid|guid|slug|key|name|username|user_?name|login|email|title|.*_id|.*Id|.*_name|.*_title|.*_uuid)$`)

// JSONIDs collects the values of identifier-like fields in a JSON answer
// (top level, the elements of an array, one envelope deep), a few per
// field: what a path such as /users/{username} can be filled with.
func JSONIDs(body []byte) map[string][]string {
	var v any
	if json.Unmarshal(body, &v) != nil {
		return nil
	}
	out := map[string][]string{}
	var objs []map[string]any
	var walk func(x any, depth int)
	walk = func(x any, depth int) {
		switch t := x.(type) {
		case map[string]any:
			objs = append(objs, t)
			if depth < 1 {
				for _, inner := range t {
					walk(inner, depth+1)
				}
			}
		case []any:
			for i, e := range t {
				if i == 20 {
					break
				}
				walk(e, depth)
			}
		}
	}
	walk(v, 0)
	for _, o := range objs {
		for k, x := range o {
			if !idKey.MatchString(k) || len(out) >= 16 && out[k] == nil {
				continue
			}
			var s string
			switch t := x.(type) {
			case string:
				s = t
			case float64:
				s = strconv.FormatFloat(t, 'f', -1, 64)
			default:
				continue
			}
			if s == "" || len(s) > 64 || strings.ContainsAny(s, "/?#") || len(out[k]) >= 10 || slices.Contains(out[k], s) {
				continue
			}
			out[k] = append(out[k], s)
		}
	}
	return out
}

// maxTechBody caps the body handed to the fingerprints: their patterns
// sit in the head of a page, and a multi-MB bundle costs seconds.
const maxTechBody = 1 << 20

// page: fingerprints describe documents. Scripts, JSON and images are
// parts of a site already fingerprinted through its pages.
func page(h http.Header) bool {
	ct := strings.ToLower(headerGet(h, "Content-Type"))
	return ct == "" || strings.Contains(ct, "html") || strings.HasPrefix(ct, "text/plain")
}

// isRoot: the favicon belongs to a site, so only its front page asks.
func isRoot(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && (u.Path == "" || u.Path == "/")
}

// favicon hashes the page's icon: its <link rel=icon> targets (.ico
// first) or /favicon.ico, at most two requests, like httpx -favicon.
func (c *Collector) favicon(ctx context.Context, page string, res fetch.Result) (hash, from string, data []byte) {
	base, err := url.Parse(page)
	if err != nil {
		return "", "", nil
	}
	icons := webextract.Icons(res.Body, base)
	if len(icons) == 0 {
		icons = []string{base.ResolveReference(&url.URL{Path: "/favicon.ico"}).String()}
	}
	tries := 0
	for _, icon := range icons {
		if tries == 2 {
			break
		}
		if h := normalize.HostFromURL(icon); !strings.HasPrefix(strings.ToLower(icon), "data:") && h != normalize.Hostname(base.Hostname()) && !normalize.SameSite(base.Hostname(), h) {
			continue // an icon on another site is outside what was asked for
		}
		if strings.HasPrefix(strings.ToLower(icon), "data:") {
			if data := decodeDataURL(icon); data != nil {
				if h, ok := fingerprint.Favicon(data); ok {
					return h, "data:", data
				}
			}
			continue
		}
		tries++
		r, _, err := fetch.Do(ctx, c.Client, icon)
		if err != nil || r.Status != http.StatusOK && (len(r.Hops) == 0 || r.Hops[len(r.Hops)-1].Status != http.StatusOK) {
			continue
		}
		if h, ok := fingerprint.Favicon(r.Body); ok {
			return h, icon, r.Body
		}
	}
	return "", "", nil
}

func decodeDataURL(raw string) []byte {
	meta, data, ok := strings.Cut(strings.TrimPrefix(raw, "data:"), ",")
	if !ok || !strings.HasSuffix(strings.ToLower(meta), ";base64") {
		return nil
	}
	out, err := base64.StdEncoding.DecodeString(strings.TrimSpace(data))
	if err != nil {
		return nil
	}
	return out
}

// sameSite: the same host, or two hosts of one registrable domain.
func sameSite(a, b string) bool {
	ha, hb := normalize.HostFromURL(a), normalize.HostFromURL(b)
	return ha != "" && (ha == hb || normalize.SameSite(ha, hb))
}

// groups0 is the first URL of the first group: the one whose host picks the
// per-host options.
func groups0(groups [][]string) string {
	if len(groups) > 0 && len(groups[0]) > 0 {
		return groups[0][0]
	}
	return ""
}
