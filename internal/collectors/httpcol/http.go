package httpcol

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/trannghiach/azhaq/catalog"
	"github.com/trannghiach/azhaq/internal/fetch"
	"github.com/trannghiach/azhaq/internal/fingerprint"
	"github.com/trannghiach/azhaq/internal/neterr"
	"github.com/trannghiach/azhaq/internal/normalize"
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
	// NoFavicon skips the favicon request on root pages.
	NoFavicon bool
	// NoTech skips technology fingerprints (about 30 MB of memory).
	NoTech bool
	// Probe answers like httpx: one request per service, no catch-all
	// check (nothing is crawled from it).
	Probe bool

	emitted sync.Map // URLs already reported in this run
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
	for _, group := range groups {
		for _, raw := range group {
			if ctx.Err() != nil {
				return meta, ctx.Err()
			}
			obs, hint, cached, err := c.fetch(ctx, raw)
			if err != nil {
				lastErr = err
				continue
			}
			answered = true
			answeredURL = raw
			if cached && seed.Type == types.TypeHostname {
				break
			}
			if _, dup := c.emitted.LoadOrStore(obs.Source, true); dup {
				break
			}
			if err := emit(obs); err != nil {
				return meta, err
			}
			meta.EmitCount++
			if hint.Key() != "" {
				meta.NextHints = append(meta.NextHints, hint)
			}
			break
		}
	}
	if seed.Type == types.TypeURL && seed.Keys[FallbackKey] != "" && len(groups) == 1 {
		// Input like host:port: the scheme that answered goes on as its own
		// URL, and the guess is dropped so the other collectors read the
		// page that exists.
		if u, err := normalize.URL(seed.Keys["url"]); err == nil && answeredURL != "" && answeredURL != u {
			meta.Drop = true
			meta.NextHints = append(meta.NextHints, types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": answeredURL, types.SameTargetKey: "1"}})
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

func (c *Collector) targets(seed types.Seed) [][]string {
	switch seed.Type {
	case types.TypeURL:
		u, err := normalize.URL(seed.Keys["url"])
		if err != nil {
			return nil
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
		if len(c.Ports) == 0 {
			return [][]string{{"https://" + h + "/", "http://" + h + "/"}}
		}
		var out [][]string
		for _, p := range c.Ports {
			hp := net.JoinHostPort(h, strconv.Itoa(p))
			switch p {
			case 80:
				out = append(out, []string{"http://" + h + "/", "https://" + hp + "/"})
			case 443:
				out = append(out, []string{"https://" + h + "/", "http://" + hp + "/"})
			default:
				out = append(out, []string{"https://" + hp + "/", "http://" + hp + "/"})
			}
		}
		return out
	}
	return nil
}

func (c *Collector) fetch(ctx context.Context, raw string) (types.Observation, types.Seed, bool, error) {
	res, cached, err := fetch.Do(ctx, c.Client, raw)
	if err != nil {
		return types.Observation{}, types.Seed{}, cached, err
	}
	title := ""
	if m := titleRE.FindSubmatch(res.Body); len(m) == 2 {
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
	row := describe(reqURL, final, res, title, c.NoTech)
	catchAll := !c.Probe && fetch.CatchAll(ctx, c.Client, res)
	if catchAll {
		// Same answer as a path that does not exist: not a page of its own.
		row["catchall"] = true
	}
	if !c.NoFavicon && !catchAll && (isRoot(reqURL) || isRoot(final)) {
		if hash, from := c.favicon(ctx, final, res); hash != "" {
			row["favicon"] = hash
			row["favicon_url"] = from
		}
	}
	payload, _ := json.Marshal(row)
	obs := types.Observation{
		Collector:  Name,
		Source:     reqURL,
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

func describe(reqURL, final string, res fetch.Result, title string, noTech bool) map[string]any {
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
	if n := len(res.Hops); n > 1 {
		out["final_status"] = res.Hops[n-1].Status
	}
	last := res.FinalHeader
	if last == nil {
		last = res.Header
	}
	// Documents get the full fingerprint; a site's front page that is not
	// HTML (an API root) still gets its headers read (Server, cookies).
	if !noTech && (page(last) || isRoot(reqURL) || isRoot(final)) {
		var body []byte
		if page(last) {
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
func (c *Collector) favicon(ctx context.Context, page string, res fetch.Result) (hash, from string) {
	base, err := url.Parse(page)
	if err != nil {
		return "", ""
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
					return h, "data:"
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
			return h, icon
		}
	}
	return "", ""
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
