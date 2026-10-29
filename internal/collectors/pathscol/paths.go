package pathscol

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/trannghiach/azhaq/catalog"
	"github.com/trannghiach/azhaq/internal/fetch"
	"github.com/trannghiach/azhaq/internal/normalize"
	"github.com/trannghiach/azhaq/internal/webextract"
	"github.com/trannghiach/azhaq/types"
)

const Name = "azhaq-paths"

const parallel = 6

// DefaultWordlist is a short recon list, not an exploit pack.
var DefaultWordlist = []string{
	"robots.txt",
	"sitemap.xml",
	"sitemap_index.xml",
	".well-known/security.txt",
	".well-known/openid-configuration",
	"login",
	"admin",
	"dashboard",
	"register",
	"signup",
	"api",
	"api/v1",
	"api/status",
	"rest",
	"graphql",
	"graphiql",
	"swagger",
	"swagger.json",
	"swagger.yaml",
	"openapi.json",
	"openapi.yaml",
	"api-docs",
	"v2/api-docs",
	"v3/api-docs",
	"swagger/v1/swagger.json",
	"api/swagger.json",
	"api/openapi.json",
	"health",
	"internal",
	"backup",
	".git/HEAD",
	"favicon.ico",
}

type Collector struct {
	Client    *http.Client
	Wordlist  []string
	probed    sync.Map // scheme://host (or scheme://host/api/v2/) → the URL whose task sweeps it; one sweep each
	baseCount sync.Map // scheme://host → API bases swept
}

func New(client *http.Client) *Collector {
	return &Collector{Client: fetch.Client(client), Wordlist: DefaultWordlist}
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

// Skip declines every URL on an origin but the one whose task sweeps it
// (the first one asked, in this process or before azhaq resume), and the
// first one under each API base it has not swept.
func (c *Collector) Skip(seed types.Seed) bool {
	raw, err := normalize.URL(seed.Keys["url"])
	if err != nil {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	origin := u.Scheme + "://" + u.Host
	if c.owner(origin, raw) == raw {
		return false
	}
	b := apiBase(u.Path)
	// The root sweep asks /api/swagger.json and /api/openapi.json.
	return b == "" || b == "/api/" || c.owner(origin+b, raw) != raw
}

// specWords are where an API's description sits under its base
// (/identity/api/v2/openapi.json): servers that mount several APIs serve
// each one's there, not at the site's root.
var specWords = []string{"openapi.json", "openapi.yaml", "swagger.json", "swagger.yaml", "api-docs", "v3/api-docs",
	"v2/api-docs", "v3/api-docs/swagger-config", "swagger-resources", "swagger/v1/swagger.json"}

// maxBases bounds the API bases swept per origin.
const maxBases = 8

var versionSeg = regexp.MustCompile(`^v\d+(\.\d+)?$`)

// apiBase is the base of the API a path is under (/api/, /api/v2/,
// /identity/api/v2/), or "" for a path under none, or under the root.
func apiBase(p string) string {
	segs := strings.Split(strings.Trim(p, "/"), "/")
	end := -1
	for i, seg := range segs[:min(len(segs), 5)] {
		low := strings.ToLower(seg)
		switch {
		case low == "api" || low == "rest" || low == "apis":
			end = i
		case versionSeg.MatchString(low) && (end == i-1 || i == 0):
			end = i
		}
	}
	if end < 0 {
		return ""
	}
	return "/" + strings.Join(segs[:end+1], "/") + "/"
}

// bases counts the API bases of origin swept so far, this one included.
func (c *Collector) bases(origin string) int {
	v, _ := c.baseCount.LoadOrStore(origin, new(atomic.Int32))
	return int(v.(*atomic.Int32).Add(1))
}

// owner is the URL whose task sweeps origin, claiming it for raw when
// nobody has.
func (c *Collector) owner(origin, raw string) string {
	if v, ok := c.probed.Load(origin); ok {
		return v.(string)
	}
	o := raw
	if catalog.Claim != nil {
		o = catalog.Claim(Name+" "+origin, raw)
	}
	v, _ := c.probed.LoadOrStore(origin, o)
	return v.(string)
}

func (c *Collector) Run(ctx context.Context, seed types.Seed, emit func(types.Observation) error) (types.RunMeta, error) {
	raw, err := normalize.URL(seed.Keys["url"])
	if err != nil {
		return types.RunMeta{Status: types.StatusError, Error: err.Error()}, err
	}
	base, err := url.Parse(raw)
	if err != nil {
		return types.RunMeta{Status: types.StatusError, Error: err.Error()}, err
	}
	prefix := probePrefix(base.Path)
	origin := base.Scheme + "://" + base.Host
	var list []string
	switch b := apiBase(base.Path); {
	case c.owner(origin, raw) == raw:
		list = c.Wordlist
		if len(list) == 0 {
			list = DefaultWordlist
		}
	case b != "" && b != "/api/" && c.owner(origin+b, raw) == raw && c.bases(origin) <= maxBases:
		// The root sweep asks /api/swagger.json and /api/openapi.json.
		prefix, list = b, specWords
	default:
		return types.RunMeta{Status: types.StatusOK}, nil
	}
	meta := types.RunMeta{Status: types.StatusOK}
	var mu sync.Mutex
	sem := make(chan struct{}, parallel)
	var wg sync.WaitGroup
	var skipped atomic.Int32
	// probe asks one location and emits what it finds; it says whether the
	// answer was an API description.
	probe := func(target, path string) bool {
		res, _, err := fetch.Do(ctx, c.Client, target)
		if err != nil || !interesting(res.Status) || fetch.CatchAll(ctx, c.Client, res) {
			return false
		}
		reqURL := target
		if n, err := normalize.URL(target); err == nil {
			reqURL = n
		}
		final := res.URL
		if n, err := normalize.URL(res.URL); err == nil {
			final = n
		}
		payload, _ := json.Marshal(map[string]any{
			"url":       reqURL,
			"via":       "paths",
			"status":    res.Status,
			"path":      "/" + path,
			"final_url": final,
			"hops":      res.Hops,
		})
		mu.Lock()
		defer mu.Unlock()
		if err := emit(types.Observation{
			Collector:  Name,
			Source:     raw,
			Kind:       "url",
			Payload:    payload,
			Confidence: 0.75,
			ObservedAt: time.Now().UTC(),
		}); err != nil {
			return false
		}
		meta.EmitCount++
		if res.Status == 200 && (strings.HasSuffix(path, "sitemap.xml") || path == "sitemap_index.xml") {
			for _, loc := range sitemapLocs(res.Body) {
				hintURL(raw, loc, &meta)
			}
		}
		if path == "robots.txt" && res.Status == 200 {
			for _, loc := range robotsRefs(res.Body, base) {
				hintURL(raw, loc, &meta)
			}
		}
		for _, u := range []string{reqURL, final} {
			if u == "" || !webextract.Hintable(u) {
				continue
			}
			low := strings.ToLower(u)
			if strings.HasSuffix(low, ".txt") || strings.HasSuffix(low, ".xml") || strings.HasSuffix(low, ".ico") {
				continue
			}
			meta.NextHints = append(meta.NextHints, types.Seed{
				Type: types.TypeURL,
				Keys: map[string]string{"url": u},
			})
		}
		return isDescLoc(path) && res.Status < 400 && describes(res.Body)
	}
	var locs, descs []string
	for _, path := range list {
		path = strings.TrimPrefix(path, "/")
		if path == "" {
			continue
		}
		if isDescLoc(path) {
			descs = append(descs, path)
		} else {
			locs = append(locs, path)
		}
	}
	// The guesses of an API description go one at a time, likeliest first,
	// and stop at the first that is one.
	slices.SortStableFunc(descs, func(a, b string) int { return descRank(a) - descRank(b) })
	targetOf := func(path string) string {
		target := base.Scheme + "://" + base.Host + prefix + path
		if u, err := normalize.URL(target); err == nil {
			target = u
		}
		return target
	}
	if len(descs) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for _, path := range descs {
				target := targetOf(path)
				if target == raw || ctx.Err() != nil {
					continue
				}
				if fetch.Described(origin) {
					skipped.Add(1)
					continue
				}
				select {
				case <-ctx.Done():
					return
				case sem <- struct{}{}:
				}
				found := probe(target, path)
				<-sem
				if found {
					fetch.MarkDescribed(origin)
				}
			}
		}()
	}
	for _, path := range locs {
		if ctx.Err() != nil {
			break
		}
		target := targetOf(path)
		if target == raw {
			continue
		}
		wg.Add(1)
		go func(target, path string) {
			defer wg.Done()
			select {
			case <-ctx.Done():
				return
			case sem <- struct{}{}:
			}
			defer func() { <-sem }()
			probe(target, path)
		}(target, path)
	}
	wg.Wait()
	if n := skipped.Load(); n > 0 {
		payload, _ := json.Marshal(map[string]any{"skipped_checks": n, "origin": origin})
		if err := emit(types.Observation{Collector: Name, Source: raw, Kind: "note", Payload: payload, Confidence: 1, ObservedAt: time.Now().UTC()}); err == nil {
			meta.EmitCount++
		}
	}
	return meta, ctx.Err()
}

var locRE = regexp.MustCompile(`(?i)<loc>\s*([^<\s]+)\s*</loc>`)

func sitemapLocs(body []byte) []string {
	var out []string
	for _, m := range locRE.FindAllSubmatch(body, 64) {
		if len(m) != 2 {
			continue
		}
		u, err := normalize.URL(string(m[1]))
		if err != nil {
			continue
		}
		out = append(out, u)
	}
	return out
}

func hintURL(raw, loc string, meta *types.RunMeta) {
	if !webextract.SameOrigin(raw, loc) || !webextract.Hintable(loc) {
		return
	}
	meta.NextHints = append(meta.NextHints, types.Seed{
		Type: types.TypeURL, Keys: map[string]string{"url": loc},
	})
}

func robotsRefs(body []byte, base *url.URL) []string {
	if base == nil {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	add := func(ref string) {
		ref = strings.TrimSpace(ref)
		if ref == "" || ref == "/" || strings.Contains(ref, "*") {
			return
		}
		u, err := base.Parse(ref)
		if err != nil {
			return
		}
		n, err := normalize.URL(u.String())
		if err != nil || seen[n] {
			return
		}
		seen[n] = true
		out = append(out, n)
	}
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "sitemap":
			add(strings.TrimSpace(val))
		case "allow", "disallow":
			add(strings.TrimSpace(val))
		}
		if len(out) >= 32 {
			break
		}
	}
	return out
}

// probePrefix is the directory under which the wordlist is joined.
// /app/sub → /app/sub/; /app/page.html → /app/; / → /.
func probePrefix(p string) string {
	if p == "" || p == "/" {
		return "/"
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	if strings.HasSuffix(p, "/") {
		return p
	}
	i := strings.LastIndex(p, "/")
	last := p[i+1:]
	if strings.Contains(last, ".") {
		if i <= 0 {
			return "/"
		}
		return p[:i+1]
	}
	return p + "/"
}

func interesting(status int) bool {
	switch status {
	case 200, 201, 204, 301, 302, 303, 307, 308, 401, 403:
		return true
	default:
		return false
	}
}
