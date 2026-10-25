package pathscol

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/trannghiach/azhaq/internal/catalog"
	"github.com/trannghiach/azhaq/internal/fetch"
	"github.com/trannghiach/azhaq/internal/normalize"
	"github.com/trannghiach/azhaq/internal/types"
	"github.com/trannghiach/azhaq/internal/webextract"
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
	"logout",
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
	Client   *http.Client
	Wordlist []string
	probed   sync.Map // scheme://host → first prefix; one sweep per origin
}

func New(client *http.Client) *Collector {
	return &Collector{Client: fetch.Client(client), Wordlist: DefaultWordlist}
}

func Register(cat *catalog.Catalog, client *http.Client) {
	cat.MustRegister(New(client))
}

func (c *Collector) Name() string { return Name }

// Info: this collector sends requests to the target.
func (c *Collector) Info() catalog.Info { return catalog.Info{Kind: catalog.Touch} }

func (c *Collector) Inputs() []types.SeedType { return []types.SeedType{types.TypeURL} }

func (c *Collector) Outputs() []string { return []string{"url"} }

// Skip declines every URL on an origin that was already swept.
func (c *Collector) Skip(seed types.Seed) bool {
	raw, err := normalize.URL(seed.Keys["url"])
	if err != nil {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	_, done := c.probed.Load(u.Scheme + "://" + u.Host)
	return done
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
	if _, loaded := c.probed.LoadOrStore(origin, prefix); loaded {
		return types.RunMeta{Status: types.StatusOK}, nil
	}

	list := c.Wordlist
	if len(list) == 0 {
		list = DefaultWordlist
	}
	meta := types.RunMeta{Status: types.StatusOK}
	var mu sync.Mutex
	sem := make(chan struct{}, parallel)
	var wg sync.WaitGroup
	for _, path := range list {
		if ctx.Err() != nil {
			break
		}
		path := strings.TrimPrefix(path, "/")
		if path == "" {
			continue
		}
		target := base.Scheme + "://" + base.Host + prefix + path
		if u, err := normalize.URL(target); err == nil {
			target = u
		}
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
			res, _, err := fetch.Do(ctx, c.Client, target)
			if err != nil || !interesting(res.Status) || fetch.CatchAll(ctx, c.Client, res) {
				return
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
				return
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
		}(target, path)
	}
	wg.Wait()
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
