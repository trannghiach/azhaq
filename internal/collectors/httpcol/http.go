package httpcol

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/trannghiach/azhaq/internal/catalog"
	"github.com/trannghiach/azhaq/internal/fetch"
	"github.com/trannghiach/azhaq/internal/neterr"
	"github.com/trannghiach/azhaq/internal/normalize"
	"github.com/trannghiach/azhaq/internal/types"
	"github.com/trannghiach/azhaq/internal/webextract"
)

const Name = "azhaq-http"

var (
	titleRE     = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	emittedURLs sync.Map
)

type Collector struct {
	Client *http.Client
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
	return []types.SeedType{types.TypeURL, types.TypeHostname}
}

func (c *Collector) Outputs() []string { return []string{"application"} }

func (c *Collector) Run(ctx context.Context, seed types.Seed, emit func(types.Observation) error) (types.RunMeta, error) {
	targets := targetsFor(seed)
	if seed.Type == types.TypeURL && len(targets) == 0 {
		return types.RunMeta{Status: types.StatusError, Error: "invalid url"}, fmt.Errorf("invalid url")
	}
	meta := types.RunMeta{Status: types.StatusOK}
	var lastErr error
	cachedOK := false
	for _, raw := range targets {
		if ctx.Err() != nil {
			return meta, ctx.Err()
		}
		obs, hint, cached, err := c.fetch(ctx, raw)
		if err != nil {
			lastErr = err
			continue
		}
		if cached && seed.Type == types.TypeHostname {
			cachedOK = true
			break
		}
		if _, dup := emittedURLs.LoadOrStore(obs.Source, true); dup {
			cachedOK = true
			if seed.Type == types.TypeHostname {
				break
			}
			continue
		}
		if err := emit(obs); err != nil {
			return meta, err
		}
		meta.EmitCount++
		if hint.Key() != "" {
			meta.NextHints = append(meta.NextHints, hint)
		}
		if seed.Type == types.TypeHostname {
			break
		}
	}
	if meta.EmitCount == 0 && !cachedOK && lastErr != nil {
		if neterr.UnknownHost(lastErr) {
			return types.RunMeta{Status: types.StatusOK}, nil
		}
		meta.Status = types.StatusError
		meta.Error = lastErr.Error()
		return meta, lastErr
	}
	return meta, nil
}

func targetsFor(seed types.Seed) []string {
	switch seed.Type {
	case types.TypeURL:
		if u, err := normalize.URL(seed.Keys["url"]); err == nil {
			return []string{u}
		}
	case types.TypeHostname:
		h := normalize.Hostname(seed.Keys["fqdn"])
		if h == "" || net.ParseIP(h) != nil {
			return nil
		}
		return []string{"https://" + h + "/", "http://" + h + "/"}
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
		title = strings.Join(strings.Fields(string(m[1])), " ")
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
	row := describe(reqURL, final, res, title)
	catchAll := fetch.CatchAll(ctx, c.Client, res)
	if catchAll {
		// Same answer as a path that does not exist: not a page of its own.
		row["catchall"] = true
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
	if final != "" && final != reqURL && !catchAll {
		hint = types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": final}}
	}
	return obs, hint, cached, nil
}

func describe(reqURL, final string, res fetch.Result, title string) map[string]any {
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
	if cookies := cookieNames(res.Header); len(cookies) > 0 {
		out["cookies"] = cookies
	}
	if xs := extraHeaders(res.Header); len(xs) > 0 {
		out["headers"] = xs
	}
	if res.Truncated {
		out["truncated"] = true
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
