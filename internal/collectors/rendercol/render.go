// Package rendercol loads pages in a Chrome installed on the machine
// (-browser) and records what only a running page shows: the requests its
// scripts send (the API calls of a single-page app), and the links and
// forms of the rendered document.
package rendercol

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/trannghiach/azhaq/catalog"
	"github.com/trannghiach/azhaq/internal/browser"
	"github.com/trannghiach/azhaq/internal/fetch"
	"github.com/trannghiach/azhaq/internal/normalize"
	"github.com/trannghiach/azhaq/internal/webextract"
	"github.com/trannghiach/azhaq/types"
)

const Name = "azhaq-render"

type Collector struct {
	Browser *browser.Browser
	PerHost int // pages rendered per host; default 30

	mu    sync.Mutex
	count map[string]int
	done  map[string]bool
	hash  map[string]bool // origins whose app routes after a # (/#/basket)
}

func (c *Collector) Name() string { return Name }

// Info: loads pages with their scripts, as a browser does; waits for the
// HTTP answer so dead URLs are not rendered.
func (c *Collector) Info() catalog.Info {
	return catalog.Info{Kind: catalog.Touch, After: "azhaq-http", Local: true}
}

func (c *Collector) Inputs() []types.SeedType { return []types.SeedType{types.TypeURL} }

func (c *Collector) Outputs() []string { return []string{"url"} }

// Skip: only with -browser, and only pages (not scripts, assets or API
// routes, which render nothing); never a logout page while signed in.
func (c *Collector) Skip(seed types.Seed) bool {
	if c.Browser == nil || fetch.EndsSession(seed.Keys["url"]) {
		return true
	}
	switch webextract.ClassifyURL(seed.Keys["url"]) {
	case "asset", "script", "api":
		return true
	}
	return strings.Contains(seed.Keys["url"], "{")
}

func (c *Collector) Run(ctx context.Context, seed types.Seed, emit func(types.Observation) error) (types.RunMeta, error) {
	raw, err := normalize.URL(seed.Keys["url"])
	if err != nil {
		return types.RunMeta{Status: types.StatusError, Error: err.Error()}, err
	}
	u, _ := url.Parse(raw)
	key := webextract.Template(raw)
	c.mu.Lock()
	if c.count == nil {
		c.count, c.done, c.hash = map[string]int{}, map[string]bool{}, map[string]bool{}
	}
	origin := u.Scheme + "://" + u.Host
	hashed := c.hash[origin]
	limit := c.PerHost
	if limit <= 0 {
		limit = 30
	}
	if c.done[key] || c.count[u.Host] >= limit {
		c.mu.Unlock()
		return types.RunMeta{Status: types.StatusOK}, nil
	}
	c.done[key] = true
	c.count[u.Host]++
	c.mu.Unlock()

	if err := fetch.Spend(ctx); err != nil {
		c.mu.Lock()
		delete(c.done, key)
		c.count[u.Host]--
		c.mu.Unlock()
		return types.RunMeta{Status: types.StatusCapped}, err
	}
	load := raw
	if hashed && u.Path != "/" && u.Path != "" && spaRoute(ctx, raw) {
		// The app routes after a #: /basket is its shell, /#/basket the
		// page whose requests are wanted.
		load = origin + "/#" + u.Path
	}
	p, err := c.Browser.Load(ctx, load, false)
	if u.Path == "/" || u.Path == "" {
		if f, err := url.Parse(p.URL); err == nil && strings.HasPrefix(f.Fragment, "/") {
			c.mu.Lock()
			c.hash[origin] = true
			c.mu.Unlock()
		}
	}
	fetch.Count(max(0, len(p.Requests)-1)) // what the page fetched besides itself
	if err != nil && p.HTML == "" && len(p.Requests) == 0 {
		return types.RunMeta{Status: types.StatusError, Error: err.Error()}, err
	}
	base, _ := url.Parse(raw)
	if p.URL != "" && load == raw {
		if f, err := url.Parse(p.URL); err == nil {
			base = f
		}
	}
	seen := map[string]string{} // URL → how it was seen
	for _, r := range p.Requests {
		if n, err := normalize.URL(r); err == nil && webextract.SameOrigin(raw, n) {
			if _, ok := seen[n]; !ok {
				seen[n] = "request"
			}
		}
	}
	for _, l := range webextract.Links([]byte(p.HTML), base) {
		if webextract.SameOrigin(raw, l) {
			if _, ok := seen[l]; !ok {
				seen[l] = "dom"
			}
		}
	}
	meta := types.RunMeta{Status: types.StatusOK}
	for link, how := range seen {
		role := webextract.ClassifyURL(link)
		if role == "asset" || link == raw {
			continue
		}
		row := map[string]any{"url": link, "via": "browser", "seen": how, "role": role}
		payload, _ := json.Marshal(row)
		if err := emit(types.Observation{Collector: Name, Source: raw, Kind: "url", Payload: payload, Confidence: 0.8, ObservedAt: time.Now().UTC()}); err != nil {
			return meta, err
		}
		meta.EmitCount++
		if role != "script" && webextract.Hintable(link) {
			meta.NextHints = append(meta.NextHints, types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": link}})
		}
	}
	for _, f := range webextract.Forms([]byte(p.HTML), base) {
		row := map[string]any{"method": f.Method, "action": f.Action, "fields": f.Fields, "via": "browser"}
		payload, _ := json.Marshal(row)
		if err := emit(types.Observation{Collector: Name, Source: raw, Kind: "form", Payload: payload, Confidence: 0.8, ObservedAt: time.Now().UTC()}); err != nil {
			return meta, err
		}
		meta.EmitCount++
	}
	return meta, nil
}

// spaRoute: the server answers this path with the app's shell, as it
// answers any unknown path (the fetch is cached from the HTTP collector).
func spaRoute(ctx context.Context, raw string) bool {
	client := fetch.Client(nil)
	res, _, err := fetch.Do(ctx, client, raw)
	return err == nil && fetch.FinalCatchAll(ctx, client, res)
}
