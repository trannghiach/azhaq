package crawlcol

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/trannghiach/azhaq/catalog"
	"github.com/trannghiach/azhaq/internal/fetch"
	"github.com/trannghiach/azhaq/internal/neterr"
	"github.com/trannghiach/azhaq/internal/normalize"
	"github.com/trannghiach/azhaq/internal/webextract"
	"github.com/trannghiach/azhaq/types"
)

const Name = "azhaq-crawl"

const maxPerPage = 64

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

// Info: this collector sends requests to the target.
func (c *Collector) Info() catalog.Info { return catalog.Info{Kind: catalog.Touch} }

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
		// Redirected: the page it landed on is visited and crawled itself.
		return meta, nil
	}
	ct := strings.ToLower(res.Header.Get("Content-Type"))
	switch {
	case strings.Contains(ct, "json"):
		return c.jsonLinks(raw, res.Body, base, emit)
	case ct != "" && !strings.Contains(ct, "html") && !strings.Contains(ct, "xml"):
		return meta, nil
	}
	if fetch.FinalCatchAll(ctx, c.Client, res) {
		// The generic page: its links were read from the real one.
		return meta, nil
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
	for _, f := range webextract.Forms(body, base) {
		if meta.EmitCount >= maxPerPage {
			break
		}
		row := map[string]any{
			"method": f.Method, "action": f.Action, "fields": f.Fields, "via": "html",
		}
		if f.ID != "" {
			row["id"] = f.ID
		}
		if f.Name != "" {
			row["name"] = f.Name
		}
		payload, _ := json.Marshal(row)
		if err := emit(types.Observation{
			Collector: Name, Source: raw, Kind: "form",
			Payload: payload, Confidence: 0.85, ObservedAt: time.Now().UTC(),
		}); err != nil {
			return meta, err
		}
		meta.EmitCount++
		if f.Action != "" && strings.EqualFold(f.Method, "GET") &&
			webextract.SameOrigin(raw, f.Action) && webextract.Hintable(f.Action) && f.Action != raw {
			meta.NextHints = append(meta.NextHints, types.Seed{
				Type: types.TypeURL, Keys: map[string]string{"url": f.Action},
			})
		}
	}
	if names := webextract.ParamNames(body, base); len(names) > 0 {
		payload, _ := json.Marshal(map[string]any{"params": names, "url": raw})
		if err := emit(types.Observation{
			Collector: Name, Source: raw, Kind: "param",
			Payload: payload, Confidence: 0.7, ObservedAt: time.Now().UTC(),
		}); err != nil {
			return meta, err
		}
		meta.EmitCount++
	}
	for _, link := range webextract.Links(body, base) {
		if meta.EmitCount >= maxPerPage {
			break
		}
		if !webextract.SameOrigin(raw, link) {
			continue
		}
		if link == raw {
			continue
		}
		payload, _ := json.Marshal(map[string]string{"url": link, "via": "html"})
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
		if webextract.Hintable(link) {
			meta.NextHints = append(meta.NextHints, types.Seed{
				Type: types.TypeURL,
				Keys: map[string]string{"url": link},
			})
		}
	}
	return meta, nil
}

// jsonLinks reads links out of a JSON response: HTML inside string values
// and values that are themselves a same-origin URL or path.
func (c *Collector) jsonLinks(raw string, body []byte, base *url.URL, emit func(types.Observation) error) (types.RunMeta, error) {
	meta := types.RunMeta{Status: types.StatusOK}
	for _, link := range webextract.JSONLinks(body, base) {
		if meta.EmitCount >= maxPerPage {
			break
		}
		if !webextract.SameOrigin(raw, link) || link == raw {
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
	return meta, nil
}
