package crawlcol

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"azhaq/internal/catalog"
	"azhaq/internal/fetch"
	"azhaq/internal/neterr"
	"azhaq/internal/normalize"
	"azhaq/internal/types"
	"azhaq/internal/webextract"
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

func (c *Collector) Inputs() []types.SeedType { return []types.SeedType{types.TypeURL} }

func (c *Collector) Outputs() []string { return []string{"url"} }

func (c *Collector) Run(ctx context.Context, seed types.Seed, emit func(types.Observation) error) (types.RunMeta, error) {
	raw, err := normalize.URL(seed.Keys["url"])
	if err != nil {
		return types.RunMeta{Status: types.StatusError, Error: err.Error()}, err
	}
	resp, body, err := fetch.GET(ctx, c.Client, raw)
	if err != nil {
		if neterr.UnknownHost(err) {
			return types.RunMeta{Status: types.StatusOK}, nil
		}
		return types.RunMeta{Status: types.StatusError, Error: err.Error()}, err
	}
	base := resp.Request.URL
	meta := types.RunMeta{Status: types.StatusOK}
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
