package jscol

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/trannghiach/azhaq/internal/catalog"
	"github.com/trannghiach/azhaq/internal/fetch"
	"github.com/trannghiach/azhaq/internal/neterr"
	"github.com/trannghiach/azhaq/internal/normalize"
	"github.com/trannghiach/azhaq/internal/types"
	"github.com/trannghiach/azhaq/internal/webextract"
)

const Name = "azhaq-js"

const maxPerPage = 64
const maxScripts = 8

var extracted sync.Map // origin → done

type Collector struct {
	Client *http.Client
}

func originOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return raw
	}
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host)
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

func (c *Collector) Inputs() []types.SeedType { return []types.SeedType{types.TypeURL} }

func (c *Collector) Outputs() []string { return []string{"url"} }

func (c *Collector) Run(ctx context.Context, seed types.Seed, emit func(types.Observation) error) (types.RunMeta, error) {
	raw, err := normalize.URL(seed.Keys["url"])
	if err != nil {
		return types.RunMeta{Status: types.StatusError, Error: err.Error()}, err
	}
	if !looksLikeJS(raw) {
		if _, loaded := extracted.LoadOrStore(originOf(raw), true); loaded {
			return types.RunMeta{Status: types.StatusOK}, nil
		}
	}
	resp, body, err := fetch.GET(ctx, c.Client, raw)
	if err != nil {
		if neterr.UnknownHost(err) {
			return types.RunMeta{Status: types.StatusOK}, nil
		}
		return types.RunMeta{Status: types.StatusError, Error: err.Error()}, err
	}
	base := resp.Request.URL
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	isJS := strings.Contains(ct, "javascript") || looksLikeJS(base.String())
	if isJS {
		extracted.Store(originOf(raw), true)
	}
	var scripts []string
	switch {
	case isJS:
		scripts = []string{string(body)}
	default:
		scripts = append(scripts, webextract.InlineScripts(body)...)
		n := 0
		for _, src := range webextract.ScriptSrcs(body, base) {
			if n >= maxScripts || !webextract.SameOrigin(raw, src) {
				continue
			}
			if ctx.Err() != nil {
				return types.RunMeta{Status: types.StatusCancelled}, ctx.Err()
			}
			_, js, err := fetch.GET(ctx, c.Client, src)
			if err != nil {
				continue
			}
			scripts = append(scripts, string(js))
			n++
		}
	}

	var found []string
	for _, script := range scripts {
		for _, link := range webextract.JSURLs(script, base) {
			if !webextract.SameOrigin(raw, link) || link == raw {
				continue
			}
			found = append(found, link)
		}
	}
	found = webextract.CollapseURLs(found)
	meta := types.RunMeta{Status: types.StatusOK}
	for _, link := range found {
		if meta.EmitCount >= maxPerPage {
			break
		}
		role := webextract.ClassifyURL(link)
		if role == "asset" {
			continue
		}
		payload, _ := json.Marshal(map[string]string{"url": link, "via": "js", "role": role})
		if err := emit(types.Observation{
			Collector:  Name,
			Source:     raw,
			Kind:       "url",
			Payload:    payload,
			Confidence: 0.7,
			ObservedAt: time.Now().UTC(),
		}); err != nil {
			return meta, err
		}
		meta.EmitCount++
		if webextract.Hintable(link) {
			meta.NextHints = append(meta.NextHints, types.Seed{
				Type: types.TypeURL,
				Keys: map[string]string{"url": webextract.RouteKey(link)},
			})
		}
	}
	return meta, nil
}
