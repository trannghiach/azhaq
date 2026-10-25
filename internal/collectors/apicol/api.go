// Package apicol reads OpenAPI 3 and Swagger 2 documents and maps the
// operations they declare. It never calls those operations: a GET in a
// spec can still change state (VAmPI's /createdb resets its database).
package apicol

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/trannghiach/azhaq/internal/catalog"
	"github.com/trannghiach/azhaq/internal/fetch"
	"github.com/trannghiach/azhaq/internal/neterr"
	"github.com/trannghiach/azhaq/internal/normalize"
	"github.com/trannghiach/azhaq/internal/types"
)

const Name = "azhaq-openapi"

const maxOps = 512

var methods = []string{"get", "put", "post", "delete", "options", "head", "patch", "trace"}

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

func (c *Collector) Outputs() []string { return []string{"api", "url"} }

// Skip declines URLs that cannot be an API description.
func (c *Collector) Skip(seed types.Seed) bool {
	u, err := url.Parse(seed.Keys["url"])
	if err != nil {
		return true
	}
	return !specLike(u.Path)
}

func specLike(p string) bool {
	p = strings.ToLower(p)
	for _, s := range []string{".json", ".yaml", ".yml"} {
		if strings.HasSuffix(p, s) {
			return true
		}
	}
	for _, s := range []string{"openapi", "swagger", "api-docs", "apispec"} {
		if strings.Contains(p, s) {
			return true
		}
	}
	return false
}

type doc struct {
	OpenAPI  string                          `json:"openapi" yaml:"openapi"`
	Swagger  string                          `json:"swagger" yaml:"swagger"`
	Info     struct{ Title, Version string } `json:"info" yaml:"info"`
	Servers  []struct{ URL string }          `json:"servers" yaml:"servers"`
	Host     string                          `json:"host" yaml:"host"`
	BasePath string                          `json:"basePath" yaml:"basePath"`
	Paths    map[string]map[string]any       `json:"paths" yaml:"paths"`
	Comps    struct {
		Schemas map[string]any `json:"schemas" yaml:"schemas"`
	} `json:"components" yaml:"components"`
	Defs map[string]any `json:"definitions" yaml:"definitions"`
}

func (c *Collector) Run(ctx context.Context, seed types.Seed, emit func(types.Observation) error) (types.RunMeta, error) {
	raw, err := normalize.URL(seed.Keys["url"])
	if err != nil {
		return types.RunMeta{Status: types.StatusError, Error: err.Error()}, err
	}
	res, _, err := fetch.Do(ctx, c.Client, raw)
	if err != nil {
		if neterr.UnknownHost(err) {
			return types.RunMeta{Status: types.StatusOK}, nil
		}
		return types.RunMeta{Status: types.StatusError, Error: err.Error()}, err
	}
	meta := types.RunMeta{Status: types.StatusOK}
	if res.Status != http.StatusOK {
		return meta, nil
	}
	d, ok := parse(res.Body)
	if !ok {
		return meta, nil
	}
	final := res.URL
	if final == "" {
		final = raw
	}
	base := apiBase(final, d)
	now := time.Now().UTC()

	paths := make([]string, 0, len(d.Paths))
	for p := range d.Paths {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	version := d.OpenAPI
	if version == "" {
		version = "swagger " + d.Swagger
	}
	summary, _ := json.Marshal(map[string]any{
		"url": raw, "spec": version, "title": d.Info.Title, "count": len(paths), "base": base,
	})
	if err := emit(types.Observation{
		Collector: Name, Source: raw, Kind: "api",
		Payload: summary, Confidence: 0.9, ObservedAt: now,
	}); err != nil {
		return meta, err
	}
	meta.EmitCount++

	for _, p := range paths {
		if meta.EmitCount > maxOps {
			break
		}
		ops := d.Paths[p]
		var ms []string
		var params []string
		params = addParams(params, ops["parameters"], d)
		for _, m := range methods {
			op, ok := ops[m].(map[string]any)
			if !ok {
				continue
			}
			ms = append(ms, strings.ToUpper(m))
			params = addParams(params, op["parameters"], d)
			params = addBody(params, op["requestBody"], d)
		}
		if len(ms) == 0 {
			continue
		}
		target, err := normalize.URL(strings.TrimSuffix(base, "/") + "/" + strings.TrimPrefix(p, "/"))
		if err != nil {
			continue
		}
		row := map[string]any{"url": target, "via": "openapi", "methods": ms, "role": "api"}
		if len(params) > 0 {
			row["params"] = params
		}
		payload, _ := json.Marshal(row)
		if err := emit(types.Observation{
			Collector: Name, Source: raw, Kind: "url",
			Payload: payload, Confidence: 0.9, ObservedAt: now,
		}); err != nil {
			return meta, err
		}
		meta.EmitCount++
	}
	return meta, nil
}

func parse(body []byte) (doc, bool) {
	var d doc
	trimmed := strings.TrimSpace(string(body))
	if strings.HasPrefix(trimmed, "{") {
		if json.Unmarshal(body, &d) != nil {
			return d, false
		}
	} else if strings.HasPrefix(trimmed, "<") || yaml.Unmarshal(body, &d) != nil {
		return d, false
	}
	if d.OpenAPI == "" && d.Swagger == "" {
		return d, false
	}
	return d, len(d.Paths) > 0
}

// apiBase is where the operations live. A server on another host (often
// localhost in a spec copied from development) keeps only its path, on
// the origin that served the document.
func apiBase(specURL string, d doc) string {
	su, err := url.Parse(specURL)
	if err != nil {
		return specURL
	}
	origin := su.Scheme + "://" + su.Host
	prefix := ""
	switch {
	case len(d.Servers) > 0 && d.Servers[0].URL != "":
		if u, err := url.Parse(d.Servers[0].URL); err == nil {
			if u.Host != "" && strings.EqualFold(u.Host, su.Host) && (u.Scheme == "http" || u.Scheme == "https") {
				origin = u.Scheme + "://" + u.Host
			}
			prefix = u.Path
		}
	case d.BasePath != "":
		prefix = d.BasePath
	}
	if strings.Contains(prefix, "{") {
		prefix = "" // server variables: unknown at map time
	}
	return origin + "/" + strings.Trim(prefix, "/")
}

func addParams(out []string, v any, d doc) []string {
	list, _ := v.([]any)
	for _, x := range list {
		m, _ := x.(map[string]any)
		if ref, _ := m["$ref"].(string); ref != "" {
			m, _ = resolve(ref, d).(map[string]any)
		}
		if name, _ := m["name"].(string); name != "" {
			out = addName(out, name)
		}
	}
	return out
}

func addBody(out []string, v any, d doc) []string {
	body, _ := v.(map[string]any)
	content, _ := body["content"].(map[string]any)
	for _, media := range content {
		m, _ := media.(map[string]any)
		schema, _ := m["schema"].(map[string]any)
		if ref, _ := schema["$ref"].(string); ref != "" {
			schema, _ = resolve(ref, d).(map[string]any)
		}
		props, _ := schema["properties"].(map[string]any)
		names := make([]string, 0, len(props))
		for name := range props {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			out = addName(out, name)
		}
	}
	return out
}

func resolve(ref string, d doc) any {
	switch {
	case strings.HasPrefix(ref, "#/components/schemas/"):
		return d.Comps.Schemas[strings.TrimPrefix(ref, "#/components/schemas/")]
	case strings.HasPrefix(ref, "#/definitions/"):
		return d.Defs[strings.TrimPrefix(ref, "#/definitions/")]
	}
	return nil
}

func addName(xs []string, n string) []string {
	for _, x := range xs {
		if x == n {
			return xs
		}
	}
	return append(xs, n)
}
