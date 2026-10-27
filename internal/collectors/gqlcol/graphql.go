// Package gqlcol recognises GraphQL endpoints and, behind -graphql, reads
// their schema through introspection. Recognising one takes a plain GET;
// introspection is a POST, so it is an active technique. The schema is
// kept whole (types, fields, arguments, input objects, enums) for the map
// and the graphql, sdl and openapi exports.
package gqlcol

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/trannghiach/azhaq/catalog"
	"github.com/trannghiach/azhaq/internal/fetch"
	"github.com/trannghiach/azhaq/internal/gqlschema"
	"github.com/trannghiach/azhaq/internal/neterr"
	"github.com/trannghiach/azhaq/internal/normalize"
	"github.com/trannghiach/azhaq/types"
)

const (
	Name       = "azhaq-graphql"
	SchemaName = "azhaq-graphql-schema"
	maxFields  = 500
)

// graphqlPath: where GraphQL servers usually listen.
var graphqlPath = regexp.MustCompile(`(?i)(^|/)(graphql|graphiql|gql|playground|altair|v\d+/graphql|graphql/v\d+|api/graphql)/?$`)

// signature: what a GraphQL server or its IDE answers to a bare GET.
var signature = regexp.MustCompile(`(?i)must provide (a )?query|graphql operations must contain|query (is )?(missing|required)|no query (string )?(was )?(present|provided)|"errors"\s*:\s*\[\s*\{\s*"message"\s*:\s*"[^"]*(query|graphql)|<title>\s*(graphiql|graphql playground|apollo|altair)|graphiql\.(min\.)?(js|css)|embeddable-sandbox|graphql-playground`)

// Collector marks URLs that answer like a GraphQL endpoint.
type Collector struct {
	Client *http.Client
}

func New(client *http.Client) *Collector { return &Collector{Client: fetch.Client(client)} }

func (c *Collector) Name() string { return Name }

// Info: one GET to the target.
func (c *Collector) Info() catalog.Info {
	return catalog.Info{Kind: catalog.Touch, After: "azhaq-http"}
}

func (c *Collector) Inputs() []types.SeedType { return []types.SeedType{types.TypeURL} }

func (c *Collector) Outputs() []string { return []string{"graphql"} }

// Skip declines URLs whose path is not a usual GraphQL location.
func (c *Collector) Skip(seed types.Seed) bool { return !looksGraphQL(seed.Keys["url"]) }

func looksGraphQL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && graphqlPath.MatchString(u.Path)
}

func (c *Collector) Run(ctx context.Context, seed types.Seed, emit func(types.Observation) error) (types.RunMeta, error) {
	raw, err := normalize.URL(seed.Keys["url"])
	if err != nil {
		return types.RunMeta{Status: types.StatusError, Error: err.Error()}, err
	}
	res, _, err := fetch.Do(ctx, c.Client, raw)
	if err != nil {
		if neterr.Quiet(err) {
			return types.RunMeta{Status: types.StatusOK, Drop: true}, nil
		}
		return types.RunMeta{Status: types.StatusError, Error: err.Error(), Drop: true}, err
	}
	if res.Status == http.StatusNotFound || !signature.Match(res.Body) {
		// Not GraphQL: the schema query is not sent.
		return types.RunMeta{Status: types.StatusOK, Drop: true}, nil
	}
	row := map[string]any{"url": raw, "role": "graphql", "status": res.Status}
	if ide := ideName(res.Body); ide != "" {
		row["ide"] = ide
	}
	return one(emit, raw, "graphql", row)
}

func ideName(body []byte) string {
	b := bytes.ToLower(body)
	for _, n := range []string{"graphiql", "graphql-playground", "embeddable-sandbox", "altair"} {
		if bytes.Contains(b, []byte(n)) {
			return strings.TrimPrefix(n, "embeddable-")
		}
	}
	return ""
}

// Schema reads a GraphQL schema with the standard introspection query, and
// with a shorter one when the server refuses that for its depth. Active
// (-graphql): it POSTs to the target.
type Schema struct {
	Client *http.Client
}

func NewSchema(client *http.Client) *Schema { return &Schema{Client: fetch.Client(client)} }

func (s *Schema) Name() string { return SchemaName }

func (s *Schema) Info() catalog.Info {
	return catalog.Info{Kind: catalog.Active, Flag: "graphql", After: Name}
}

func (s *Schema) Inputs() []types.SeedType { return []types.SeedType{types.TypeURL} }

func (s *Schema) Outputs() []string { return []string{"graphql"} }

func (s *Schema) Skip(seed types.Seed) bool { return !looksGraphQL(seed.Keys["url"]) }

// short asks for the operation fields and type names only: what is read
// from a server that refuses the full query for its depth.
const short = `query AzhaqSchema { __schema { queryType { name } mutationType { name } subscriptionType { name } types { name kind fields { name } } } }`

// maxSchema bounds the schema kept in the observation; a larger one loses
// its descriptions, then is not kept (its operation names still are).
const maxSchema = 8 << 20

// introOff: what a server says when introspection is turned off.
var introOff = regexp.MustCompile(`(?i)introspection[^"]{0,60}(disabled|not allowed|forbidden|blocked|not permitted|turned off)|(not allowed|disabled)[^"]{0,40}introspection`)

// introspectionOff says whether an answer refuses introspection itself.
func introspectionOff(data []byte) bool { return introOff.Match(data) }

func (s *Schema) Run(ctx context.Context, seed types.Seed, emit func(types.Observation) error) (types.RunMeta, error) {
	raw, err := normalize.URL(seed.Keys["url"])
	if err != nil {
		return types.RunMeta{Status: types.StatusError, Error: err.Error()}, err
	}
	status, data, err := s.post(ctx, raw, gqlschema.Query)
	if err != nil {
		return failed(err)
	}
	full, sc, ok := gqlschema.Read(data)
	if !ok && !introspectionOff(data) {
		// Refused for its depth or cost, cut short, blocked for its size or
		// one of its fields: the names are still worth a second ask. A
		// server that turned introspection off is not asked again.
		if status, data, err = s.post(ctx, raw, short); err != nil {
			return failed(err)
		}
		_, sc, ok = gqlschema.Read(data)
		full = nil
	}
	if !ok {
		// Introspection is off or refused: the fields the server's errors
		// name are what can still be read.
		return s.recoverSchema(ctx, raw, status, emit)
	}
	row := summary(sc)
	if full != nil {
		if kept, fits := gqlschema.Bound(full, maxSchema); fits {
			row["schema"] = kept
		} else {
			row["schema_bytes"] = len(full)
		}
	}
	row["url"], row["role"], row["status"] = raw, "graphql", status
	return one(emit, raw, "graphql", row)
}

// recoverSchema reads the root fields of the query and mutation types
// from the server's validation errors, when introspection gave nothing.
func (s *Schema) recoverSchema(ctx context.Context, raw string, status int, emit func(types.Observation) error) (types.RunMeta, error) {
	q, err := s.recoverType(ctx, raw, "query")
	if err != nil {
		return failed(err)
	}
	if q == nil {
		return types.RunMeta{Status: types.StatusOK}, nil
	}
	m, err := s.recoverType(ctx, raw, "mutation")
	if err != nil {
		return failed(err)
	}
	row := map[string]any{"url": raw, "role": "graphql", "status": status, "introspection": false, "recovered": "suggestions",
		"queries": q.names(), "types": typeNames(q, m)}
	sigs := map[string]any{"queries": q.signatures()}
	if m != nil {
		row["mutations"] = m.names()
		sigs["mutations"] = m.signatures()
	}
	row["signatures"] = sigs
	return one(emit, raw, "graphql", row)
}

// failed is what a query that got no answer leaves: capped by the request
// budget, nothing for a host that does not resolve, else an error.
func failed(err error) (types.RunMeta, error) {
	switch {
	case errors.Is(err, neterr.ErrBudget):
		return types.RunMeta{Status: types.StatusCapped}, err
	case neterr.Quiet(err):
		return types.RunMeta{Status: types.StatusOK}, nil
	}
	return types.RunMeta{Status: types.StatusError, Error: err.Error()}, err
}

// post sends one GraphQL query and reads the answer.
func (s *Schema) post(ctx context.Context, raw, query string) (int, []byte, error) {
	body, _ := json.Marshal(map[string]string{"query": query})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, raw, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	for k, vs := range fetch.Extra {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", fetch.UserAgent)
	}
	if err := fetch.Spend(ctx); err != nil {
		return 0, nil, err
	}
	resp, err := s.Client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, fetch.MaxScriptBody))
	return resp.StatusCode, data, nil
}

// summary lists the fields of the query, mutation and subscription types
// and the names of the other object types.
func summary(sc *gqlschema.Schema) map[string]any {
	root := map[string]string{}
	for key, t := range map[string]*gqlschema.Named{"queries": sc.QueryType, "mutations": sc.MutationType, "subscriptions": sc.SubscriptionType} {
		if t != nil {
			root[t.Name] = key
		}
	}
	row := map[string]any{"introspection": true}
	var objects []string
	for _, t := range sc.Types {
		if key, ok := root[t.Name]; ok {
			var names []string
			for _, f := range t.Fields {
				if len(names) < maxFields {
					names = append(names, f.Name)
				}
			}
			sort.Strings(names)
			row[key] = names
			continue
		}
		if t.Kind == "OBJECT" && !strings.HasPrefix(t.Name, "__") && len(objects) < maxFields {
			objects = append(objects, t.Name)
		}
	}
	sort.Strings(objects)
	row["types"] = objects
	return row
}

func one(emit func(types.Observation) error, source, kind string, row map[string]any) (types.RunMeta, error) {
	payload, _ := json.Marshal(row)
	if err := emit(types.Observation{
		Collector: kindName(row), Source: source, Kind: kind,
		Payload: payload, Confidence: 0.9, ObservedAt: time.Now().UTC(),
	}); err != nil {
		return types.RunMeta{}, err
	}
	return types.RunMeta{Status: types.StatusOK, EmitCount: 1}, nil
}

func kindName(row map[string]any) string {
	if row["introspection"] == true || row["recovered"] != nil {
		return SchemaName
	}
	return Name
}
