// Package gqlcol recognises GraphQL endpoints and, behind -graphql, reads
// their schema through introspection. Recognising one takes a plain GET;
// introspection is a POST, so it is an active technique.
package gqlcol

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/trannghiach/azhaq/catalog"
	"github.com/trannghiach/azhaq/internal/fetch"
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
func (c *Collector) Info() catalog.Info { return catalog.Info{Kind: catalog.Touch} }

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

// Schema reads a GraphQL schema with one introspection query. Active
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

// introspection asks for the operation fields and type names only.
const introspection = `query AzhaqSchema { __schema { queryType { name } mutationType { name } subscriptionType { name } types { name kind fields { name } } } }`

func (s *Schema) Run(ctx context.Context, seed types.Seed, emit func(types.Observation) error) (types.RunMeta, error) {
	raw, err := normalize.URL(seed.Keys["url"])
	if err != nil {
		return types.RunMeta{Status: types.StatusError, Error: err.Error()}, err
	}
	body, _ := json.Marshal(map[string]string{"query": introspection})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, raw, bytes.NewReader(body))
	if err != nil {
		return types.RunMeta{Status: types.StatusError, Error: err.Error()}, err
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
	resp, err := s.Client.Do(req)
	if err != nil {
		if neterr.Quiet(err) {
			return types.RunMeta{Status: types.StatusOK}, nil
		}
		return types.RunMeta{Status: types.StatusError, Error: err.Error()}, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, fetch.MaxScriptBody))
	row, ok := readSchema(data)
	if !ok {
		return types.RunMeta{Status: types.StatusOK}, nil
	}
	row["url"], row["role"], row["status"] = raw, "graphql", resp.StatusCode
	return one(emit, raw, "graphql", row)
}

// readSchema summarises an introspection answer: the fields of the query,
// mutation and subscription types and the names of the other object types.
func readSchema(data []byte) (map[string]any, bool) {
	var r struct {
		Data struct {
			Schema struct {
				QueryType, MutationType, SubscriptionType *struct{ Name string }
				Types                                     []struct {
					Name, Kind string
					Fields     []struct{ Name string }
				}
			} `json:"__schema"`
		}
	}
	if json.Unmarshal(data, &r) != nil || len(r.Data.Schema.Types) == 0 {
		return nil, false
	}
	sc := r.Data.Schema
	root := map[string]string{}
	if sc.QueryType != nil {
		root[sc.QueryType.Name] = "queries"
	}
	if sc.MutationType != nil {
		root[sc.MutationType.Name] = "mutations"
	}
	if sc.SubscriptionType != nil {
		root[sc.SubscriptionType.Name] = "subscriptions"
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
	return row, true
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
	if row["introspection"] == true {
		return SchemaName
	}
	return Name
}
