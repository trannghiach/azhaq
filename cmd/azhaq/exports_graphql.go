package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strings"

	"github.com/trannghiach/azhaq/internal/gqlschema"
	"github.com/trannghiach/azhaq/types"
)

// gqlEndpoint is a GraphQL endpoint whose schema was read by
// introspection (run -graphql).
type gqlEndpoint struct {
	URL    string
	Raw    json.RawMessage // the __schema object, as the server sent it
	Schema *gqlschema.Schema
}

// graphqlEndpoints lists the endpoints with a whole schema, by URL; a
// later answer from the same URL replaces an earlier one.
func graphqlEndpoints(obs []types.StoredObservation) []gqlEndpoint {
	byURL := map[string]gqlEndpoint{}
	for _, o := range obs {
		if o.Collector != "azhaq-graphql-schema" || o.Kind != "graphql" {
			continue
		}
		var p struct {
			URL    string          `json:"url"`
			Schema json.RawMessage `json:"schema"`
		}
		if json.Unmarshal(o.Payload, &p) != nil || p.URL == "" {
			continue
		}
		s, err := gqlschema.Parse(p.Schema)
		if err != nil {
			continue
		}
		byURL[p.URL] = gqlEndpoint{URL: p.URL, Raw: p.Schema, Schema: s}
	}
	out := make([]gqlEndpoint, 0, len(byURL))
	for _, ep := range byURL {
		out = append(out, ep)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].URL < out[j].URL })
	return out
}

// graphqlExport writes the schemas read by introspection. graphql: the
// introspection result, {"data":{"__schema":…}}, as InQL, Burp, Postman,
// graphql-voyager and clairvoyance read it; with several endpoints, one
// object keyed by endpoint URL. sdl: the schema in the GraphQL schema
// language, each endpoint's under a "# URL" comment. origin (-origin)
// keeps the endpoints on that origin, or the one at that URL.
func graphqlExport(g *graphView, format, origin string, w io.Writer) error {
	all := graphqlEndpoints(g.obs)
	var eps []gqlEndpoint
	want := strings.TrimSuffix(origin, "/")
	for _, ep := range all {
		u, err := url.Parse(ep.URL)
		if want == "" || err == nil && (u.Scheme+"://"+u.Host == want || strings.TrimSuffix(ep.URL, "/") == want) {
			eps = append(eps, ep)
		}
	}
	if len(eps) == 0 {
		switch {
		case len(all) > 0:
			var urls []string
			for _, ep := range all {
				urls = append(urls, ep.URL)
			}
			return fmt.Errorf("no GraphQL schema on %s (there is one at %s)", origin, strings.Join(urls, ", "))
		case hasGraphQLNames(g.obs):
			return fmt.Errorf("the GraphQL schemas in %s were kept by operation names only (the server refused the full introspection query, or the run is older): see azhaq show", g.path)
		default:
			return fmt.Errorf("no GraphQL schema in %s: map with -graphql (and -allow or -scope) to read one by introspection", g.path)
		}
	}
	if format == "sdl" {
		for i, ep := range eps {
			if i > 0 {
				fmt.Fprintln(w)
			}
			fmt.Fprintf(w, "# %s\n# read by introspection; mapped by azhaq %s\n\n", ep.URL, version)
			if _, err := io.WriteString(w, ep.Schema.SDL()); err != nil {
				return err
			}
		}
		return nil
	}
	result := func(ep gqlEndpoint) map[string]any {
		return map[string]any{"data": map[string]any{"__schema": ep.Raw}}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if len(eps) == 1 {
		return enc.Encode(result(eps[0]))
	}
	byURL := map[string]any{}
	for _, ep := range eps {
		byURL[ep.URL] = result(ep)
	}
	return enc.Encode(byURL)
}

// hasGraphQLNames: an introspection answer is stored, by names only.
func hasGraphQLNames(obs []types.StoredObservation) bool {
	for _, o := range obs {
		if o.Collector == "azhaq-graphql-schema" && o.Kind == "graphql" {
			return true
		}
	}
	return false
}
