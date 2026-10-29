package engine

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/trannghiach/azhaq/types"
)

// GQLSchema is how a GraphQL endpoint's schema is known: read whole by
// introspection, read by names only, or recovered from the server's
// validation errors while introspection is off.
type GQLSchema struct {
	URL           string
	Introspection bool   // the server answered the introspection query
	Whole         bool   // the answer was kept whole (types, fields, arguments)
	Recovered     string // how a schema was recovered ("suggestions"), else ""
	Errors        int    // validation errors read to recover it, 0 when not recorded
	ClientOps     []string
	Queries       []string // recovered signatures: name(arg: Type!): Type
	Mutations     []string
	QueryType     string
	MutationType  string
}

// Partial: the schema is a recovery and may lack types and fields.
func (s GQLSchema) Partial() bool { return s.Recovered != "" }

// Mark is the sentence that goes with a recovered schema wherever it is
// printed.
func (s GQLSchema) Mark() string {
	from := "validation errors"
	if s.Errors > 0 {
		from = fmt.Sprintf("%d validation errors", s.Errors)
	}
	return fmt.Sprintf("introspection disabled on %s; recovered from %s and %d client operations: partial, may lack types and fields",
		s.URL, from, len(s.ClientOps))
}

// GraphQLSchemas lists the endpoints a run read the schema of, by URL,
// the newest answer of each, with the client operations scripts on the
// endpoint's origin carry.
func GraphQLSchemas(obs []types.StoredObservation) []GQLSchema {
	byURL := map[string]GQLSchema{}
	ops := map[string]map[string]bool{} // origin → "query GetUser"
	for _, o := range obs {
		if o.Kind != "graphql" {
			continue
		}
		switch o.Collector {
		case "azhaq-js":
			var p struct {
				URL string   `json:"url"`
				Ops []string `json:"graphql_operations"`
			}
			if json.Unmarshal(o.Payload, &p) != nil {
				continue
			}
			origin := originOf(p.URL)
			for _, op := range p.Ops {
				if ops[origin] == nil {
					ops[origin] = map[string]bool{}
				}
				ops[origin][op] = true
			}
		case "azhaq-graphql-schema":
			var p struct {
				URL           string          `json:"url"`
				Introspection bool            `json:"introspection"`
				Schema        json.RawMessage `json:"schema"`
				SchemaBytes   int             `json:"schema_bytes"`
				Recovered     string          `json:"recovered"`
				Errors        int             `json:"errors"`
				QueryType     string          `json:"query_type"`
				MutationType  string          `json:"mutation_type"`
				Signatures    struct {
					Queries   []string `json:"queries"`
					Mutations []string `json:"mutations"`
				} `json:"signatures"`
			}
			if json.Unmarshal(o.Payload, &p) != nil || p.URL == "" {
				continue
			}
			byURL[p.URL] = GQLSchema{URL: p.URL, Introspection: p.Introspection, Whole: len(p.Schema) > 0 || p.SchemaBytes > 0,
				Recovered: p.Recovered, Errors: p.Errors, Queries: p.Signatures.Queries, Mutations: p.Signatures.Mutations,
				QueryType: p.QueryType, MutationType: p.MutationType}
		}
	}
	out := make([]GQLSchema, 0, len(byURL))
	for _, s := range byURL {
		for op := range ops[originOf(s.URL)] {
			s.ClientOps = append(s.ClientOps, op)
		}
		sort.Strings(s.ClientOps)
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].URL < out[j].URL })
	return out
}

// GraphQLNotes say, per endpoint, how its schema is known.
func GraphQLNotes(obs []types.StoredObservation) []string {
	var out []string
	for _, s := range GraphQLSchemas(obs) {
		switch {
		case s.Partial():
			out = append(out, fmt.Sprintf("GraphQL %s: introspection disabled: schema recovered (partial)", s.URL))
		case s.Whole:
			out = append(out, fmt.Sprintf("GraphQL %s: introspection: full schema", s.URL))
		case s.Introspection:
			out = append(out, fmt.Sprintf("GraphQL %s: introspection: names only (the server refused the full query)", s.URL))
		}
	}
	return out
}
