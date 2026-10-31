package engine

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/trannghiach/azhaq/types"
)

// RecoveryCount is how many of one root type's fields a recovery without
// introspection found, and how: never proof it found them all.
type RecoveryCount struct {
	Fields     int            `json:"fields"`
	By         map[string]int `json:"by"` // "client", "probe" or "suggestion" -> count
	WordsTried int            `json:"words_tried"`
}

// GQLSchema is how a GraphQL endpoint's schema is known: read whole by
// introspection, read by names only, or recovered from the server's
// validation errors while introspection is off.
type GQLSchema struct {
	URL              string
	Introspection    bool   // the server answered the introspection query
	Whole            bool   // the answer was kept whole (types, fields, arguments)
	Recovered        string // how a schema was recovered ("suggestions"), else ""
	Errors           int    // validation errors read to recover it, 0 when not recorded
	ClientOps        []string
	ClientWords      int // field, argument and type names read from the map's own HTML and scripts
	QueryRecovery    *RecoveryCount
	MutationRecovery *RecoveryCount
	Queries          []string // recovered signatures: name(arg: Type!): Type
	Mutations        []string
	QueryType        string
	MutationType     string
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
	return fmt.Sprintf("introspection disabled on %s; recovered from %s and %d client operations: partial, may lack types and fields; recovery does not prove there are no others",
		s.URL, from, len(s.ClientOps))
}

// Counts is the recovered field count and how it was found, per root type
// (query NAME: N fields (a client, b probe, c suggestion), M words tried),
// for the summary note and the exports.
func (s GQLSchema) Counts() string {
	var parts []string
	for _, r := range []struct {
		label string
		c     *RecoveryCount
	}{{"query " + s.QueryType, s.QueryRecovery}, {"mutation " + s.MutationType, s.MutationRecovery}} {
		if r.c == nil {
			continue
		}
		var by []string
		for _, k := range []string{"client", "probe", "suggestion"} {
			if n := r.c.By[k]; n > 0 {
				by = append(by, fmt.Sprintf("%d %s", n, k))
			}
		}
		parts = append(parts, fmt.Sprintf("%s: %d fields (%s), %d words tried", r.label, r.c.Fields, strings.Join(by, ", "), r.c.WordsTried))
	}
	return strings.Join(parts, "; ")
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
				ClientWords   int             `json:"client_words"`
				Signatures    struct {
					Queries   []string `json:"queries"`
					Mutations []string `json:"mutations"`
				} `json:"signatures"`
				Recovery struct {
					Queries   *RecoveryCount `json:"queries"`
					Mutations *RecoveryCount `json:"mutations"`
				} `json:"recovery"`
			}
			if json.Unmarshal(o.Payload, &p) != nil || p.URL == "" {
				continue
			}
			byURL[p.URL] = GQLSchema{URL: p.URL, Introspection: p.Introspection, Whole: len(p.Schema) > 0 || p.SchemaBytes > 0,
				Recovered: p.Recovered, Errors: p.Errors, Queries: p.Signatures.Queries, Mutations: p.Signatures.Mutations,
				QueryType: p.QueryType, MutationType: p.MutationType, ClientWords: p.ClientWords,
				QueryRecovery: p.Recovery.Queries, MutationRecovery: p.Recovery.Mutations}
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
			note := fmt.Sprintf("GraphQL %s: introspection disabled: schema recovered (partial", s.URL)
			if c := s.Counts(); c != "" {
				note += ": " + c
			}
			out = append(out, note+"; not proof there is nothing more)")
		case s.Whole:
			out = append(out, fmt.Sprintf("GraphQL %s: introspection: full schema", s.URL))
		case s.Introspection:
			out = append(out, fmt.Sprintf("GraphQL %s: introspection: names only (the server refused the full query)", s.URL))
		}
	}
	return out
}
