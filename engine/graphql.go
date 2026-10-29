package engine

import (
	"encoding/json"

	"github.com/trannghiach/azhaq/internal/gqlschema"
	"github.com/trannghiach/azhaq/types"
)

// maxGraphQLLines caps the GraphQL operations the text map prints under
// an endpoint; the JSON row and the exports have them all.
const maxGraphQLLines = 50

// graphqlOps are the operations of the schema a GraphQL endpoint gave by
// introspection (-graphql), one per query, mutation and subscription:
// POST, the arguments as body names, the signature as the summary. A
// schema kept by names only gives names.
func graphqlOps(obs []types.StoredObservation) []Op {
	type answer struct {
		Schema        json.RawMessage `json:"schema"`
		Queries       []string        `json:"queries"`
		Mutations     []string        `json:"mutations"`
		Subscriptions []string        `json:"subscriptions"`
		Recovered     string          `json:"recovered"`
	}
	var p *answer
	for _, o := range obs {
		if o.Collector != "azhaq-graphql-schema" || o.Kind != "graphql" {
			continue
		}
		var a answer
		if json.Unmarshal(o.Payload, &a) == nil {
			p = &a // the newest answer wins
		}
	}
	if p == nil {
		return nil
	}
	var out []Op
	defer func() {
		for i := range out {
			out[i].Partial = p.Recovered != "" // names the server's errors gave, not its schema
		}
	}()
	if s, err := gqlschema.Parse(p.Schema); err == nil {
		for _, o := range s.Operations() {
			op := Op{Method: "POST", Summary: o.Kind + " " + o.Signature(), OperationID: o.Name, Source: "graphql"}
			for _, a := range o.Args {
				op.Body = append(op.Body, a.Name)
			}
			out = append(out, op)
		}
		return out
	}
	for _, k := range []struct {
		kind  string
		names []string
	}{{"query", p.Queries}, {"mutation", p.Mutations}, {"subscription", p.Subscriptions}} {
		for _, n := range k.names {
			out = append(out, Op{Method: "POST", Summary: k.kind + " " + n, OperationID: n, Source: "graphql"})
		}
	}
	return out
}
