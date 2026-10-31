package main

import (
	"encoding/json"
	"regexp"
	"strings"

	"github.com/trannghiach/azhaq/engine"
	"github.com/trannghiach/azhaq/internal/gqlschema"
)

// sigRE reads a recovered field: name(arg: Type!, …): Type, with the
// arguments and the type each optional.
var sigRE = regexp.MustCompile(`^(\w+)(?:\((.*)\))?(?::\s*(.+))?$`)

var builtinScalar = map[string]bool{"String": true, "Int": true, "Float": true, "Boolean": true, "ID": true}

// typeRef reads "[UserObject!]!" as introspection writes it. Whether a
// named type is an object or an input object was not recovered; it is
// taken as one for a field and the other for an argument.
func typeRef(s string, input bool) gqlschema.TypeRef {
	s = strings.TrimSpace(s)
	switch {
	case strings.HasSuffix(s, "!"):
		in := typeRef(strings.TrimSuffix(s, "!"), input)
		return gqlschema.TypeRef{Kind: "NON_NULL", OfType: &in}
	case strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]"):
		in := typeRef(s[1:len(s)-1], input)
		return gqlschema.TypeRef{Kind: "LIST", OfType: &in}
	case builtinScalar[s]:
		return gqlschema.TypeRef{Kind: "SCALAR", Name: s}
	case input:
		return gqlschema.TypeRef{Kind: "INPUT_OBJECT", Name: s}
	}
	return gqlschema.TypeRef{Kind: "OBJECT", Name: s}
}

// recoveredType builds one root type from recovered signatures; fields
// whose type the errors never named are returned apart, not given a type
// nobody saw.
func recoveredType(name string, sigs []string) (gqlschema.Type, []string) {
	t := gqlschema.Type{Kind: "OBJECT", Name: name}
	var untyped []string
	for _, sig := range sigs {
		m := sigRE.FindStringSubmatch(sig)
		if m == nil {
			continue
		}
		if m[3] == "" {
			untyped = append(untyped, m[1])
			continue
		}
		f := gqlschema.Field{Name: m[1], Type: typeRef(m[3], false)}
		if m[2] != "" {
			for _, a := range strings.Split(m[2], ", ") {
				if n, ty, ok := strings.Cut(a, ": "); ok {
					f.Args = append(f.Args, gqlschema.InputValue{Name: n, Type: typeRef(ty, true)})
				}
			}
		}
		t.Fields = append(t.Fields, f)
	}
	return t, untyped
}

// recoveredSchema is the schema a run recovered from validation errors,
// in the shape introspection gives, and the root fields left without a type.
func recoveredSchema(s engine.GQLSchema) (*gqlschema.Schema, map[string][]string) {
	sc := &gqlschema.Schema{Types: []gqlschema.Type{}}
	untyped := map[string][]string{}
	for _, r := range []struct {
		name, usual string
		sigs        []string
	}{{s.QueryType, "Query", s.Queries}, {s.MutationType, "Mutation", s.Mutations}} {
		if len(r.sigs) == 0 {
			continue
		}
		if r.name == "" {
			r.name = r.usual
		}
		t, un := recoveredType(r.name, r.sigs)
		if len(un) > 0 {
			untyped[r.name] = un
		}
		if len(t.Fields) > 0 {
			sc.Types = append(sc.Types, t)
		}
		if r.usual == "Query" {
			sc.QueryType = &gqlschema.Named{Name: r.name}
		} else {
			sc.MutationType = &gqlschema.Named{Name: r.name}
		}
	}
	return sc, untyped
}

// recoveredEndpoints are the endpoints whose schema was recovered, not
// introspected, that no whole schema of the same URL replaces.
func recoveredEndpoints(schemas []engine.GQLSchema, whole []gqlEndpoint) []gqlEndpoint {
	have := map[string]bool{}
	for _, ep := range whole {
		have[ep.URL] = true
	}
	var out []gqlEndpoint
	for _, s := range schemas {
		if !s.Partial() || have[s.URL] {
			continue
		}
		sc, untyped := recoveredSchema(s)
		if len(sc.Types) == 0 && len(untyped) == 0 {
			continue
		}
		raw, _ := json.Marshal(sc)
		mark := map[string]any{"introspection": false, "recovered": s.Recovered, "partial": true, "complete": false}
		if s.Errors > 0 {
			mark["validation_errors"] = s.Errors
		}
		if len(s.ClientOps) > 0 {
			mark["client_operations"] = s.ClientOps
		}
		if s.ClientWords > 0 {
			mark["client_words"] = s.ClientWords
		}
		if len(untyped) > 0 {
			mark["untyped_fields"] = untyped
		}
		out = append(out, gqlEndpoint{URL: s.URL, Raw: raw, Schema: sc, Recovered: &s, Mark: mark, Untyped: untyped})
	}
	return out
}

// recoveredSDLNotes are the comment lines that follow the mark in an SDL
// export: what the schema does not hold.
func recoveredSDLNotes(ep gqlEndpoint) string {
	var b strings.Builder
	if c := ep.Recovered.Counts(); c != "" {
		b.WriteString("# recovered fields: " + c + "\n")
	}
	for _, root := range []string{ep.Recovered.QueryType, ep.Recovered.MutationType} {
		if names := ep.Untyped[root]; len(names) > 0 {
			b.WriteString("# fields whose type was not recovered, left out of " + root + ": " + strings.Join(names, ", ") + "\n")
		}
	}
	if len(ep.Recovered.ClientOps) > 0 {
		b.WriteString("# client operations seen in scripts: " + strings.Join(ep.Recovered.ClientOps, ", ") + "\n")
	}
	return b.String()
}
