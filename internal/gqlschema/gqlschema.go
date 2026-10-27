// Package gqlschema reads the answer to a GraphQL introspection query: the
// operations a schema offers, and the schema in the GraphQL schema
// language (SDL).
package gqlschema

import (
	"bytes"
	"encoding/json"
	"errors"
	"sort"
	"strings"
)

// Query is the standard introspection query, as graphql-js writes it
// without the options older servers reject (the schema's description,
// repeatable directives, deprecated arguments).
const Query = `query IntrospectionQuery { __schema { queryType { name } mutationType { name } subscriptionType { name } types { ...FullType } directives { name description locations args { ...InputValue } } } }
fragment FullType on __Type { kind name description fields(includeDeprecated: true) { name description args { ...InputValue } type { ...TypeRef } isDeprecated deprecationReason } inputFields { ...InputValue } interfaces { ...TypeRef } enumValues(includeDeprecated: true) { name description isDeprecated deprecationReason } possibleTypes { ...TypeRef } }
fragment InputValue on __InputValue { name description type { ...TypeRef } defaultValue }
fragment TypeRef on __Type { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } } } } } }`

// Schema is the __schema object of an introspection answer.
type Schema struct {
	QueryType        *Named      `json:"queryType"`
	MutationType     *Named      `json:"mutationType"`
	SubscriptionType *Named      `json:"subscriptionType"`
	Types            []Type      `json:"types"`
	Directives       []Directive `json:"directives"`
}

// Named is a reference to a type by its name.
type Named struct {
	Name string `json:"name"`
}

// Type is a named type with what its kind has: fields and the interfaces
// it implements, input fields, enum values, or the types it stands for.
type Type struct {
	Kind          string       `json:"kind"`
	Name          string       `json:"name"`
	Description   string       `json:"description"`
	Fields        []Field      `json:"fields"`
	InputFields   []InputValue `json:"inputFields"`
	Interfaces    []TypeRef    `json:"interfaces"`
	EnumValues    []EnumValue  `json:"enumValues"`
	PossibleTypes []TypeRef    `json:"possibleTypes"`
}

// Field is a field of an object or interface type.
type Field struct {
	Name              string       `json:"name"`
	Description       string       `json:"description"`
	Args              []InputValue `json:"args"`
	Type              TypeRef      `json:"type"`
	IsDeprecated      bool         `json:"isDeprecated"`
	DeprecationReason *string      `json:"deprecationReason"`
}

// InputValue is an argument or an input object's field. DefaultValue is
// a GraphQL literal ("10", "\"asc\"", "{a: 1}").
type InputValue struct {
	Name         string  `json:"name"`
	Description  string  `json:"description"`
	Type         TypeRef `json:"type"`
	DefaultValue *string `json:"defaultValue"`
}

// EnumValue is one value of an enum type.
type EnumValue struct {
	Name              string  `json:"name"`
	Description       string  `json:"description"`
	IsDeprecated      bool    `json:"isDeprecated"`
	DeprecationReason *string `json:"deprecationReason"`
}

// TypeRef is a type as a field or argument uses it: a named type, or a
// list or non-null wrapper around one.
type TypeRef struct {
	Kind   string   `json:"kind"`
	Name   string   `json:"name"`
	OfType *TypeRef `json:"ofType"`
}

// Directive is a directive the schema declares.
type Directive struct {
	Name        string       `json:"name"`
	Description string       `json:"description"`
	Locations   []string     `json:"locations"`
	Args        []InputValue `json:"args"`
}

// String writes the type as GraphQL does: [User!]!.
func (t TypeRef) String() string {
	switch {
	case t.Kind == "NON_NULL" && t.OfType != nil:
		return t.OfType.String() + "!"
	case t.Kind == "LIST" && t.OfType != nil:
		return "[" + t.OfType.String() + "]"
	}
	return t.Name
}

// Read takes an introspection answer ({"data":{"__schema":…}}) and returns
// its __schema object as it came, compacted, and the schema read from it.
// ok is false when the answer holds no schema.
func Read(answer []byte) (raw json.RawMessage, s *Schema, ok bool) {
	var r struct {
		Data struct {
			Schema json.RawMessage `json:"__schema"`
		} `json:"data"`
	}
	if json.Unmarshal(answer, &r) != nil || len(r.Data.Schema) == 0 {
		return nil, nil, false
	}
	s, err := Parse(r.Data.Schema)
	if err != nil {
		return nil, nil, false
	}
	var buf bytes.Buffer
	if json.Compact(&buf, r.Data.Schema) != nil {
		return nil, nil, false
	}
	return buf.Bytes(), s, true
}

// Parse reads a __schema object.
func Parse(raw json.RawMessage) (*Schema, error) {
	var s Schema
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, err
	}
	if len(s.Types) == 0 {
		return nil, errNoTypes
	}
	return &s, nil
}

var errNoTypes = errors.New("the schema has no types")

// Bound keeps a __schema object within max bytes: past it, descriptions
// are dropped; a schema still larger is not kept (ok is false).
func Bound(raw json.RawMessage, max int) (json.RawMessage, bool) {
	if len(raw) <= max {
		return raw, true
	}
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return nil, false
	}
	dropDescriptions(v)
	out, err := json.Marshal(v)
	if err != nil || len(out) > max {
		return nil, false
	}
	return out, true
}

func dropDescriptions(v any) {
	switch x := v.(type) {
	case map[string]any:
		for k, y := range x {
			if k == "description" {
				x[k] = nil
				continue
			}
			dropDescriptions(y)
		}
	case []any:
		for _, y := range x {
			dropDescriptions(y)
		}
	}
}

// Type finds a type by name.
func (s *Schema) Type(name string) *Type {
	for i := range s.Types {
		if s.Types[i].Name == name {
			return &s.Types[i]
		}
	}
	return nil
}

// Operation is a field of the query, mutation or subscription type.
type Operation struct {
	Kind       string // query, mutation, subscription
	Name       string
	Args       []InputValue
	Type       TypeRef
	Deprecated bool
}

// Signature is the operation as GraphQL writes it, without its kind:
// users(limit: Int, offset: Int): [User].
func (o Operation) Signature() string {
	var b strings.Builder
	b.WriteString(o.Name)
	if len(o.Args) > 0 {
		b.WriteByte('(')
		for i, a := range o.Args {
			if i > 0 {
				b.WriteString(", ")
			}
			b.WriteString(a.Name + ": " + a.Type.String())
			if a.DefaultValue != nil {
				b.WriteString(" = " + *a.DefaultValue)
			}
		}
		b.WriteByte(')')
	}
	if t := o.Type.String(); t != "" {
		b.WriteString(": " + t)
	}
	return b.String()
}

// Operations lists the queries, then the mutations, then the
// subscriptions, each by name.
func (s *Schema) Operations() []Operation {
	var out []Operation
	for _, root := range []struct {
		kind string
		t    *Named
	}{{"query", s.QueryType}, {"mutation", s.MutationType}, {"subscription", s.SubscriptionType}} {
		if root.t == nil {
			continue
		}
		t := s.Type(root.t.Name)
		if t == nil {
			continue
		}
		var ops []Operation
		for _, f := range t.Fields {
			ops = append(ops, Operation{Kind: root.kind, Name: f.Name, Args: f.Args, Type: f.Type, Deprecated: f.IsDeprecated})
		}
		sort.SliceStable(ops, func(i, j int) bool { return ops[i].Name < ops[j].Name })
		out = append(out, ops...)
	}
	return out
}
