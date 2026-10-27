package gqlschema

import (
	"bytes"
	"encoding/json"
	"strings"
)

// builtinScalars and builtinDirectives come with every schema; SDL leaves
// them out, as graphql-js's printSchema does.
var (
	builtinScalars    = map[string]bool{"String": true, "Int": true, "Float": true, "Boolean": true, "ID": true}
	builtinDirectives = map[string]bool{"skip": true, "include": true, "deprecated": true, "specifiedBy": true, "oneOf": true}
)

const defaultDeprecation = "No longer supported"

// SDL writes the schema in the GraphQL schema language, in the order the
// server listed its types. A schema block is written only when the root
// types are not simply Query, Mutation and Subscription.
func (s *Schema) SDL() string {
	var blocks []string
	if b := s.schemaBlock(); b != "" {
		blocks = append(blocks, b)
	}
	for _, d := range s.Directives {
		if !builtinDirectives[d.Name] {
			blocks = append(blocks, directiveSDL(d))
		}
	}
	for _, t := range s.Types {
		if t.Name == "" || strings.HasPrefix(t.Name, "__") || (t.Kind == "SCALAR" && builtinScalars[t.Name]) {
			continue
		}
		blocks = append(blocks, typeSDL(t))
	}
	return strings.Join(blocks, "\n\n") + "\n"
}

func (s *Schema) schemaBlock() string {
	roots := []struct {
		op, usual string
		t         *Named
	}{{"query", "Query", s.QueryType}, {"mutation", "Mutation", s.MutationType}, {"subscription", "Subscription", s.SubscriptionType}}
	usual := true
	for _, r := range roots {
		// A type named Mutation that is not the mutation type would be
		// taken for it without a schema block.
		if r.t != nil && r.t.Name != r.usual || r.t == nil && s.Type(r.usual) != nil {
			usual = false
		}
	}
	if usual {
		return ""
	}
	var b strings.Builder
	b.WriteString("schema {\n")
	for _, r := range roots {
		if r.t != nil && r.t.Name != "" {
			b.WriteString("  " + r.op + ": " + r.t.Name + "\n")
		}
	}
	b.WriteString("}")
	return b.String()
}

func typeSDL(t Type) string {
	var b strings.Builder
	description(&b, t.Description, "")
	switch t.Kind {
	case "SCALAR":
		b.WriteString("scalar " + t.Name)
	case "OBJECT", "INTERFACE":
		if t.Kind == "OBJECT" {
			b.WriteString("type " + t.Name)
		} else {
			b.WriteString("interface " + t.Name)
		}
		if len(t.Interfaces) > 0 {
			names := make([]string, len(t.Interfaces))
			for i, x := range t.Interfaces {
				names[i] = x.String()
			}
			b.WriteString(" implements " + strings.Join(names, " & "))
		}
		if len(t.Fields) > 0 {
			b.WriteString(" {\n")
			for _, f := range t.Fields {
				description(&b, f.Description, "  ")
				b.WriteString("  " + f.Name + args(f.Args, "  ") + ": " + f.Type.String() + deprecated(f.IsDeprecated, f.DeprecationReason) + "\n")
			}
			b.WriteString("}")
		}
	case "UNION":
		b.WriteString("union " + t.Name)
		if len(t.PossibleTypes) > 0 {
			names := make([]string, len(t.PossibleTypes))
			for i, x := range t.PossibleTypes {
				names[i] = x.String()
			}
			b.WriteString(" = " + strings.Join(names, " | "))
		}
	case "ENUM":
		b.WriteString("enum " + t.Name)
		if len(t.EnumValues) > 0 {
			b.WriteString(" {\n")
			for _, v := range t.EnumValues {
				description(&b, v.Description, "  ")
				b.WriteString("  " + v.Name + deprecated(v.IsDeprecated, v.DeprecationReason) + "\n")
			}
			b.WriteString("}")
		}
	case "INPUT_OBJECT":
		b.WriteString("input " + t.Name)
		if len(t.InputFields) > 0 {
			b.WriteString(" {\n")
			for _, f := range t.InputFields {
				description(&b, f.Description, "  ")
				b.WriteString("  " + inputValue(f) + "\n")
			}
			b.WriteString("}")
		}
	default:
		// A kind this printer does not know: kept as a comment, so the
		// rest still parses.
		b.WriteString("# " + strings.ToLower(t.Kind) + " " + t.Name)
	}
	return b.String()
}

func directiveSDL(d Directive) string {
	var b strings.Builder
	description(&b, d.Description, "")
	b.WriteString("directive @" + d.Name + args(d.Args, "") + " on " + strings.Join(d.Locations, " | "))
	return b.String()
}

// args writes arguments on one line, or one per line when any has a
// description.
func args(as []InputValue, indent string) string {
	if len(as) == 0 {
		return ""
	}
	multi := false
	for _, a := range as {
		if a.Description != "" {
			multi = true
		}
	}
	parts := make([]string, len(as))
	if !multi {
		for i, a := range as {
			parts[i] = inputValue(a)
		}
		return "(" + strings.Join(parts, ", ") + ")"
	}
	var b strings.Builder
	b.WriteString("(\n")
	for _, a := range as {
		description(&b, a.Description, indent+"  ")
		b.WriteString(indent + "  " + inputValue(a) + "\n")
	}
	b.WriteString(indent + ")")
	return b.String()
}

func inputValue(v InputValue) string {
	s := v.Name + ": " + v.Type.String()
	if v.DefaultValue != nil {
		s += " = " + *v.DefaultValue
	}
	return s
}

func deprecated(is bool, reason *string) string {
	if !is {
		return ""
	}
	if reason == nil || *reason == defaultDeprecation {
		return " @deprecated"
	}
	return " @deprecated(reason: " + quote(*reason) + ")"
}

// description writes a block string above a definition.
func description(b *strings.Builder, d, indent string) {
	if d == "" {
		return
	}
	d = strings.ReplaceAll(strings.ReplaceAll(d, "\r\n", "\n"), "\r", "\n")
	d = strings.Map(func(r rune) rune {
		if r < 0x20 && r != '\n' && r != '\t' {
			return -1 // not allowed in GraphQL source
		}
		return r
	}, d)
	d = strings.ReplaceAll(d, `"""`, `\"""`)
	b.WriteString(indent + `"""` + "\n")
	for _, line := range strings.Split(d, "\n") {
		if strings.TrimSpace(line) == "" {
			b.WriteString("\n")
			continue
		}
		b.WriteString(indent + line + "\n")
	}
	b.WriteString(indent + `"""` + "\n")
}

// quote writes a GraphQL string: its escapes are JSON's.
func quote(s string) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s)
	return strings.TrimSuffix(buf.String(), "\n")
}
