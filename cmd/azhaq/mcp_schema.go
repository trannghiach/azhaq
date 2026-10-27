package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"
)

// The arguments of a tool call are checked against the inputSchema the
// server publishes and nothing else, so what tools/list tells a client
// and what a call is held to cannot drift apart. The schemas use a small
// part of JSON Schema: type, properties, required, additionalProperties,
// items, enum, minimum, minItems, dependentRequired and examples.

var errUnknownTool = errors.New("unknown tool")

// toolSchemas are the input schemas of the tools, by name.
var toolSchemas = sync.OnceValue(func() map[string]map[string]any {
	out := map[string]map[string]any{}
	for _, t := range mcpTools() {
		out[t["name"].(string)] = t["inputSchema"].(map[string]any)
	}
	return out
})

// checkArgs refuses a tool the server does not have and arguments that do
// not fit its schema: a misspelt limit or a scope the tools would ignore
// must not pass in silence, nor a string where a list or a role goes.
func checkArgs(tool string, args any) error {
	schema, ok := toolSchemas()[tool]
	if !ok {
		return fmt.Errorf("%w %q", errUnknownTool, tool)
	}
	if args == nil {
		args = map[string]any{} // a call without arguments gives none
	}
	if err := (argCheck{tool}).value(schema, args, ""); err != nil {
		return fmt.Errorf("invalid params: %w", err)
	}
	return nil
}

type argCheck struct{ tool string }

// name is the argument at a path (roles[1].header) as an error names it.
func (c argCheck) name(at string) string {
	if at == "" {
		return "the arguments of " + c.tool
	}
	return "argument " + at + " of " + c.tool
}

func (c argCheck) value(s map[string]any, v any, at string) error {
	if !hasType(s, v) {
		return fmt.Errorf("%s must be %s, not %s", c.name(at), expected(s), given(v))
	}
	if enum := strings1(s["enum"]); enum != nil {
		if x, _ := v.(string); !slices.Contains(enum, x) {
			return fmt.Errorf("%s must be one of %s, not %s", c.name(at), strings.Join(enum, ", "), given(v))
		}
	}
	if lo, ok := number(s["minimum"]); ok {
		if f, _ := v.(float64); f < lo {
			return fmt.Errorf("%s must be %s, not %s", c.name(at), expected(s), given(v))
		}
	}
	switch v := v.(type) {
	case []any:
		if n, ok := number(s["minItems"]); ok && float64(len(v)) < n {
			return fmt.Errorf("%s must hold at least %g items, not %d", c.name(at), n, len(v))
		}
		if items, ok := s["items"].(map[string]any); ok {
			for i, x := range v {
				if err := c.value(items, x, fmt.Sprintf("%s[%d]", at, i)); err != nil {
					return err
				}
			}
		}
	case map[string]any:
		return c.object(s, v, at)
	}
	return nil
}

func (c argCheck) object(s map[string]any, v map[string]any, at string) error {
	props, _ := s["properties"].(map[string]any)
	known := propNames(s)
	if s["additionalProperties"] == false {
		var bad []string
		for k := range v {
			if _, ok := props[k]; !ok {
				bad = append(bad, strconv.Quote(k))
			}
		}
		if len(bad) > 0 {
			sort.Strings(bad)
			takes := "it takes none"
			if len(known) > 0 {
				takes = "it takes " + strings.Join(known, ", ")
			}
			word := "argument"
			if at != "" {
				word = "property"
			}
			if len(bad) > 1 {
				word += "s"
			}
			where := "for " + c.tool
			if at != "" {
				where = "in " + at + " of " + c.tool
			}
			return fmt.Errorf("unknown %s %s %s; %s", word, strings.Join(bad, ", "), where, takes)
		}
	}
	var missing []string
	for _, k := range strings1(s["required"]) {
		if _, ok := v[k]; !ok {
			missing = append(missing, strconv.Quote(k))
		}
	}
	if len(missing) > 0 {
		word := "argument"
		if len(missing) > 1 {
			word += "s"
		}
		if at == "" {
			return fmt.Errorf("%s needs the %s %s", c.tool, word, strings.Join(missing, ", "))
		}
		return fmt.Errorf("%s needs %s%s", c.name(at), strings.Join(missing, ", "), such(s))
	}
	keys := make([]string, 0, len(v))
	for k := range v {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		p, _ := props[k].(map[string]any)
		if p == nil {
			continue
		}
		sub := k
		if at != "" {
			sub = at + "." + k
		}
		if err := c.value(p, v[k], sub); err != nil {
			return err
		}
	}
	deps, _ := s["dependentRequired"].(map[string][]string)
	for _, k := range keys {
		for _, d := range deps[k] {
			if _, ok := v[d]; !ok {
				return fmt.Errorf("%s gives %q without %q", c.name(at), k, d)
			}
		}
	}
	return nil
}

func hasType(s map[string]any, v any) bool {
	switch s["type"] {
	case "string":
		_, ok := v.(string)
		return ok
	case "boolean":
		_, ok := v.(bool)
		return ok
	case "number":
		_, ok := v.(float64)
		return ok
	case "integer":
		f, ok := v.(float64)
		return ok && f == math.Trunc(f) && !math.IsInf(f, 0)
	case "array":
		_, ok := v.([]any)
		return ok
	case "object":
		_, ok := v.(map[string]any)
		return ok
	}
	return true
}

// expected says what a schema takes: "an array of strings", "an object
// {name, header, user, password}".
func expected(s map[string]any) string {
	switch s["type"] {
	case "string":
		return "a string"
	case "integer":
		if lo, ok := number(s["minimum"]); ok {
			return fmt.Sprintf("an integer of at least %g", lo)
		}
		return "an integer"
	case "number":
		return "a number"
	case "boolean":
		return "true or false"
	case "array":
		items, _ := s["items"].(map[string]any)
		switch items["type"] {
		case "string":
			return "an array of strings"
		case "object":
			return "an array of objects " + shape(items) + such(items)
		}
		return "an array"
	case "object":
		return "an object " + shape(s) + such(s)
	}
	return "a value"
}

// shape lists an object's properties, the required ones first.
func shape(s map[string]any) string {
	req := strings1(s["required"])
	names := slices.Clone(req)
	for _, k := range propNames(s) {
		if !slices.Contains(req, k) {
			names = append(names, k)
		}
	}
	return "{" + strings.Join(names, ", ") + "}"
}

// such is ", such as" and a schema's examples, when it has some.
func such(s map[string]any) string {
	ex, _ := s["examples"].([]any)
	if len(ex) == 0 {
		return ""
	}
	parts := make([]string, len(ex))
	for i, x := range ex {
		raw, _ := json.Marshal(x)
		parts[i] = string(raw)
	}
	if len(parts) == 1 {
		return ", such as " + parts[0]
	}
	return ", such as " + strings.Join(parts[:len(parts)-1], ", ") + " or " + parts[len(parts)-1]
}

// given says what a call gave, briefly.
func given(v any) string {
	switch v := v.(type) {
	case nil:
		return "null"
	case string:
		if utf8.RuneCountInString(v) > 40 {
			v = string([]rune(v)[:40]) + "…"
		}
		return "the string " + strconv.Quote(v)
	case float64:
		return "the number " + strconv.FormatFloat(v, 'g', -1, 64)
	case bool:
		return "the boolean " + strconv.FormatBool(v)
	case []any:
		return fmt.Sprintf("an array of %d", len(v))
	case map[string]any:
		return "an object"
	}
	return fmt.Sprintf("a %T", v)
}

func propNames(s map[string]any) []string {
	props, _ := s["properties"].(map[string]any)
	names := make([]string, 0, len(props))
	for k := range props {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

// strings1 reads a list of strings a schema holds as []string or []any.
func strings1(v any) []string {
	switch v := v.(type) {
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, x := range v {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func number(v any) (float64, bool) {
	switch v := v.(type) {
	case int:
		return float64(v), true
	case float64:
		return v, true
	}
	return 0, false
}
