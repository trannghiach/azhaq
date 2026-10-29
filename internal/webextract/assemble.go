package webextract

import (
	"sort"
	"strings"
)

// Bundles often keep an API prefix and the paths under it in separate
// constants and join them where the request is made:
//
//	og="identity/",sg={LOGIN:"api/auth/login",…}; … fetch(og+sg.LOGIN, …)
//
// Assembled resolves such joins: a variable plus a property of an object
// literal, a variable plus a string, and the same two in template
// literals. Only names bound once in the script are trusted, so a short
// minified name reused across modules is left alone.

const ident = `[A-Za-z_$][\w$]*`

var (
	pathish     = lazyRE(`^(https?://[\w.-]+(:\d+)?)?/?[\w.~%<>{}:-]+(/[\w.~%<>{}:-]*)+$`)
	twoSegments = lazyRE(`[\w-]/[\w{<]`)
	placeholder = lazyRE(`<(\w+)>`)
)

type memberRef struct {
	base, obj, key string
	at, end        int // the join in the script
}

type strRef struct {
	name, lit string // variable, literal suffix
	at, end   int
}

// Assembled returns the paths a script builds by joining constants, as
// written ("identity/api/auth/login"), with <name> placeholders turned
// into {name}. Callers resolve them against the page's origin.
func Assembled(script string) []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range AssembledRefs(script) {
		if !seen[r.URL] {
			seen[r.URL] = true
			out = append(out, r.URL)
		}
	}
	sort.Strings(out)
	return out
}

// AssembledRefs is Assembled with each join that builds a path; URL is
// the path as built.
func AssembledRefs(script string) []Ref {
	var members []memberRef
	var strs []strRef
	needStr, needObj := map[string]bool{}, map[string]bool{}
	// Joins: a+b.c, a+"…", `${a}${b.c}`, `${a}…`.
	for i := 0; i < len(script); i++ {
		switch script[i] {
		case '+':
			if i+1 < len(script) && script[i+1] == '+' || i > 0 && script[i-1] == '+' {
				continue
			}
			left, ok := identBefore(script, i)
			if !ok {
				continue
			}
			at := max(0, i-len(left))
			j := skipSpace(script, i+1)
			if j < len(script) && script[j] == '"' {
				if lit, ok := stringAt(script, j); ok {
					strs = append(strs, strRef{left, lit, at, j + len(lit) + 2})
					needStr[left] = true
				}
				continue
			}
			obj, j := identAt(script, j)
			if obj == "" || j >= len(script) || script[j] != '.' {
				continue
			}
			if key, k := identAt(script, j+1); key != "" {
				members = append(members, memberRef{left, obj, key, at, k})
				needStr[left], needObj[obj] = true, true
			}
		case '`':
			if !strings.HasPrefix(script[i+1:], "${") {
				continue
			}
			a, j := identAt(script, i+3)
			if a == "" || j >= len(script) || script[j] != '}' {
				continue
			}
			j++
			if strings.HasPrefix(script[j:], "${") {
				obj, k := identAt(script, j+2)
				if obj == "" || k >= len(script) || script[k] != '.' {
					continue
				}
				key, k := identAt(script, k+1)
				if key != "" && strings.HasPrefix(script[k:], "}`") {
					members = append(members, memberRef{a, obj, key, i, k + 2})
					needStr[a], needObj[obj] = true, true
				}
				continue
			}
			end := strings.IndexAny(script[j:], "`$\\\n")
			if end > 0 && end <= 200 && script[j+end] == '`' {
				strs = append(strs, strRef{a, script[j : j+end], i, j + end + 1})
				needStr[a] = true
			}
		}
	}
	if len(members) == 0 && len(strs) == 0 {
		return nil
	}

	// Bindings: name="…" and name={…} for the names the joins use.
	values := map[string]map[string]bool{}
	objects := map[string][]map[string]string{}
	for i := 0; i < len(script); i++ {
		if script[i] != '=' || i+1 < len(script) && (script[i+1] == '=' || script[i+1] == '>') {
			continue
		}
		if i > 0 && strings.IndexByte("=!<>+-*/%&|^", script[i-1]) >= 0 {
			continue
		}
		name, ok := identBefore(script, i)
		if !ok || !needStr[name] && !needObj[name] {
			continue
		}
		j := skipSpace(script, i+1)
		switch {
		case j < len(script) && script[j] == '"' && needStr[name]:
			if v, ok := stringAt(script, j); ok {
				if values[name] == nil {
					values[name] = map[string]bool{}
				}
				values[name][v] = true
			}
		case j < len(script) && script[j] == '{' && needObj[name]:
			objects[name] = append(objects[name], objectStrings(balanced(script[j:])))
		}
	}
	single := func(name string) (string, bool) {
		vs := values[name]
		if len(vs) != 1 {
			return "", false
		}
		for v := range vs {
			return v, true
		}
		return "", false
	}

	var out []Ref
	add := func(p string, at, end int) {
		p = placeholder.ReplaceAllString(p, "{$1}")
		if len(p) <= 300 && strings.Contains(p, "/") && !strings.HasPrefix(p, "//") && pathish.MatchString(p) && twoSegments.MatchString(p) {
			out = append(out, Ref{URL: p, Start: at, End: end})
		}
	}
	for _, r := range members {
		base, ok := single(r.base)
		if !ok || len(objects[r.obj]) != 1 {
			continue
		}
		if v, ok := objects[r.obj][0][r.key]; ok {
			add(base+v, r.at, r.end)
		}
	}
	for _, r := range strs {
		if base, ok := single(r.name); ok {
			add(base+r.lit, r.at, r.end)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Start < out[j].Start })
	return out
}

func isIdentByte(c byte) bool {
	return c == '_' || c == '$' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

func skipSpace(s string, i int) int {
	for i < len(s) && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r') {
		i++
	}
	return i
}

// identAt reads the identifier at i and returns it with the index after it.
func identAt(s string, i int) (string, int) {
	j := i
	for j < len(s) && isIdentByte(s[j]) {
		j++
	}
	if j == i || s[i] >= '0' && s[i] <= '9' {
		return "", i
	}
	return s[i:j], j
}

// identBefore reads the identifier that ends just before s[end] (spaces
// allowed), rejecting a property (x.name) or part of a longer token.
func identBefore(s string, end int) (string, bool) {
	j := end
	for j > 0 && (s[j-1] == ' ' || s[j-1] == '\t') {
		j--
	}
	i := j
	for i > 0 && isIdentByte(s[i-1]) {
		i--
	}
	if i == j || s[i] >= '0' && s[i] <= '9' || i > 0 && s[i-1] == '.' {
		return "", false
	}
	return s[i:j], true
}

// stringAt reads a double-quoted literal without escapes or newlines, up
// to 200 bytes.
func stringAt(s string, i int) (string, bool) {
	for j := i + 1; j < len(s) && j <= i+201; j++ {
		switch s[j] {
		case '"':
			return s[i+1 : j], true
		case '\\', '\n':
			return "", false
		}
	}
	return "", false
}

// objectStrings reads the KEY:"value" properties at the top level of an
// object literal.
func objectStrings(body string) map[string]string {
	props := map[string]string{}
	depth := 0
	for i := 0; i < len(body); i++ {
		switch c := body[i]; {
		case c == '"' || c == '\'' || c == '`':
			k := i + 1
			for k < len(body) && body[k] != c {
				if body[k] == '\\' {
					k++
				}
				k++
			}
			if depth == 1 && c == '"' && k+1 < len(body) && (i > 0 && (body[i-1] == ',' || body[i-1] == '{')) {
				// "KEY":"value"
				if j := skipSpace(body, k+1); j < len(body) && body[j] == ':' {
					if j = skipSpace(body, j+1); j < len(body) && body[j] == '"' {
						if v, ok := stringAt(body, j); ok {
							props[body[i+1:k]] = v
						}
					}
				}
			}
			i = k
		case c == '{' || c == '[' || c == '(':
			depth++
		case c == '}' || c == ']' || c == ')':
			depth--
		}
		if depth == 1 && (body[i] == ',' || body[i] == '{') {
			j := skipSpace(body, i+1)
			key, k := identAt(body, j)
			if key == "" {
				continue
			}
			if k = skipSpace(body, k); k < len(body) && body[k] == ':' {
				if k = skipSpace(body, k+1); k < len(body) && body[k] == '"' {
					if v, ok := stringAt(body, k); ok {
						props[key] = v
					}
				}
			}
		}
	}
	return props
}

// balanced returns the {...} that s starts with, skipping strings, or ""
// when it does not close within 64 KiB.
func balanced(s string) string {
	depth := 0
	var quote byte
	for i := 0; i < len(s) && i < 64<<10; i++ {
		c := s[i]
		switch {
		case quote != 0:
			if c == '\\' {
				i++
			} else if c == quote {
				quote = 0
			}
		case c == '"' || c == '\'' || c == '`':
			quote = c
		case c == '{':
			depth++
		case c == '}':
			depth--
			if depth == 0 {
				return s[:i+1]
			}
		}
	}
	return ""
}
