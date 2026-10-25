package webextract

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Webpack names lazily loaded chunks in a function of the chunk ID:
//
//	n.u=e=>"static/js/"+e+"."+{12:"a1b2",45:"c3d4"}[e]+".chunk.js"   (webpack 5)
//	n.u=e=>"static/js/"+e+".7db48f2d.chunk.js"                       (one hash)
//	function u(e){return o.p+"js/"+({1:"admin"}[e]||e)+"."+{1:"ab"}[e]+".js"}  (webpack 4)
//
// ChunkURLs evaluates that function for every chunk ID the script names:
// the keys of its lookup tables, or the IDs passed to the chunk loader
// (n.e(742)) when it has none.

var (
	chunkFnV5   = regexp.MustCompile(`(?:^|[^\w$])` + ident + `\.u\s*=\s*(?:function\s*\((` + ident + `)\)\s*\{\s*return\s*|\(?(` + ident + `)\)?\s*=>\s*)`)
	chunkFnV4   = regexp.MustCompile(`function\s+` + ident + `\s*\((` + ident + `)\)\s*\{\s*return\s+(` + ident + `)\.p\s*\+`)
	publicPath  = regexp.MustCompile(`(?:^|[^\w$])` + ident + `\.p\s*=\s*"([^"\\\n]*)"`)
	chunkLoad   = regexp.MustCompile(`(?:^|[^\w$])` + ident + `\.e\(\s*(\d+|"[\w.-]+")\s*\)`)
	tablePair   = regexp.MustCompile(`["']?([\w.-]+)["']?\s*:\s*"([^"\\\n]*)"`)
	maxChunkIDs = 256
)

// ChunkURLs returns chunk paths as the loader builds them, prefixed with
// the bundle's public path ("/" when it sets none).
func ChunkURLs(script string) []string {
	var param, expr string
	if loc := chunkFnV5.FindStringSubmatchIndex(script); loc != nil {
		param = submatch(script, loc, 1)
		if param == "" {
			param = submatch(script, loc, 2)
		}
		expr = topExpr(script[loc[1]:])
	} else if loc := chunkFnV4.FindStringSubmatchIndex(script); loc != nil {
		param = submatch(script, loc, 1)
		expr = topExpr(script[loc[4]:]) // keep "o.p+" in the expression
	}
	if param == "" || expr == "" {
		return nil
	}
	terms := splitTop(expr, "+")
	ids := map[string]bool{}
	for _, t := range terms {
		for k := range tableIn(t) {
			ids[k] = true
		}
	}
	if len(ids) == 0 {
		for _, m := range chunkLoad.FindAllStringSubmatch(script, -1) {
			ids[strings.Trim(m[1], `"`)] = true
		}
	}
	prefix := "/"
	if m := publicPath.FindStringSubmatch(script); m != nil {
		prefix = m[1]
	}
	var out []string
	for _, id := range sortedIDs(ids) {
		if len(out) >= maxChunkIDs {
			break
		}
		name, ok := evalChunk(terms, param, id, prefix)
		if ok && strings.HasSuffix(name, ".js") {
			if !strings.HasPrefix(name, "/") && !strings.Contains(name, "://") {
				name = prefix + name
			}
			out = append(out, name)
		}
	}
	return out
}

func submatch(s string, loc []int, i int) string {
	if loc[2*i] < 0 {
		return ""
	}
	return s[loc[2*i]:loc[2*i+1]]
}

// evalChunk computes one chunk name from the "+"-joined terms.
func evalChunk(terms []string, param, id, prefix string) (string, bool) {
	var b strings.Builder
	for _, t := range terms {
		v, ok := evalTerm(strings.TrimSpace(t), param, id, prefix)
		if !ok {
			return "", false
		}
		b.WriteString(v)
	}
	return b.String(), true
}

func evalTerm(t, param, id, prefix string) (string, bool) {
	for strings.HasPrefix(t, "(") && strings.HasSuffix(t, ")") && len(splitTop(t[1:len(t)-1], ",")) == 1 {
		t = strings.TrimSpace(t[1 : len(t)-1])
	}
	switch {
	case t == param:
		return id, true
	case len(t) >= 2 && (t[0] == '"' || t[0] == '\'') && t[len(t)-1] == t[0]:
		return t[1 : len(t)-1], true
	case strings.HasSuffix(t, ".p") && !strings.ContainsAny(t, "{(\"'"):
		return prefix, true // webpack 4: o.p is the public path
	}
	if alts := splitTop(t, "||"); len(alts) > 1 {
		for _, a := range alts {
			if v, ok := evalTerm(strings.TrimSpace(a), param, id, prefix); ok {
				return v, true
			}
		}
		return "", false
	}
	if strings.HasPrefix(t, "{") && strings.HasSuffix(t, "["+param+"]") {
		v, ok := tableIn(t)[id]
		return v, ok
	}
	return "", false
}

// tableIn reads the {id:"value",…} lookup a term starts with.
func tableIn(t string) map[string]string {
	t = strings.TrimLeft(t, "( ")
	if !strings.HasPrefix(t, "{") {
		return nil
	}
	body := balanced(t)
	if body == "" {
		return nil
	}
	out := map[string]string{}
	for _, m := range tablePair.FindAllStringSubmatch(body, -1) {
		out[m[1]] = m[2]
	}
	return out
}

// topExpr returns the expression s starts with, up to the first ",", ";"
// or unmatched closing bracket outside brackets and strings.
func topExpr(s string) string {
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
		case c == '(' || c == '{' || c == '[':
			depth++
		case c == ')' || c == '}' || c == ']':
			if depth == 0 {
				return strings.TrimSpace(s[:i])
			}
			depth--
		case (c == ',' || c == ';') && depth == 0:
			return strings.TrimSpace(s[:i])
		}
	}
	return ""
}

// splitTop splits s on sep outside brackets and strings.
func splitTop(s, sep string) []string {
	var out []string
	depth, start := 0, 0
	var quote byte
	for i := 0; i < len(s); i++ {
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
		case c == '(' || c == '{' || c == '[':
			depth++
		case c == ')' || c == '}' || c == ']':
			depth--
		case depth == 0 && strings.HasPrefix(s[i:], sep):
			out = append(out, s[start:i])
			i += len(sep) - 1
			start = i + 1
		}
	}
	return append(out, s[start:])
}

func sortedIDs(ids map[string]bool) []string {
	out := make([]string, 0, len(ids))
	for id := range ids {
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool {
		a, errA := strconv.Atoi(out[i])
		b, errB := strconv.Atoi(out[j])
		if errA == nil && errB == nil {
			return a < b
		}
		return out[i] < out[j]
	})
	return out
}
