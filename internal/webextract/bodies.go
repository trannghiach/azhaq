package webextract

import (
	"regexp"
	"strings"
)

// maxBodyReach is how far before a request a variable it sends may be set.
const maxBodyReach = 3000

// bodyNames are the field names of a request body expression: an object
// literal, JSON.stringify of one, new URLSearchParams({…}), Object.assign
// of literals, or a variable set to one of these before the request (a
// FormData or URLSearchParams built with append). pos is where the request
// is. A body only known at run time has none.
func (ev evaluator) bodyNames(expr string, pos, depth int) []string {
	expr = strings.TrimSpace(expr)
	if expr == "" || depth > 3 {
		return nil
	}
	switch {
	case strings.HasPrefix(expr, "{"):
		return objectKeys(expr)
	case strings.HasPrefix(expr, "JSON.stringify("):
		if args := callArgs(expr, len("JSON.stringify")); len(args) > 0 {
			return ev.bodyNames(args[0], pos, depth+1)
		}
	case strings.HasPrefix(expr, "new URLSearchParams("), strings.HasPrefix(expr, "new FormData("):
		open := strings.IndexByte(expr, '(')
		if args := callArgs(expr, open); len(args) > 0 && strings.TrimSpace(args[0]) != "" {
			return ev.bodyNames(args[0], pos, depth+1)
		}
	case strings.HasPrefix(expr, "Object.assign("):
		var out []string
		for _, a := range callArgs(expr, len("Object.assign")) {
			out = union(out, ev.bodyNames(a, pos, depth+1))
		}
		return out
	case identChain.MatchString(expr):
		name := strings.Join(strings.Fields(expr), "")
		rhs, ok := ev.assignedRHS(name, pos)
		if !ok {
			return nil
		}
		out := ev.bodyNames(rhs, pos, depth+1)
		if strings.HasPrefix(rhs, "new FormData(") || strings.HasPrefix(rhs, "new URLSearchParams(") {
			out = union(out, appended(ev.src, name, pos))
		}
		return out
	}
	return nil
}

// assignedRHS is what a variable or a field was last set to before pos:
// let r={…}, this.payload={…}, r=….
func (ev evaluator) assignedRHS(name string, pos int) (string, bool) {
	field := strings.TrimPrefix(name, "this.")
	if strings.Contains(field, ".") {
		return "", false
	}
	if len(field) <= 2 && field == name {
		rhs, at, ok := ev.declared(field, pos) // a minified local: only a declaration just before
		return rhs, ok && !parameterDefault(ev.src, at, rhs)
	}
	start := max(0, pos-maxBodyReach)
	re, err := regexp.Compile(`(?:^|[^\w$.]|this\.)` + regexp.QuoteMeta(field) + `\s*=([^=>])`)
	if err != nil {
		return "", false
	}
	locs := re.FindAllStringSubmatchIndex(ev.src[start:pos], -1)
	if len(locs) == 0 {
		return "", false
	}
	at := start + locs[len(locs)-1][2]
	rhs := topExpr(ev.src[at:])
	return rhs, rhs != "" && !parameterDefault(ev.src, at, rhs)
}

// parameterDefault says whether the expression rhs found at at is a
// parameter's default (function f(url, opts = {})), which a caller
// replaces, and not a value the variable holds.
func parameterDefault(src string, at int, rhs string) bool {
	i := strings.Index(src[at:], rhs)
	if i < 0 {
		return false
	}
	j := skipSpace(src, at+i+len(rhs))
	return j < len(src) && src[j] == ')'
}

// appended are the names of name.append("level", …) and name.set(…) calls
// just before pos: the fields of a FormData or URLSearchParams built by hand.
func appended(src, name string, pos int) []string {
	win := src[max(0, pos-maxBodyReach):pos]
	var out []string
	for _, verb := range []string{".append(", ".set("} {
		key := name + verb
		for from := 0; ; {
			i := strings.Index(win[from:], key)
			if i < 0 {
				break
			}
			i += from
			from = i + len(key)
			if i > 0 && (isIdentByte(win[i-1]) || win[i-1] == '.') {
				continue
			}
			args := callArgs(win, from-1)
			if len(args) == 0 {
				continue
			}
			if lit, ok := literal(args[0]); ok && plainIdent.MatchString(strings.NewReplacer("-", "_").Replace(lit)) {
				out = union(out, []string{lit})
			}
		}
	}
	return out
}

// xhrBody is the body sent by the XMLHttpRequest opened at open (the
// index of its ".open(") with xhr.send(…) after it.
func (ev evaluator) xhrBody(open, after int) []string {
	recv := ev.src[receiverStart(ev.src, open):open]
	if recv == "" {
		return nil
	}
	key := recv + ".send("
	win := ev.src[after:min(len(ev.src), after+maxBodyReach)]
	i := strings.Index(win, key)
	if i < 0 {
		return nil
	}
	args := callArgs(win, i+len(key)-1)
	if len(args) == 0 {
		return nil
	}
	return ev.bodyNames(args[0], after+i, 0)
}
