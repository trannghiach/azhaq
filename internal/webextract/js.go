package webextract

import (
	"bytes"
	"encoding/json"
	"net/url"
	"regexp"
	"strings"
)

var (
	absURL = regexp.MustCompile(`https?://[A-Za-z0-9._~:/?#\[\]@!$&*+,;=%-]+`)
	relURL = regexp.MustCompile(`['"\x60](/[A-Za-z0-9._~/?#&=+-]{1,256})['"\x60]`)
	// dotURL is a link written relative to the page: "./redirect?to=".
	dotURL = regexp.MustCompile(`['"\x60](\./[A-Za-z][A-Za-z0-9._~/-]{0,200})(?:\?[A-Za-z0-9._~&=+-]*)?['"\x60?]`)
	// numericPath is "/160" or "/2/3": sizes and ratios, not routes.
	numericPath = regexp.MustCompile(`^[/0-9.]+$`)
	jsonPath    = regexp.MustCompile(`"(?:url|href|path|route|page|api|endpoint)"\s*:\s*"(/[A-Za-z0-9._~/?#&=+-]{1,256})"`)
	// scriptRef matches module imports and chunk names: "./chunk-AB12.js",
	// "../lib/x.mjs", "/static/js/42.3f9c.chunk.js", "chunk-AB12.js".
	scriptRef = regexp.MustCompile(`['"\x60]((?:\.{1,2}/|/)?[A-Za-z0-9_~@/-][A-Za-z0-9._~@/-]{0,200}\.m?js)['"\x60]`)
)

func JSURLs(script string, base *url.URL) []string {
	if base == nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	add := func(raw string) {
		if u, ok := resolve(base, raw); ok && !seen[u] {
			seen[u] = true
			out = append(out, u)
		}
	}
	for _, m := range absURL.FindAllString(script, -1) {
		add(trimURLJunk(m))
	}
	for _, m := range relURL.FindAllStringSubmatch(script, -1) {
		if len(m) == 2 && !numericPath.MatchString(m[1]) {
			add(m[1])
		}
	}
	for _, m := range dotURL.FindAllStringSubmatch(script, -1) {
		if p := m[1]; !strings.HasSuffix(p, ".js") && !strings.HasSuffix(p, ".mjs") && !strings.HasSuffix(p, ".css") {
			// Relative to the app's root, where a single-page app runs.
			add("/" + strings.TrimPrefix(p, "./"))
		}
	}
	for _, m := range jsonPath.FindAllStringSubmatch(script, -1) {
		if len(m) == 2 {
			add(m[1])
		}
	}
	return out
}

// ScriptRefs returns the scripts a script imports or loads as chunks,
// resolved against the script's own URL as a browser would.
func ScriptRefs(script string, scriptURL *url.URL) []string {
	if scriptURL == nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, m := range scriptRef.FindAllStringSubmatch(script, -1) {
		ref := m[1]
		if strings.Contains(ref, "//") || strings.HasPrefix(ref, "@") {
			continue
		}
		if u, ok := resolve(scriptURL, ref); ok && !seen[u] {
			seen[u] = true
			out = append(out, u)
		}
	}
	return out
}

// JSONLinks returns links in a JSON document: href/src attributes inside
// HTML string values, and string values that are a URL or an absolute path.
func JSONLinks(body []byte, base *url.URL) []string {
	if base == nil {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	var doc any
	if err := dec.Decode(&doc); err != nil {
		return nil
	}
	var markup strings.Builder
	seen := map[string]bool{}
	var out []string
	add := func(u string) {
		if !seen[u] {
			seen[u] = true
			out = append(out, u)
		}
	}
	var walk func(v any)
	walk = func(v any) {
		switch t := v.(type) {
		case map[string]any:
			for _, x := range t {
				walk(x)
			}
		case []any:
			for _, x := range t {
				walk(x)
			}
		case string:
			switch {
			case strings.Contains(t, "<"):
				markup.WriteString(t)
				markup.WriteByte('\n')
			case len(t) < 512 && !strings.ContainsAny(t, " \t\n") &&
				(strings.HasPrefix(t, "http://") || strings.HasPrefix(t, "https://") ||
					(strings.HasPrefix(t, "/") && !strings.HasPrefix(t, "//"))):
				if u, ok := resolve(base, t); ok {
					add(u)
				}
			}
		}
	}
	walk(doc)
	for _, u := range Links([]byte(markup.String()), base) {
		add(u)
	}
	return out
}

func trimURLJunk(s string) string {
	return strings.TrimRight(s, ".,);'\"")
}

var sourceMapRE = regexp.MustCompile(`//[#@]\s*sourceMappingURL=(\S+)\s*$`)

// SourceMapURL is the map a script names in its last line, resolved
// against the script, or "" (inline data: maps included as given).
func SourceMapURL(script string, scriptURL *url.URL) string {
	tail := script
	if len(tail) > 2048 {
		tail = tail[len(tail)-2048:]
	}
	m := sourceMapRE.FindStringSubmatch(strings.TrimRight(tail, " \t\r\n;"))
	if m == nil || scriptURL == nil {
		return ""
	}
	if strings.HasPrefix(m[1], "data:") {
		return m[1]
	}
	u, err := scriptURL.Parse(m[1])
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return ""
	}
	return u.String()
}

var (
	gqlDocument = regexp.MustCompile(`\b(query|mutation|subscription)\s+([A-Za-z_]\w*)\s*[({]`)
	gqlAST      = regexp.MustCompile(`"?operation"?\s*:\s*"(query|mutation|subscription)"\s*,\s*"?name"?\s*:\s*\{\s*"?kind"?\s*:\s*"Name"\s*,\s*"?value"?\s*:\s*"(\w+)"`)
)

// GraphQLOps lists the GraphQL operations a script carries, as
// "query GetUser", from query documents or from the parsed form bundlers
// emit for gql tags.
func GraphQLOps(script string) []string {
	seen := map[string]bool{}
	var out []string
	for _, re := range []*regexp.Regexp{gqlDocument, gqlAST} {
		for _, m := range re.FindAllStringSubmatch(script, -1) {
			op := m[1] + " " + m[2]
			if !seen[op] && len(out) < 500 {
				seen[op] = true
				out = append(out, op)
			}
		}
	}
	return out
}
