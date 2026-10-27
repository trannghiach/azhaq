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
	// relURL is a path in a string; [id] and [...slug] are a file-system
	// router's parameters (/admin/users/[userId]).
	relURL = regexp.MustCompile(`['"\x60](/[A-Za-z0-9._~/?#&=+\[\]-]{1,256})['"\x60]`)
	// dotURL is a link written relative to the page: "./redirect?to=".
	dotURL = regexp.MustCompile(`['"\x60](\./[A-Za-z][A-Za-z0-9._~/-]{0,200})(?:\?[A-Za-z0-9._~&=+-]*)?['"\x60?]`)
	// numericPath is "/160" or "/2/3": sizes and ratios, not routes.
	numericPath = regexp.MustCompile(`^[/0-9.]+$`)
	jsonPath    = regexp.MustCompile(`"(?:url|href|path|route|page|api|endpoint)"\s*:\s*"(/[A-Za-z0-9._~/?#&=+-]{1,256})"`)
	// scriptRef matches module imports and chunk names: "./chunk-AB12.js",
	// "../lib/x.mjs", "/static/js/42.3f9c.chunk.js", "chunk-AB12.js".
	scriptRef = regexp.MustCompile(`['"\x60]((?:\.{1,2}/|/)?[A-Za-z0-9_~@/-][A-Za-z0-9._~@/\[\]-]{0,200}\.m?js)['"\x60]`)
	// brackets is a path segment with a file-system router's parameter.
	brackets = regexp.MustCompile(`\[\[?(?:\.\.\.)?[A-Za-z_$][\w$]*\]\]?`)
)

// bracketPath maps a file-system router's parameters to the map's:
// /admin/users/[userId] → /admin/users/{userId}, [...slug] → {slug}.
// ok is false for brackets that are not one (/[a-z]).
func bracketPath(p string) (string, bool) {
	if !strings.Contains(p, "[") && !strings.Contains(p, "]") {
		return p, true
	}
	out := brackets.ReplaceAllStringFunc(p, dynamicSegment)
	return out, !strings.ContainsAny(out, "[]")
}

// JSURLs returns the URLs and paths a script names in its strings,
// resolved against base, each once.
func JSURLs(script string, base *url.URL) []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range JSURLRefs(script, base) {
		if !seen[r.URL] {
			seen[r.URL] = true
			out = append(out, r.URL)
		}
	}
	return out
}

// Ref is a URL a script names, and where: Start and End are the byte
// offsets of what names it.
type Ref struct {
	URL        string
	Start, End int
}

// JSURLRefs is JSURLs with every place each URL is named, in the order
// JSURLs lists them.
func JSURLRefs(script string, base *url.URL) []Ref {
	if base == nil {
		return nil
	}
	var out []Ref
	add := func(raw string, start, end int) {
		if u, ok := resolve(base, raw); ok && !StringNoise(u) {
			out = append(out, Ref{URL: u, Start: start, End: end})
		}
	}
	for _, m := range absURL.FindAllStringIndex(script, -1) {
		add(trimURLJunk(script[m[0]:m[1]]), m[0], m[1])
	}
	for _, m := range relURL.FindAllStringSubmatchIndex(script, -1) {
		if p, ok := bracketPath(script[m[2]:m[3]]); ok && !numericPath.MatchString(p) {
			add(p, m[0], m[1])
		}
	}
	for _, m := range dotURL.FindAllStringSubmatchIndex(script, -1) {
		if p := script[m[2]:m[3]]; !strings.HasSuffix(p, ".js") && !strings.HasSuffix(p, ".mjs") && !strings.HasSuffix(p, ".css") {
			// Relative to the app's root, where a single-page app runs.
			add("/"+strings.TrimPrefix(p, "./"), m[0], m[1])
		}
	}
	for _, m := range jsonPath.FindAllStringSubmatchIndex(script, -1) {
		add(script[m[2]:m[3]], m[0], m[1])
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
	// Next.js names chunks from its asset root (static/chunks/…), not
	// from the folder of the manifest that lists them.
	nextRoot := scriptURL
	if i := strings.Index(scriptURL.Path, "/_next/"); i >= 0 {
		r := *scriptURL
		r.Path, r.RawPath, r.RawQuery = scriptURL.Path[:i+len("/_next/")], "", ""
		nextRoot = &r
	}
	for _, m := range scriptRef.FindAllStringSubmatch(script, -1) {
		ref := m[1]
		if strings.Contains(ref, "//") || strings.HasPrefix(ref, "@") {
			continue
		}
		if strings.ContainsAny(ref, "[]") && strings.ContainsAny(brackets.ReplaceAllString(ref, ""), "[]") {
			continue // a name template ([name].[contenthash].js), not a file
		}
		base := scriptURL
		if strings.HasPrefix(ref, "static/") {
			base = nextRoot
		}
		if u, ok := resolve(base, ref); ok && !seen[u] {
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
				if u, ok := resolve(base, t); ok && !StringNoise(t) {
					add(u)
				}
			case strings.Contains(t, "]("):
				for _, u := range MarkdownLinks(t, base) {
					add(u) // text a page renders as Markdown
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
