package paramcol

import (
	_ "embed"
	"fmt"
	"regexp"
	"strings"
)

// names is the built-in parameter list, the likelier names first: SecLists'
// Discovery/Web-Content/burp-parameter-names.txt (MIT, Copyright (c) 2018
// Daniel Miessler, data/LICENSE-SecLists) and names azhaq's own passes
// found, ranked by that evidence.
//
//go:embed data/names.txt
var names string

// Sizes of the built-in lists: the first lines of names.txt.
var sizes = map[string]int{"small": 1000, "medium": 3000, "large": 0}

// Builtin is a built-in list by its name: small, medium or large.
func Builtin(name string) ([]string, bool) {
	n, ok := sizes[name]
	if !ok {
		return nil, false
	}
	var out []string
	for _, l := range strings.Split(names, "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	if n > 0 && n < len(out) {
		out = out[:n]
	}
	return out, true
}

var humpRE = regexp.MustCompile(`([a-z0-9])([A-Z])`)

// Recase writes names in one style: snake (like_this), camel (likeThis) or
// lower (likethis). arjun's spellings of them are accepted too.
func Recase(words []string, style string) ([]string, error) {
	var join func(parts []string) string
	switch style {
	case "snake", "like_this":
		join = func(p []string) string { return strings.Join(p, "_") }
	case "camel", "likeThis":
		join = camel
	case "lower", "likethis":
		join = func(p []string) string { return strings.Join(p, "") }
	default:
		return nil, fmt.Errorf("-casing %q: use snake (like_this), camel (likeThis) or lower (likethis)", style)
	}
	seen := map[string]bool{}
	var out []string
	for _, w := range words {
		parts := splitName(w)
		r := w
		if len(parts) > 0 {
			r = join(parts)
		}
		if !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
	}
	return out, nil
}

// splitName cuts a name into lower-case words at "_", "-", "." and humps.
func splitName(n string) []string {
	n = humpRE.ReplaceAllString(n, "${1}_${2}")
	var out []string
	for _, p := range strings.FieldsFunc(n, func(r rune) bool { return r == '_' || r == '-' || r == '.' }) {
		out = append(out, strings.ToLower(p))
	}
	return out
}

func camel(p []string) string {
	var b strings.Builder
	for i, w := range p {
		if i > 0 && w != "" {
			w = strings.ToUpper(w[:1]) + w[1:]
		}
		b.WriteString(w)
	}
	return b.String()
}
