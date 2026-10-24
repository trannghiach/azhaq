package webextract

import (
	"net/url"
	"regexp"
	"strings"
)

var (
	absURL   = regexp.MustCompile(`https?://[A-Za-z0-9._~:/?#\[\]@!$&*+,;=%-]+`)
	relURL   = regexp.MustCompile(`['"\x60](/[A-Za-z0-9._~/?#&=+-]{1,256})['"\x60]`)
	jsonPath = regexp.MustCompile(`"(?:url|href|path|route|page|api|endpoint)"\s*:\s*"(/[A-Za-z0-9._~/?#&=+-]{1,256})"`)
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
		if len(m) == 2 {
			add(m[1])
		}
	}
	for _, m := range jsonPath.FindAllStringSubmatch(script, -1) {
		if len(m) == 2 {
			add(m[1])
		}
	}
	return out
}

func trimURLJunk(s string) string {
	return strings.TrimRight(s, ".,);'\"")
}
