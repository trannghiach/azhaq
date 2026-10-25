package webextract

import (
	"net/url"
	"strings"

	"github.com/trannghiach/azhaq/internal/normalize"
)

// ClassifyURL is page, api, or asset for ranking and JS collapse.
func ClassifyURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "page"
	}
	path := strings.ToLower(u.Path)
	for ext := range skipExt {
		if strings.HasSuffix(path, ext) {
			return "asset"
		}
	}
	if strings.Contains(path, "/api/") || strings.HasSuffix(path, "/api") ||
		strings.Contains(path, "/rest/") || strings.HasSuffix(path, "/rest") ||
		strings.Contains(path, "/graphql") || strings.Contains(path, "/graphiql") ||
		strings.Contains(path, "/swagger") || strings.Contains(path, "/openapi") ||
		strings.HasSuffix(path, ".json") {
		return "api"
	}
	return "page"
}

// RouteKey is scheme://host/path without query, fragment, or a trailing slash.
func RouteKey(raw string) string {
	n, err := normalize.URL(raw)
	if err != nil {
		return raw
	}
	u, err := url.Parse(n)
	if err != nil {
		return n
	}
	u.RawQuery = ""
	u.Fragment = ""
	u.Path = strings.TrimSuffix(u.Path, "/")
	if u.Path == "" {
		u.Path = "/"
	}
	out, err := normalize.URL(u.String())
	if err != nil {
		return n
	}
	return out
}

// CollapseURLs keeps one URL per route (shortest / no query wins).
func CollapseURLs(in []string) []string {
	best := map[string]string{}
	order := []string{}
	for _, raw := range in {
		k := RouteKey(raw)
		if k == "" {
			continue
		}
		cur, ok := best[k]
		if !ok {
			best[k] = raw
			order = append(order, k)
			continue
		}
		if preferURL(raw, cur) {
			best[k] = raw
		}
	}
	out := make([]string, 0, len(order))
	for _, k := range order {
		out = append(out, best[k])
	}
	return out
}

func preferURL(a, b string) bool {
	ua, errA := url.Parse(a)
	ub, errB := url.Parse(b)
	if errA != nil || errB != nil {
		return len(a) < len(b)
	}
	if (ua.RawQuery == "") != (ub.RawQuery == "") {
		return ua.RawQuery == ""
	}
	return len(ua.Path) < len(ub.Path)
}
