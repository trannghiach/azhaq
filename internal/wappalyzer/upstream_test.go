package wappalyzer

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"

	upstream "github.com/projectdiscovery/wappalyzergo"
)

// TestSameAsUpstream builds, for every fingerprint, a page and headers
// from the literals of its patterns, so nearly every pattern compiles and
// runs, and requires the same technologies and versions as upstream. One
// app per page with one version string: upstream keeps the first version
// it meets in map order, so mixed versions on one page are not stable.
func TestSameAsUpstream(t *testing.T) {
	fork, err := New()
	if err != nil {
		t.Fatal(err)
	}
	up, err := upstream.New()
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(fork.fingerprints.Apps))
	for name := range fork.fingerprints.Apps {
		names = append(names, name)
	}
	sort.Strings(names)
	lit := func(p *ParsedPattern) string {
		if len(p.literals) == 0 {
			return ""
		}
		return strings.Join(p.literals[0], " ")
	}
	hits := 0
	for _, name := range names {
		app := fork.fingerprints.Apps[name]
		var body strings.Builder
		headers := map[string][]string{}
		body.WriteString("<html><head>")
		for _, p := range app.scriptSrc {
			fmt.Fprintf(&body, `<script src="/%s-1.4.2.js"></script>`, lit(p))
		}
		for key, ps := range app.meta {
			for _, p := range ps {
				fmt.Fprintf(&body, `<meta name="%s" content="%s 1.4.2">`, key, lit(p))
			}
		}
		for _, p := range app.html {
			fmt.Fprintf(&body, "<div>%s 1.4.2</div>", lit(p))
		}
		for key, p := range app.headers {
			headers[key] = []string{lit(p) + " 1.4.2"}
		}
		var cookies []string
		for key, p := range app.cookies {
			cookies = append(cookies, key+"="+strings.ReplaceAll(lit(p), " ", "")+"1.4.2")
		}
		if len(cookies) > 0 {
			headers["Set-Cookie"] = []string{strings.Join(cookies, "; ")}
		}
		body.WriteString("</head></html>")
		page := []byte(body.String())
		want := up.Fingerprint(headers, page)
		got := fork.Fingerprint(headers, page)
		if _, cdn := want["cdnjs"]; cdn {
			delete(want, "Cloudflare") // cdnjs no longer implies it (doc.go)
		}
		hits += len(want)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s: fork only %q, upstream only %q", name, minus(got, want), minus(want, got))
		}
	}
	// Apps with only js or dom rules cannot be seen passively.
	if hits < 5000 {
		t.Fatalf("only %d detections for %d apps: the corpus does not exercise the patterns", hits, len(names))
	}
	t.Logf("%d apps, %d detections", len(names), hits)
}

func minus(a, b map[string]struct{}) []string {
	var out []string
	for k := range a {
		if _, ok := b[k]; !ok {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}
