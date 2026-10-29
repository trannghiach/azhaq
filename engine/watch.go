package engine

import (
	"regexp"
	"sort"
	"strings"
)

// watchKinds name what a parameter's name says it takes, for the bugs
// hunters try there first (as GAP and InQL mark them): a URL to fetch or
// redirect to, a path to read, a command, an object's identifier, a
// switch a client should not hold.
var watchKinds = []struct {
	kind string
	re   *regexp.Regexp
}{
	{"redirect", regexp.MustCompile(`(?i)^(redirect|redir|redirect_?(uri|url|to)|return_?(url|to|path)?|returnurl|next|continue|dest(ination)?|goto|forward|callback_?url|success_?url|back_?url|target_?url|to)$`)},
	{"url", regexp.MustCompile(`(?i)^(url|uri|link|href|src|source_?url|image_?url|img_?url|feed|webhook(_?url)?|proxy|host|domain|endpoint|site|fetch|load)$`)},
	{"file", regexp.MustCompile(`(?i)^(file|filename|file_?name|path|filepath|file_?path|dir|directory|folder|document|template|include|download|attachment)$`)},
	{"command", regexp.MustCompile(`(?i)^(cmd|command|exec|execute|run|shell|eval|ping)$`)},
	{"debug", regexp.MustCompile(`(?i)^(debug|is_?admin|is_?staff|is_?superuser|privileges?|verbose|test_?mode|impersonate)$`)},
	{"id", regexp.MustCompile(`(?i)^(id|uid|user_?id|account_?id|customer_?id|order_?id|owner_?id|profile_?id|member_?id|basket_?id|invoice_?id)$`)},
	{"callback", regexp.MustCompile(`(?i)^(callback|jsonp|cb)$`)},
}

// Watch lists a row's parameter and body names worth trying first, as
// "returnUrl (redirect)", sorted.
func Watch(r MapEntry) []string {
	seen := map[string]bool{}
	var out []string
	add := func(name string) {
		if name == "" || seen[name] {
			return
		}
		seen[name] = true
		for _, k := range watchKinds {
			if k.re.MatchString(name) {
				out = append(out, name+" ("+k.kind+")")
				return
			}
		}
	}
	for _, n := range r.Params {
		add(n)
	}
	for _, n := range r.Body {
		add(n)
	}
	for _, o := range r.Ops {
		for _, n := range append(append([]string{}, o.Query...), o.Body...) {
			add(n)
		}
	}
	for _, f := range r.Forms {
		for _, n := range f.Fields {
			if !strings.EqualFold(n, "submit") {
				add(n)
			}
		}
	}
	sort.Strings(out)
	return out
}
