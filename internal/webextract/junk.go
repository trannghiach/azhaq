package webextract

import (
	"net/url"
	"regexp"
	"strings"
)

// payloadMarks are what scanners send and archives keep: path traversal,
// command and template injection, SQL, script, and the callback domains
// of out-of-band testing. A URL holding one in its path or query is never
// stored, so it can never be requested. Each mark sits on a boundary, so
// curlang=en, onload=init or next=../home stay.
var payloadMarks = regexp.MustCompile(`(?i)` + strings.Join([]string{
	`(\.\./){2,}|(\.\.\\){2,}|/etc/(passwd|shadow|hosts)\b|\bwin\.ini\b|\bboot\.ini\b|/proc/self/`,
	`[;|&]\s*(curl|wget|nslookup|ping|id|whoami|cat|sleep|uname)\b\s`,
	`\$\(\s*(curl|wget|id|whoami|cat|sleep|nslookup|ping|echo|uname)\b|` + "`" + `\s*(id|whoami|curl|wget|cat|sleep|uname)\b`,
	`\$\{|#\{|\{\{|<%`,
	`\bunion(\s|/\*.*?\*/)+(all\s+)?select\b|'\s*(or|and)\s+['"\d]|\bsleep\(\s*\d|\bbenchmark\(\s*\d|\bwaitfor\s+delay\b|\bxp_cmdshell\b`,
	`<\s*(script|svg|img|iframe)\b|\bjavascript:|[\s"'/]on(error|load|mouseover|focus)\s*=|\balert\(|\bprompt\(|document\.cookie`,
	`\b(oast\.(live|fun|pro|me|site|online)|interact\.sh|interactsh|burpcollaborator\.net|oastify\.com|dnslog\.cn|ceye\.io|requestbin\.|pipedream\.net|canarytokens\.|xss\.ht)\b`,
}, "|"))

// Payload reports a URL that carries a scanner's payload in its path or
// query (see payloadMarks).
func Payload(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	low := u.EscapedPath()
	if u.RawQuery != "" {
		low += "?" + u.RawQuery
	}
	for i := 0; i < 2; i++ { // twice: archives keep payloads encoded twice
		if d, err := url.PathUnescape(strings.ReplaceAll(low, "+", " ")); err == nil {
			low = d
		}
	}
	return payloadMarks.MatchString(low)
}

// JunkURL reports a URL that is not one: a script that ran without its
// data (/rest/basket/NaN), a link cut short in an archive (login.ph…,
// login.php).), or a scanner's payload kept by an archive
// (/1234567890*~1*/, <script>, ;curl …oast.live, /etc/passwd).
func JunkURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return true
	}
	if Payload(raw) {
		return true
	}
	p := u.EscapedPath()
	lp := strings.ToLower(p)
	for _, seg := range strings.Split(lp, "/") {
		switch seg {
		case "nan", "undefined", "null", "[object%20object]", "%5bobject%20object%5d":
			return true
		case ".", "..", "%2e", "%2e%2e", ".%2e", "%2e.":
			// http://site/.. in an archive: no browser asks for a dot
			// segment, it resolves it first.
			return true
		}
	}
	for _, bad := range []string{"%e2%80%a6", "\u2026", "*", "%2a", "%3c", "%3e", "<", ">", "\\", "%5c", "%22", "%27"} {
		if strings.Contains(lp, bad) {
			return true
		}
	}
	last := strings.NewReplacer("%28", "(", "%29", ")", "%5b", "[", "%5d", "]").Replace(lp[strings.LastIndex(lp, "/")+1:])
	if strings.Count(last, ")") > strings.Count(last, "(") || strings.Count(last, "]") > strings.Count(last, "[") {
		return true // the end of the sentence the link sat in
	}
	for _, tail := range []string{").", "),", ".[", "[", "'", ",", ";"} {
		if strings.HasSuffix(last, tail) {
			return true
		}
	}
	return false
}

// StringNoise reports a path read out of a string in a script or a JSON
// document that names no route: a parser table or a minified name cut
// out of a longer string (/pQ, /SQ: every segment one or two characters,
// one of them letters with a capital), or a package named after its
// owner (/juice-shop/juice-shop). Short routes in lower case (/v1, /me,
// /id) are kept, and so is anything a page links to: this is for strings.
func StringNoise(p string) bool {
	if u, err := url.Parse(p); err == nil && u.Host != "" {
		p = u.Path
	}
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	segs := strings.Split(strings.Trim(p, "/"), "/")
	if len(segs) == 2 && segs[0] == segs[1] && len(segs[0]) >= 3 && pkgName.MatchString(segs[0]) {
		return true
	}
	short, capital := true, false
	for _, s := range segs {
		if len(s) == 0 || len(s) > 2 {
			short = false
			break
		}
		if letters.MatchString(s) && strings.ToLower(s) != s {
			capital = true
		}
	}
	return short && capital
}

var (
	pkgName = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)
	letters = regexp.MustCompile(`^[A-Za-z]+$`)
	// versionOnly is an API version prefix and nothing under it: /v3,
	// /api/v2.
	versionOnly = regexp.MustCompile(`^/(?:api/)?v\d{1,2}(?:\.\d{1,2})?/?$`)
)

// VersionPrefix reports a URL whose path is an API version prefix alone
// (/v3, /api/v2): scripts build routes under it, and it is a route of
// its own only when something answers there.
func VersionPrefix(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && versionOnly.MatchString(strings.ToLower(u.Path))
}
