package webextract

import (
	"net/url"
	"strings"
)

// payloadMarks are what scanners send and archives keep: path traversal,
// command and template injection, SQL, script, and the callback domains
// of out-of-band testing. A URL holding one in its path or query is never
// stored, so it can never be requested. Each mark sits on a boundary, so
// curlang=en, onload=init or next=../home stay.
var payloadMarks = lazyRE(`(?i)` + strings.Join([]string{
	`(\.\./){2,}|(\.\.\\){2,}|/etc/(passwd|shadow|hosts)\b|\bwin\.ini\b|\bboot\.ini\b|/proc/self/`,
	`[;|&]\s*(curl|wget|nslookup|ping|id|whoami|cat|sleep|uname)\b\s`,
	`\$\(\s*(curl|wget|id|whoami|cat|sleep|nslookup|ping|echo|uname)\b|` + "`" + `\s*(id|whoami|curl|wget|cat|sleep|uname)\b`,
	`\$\{|#\{|\{\{|<%`,
	`\bunion(\s|/\*.*?\*/)+(all\s+)?select\b|'\s*(or|and)\s+['"\d]|\bsleep\(\s*\d|\bbenchmark\(\s*\d|\bwaitfor\s+delay\b|\bxp_cmdshell\b`,
	`<\s*(script|svg|img|iframe)\b|\bjavascript:|[\s"'/]on(error|load|mouseover|focus)\s*=|\balert\(|\bprompt\(|document\.cookie`,
	`\b(oast\.(live|fun|pro|me|site|online)|interact\.sh|interactsh|burpcollaborator\.net|oastify\.com|dnslog\.cn|ceye\.io|requestbin\.|pipedream\.net|canarytokens\.|xss\.ht)\b`,
}, "|"))

// scannerMarks are the names scanners leave in a target's archive: the
// files they ask for to prove an inclusion (acunetix_xsl_inclusion_test,
// netsparker(0).txt), the parameters they tag their requests with
// (?invicti=1), the hosts of their blind tests (bxss.me, xss.rocks) and
// the probes of those whose name a product page could carry
// (/products/nessus is a page; nessus_test, appscan_fingerprint and
// qualystest are not). A word searched for (?q=netsparker) is the
// user's.
var scannerMarks = lazyRE(`(?i)` + strings.Join([]string{
	`(?:^|/)(?:acunetix|acumonitor|netsparker|invicti|bxss|burpcollaborator)`,
	`[?&](?:acunetix|netsparker|invicti|bxss)[\w-]*=`,
	`(?:^|[/?&=.])(?:bxss\.me|xss\.rocks|interactsh|oastify|burpcollaborator)`,
	`(?:appscan|nessus|qualys|webinspect)(?:[_(]|test\b|\.txt)`,
}, "|"))

// randomExe is an executable at the root named by a scanner's random
// token: /7zSo1DIz.exe. Letters and digits, 6 to 10 of them, and nothing
// else in the path.
var randomExe = lazyRE(`^/([A-Za-z0-9]{6,10})\.(?:exe|dll|scr)$`)

// Payload reports a URL that carries a scanner's payload in its path or
// query (see payloadMarks), or a scanner's own name or random file
// (scannerMarks, randomExe).
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
	if payloadMarks.MatchString(low) || scannerMarks.MatchString(low) {
		return true
	}
	if m := randomExe.FindStringSubmatch(u.Path); m != nil {
		return randomToken(m[1])
	}
	return false
}

// randomToken: a digit among the letters, and the case changing at least
// twice (7zSo1DIz, NhYzAp8A), which no name a person gave a file does
// (Setup64, winrar).
func randomToken(s string) bool {
	digit, changes := false, 0
	var last rune
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
			digit = true
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z':
			if last != 0 && (last <= 'Z') != (r <= 'Z') {
				changes++
			}
			last = r
		}
	}
	return digit && changes >= 2
}

// JunkURL reports a URL that is not one: a script that ran without its
// data (/rest/basket/NaN), a link cut short in an archive (login.ph…,
// login.php).), a scanner's payload kept by an archive
// (/1234567890*~1*/, <script>, ;curl …oast.live, /etc/passwd), or a
// directory listing sorted another way (see ListingSort).
func JunkURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return true
	}
	if Payload(raw) || ListingSort(raw) {
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

// ListingSort reports the sort links of an Apache or nginx directory
// listing: ?C=N;O=D, ?C=M&O=A, with Apache's F, V and P options. They
// are the same listing in another order, eight of them under every
// column of every directory.
func ListingSort(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.RawQuery == "" {
		return false
	}
	var c, o bool
	for _, kv := range strings.FieldsFunc(u.RawQuery, func(r rune) bool { return r == ';' || r == '&' }) {
		k, v, _ := strings.Cut(kv, "=")
		switch k {
		case "C":
			c = len(v) == 1 && strings.Contains("NMSD", v)
		case "O":
			o = v == "A" || v == "D"
		case "F":
			if v != "0" && v != "1" && v != "2" {
				return false
			}
		case "V":
			if v != "0" && v != "1" {
				return false
			}
		case "P":
		default:
			return false
		}
	}
	return c && o
}

// StringNoise reports a path read out of a string in a script or a JSON
// document that names no route: a parser table or a minified name cut
// out of a longer string (/pQ, /SQ: one segment of one or two letters
// with a capital), or a package named after its owner
// (/juice-shop/juice-shop: a slug with a hyphen or a dot, twice). Short
// routes in lower case (/v1, /me, /id) are kept, and so are a locale
// (/en/US), words repeated (/admin/admin, /api/api), and anything a page
// links to: this is for strings.
func StringNoise(p string) bool {
	if u, err := url.Parse(p); err == nil && u.Host != "" {
		p = u.Path
	}
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	segs := strings.Split(strings.Trim(p, "/"), "/")
	if len(segs) == 2 && segs[0] == segs[1] && len(segs[0]) >= 3 && pkgName.MatchString(segs[0]) && strings.ContainsAny(segs[0], "-.") {
		return true
	}
	s := segs[0]
	return len(segs) == 1 && len(s) <= 2 && letters.MatchString(s) && strings.ToLower(s) != s
}

var (
	pkgName = lazyRE(`^[a-z0-9][a-z0-9._-]*$`)
	letters = lazyRE(`^[A-Za-z]+$`)
	// versionOnly is an API version prefix and nothing under it: /v3,
	// /api/v2.
	versionOnly = lazyRE(`^/(?:api/)?v\d{1,2}(?:\.\d{1,2})?/?$`)
)

// VersionPrefix reports a URL whose path is an API version prefix alone
// (/v3, /api/v2): scripts build routes under it, and it is a route of
// its own only when something answers there.
func VersionPrefix(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && versionOnly.MatchString(strings.ToLower(u.Path))
}
