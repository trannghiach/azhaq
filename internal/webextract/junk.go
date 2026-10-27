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
