package webextract

import (
	"net/url"
	"strings"
)

// JunkURL reports a URL that is not one: a script that ran without its
// data (/rest/basket/NaN), a link cut short in an archive (login.ph…,
// login.php).), or a scanner's payload kept by an archive
// (/1234567890*~1*/, <script>).
func JunkURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
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
