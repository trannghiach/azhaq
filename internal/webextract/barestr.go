package webextract

import (
	"net/url"
	"path"
	"regexp"
	"strings"
)

// The patterns below are those of projectdiscovery/katana
// (pkg/utils/regex.go, MIT), which reads every quoted or spaced string of
// a script that looks like a path or a file. azhaq reads such strings
// itself; these find the ones it did not take as a URL, each of which is
// then either a URL the app may serve (a bare page name) or a rejected
// candidate that crawl -rejected lists with its reason.
var (
	katanaScript = lazyRE(`(?:"|'|\s)(` +
		`((https?://[A-Za-z0-9_\-.]+(?:\:\d{1,5})?)+([\.]{1,2})?/[A-Za-z0-9/\-_\\.%]+(?:[\?|#][^"']+)?)` +
		`|((\.{1,2}/)?[a-zA-Z0-9\-_/\\%]+\.(aspx?|js(?:on|p)?|html|php5?|action|do)(?:[\?|#][^"']+)?)` +
		`|((\.{0,2}/)[a-zA-Z0-9\-_/\\%]+(?:/|\\)[a-zA-Z0-9\-_]{3,}(?:[\?|#][^"']+)?)` +
		`|((\.{0,2})[a-zA-Z0-9\-_/\\%]{3,}/)` +
		`)(?:"|'|\s)`)
	katanaBody = lazyRE(`(?:(` +
		`(?:[\.]{1,2}/[A-Za-z0-9\-_/\\?&@\.?=%]+)` +
		`|(https?://[A-Za-z0-9_\-\.]+([\.]{0,2})?\/[A-Za-z0-9\-_/\\?&@\.?=%]+)` +
		`|(/[A-Za-z0-9\-_/\\?&@\.%]+\.(aspx?|action|cfm|cgi|do|pl|css|x?html?|js(p|on)?|pdf|php5?|py|rss))` +
		`|([A-Za-z0-9\-_?&@\.%]+/[A-Za-z0-9/\\\-_?&@\.%]+\.(aspx?|action|cfm|cgi|do|pl|css|x?html?|js(p|on)?|pdf|php5?|py|rss))` +
		`))`)
)

// Str is a string a script or a page names, and where.
type Str struct {
	Text       string
	Start, End int
}

// ScriptStrings are the strings katana's script regex takes from a script.
func ScriptStrings(script string) []Str { return findStrs(katanaScript, script) }

// BodyStrings are the strings katana's body regex takes from any text.
func BodyStrings(body string) []Str { return findStrs(katanaBody, body) }

func findStrs(re *lazyRegexp, s string) []Str {
	var out []Str
	seen := map[string]bool{}
	for _, m := range re.get().FindAllStringSubmatchIndex(s, -1) {
		if m[2] < 0 || seen[s[m[2]:m[3]]] {
			continue
		}
		seen[s[m[2]:m[3]]] = true
		out = append(out, Str{Text: s[m[2]:m[3]], Start: m[2], End: m[3]})
	}
	return out
}

var (
	mimePrefix = lazyRE(`(?i)^(application|text|image|audio|video|font|multipart|message|model|chemical|x-[a-z]+)/`)
	pageExt    = map[string]bool{".php": true, ".php5": true, ".asp": true, ".aspx": true, ".jsp": true, ".jspx": true,
		".action": true, ".do": true, ".html": true, ".htm": true, ".xhtml": true, ".cgi": true, ".cfm": true, ".pl": true, ".py": true}
	plainPath = regexp.MustCompile(`^[A-Za-z0-9._~/?#&=+@%:-]+$`)
	dirWord   = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{2,}(/[A-Za-z0-9_.-]+)*/$`)
)

// BareString decides what a string katana's patterns took from a script is.
// page is the URL of the page that runs it: a browser resolves a relative
// fetch or link against the page. When the string names a page of the
// application (users.php, admin/) link is its URL and reason is empty;
// otherwise reason says why it is no URL to request.
func BareString(s string, page *url.URL) (link, reason string) {
	s = strings.TrimSpace(s)
	switch {
	case s == "":
		return "", ReasonNotPath
	case mimePrefix.get().MatchString(s):
		return "", ReasonNotPath + " (a media type)"
	case strings.ContainsAny(s, `\`) || strings.Contains(s, "${") || strings.Contains(s, "{{"):
		return "", ReasonExpression
	}
	if strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") {
		u, err := page.Parse(s)
		if err != nil {
			return "", ReasonNotPath
		}
		n, ok := resolve(page, u.String())
		if !ok {
			return "", ReasonNotPath
		}
		if JunkURL(n) || StringNoise(n) {
			return "", ReasonJunk
		}
		return n, ""
	}
	if !plainPath.MatchString(s) {
		return "", ReasonExpression
	}
	bare := !strings.HasPrefix(s, "/") && !strings.HasPrefix(s, "./") && !strings.HasPrefix(s, "../")
	p := s
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	ext := strings.ToLower(path.Ext(p))
	switch {
	case numericPath.MatchString(p):
		return "", ReasonNotPath
	case ext != "" && !pageExt[ext]:
		return "", ReasonAsset
	}
	n, ok := resolve(page, s)
	if !ok {
		return "", ReasonNotPath
	}
	if JunkURL(n) || StringNoise(n) {
		return "", ReasonJunk
	}
	if bare && !pageExt[ext] && !dirWord.MatchString(p) {
		return "", ReasonNotPath
	}
	return n, ""
}

// ReasonScriptRel is why the URL a script-relative reading gives is not
// asked: a browser resolves a path a script fetches against the page.
const ReasonScriptRel = "relative to the script's own file; a browser resolves it against the page, where it is asked"

// Cand is a string read from a text, what it is as a URL on the page, and
// why it is not one.
type Cand struct {
	Str
	Link     string // the application's page it names, "" when Reason says why not
	Reason   string
	Resolved string // the URL it makes against the page, whatever Reason says
	Alt      string // the URL against the script's own address, when it differs from Link
}

// Candidates reads katana's patterns over text, a script (script true:
// its string regex too) or any page, and judges each string. page is the
// page that runs or holds it; src the text's own URL.
func Candidates(text string, page, src *url.URL, script bool) []Cand {
	var strs []Str
	if script {
		strs = ScriptStrings(text)
	}
	seen := map[string]bool{}
	for _, s := range strs {
		seen[s.Text] = true
	}
	for _, s := range BodyStrings(text) {
		if !seen[s.Text] {
			strs = append(strs, s)
		}
	}
	out := make([]Cand, 0, len(strs))
	for _, s := range strs {
		c := Cand{Str: s}
		c.Link, c.Reason = BareString(s.Text, page)
		c.Resolved = c.Link
		if c.Resolved == "" {
			if n, ok := resolve(page, strings.TrimSpace(s.Text)); ok {
				c.Resolved = n
			}
		}
		if src != nil && src.String() != page.String() {
			if alt, ok := resolve(src, strings.TrimSpace(s.Text)); ok && alt != c.Resolved {
				c.Alt = alt
			}
		}
		out = append(out, c)
	}
	return out
}
