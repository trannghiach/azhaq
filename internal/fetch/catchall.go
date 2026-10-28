package fetch

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"html"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// A catch-all response is what an origin returns for a path that does not
// exist: an SPA index served for every route, a soft 404 page with status
// 200, an error page that echoes the path, or a redirect every unknown path
// gets. CatchAll compares a response with the origin's answer for a random
// path in the same directory.

// maxProbeDirs caps baseline requests per origin; further directories fall
// back to the nearest one above them that was asked.
const maxProbeDirs = 24

var probeToken = RandomName()

var (
	probeMu   sync.Mutex
	baselines = map[string]*baseline{} // origin + dir
	probeDirs = map[string]int{}       // origin → directories probed
)

type baseline struct {
	once sync.Once
	ok   bool
	fp   fingerprint
}

type fingerprint struct {
	status   int
	location string
	hash     string
	title    string
	lines    int
	words    int
	size     int
	keys     string // a JSON answer's top-level fields; "" for anything else
}

var titleRE = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

// RandomName is a path segment no site has: 10 to 14 lowercase letters
// and digits, starting with a letter. It names nothing that would tell a
// log reader which tool asked.
func RandomName() string {
	const letters = "abcdefghijklmnopqrstuvwxyz"
	const alnum = letters + "0123456789"
	var b [15]byte
	_, _ = rand.Read(b[:])
	n := 10 + int(b[0])%5
	out := make([]byte, n)
	out[0] = letters[int(b[1])%len(letters)]
	for i := 1; i < n; i++ {
		out[i] = alnum[int(b[i+1])%len(alnum)]
	}
	return string(out)
}

// SetProbeToken makes the catch-all checks ask for name: a resumed run
// asks for the same paths as the run it continues, whose answers it kept.
func SetProbeToken(name string) {
	probeMu.Lock()
	defer probeMu.Unlock()
	if name != "" {
		probeToken = name
	}
}

// ProbeToken is the name the catch-all checks ask for.
func ProbeToken() string {
	probeMu.Lock()
	defer probeMu.Unlock()
	return probeToken
}

func resetProbes() {
	probeMu.Lock()
	baselines = map[string]*baseline{}
	probeDirs = map[string]int{}
	probeMu.Unlock()
}

// CatchAll reports whether res is the origin's generic answer rather than a
// page of its own. The site root is never a catch-all, and 404/410 are
// already a "no".
func CatchAll(ctx context.Context, c *http.Client, res Result) bool {
	if res.Status == 0 || res.Status == http.StatusNotFound || res.Status == http.StatusGone {
		return false
	}
	u, err := url.Parse(res.RequestURL)
	if err != nil || u.Host == "" {
		return false
	}
	path := u.EscapedPath()
	if path == "" || path == "/" {
		return false
	}
	origin := u.Scheme + "://" + u.Host
	b := baselineFor(ctx, c, origin, parentDir(path))
	if b == nil || !b.ok {
		return false
	}
	return b.fp.matches(fingerprintOf(res, origin, requestTarget(u)))
}

// FinalCatchAll is CatchAll for the page a redirect chain ended on: the
// body crawlers parse. /assets/i18n → 301 → /assets/i18n/ can land on an
// SPA index although the redirect itself is real.
func FinalCatchAll(ctx context.Context, c *http.Client, res Result) bool {
	if len(res.Hops) <= 1 {
		return CatchAll(ctx, c, res)
	}
	last := res.Hops[len(res.Hops)-1]
	return CatchAll(ctx, c, Result{RequestURL: last.URL, Status: last.Status, Body: res.Body, Header: http.Header{}})
}

func baselineFor(ctx context.Context, c *http.Client, origin, dir string) *baseline {
	probeMu.Lock()
	key := origin + dir
	b, ok := baselines[key]
	if !ok {
		if dir != "/" && probeDirs[origin] >= maxProbeDirs {
			// The nearest directory above it that was asked: /rest/memories/
			// answers like /rest/ (an error page), not like the site's root
			// (a single-page app's shell).
			probeMu.Unlock()
			return baselineFor(ctx, c, origin, parentDir(dir))
		}
		b = &baseline{}
		baselines[key] = b
		probeDirs[origin]++
	}
	probeMu.Unlock()
	b.once.Do(func() {
		target := origin + dir + ProbeToken()
		res, _, err := Do(ctx, c, target)
		if err != nil || res.Status == 0 {
			return
		}
		u, _ := url.Parse(target)
		b.fp = fingerprintOf(res, origin, requestTarget(u))
		b.ok = true
	})
	return b
}

// parentDir is the directory a path lives in: /a/b → /a/, /a/b/ → /a/.
func parentDir(p string) string {
	p = strings.TrimSuffix(p, "/")
	i := strings.LastIndex(p, "/")
	if i <= 0 {
		return "/"
	}
	return p[:i+1]
}

func requestTarget(u *url.URL) string {
	if u.RawQuery != "" {
		return u.EscapedPath() + "?" + u.RawQuery
	}
	return u.EscapedPath()
}

func fingerprintOf(res Result, origin, target string) fingerprint {
	return fingerprintBy(res, origin, func(s string) string { return stripEcho(s, origin, target) })
}

// SamePage says whether two answers, of two origins, are the same page
// as a catch-all check compares them, once each answer's links to its own
// origin are taken out: one site served over http and https.
func SamePage(a, b Result) bool {
	if a.Status == 0 || b.Status == 0 {
		return false
	}
	return ownPage(a).matches(ownPage(b))
}

func ownPage(res Result) fingerprint {
	origin := ""
	if u, err := url.Parse(res.RequestURL); err == nil {
		origin = u.Scheme + "://" + u.Host
	}
	escaped := strings.ReplaceAll(origin, "/", `\/`) // in JSON strings
	return fingerprintBy(res, origin, func(s string) string {
		return strings.ReplaceAll(strings.ReplaceAll(s, origin, ""), escaped, "")
	})
}

func fingerprintBy(res Result, origin string, strip func(string) string) fingerprint {
	fp := fingerprint{status: res.Status}
	if res.Header != nil {
		fp.location = strip(strings.TrimPrefix(res.Header.Get("Location"), origin))
	}
	body := strip(string(res.Body))
	sum := sha256.Sum256([]byte(body))
	fp.hash = hex.EncodeToString(sum[:8])
	if m := titleRE.FindStringSubmatch(body); len(m) == 2 {
		fp.title = strings.Join(strings.Fields(m[1]), " ")
	}
	fp.lines = strings.Count(body, "\n")
	fp.words = len(strings.Fields(body))
	fp.size = len(body)
	fp.keys = jsonShape(body)
	return fp
}

// jsonShape is a JSON object's sorted top-level field names ("[]" for an
// array), or "" when the body is not JSON.
func jsonShape(body string) string {
	t := strings.TrimSpace(body)
	if !strings.HasPrefix(t, "{") && !strings.HasPrefix(t, "[") {
		return ""
	}
	var v any
	if json.Unmarshal([]byte(t), &v) != nil {
		return ""
	}
	m, ok := v.(map[string]any)
	if !ok {
		return "[]"
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return "{" + strings.Join(keys, ",") + "}"
}

// near: two sizes within a fraction of the larger.
func near(a, b int, frac float64) bool {
	d := a - b
	if d < 0 {
		d = -d
	}
	return float64(d) <= frac*float64(max(a, b))
}

// stripEcho removes the requested path from a body or header, in the forms
// error pages usually echo it, so two unknown paths compare equal.
func stripEcho(s, origin, target string) string {
	forms := []string{origin + target, target}
	if dec, err := url.PathUnescape(target); err == nil && dec != target {
		forms = append(forms, origin+dec, dec)
	}
	for _, f := range append([]string(nil), forms...) {
		if esc := html.EscapeString(f); esc != f {
			forms = append(forms, esc)
		}
		if esc := url.QueryEscape(f); esc != f {
			forms = append(forms, esc)
		}
	}
	for _, f := range forms {
		s = strings.ReplaceAll(s, f, "\x00")
	}
	return s
}

func (b fingerprint) matches(o fingerprint) bool {
	if b.status != o.status {
		return false
	}
	if isRedirect(b.status) {
		return b.location == o.location
	}
	if b.hash == o.hash {
		return true
	}
	if b.keys != "" || o.keys != "" {
		// JSON on one line has one "word": an object with data and the
		// same object empty would read alike. Fields and size decide.
		return b.keys == o.keys && near(b.size, o.size, 0.1)
	}
	// Pages with a CSRF token or timestamp differ byte-wise but keep their shape.
	return b.title == o.title && b.lines == o.lines && b.words == o.words && b.words > 0 && near(b.size, o.size, 0.2)
}
