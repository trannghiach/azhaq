package urlcol

import (
	"fmt"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"
	"time"
)

// Filters narrow what the archives are asked for: the status and type
// they recorded for a capture, and the time of the capture. The query
// parameters follow gau's (github.com/lc/gau, MIT, providers/filters.go).
type Filters struct {
	MatchStatus, DropStatus []string // 200, 301
	MatchMime, DropMime     []string // text/html
	From, To                string   // YYYY, YYYYMM, YYYYMMDD or YYYYMMDDhhmmss
}

// Active says whether any filter is set.
func (f Filters) Active() bool { return f.needs() != 0 }

// what a filter reaches.
const (
	byStatus = 1 << iota
	byMime
	byDate
)

func (f Filters) needs() int {
	n := 0
	if len(f.MatchStatus)+len(f.DropStatus) > 0 {
		n |= byStatus
	}
	if len(f.MatchMime)+len(f.DropMime) > 0 {
		n |= byMime
	}
	if f.From != "" || f.To != "" {
		n |= byDate
	}
	return n
}

var statusRE = regexp.MustCompile(`^[1-5][0-9][0-9]$`)

// Validate refuses a value no archive would understand: gau ignores a bad
// date and sends it on a bad status; a mistake is better said than sent.
func (f Filters) Validate() error {
	for _, list := range [][]string{f.MatchStatus, f.DropStatus} {
		for _, s := range list {
			if !statusRE.MatchString(s) {
				return fmt.Errorf("%q is not an HTTP status code", s)
			}
		}
	}
	for _, list := range [][]string{f.MatchMime, f.DropMime} {
		for _, m := range list {
			if m == "" || strings.ContainsAny(m, " \t\r\n") {
				return fmt.Errorf("%q is not a MIME type", m)
			}
		}
	}
	for name, d := range map[string]string{"-from": f.From, "-to": f.To} {
		if d == "" {
			continue
		}
		if err := checkDate(d); err != nil {
			return fmt.Errorf("%s %q: %w", name, d, err)
		}
	}
	if f.From != "" && f.To != "" {
		// Compared as the timestamps they stand for.
		a, b := f.From+strings.Repeat("0", 14-len(f.From)), f.To+strings.Repeat("0", 14-len(f.To))
		if a > b {
			return fmt.Errorf("-from %s is after -to %s", f.From, f.To)
		}
	}
	return nil
}

var dateLayouts = map[int]string{4: "2006", 6: "200601", 8: "20060102", 14: "20060102150405"}

func checkDate(d string) error {
	layout, ok := dateLayouts[len(d)]
	if !ok {
		return fmt.Errorf("want YYYY, YYYYMM, YYYYMMDD or YYYYMMDDhhmmss")
	}
	if _, err := time.Parse(layout, d); err != nil {
		return fmt.Errorf("not a date in the form %s", layout)
	}
	return nil
}

// Flavours of an archive's CDX server: the Wayback Machine names its
// fields statuscode and mimetype, the pywb servers (Common Crawl,
// arquivo.pt) status and mime and spell a negation !=.
const (
	cdxWayback = iota
	cdxPywb
)

// params adds the filters to a CDX query. Several values of a kind to
// keep are alternatives of one filter (CDX ANDs separate filters, so
// gau's one filter each keeps nothing); values to drop are one filter
// each.
func (f Filters) params(q url.Values, flavour int) {
	if f.From != "" {
		q.Set("from", f.From)
	}
	if f.To != "" {
		q.Set("to", f.To)
	}
	status, mime, not := "statuscode", "mimetype", "!"
	if flavour == cdxPywb {
		status, mime, not = "status", "mime", "!="
	}
	if len(f.MatchStatus) > 0 {
		q.Add("filter", status+":"+strings.Join(f.MatchStatus, "|"))
	}
	if len(f.MatchMime) > 0 {
		q.Add("filter", mime+":"+strings.Join(f.MatchMime, "|"))
	}
	for _, s := range f.DropStatus {
		q.Add("filter", not+status+":"+s)
	}
	for _, m := range f.DropMime {
		q.Add("filter", not+mime+":"+m)
	}
}

// ParseProxy reads a proxy address: http, https or socks5.
func ParseProxy(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("%q is not a proxy address such as http://127.0.0.1:8080 or socks5://127.0.0.1:9050", raw)
	}
	switch u.Scheme {
	case "http", "https", "socks5", "socks5h":
		return u, nil
	}
	return nil, fmt.Errorf("proxy scheme %q: use http, https or socks5", u.Scheme)
}

// transport is the default one, through proxy when one is given.
func transport(proxy string) http.RoundTripper {
	t := http.DefaultTransport.(*http.Transport).Clone()
	if u, err := ParseProxy(proxy); err == nil && proxy != "" {
		t.Proxy = http.ProxyURL(u)
	}
	return t
}

// Sources names the archives a run can ask.
func Sources() []string {
	var out []string
	for _, s := range allSources() {
		out = append(out, s.name)
	}
	return out
}

// CheckSources refuses a name that is not an archive.
func CheckSources(names []string) error {
	known := Sources()
	for _, n := range names {
		ok := false
		for _, k := range known {
			ok = ok || n == k
		}
		if !ok {
			return fmt.Errorf("%q is not an archive (%s)", n, strings.Join(known, ", "))
		}
	}
	return nil
}

// outFilter is gau's --blacklist and --fp: URLs left out of the output by
// the extension of their path, and all but the first of each host and path.
type outFilter struct {
	ext   map[string]bool
	first bool
	seen  map[string]bool
}

func newOutFilter(exts []string, firstPerPath bool) *outFilter {
	f := &outFilter{ext: map[string]bool{}, first: firstPerPath, seen: map[string]bool{}}
	for _, e := range exts {
		e = strings.ToLower(strings.TrimSpace(e))
		if e = strings.TrimPrefix(e, "."); e != "" {
			f.ext[e] = true
		}
	}
	return f
}

// blocked: the URL's path ends in a listed extension.
func (f *outFilter) blocked(raw string) bool {
	if len(f.ext) == 0 {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	return f.ext[strings.TrimPrefix(strings.ToLower(path.Ext(u.Path)), ".")]
}

// repeat: another URL with this host and path was kept already.
func (f *outFilter) repeat(raw string) bool {
	if !f.first {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	k := strings.ToLower(u.Host) + u.Path
	if f.seen[k] {
		return true
	}
	f.seen[k] = true
	return false
}
