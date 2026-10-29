package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/trannghiach/azhaq/internal/fetch"
	"github.com/trannghiach/azhaq/internal/normalize"
	"github.com/trannghiach/azhaq/internal/webextract"
)

// A role's history: the requests an account sent through a proxy or the
// browser's devtools (a HAR file, a Burp "Save items" file). roles takes its
// session, the pages it reached and its writes from them.

// histEntry is one request of a history.
type histEntry struct {
	method string
	url    string
	header http.Header
	body   []byte
	mime   string
	status int
	at     time.Time // zero when the file gave none
	seq    int       // the order in the file
}

// history is what one role's files recorded.
type history struct {
	name    string
	files   []string
	entries []histEntry
}

// har is the part of an HTTP Archive roles reads.
type har struct {
	Log struct {
		Entries []struct {
			Started string `json:"startedDateTime"`
			Request struct {
				Method   string `json:"method"`
				URL      string `json:"url"`
				Headers  []struct{ Name, Value string }
				Cookies  []struct{ Name, Value string }
				PostData *struct {
					MimeType string `json:"mimeType"`
					Text     string `json:"text"`
					Params   []struct{ Name, Value string }
				} `json:"postData"`
			} `json:"request"`
			Response struct {
				Status int `json:"status"`
			} `json:"response"`
		} `json:"entries"`
	} `json:"log"`
}

// readHAR reads the requests of a HAR file.
func readHAR(path string) ([]histEntry, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var h har
	if err := json.Unmarshal(raw, &h); err != nil {
		return nil, fmt.Errorf("%s: not a HAR file: %w", path, err)
	}
	var out []histEntry
	for i, e := range h.Log.Entries {
		r := e.Request
		if r.URL == "" || r.Method == "" {
			continue
		}
		he := histEntry{method: strings.ToUpper(r.Method), url: r.URL, header: http.Header{}, status: e.Response.Status, seq: i}
		if t, err := time.Parse(time.RFC3339Nano, e.Started); err == nil {
			he.at = t
		}
		for _, hd := range r.Headers {
			if hd.Name != "" && !strings.HasPrefix(hd.Name, ":") { // HTTP/2 pseudo-headers
				he.header.Add(hd.Name, hd.Value)
			}
		}
		if he.header.Get("Cookie") == "" && len(r.Cookies) > 0 {
			var parts []string
			for _, c := range r.Cookies {
				parts = append(parts, c.Name+"="+c.Value)
			}
			he.header.Set("Cookie", strings.Join(parts, "; "))
		}
		if p := r.PostData; p != nil {
			he.mime = p.MimeType
			he.body = []byte(p.Text)
			if p.Text == "" && len(p.Params) > 0 {
				form := url.Values{}
				for _, q := range p.Params {
					form.Add(q.Name, q.Value)
				}
				he.body = []byte(form.Encode())
			}
		}
		out = append(out, he)
	}
	return out, nil
}

// burpItem is one <item> of a Burp "Save items" file.
type burpItem struct {
	Time    string `xml:"time"`
	URL     string `xml:"url"`
	Method  string `xml:"method"`
	Status  int    `xml:"status"`
	Request struct {
		Base64 string `xml:"base64,attr"`
		Text   string `xml:",chardata"`
	} `xml:"request"`
}

// readBurp reads the requests of a Burp XML file, one raw request each.
func readBurp(path string) ([]histEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	dec := xml.NewDecoder(f)
	dec.Strict = false
	var out []histEntry
	seq := 0
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%s: not a Burp XML file: %w", path, err)
		}
		se, ok := tok.(xml.StartElement)
		if !ok || se.Name.Local != "item" {
			continue
		}
		var it burpItem
		if err := dec.DecodeElement(&it, &se); err != nil {
			return nil, fmt.Errorf("%s: not a Burp XML file: %w", path, err)
		}
		seq++
		if e, ok := burpEntry(it, seq); ok {
			out = append(out, e)
		}
	}
	if seq == 0 {
		return nil, fmt.Errorf("%s: not a Burp XML file: no <item>", path)
	}
	return out, nil
}

var burpTime = []string{"Mon Jan _2 15:04:05 MST 2006", time.RFC1123, time.RFC3339}

func burpEntry(it burpItem, seq int) (histEntry, bool) {
	text := strings.TrimSpace(it.Request.Text)
	raw := []byte(it.Request.Text)
	if strings.EqualFold(it.Request.Base64, "true") {
		b, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(text), ""))
		if err != nil {
			return histEntry{}, false
		}
		raw = b
	}
	method, target, h, body := parseRawRequest(raw)
	if method == "" {
		method = strings.ToUpper(strings.TrimSpace(it.Method))
	}
	u := strings.TrimSpace(it.URL)
	if u == "" && h.Get("Host") != "" {
		u = "http://" + h.Get("Host") + target
	}
	if u == "" || method == "" {
		return histEntry{}, false
	}
	e := histEntry{method: method, url: u, header: h, body: body, mime: h.Get("Content-Type"), status: it.Status, seq: seq}
	for _, layout := range burpTime {
		if t, err := time.Parse(layout, strings.TrimSpace(it.Time)); err == nil {
			e.at = t
			break
		}
	}
	return e, true
}

// parseRawRequest splits a raw HTTP request into its method, target,
// headers and body.
func parseRawRequest(raw []byte) (method, target string, h http.Header, body []byte) {
	h = http.Header{}
	head, rest := raw, []byte(nil)
	if i := bytes.Index(raw, []byte("\r\n\r\n")); i >= 0 {
		head, rest = raw[:i], raw[i+4:]
	} else if i := bytes.Index(raw, []byte("\n\n")); i >= 0 {
		head, rest = raw[:i], raw[i+2:]
	}
	for n, line := range strings.Split(strings.ReplaceAll(string(head), "\r\n", "\n"), "\n") {
		if n == 0 {
			if parts := strings.Fields(line); len(parts) >= 2 {
				method, target = strings.ToUpper(parts[0]), parts[1]
			}
			continue
		}
		if k, v, ok := strings.Cut(line, ":"); ok && strings.TrimSpace(k) != "" {
			h.Add(strings.TrimSpace(k), strings.TrimSpace(v))
		}
	}
	return method, target, h, rest
}

// readHistory reads a history file: a HAR, or a Burp XML file.
func readHistory(path string, burp bool) ([]histEntry, error) {
	if burp {
		return readBurp(path)
	}
	return readHAR(path)
}

// loadHistories reads the -har and -burp files, one history per role name,
// in the order the names were given.
func loadHistories(hars, burps []string) ([]*history, error) {
	var out []*history
	byName := map[string]*history{}
	for _, set := range []struct {
		flag  string
		specs []string
		burp  bool
	}{{"-har", hars, false}, {"-burp", burps, true}} {
		for _, s := range set.specs {
			name, file, ok := strings.Cut(s, "=")
			name = strings.TrimSpace(name)
			if !ok || name == "" || file == "" || strings.ContainsAny(name, `/\ `) {
				return nil, usagef("%s %q: want NAME=FILE", set.flag, s)
			}
			es, err := readHistory(file, set.burp)
			if err != nil {
				return nil, usagef("%s %s: %v", set.flag, name, err)
			}
			h := byName[name]
			if h == nil {
				h = &history{name: name}
				byName[name] = h
				out = append(out, h)
			}
			for _, e := range es {
				e.seq += len(h.entries) // files after the first come later
				h.entries = append(h.entries, e)
			}
			h.files = append(h.files, filepathBase(file))
		}
	}
	return out, nil
}

// histScope says which origins of the histories are the target's: the ones
// most of a role's requests go to (not the analytics and CDNs its pages
// call), and the hosts given with -allow.
type histScope struct {
	origins map[string]bool
	hosts   map[string]bool
	top     map[string]string // role → the origin most of its requests go to
	ignored map[string]int    // origin → requests left out
}

// minShare is the share of a role's requests an origin needs to count when
// it is not the one most go to.
const minShare = 0.25

// histOrigin is scheme://host[:port] of a URL, lower case, without a
// default port; "" for one that is none.
func histOrigin(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return ""
	}
	scheme, host := strings.ToLower(u.Scheme), normalize.Hostname(u.Hostname())
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if p := u.Port(); p != "" && !(scheme == "http" && p == "80") && !(scheme == "https" && p == "443") {
		host += ":" + p
	}
	return scheme + "://" + host
}

func historyScope(hs []*history, allow []string) histScope {
	sc := histScope{origins: map[string]bool{}, hosts: map[string]bool{}, top: map[string]string{}, ignored: map[string]int{}}
	for _, a := range allow {
		a = strings.TrimSpace(a)
		if !strings.Contains(a, "://") {
			a = "http://" + a
		}
		if u, err := url.Parse(a); err == nil && u.Hostname() != "" {
			sc.hosts[normalize.Hostname(u.Hostname())] = true
		}
	}
	for _, h := range hs {
		count := map[string]int{}
		total := 0
		for _, e := range h.entries {
			if o := histOrigin(e.url); o != "" {
				count[o]++
				total++
			}
		}
		var order []string
		for o := range count {
			order = append(order, o)
		}
		sort.Slice(order, func(i, j int) bool {
			if count[order[i]] != count[order[j]] {
				return count[order[i]] > count[order[j]]
			}
			return order[i] < order[j]
		})
		for i, o := range order {
			if i == 0 {
				sc.top[h.name] = o
			}
			if i == 0 || float64(count[o]) >= minShare*float64(total) {
				sc.origins[o] = true
			}
		}
	}
	for _, h := range hs {
		for _, e := range h.entries {
			if o := histOrigin(e.url); o != "" && !sc.has(e.url) {
				sc.ignored[o]++
			}
		}
	}
	return sc
}

// has: the URL is on one of the target's origins.
func (s histScope) has(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return false
	}
	return s.origins[histOrigin(raw)] || s.hosts[normalize.Hostname(u.Hostname())]
}

// hostnames are the hosts the target is on.
func (s histScope) hostnames() []string {
	set := map[string]bool{}
	for o := range s.origins {
		if u, err := url.Parse(o); err == nil {
			set[normalize.Hostname(u.Hostname())] = true
		}
	}
	for h := range s.hosts {
		set[h] = true
	}
	out := make([]string, 0, len(set))
	for h := range set {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

// note says what the scope left out of the histories, or "".
func (s histScope) note() string {
	if len(s.ignored) == 0 {
		return ""
	}
	var parts []string
	for _, o := range sortedCountKeys(s.ignored) {
		parts = append(parts, fmt.Sprintf("%s (%d)", strings.TrimPrefix(strings.TrimPrefix(o, "https://"), "http://"), s.ignored[o]))
	}
	return "history: requests to other origins were left out (third parties; -allow HOST keeps one): " + strings.Join(parts, ", ")
}

// later: a was sent after b.
func (a histEntry) later(b histEntry) bool {
	if !a.at.IsZero() && !b.at.IsZero() && !a.at.Equal(b.at) {
		return a.at.After(b.at)
	}
	return a.seq > b.seq
}

// session is the session a role's history ends with: the Authorization and
// the Cookie header of its most recent request to the target (to the
// origin most of its requests go to first). A token the page had not got
// yet (Bearer null) is no session.
func (h *history) session(sc histScope) []string {
	var lines []string
	for _, name := range []string{"Authorization", "Cookie"} {
		var best, bestTop *histEntry
		for i := range h.entries {
			e := &h.entries[i]
			v := e.header.Get(name)
			if v == "" || !sc.has(e.url) || emptyCredential(name, v) {
				continue
			}
			if best == nil || e.later(*best) {
				best = e
			}
			if histOrigin(e.url) == sc.top[h.name] && (bestTop == nil || e.later(*bestTop)) {
				bestTop = e
			}
		}
		if bestTop != nil {
			best = bestTop
		}
		if best != nil {
			lines = append(lines, name+": "+best.header.Get(name))
		}
	}
	return lines
}

func emptyCredential(name, v string) bool {
	if name != "Authorization" {
		return false
	}
	_, tok, _ := strings.Cut(v, " ")
	switch strings.ToLower(strings.TrimSpace(tok)) {
	case "", "null", "undefined":
		return true
	}
	return false
}

// gets are the pages a role's history reached, on the target: one request
// each, with the status the history saw. A GET a name says changes
// something, a logout, a script or a file is left out, as it is from any
// replay.
func (h *history) gets(sc histScope, own map[string]bool) (urls []string, seen map[string]int) {
	seen = map[string]int{}
	for _, e := range h.entries {
		if e.method != http.MethodGet || !sc.has(e.url) {
			continue
		}
		u, err := normalize.URL(e.url)
		if err != nil || !replayable(u, own) {
			continue
		}
		if pu, err := url.Parse(u); err != nil || endsSession(pu) {
			continue
		}
		if _, ok := seen[u]; !ok {
			urls = append(urls, u)
			seen[u] = e.status
		}
	}
	return urls, seen
}

// readHistoryURLs asks role r for each URL its history reached, as r, and
// keeps the answers as its run would have: the pages it reached, and what
// their JSON held. budget counts the requests; the number asked is
// returned, with an error when it ran out first.
func readHistoryURLs(r role, urls []string, got map[string]answer, raw map[string]string, seen runSeen, own map[string]bool, rate float64, budget int) (int, error) {
	fetch.Reset()
	defer fetch.Reset()
	fetch.SetRate(rate)
	fetch.Allow = func(h string) bool { return own[normalize.Hostname(h)] }
	fetch.Extra = r.session.Clone()
	ctx := context.Background()
	client := fetch.Client(nil)
	sent := 0
	for _, u := range urls {
		if _, ok := got[u]; ok {
			continue // its run reached it already
		}
		if sent >= budget {
			return sent, fmt.Errorf("%w: stopped after -replay-max %d requests; role %s's history has pages that were not read", errReplayMax, budget, r.name)
		}
		sent++
		res, _, err := fetch.Do(ctx, client, u)
		if err != nil {
			if fetch.Stopped(ctx) != nil {
				return sent, fetch.Stopped(ctx)
			}
			continue
		}
		a, f := resultAnswer(res)
		got[u], raw[u] = a, u
		if f != nil {
			seen.add(u, f.ids)
			if len(f.objects) > 0 {
				seen.objects[u] = f.objects
			}
		}
	}
	return sent, nil
}

// historyWrites are the writes a role's history sent, on the target.
func historyWrites(h *history, sc histScope, methods map[string]bool, own map[string]bool) []writeReq {
	var es []histEntry
	for _, e := range h.entries {
		if sc.has(e.url) {
			es = append(es, e)
		}
	}
	return writesFrom(h.name, strings.Join(h.files, ", "), es, methods, own)
}

// runAllows are the values of -allow in the run options.
func runAllows(args []string) []string {
	var out []string
	for i, a := range args {
		k, v, eq := strings.Cut(strings.TrimLeft(a, "-"), "=")
		if !strings.HasPrefix(a, "-") || k != "allow" {
			continue
		}
		if !eq && i+1 < len(args) {
			v = args[i+1]
		}
		out = append(out, v)
	}
	return out
}

// addHistories gives each history its role: the -role of that name, or a
// new one. A role with no headers takes its session from its history, and
// unless noAnon an anonymous role is added when none is there.
func addHistories(roles []role, hs []*history, sc histScope, noAnon bool) []role {
	for _, h := range hs {
		i := slices.IndexFunc(roles, func(r role) bool { return r.name == h.name })
		if i < 0 {
			roles = append(roles, role{name: h.name})
			i = len(roles) - 1
		}
		if roles[i].anonymous() {
			roles[i].headers = h.session(sc)
		}
	}
	if len(hs) > 0 && !noAnon && !slices.ContainsFunc(roles, role.anonymous) {
		name := "anon"
		for n := 2; slices.ContainsFunc(roles, func(r role) bool { return r.name == name }); n++ {
			name = fmt.Sprintf("anon%d", n)
		}
		roles = append(roles, role{name: name})
	}
	return roles
}

// ---- routes from the URLs of a history ----

var paramWord = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

var (
	segNumber = regexp.MustCompile(`^\d+$`)
	segUUID   = regexp.MustCompile(`^(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	segHex    = regexp.MustCompile(`^(?i)[0-9a-f]{16,}$`)
)

// historyTemplates are the routes with a path parameter the URLs of the
// histories are instances of, so that every role is asked for every
// other's objects without a crawl: /rest/basket/6 and /rest/basket/7 are
// /rest/basket/{id}. A number, a UUID or a long hex string is a
// parameter. A word is one when the URLs differ in it alone (/books/v1/a
// and /books/v1/b) and some value of it is an identifier an answer held
// (/rest/user/whoami and /rest/user/login are two pages, not two users).
// The parameter takes the name of the field that held the value.
func historyTemplates(urls []string, seen map[string]runSeen) []string {
	type parsed struct {
		u    *url.URL
		segs []string
	}
	var all []parsed
	for _, raw := range urls {
		u, err := url.Parse(raw)
		if err != nil {
			continue
		}
		all = append(all, parsed{u, strings.Split(u.EscapedPath(), "/")})
	}
	held := map[string]bool{} // every value an answer held under a field
	for _, s := range seen {
		for _, vs := range s.ids {
			for _, v := range vs {
				held[v] = true
			}
		}
	}
	// A word position: the URLs that share everything else, by its place.
	groups := map[string]map[string]bool{}
	keyOf := func(p parsed, i int) string {
		rest := append(append([]string{}, p.segs[:i]...), p.segs[i+1:]...)
		return fmt.Sprint(p.u.Host, i, len(p.segs), rest)
	}
	for _, p := range all {
		for i := 1; i < len(p.segs); i++ {
			if p.segs[i] == "" || variable(p.segs[i]) {
				continue
			}
			k := keyOf(p, i)
			if groups[k] == nil {
				groups[k] = map[string]bool{}
			}
			groups[k][p.segs[i]] = true
		}
	}
	isParam := func(p parsed, i int) bool {
		if variable(p.segs[i]) {
			return true
		}
		vals := groups[keyOf(p, i)]
		if len(vals) < 2 {
			return false
		}
		for v := range vals {
			if held[v] {
				return true
			}
		}
		return false
	}
	out := map[string]bool{}
	for _, p := range all {
		segs := append([]string{}, p.segs...)
		n := 0
		for i := 1; i < len(segs); i++ {
			if segs[i] == "" || !isParam(p, i) {
				continue
			}
			segs[i] = "{" + paramName(p.segs[i], p.u.String(), seen, n) + "}"
			n++
		}
		if n == 0 {
			continue
		}
		t := *p.u
		t.RawQuery, t.Fragment = "", ""
		t.Path = ""
		t.RawPath = ""
		s := t.Scheme + "://" + t.Host + strings.Join(segs, "/")
		if k := webextract.RouteKey(s); strings.Contains(k, "{") {
			out[k] = true
		}
	}
	return sortedKeys(out)
}

func variable(seg string) bool {
	return segNumber.MatchString(seg) || segUUID.MatchString(seg) || segHex.MatchString(seg)
}

// paramName is what the parameter holding value is called: the field the
// answer at its own URL held it under (username for /users/v1/alice), else
// the one field any answer held it under, else id. n is its place among
// the URL's parameters.
func paramName(value, u string, seen map[string]runSeen, n int) string {
	unescaped, err := url.PathUnescape(value)
	if err != nil {
		unescaped = value
	}
	name := "id"
	if !variable(value) {
		own, anyField := map[string]bool{}, map[string]bool{}
		for _, s := range seen {
			for k, vs := range s.ids {
				for _, v := range vs {
					if v == unescaped {
						anyField[k] = true
					}
				}
			}
			for k, vs := range s.lists[u] {
				for _, v := range vs {
					if v == unescaped {
						own[k] = true
					}
				}
			}
		}
		switch {
		case len(own) > 0:
			name = sortedKeys(own)[0]
		case len(anyField) == 1:
			name = sortedKeys(anyField)[0]
		}
	}
	if !paramWord.MatchString(name) {
		name = "id"
	}
	if n > 0 {
		name += fmt.Sprint(n + 1)
	}
	return name
}
