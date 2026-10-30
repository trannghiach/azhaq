package gallery

import (
	"bytes"
	"io"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/html"
)

// Query is what the page asks for: the filters, the search, the order and
// the page of results.
type Query struct {
	Q         string   // free text and field:value terms
	Status    []string // 200, 2xx or none
	Tech      []string // every one must be among a page's technologies
	Title     string
	Host      string
	Workspace string
	Partial   string // yes or no
	Group     int    // -1: any
	Sort      string
	Desc      bool
	Collapse  bool // one page for each look-alike group
	Offset    int
	Limit     int
}

// terms are the parsed search: each must hold for a page.
type term struct {
	field, val string
	neg        bool
}

var searchFields = map[string]bool{"url": true, "title": true, "body": true, "tech": true, "header": true, "p": true, "host": true, "status": true}

// parseSearch splits a search into terms: words, "quoted phrases" and
// field:value (title:login, body:"sign in", tech:nginx), a leading - for
// a term that must not hold.
func parseSearch(q string) []term {
	var out []term
	var cur strings.Builder
	inQuote := false
	flush := func() {
		w := cur.String()
		cur.Reset()
		var t term
		if len(w) > 1 && w[0] == '-' {
			t.neg, w = true, w[1:]
		}
		if c := strings.IndexByte(w, ':'); c > 0 && searchFields[strings.ToLower(w[:c])] {
			t.field, w = strings.ToLower(w[:c]), w[c+1:]
		}
		if t.val = strings.ToLower(w); t.val != "" {
			out = append(out, t)
		}
	}
	for _, r := range q {
		switch {
		case r == '"':
			inQuote = !inQuote
		case !inQuote && (r == ' ' || r == '\t'):
			flush()
		default:
			cur.WriteRune(r)
		}
	}
	flush()
	return out
}

func (t term) needsBody() bool { return t.field == "body" || t.field == "" }

func (t term) match(s *Shot) bool {
	var ok bool
	switch t.field {
	case "url":
		ok = strings.Contains(s.lurl, t.val)
	case "title":
		ok = strings.Contains(s.ltitle, t.val)
	case "host":
		ok = strings.Contains(s.lhost, t.val)
	case "body":
		ok = strings.Contains(s.body, t.val)
	case "header":
		ok = strings.Contains(s.lheaders, t.val)
	case "tech":
		for _, x := range s.ltech {
			if strings.Contains(x, t.val) {
				ok = true
				break
			}
		}
	case "p":
		ok = strings.HasPrefix(strings.ToLower(s.Hash), strings.ToLower(t.val)) || strings.HasPrefix(strings.ToLower(s.Hash), "p:"+t.val)
	case "status":
		ok = statusMatch(s.Status, t.val)
	default:
		ok = strings.Contains(s.lurl, t.val) || strings.Contains(s.ltitle, t.val) || strings.Contains(s.body, t.val)
	}
	return ok != t.neg
}

func statusMatch(code int, want string) bool {
	want = strings.ToLower(strings.TrimSpace(want))
	switch {
	case want == "none" || want == "0":
		return code == 0
	case len(want) == 3 && strings.HasSuffix(want, "xx"):
		return code != 0 && strconv.Itoa(code)[0] == want[0]
	}
	n, err := strconv.Atoi(want)
	return err == nil && code == n
}

// matches filters the pages and returns them in the order asked, as
// indexes. skip names one filter to leave out (for facet counts).
func (g *Gallery) matches(q Query, skip string) []int {
	order := g.orders[q.Sort]
	if order == nil {
		order = g.orders["url"]
	}
	terms := parseSearch(q.Q)
	for _, t := range terms {
		if t.needsBody() && g.bodyKept > 0 {
			<-g.bodyDone
			break
		}
	}
	title, host := strings.ToLower(q.Title), strings.ToLower(q.Host)
	techs := make([]string, 0, len(q.Tech))
	for _, t := range q.Tech {
		techs = append(techs, strings.ToLower(t))
	}
	ok := func(s *Shot) bool {
		if skip != "status" && len(q.Status) > 0 {
			hit := false
			for _, st := range q.Status {
				if statusMatch(s.Status, st) {
					hit = true
					break
				}
			}
			if !hit {
				return false
			}
		}
		if skip != "tech" {
			for _, t := range techs {
				if !slices.Contains(s.lname, t) && !slices.Contains(s.ltech, t) {
					return false
				}
			}
		}
		switch {
		case title != "" && !strings.Contains(s.ltitle, title),
			skip != "host" && host != "" && !strings.Contains(s.lhost, host),
			skip != "workspace" && q.Workspace != "" && s.Workspace != q.Workspace,
			skip != "partial" && q.Partial == "yes" && !s.Partial,
			skip != "partial" && q.Partial == "no" && s.Partial,
			q.Group >= 0 && s.Group != q.Group:
			return false
		}
		for _, t := range terms {
			if !t.match(s) {
				return false
			}
		}
		return true
	}
	out := make([]int, 0, 64)
	step, from := 1, 0
	if q.Desc {
		step, from = -1, len(order)-1
	}
	seen := map[int]bool{}
	for k, n := from, 0; n < len(order); k, n = k+step, n+1 {
		i := order[k]
		s := g.shots[i]
		if !ok(s) {
			continue
		}
		if q.Collapse && skip == "" {
			if seen[s.Group] {
				continue
			}
			seen[s.Group] = true
		}
		out = append(out, i)
	}
	return out
}

// ShotView is a page in a list, with how many pages of its group matched
// when the list shows one page for each group.
type ShotView struct {
	*Shot
	GroupMatches int `json:"group_matches,omitempty"`
}

// List is one page of results.
type List struct {
	Total  int        `json:"total"`
	Offset int        `json:"offset"`
	Limit  int        `json:"limit"`
	Shots  []ShotView `json:"shots"`
	TookMS float64    `json:"took_ms"`
}

func (g *Gallery) list(q Query) List {
	idx := g.matches(q, "")
	out := List{Total: len(idx), Offset: q.Offset, Limit: q.Limit, Shots: []ShotView{}}
	if q.Offset >= len(idx) {
		return out
	}
	end := min(q.Offset+q.Limit, len(idx))
	var per map[int]int
	if q.Collapse {
		cq := q
		cq.Collapse = false
		per = map[int]int{}
		for _, i := range g.matches(cq, "") {
			per[g.shots[i].Group]++
		}
	}
	for _, i := range idx[q.Offset:end] {
		v := ShotView{Shot: g.shots[i]}
		if per != nil {
			v.GroupMatches = per[v.Group]
		}
		out.Shots = append(out.Shots, v)
	}
	return out
}

// Facets count the values a filter offers, each under every other filter.
type Facets struct {
	Status     []Count `json:"status"`
	Tech       []Count `json:"technologies"`
	Host       []Count `json:"hosts"`
	Partial    []Count `json:"partial"`
	Workspaces []Count `json:"workspaces,omitempty"`
}

func (g *Gallery) facets(q Query) Facets {
	count := func(skip string, add func(s *Shot, m map[string]int)) map[string]int {
		cq := q
		cq.Collapse = false
		m := map[string]int{}
		for _, i := range g.matches(cq, skip) {
			add(g.shots[i], m)
		}
		return m
	}
	var f Facets
	st := count("status", func(s *Shot, m map[string]int) { m[statusName(s.Status)]++ })
	f.Status = topCounts(st, 200)
	sort.SliceStable(f.Status, func(i, j int) bool { return f.Status[i].Value < f.Status[j].Value })
	f.Tech = topCounts(count("tech", func(s *Shot, m map[string]int) {
		for _, t := range uniq(s.Tech) {
			m[t]++
		}
	}), 60)
	f.Host = topCounts(count("host", func(s *Shot, m map[string]int) { m[s.Host]++ }), 30)
	f.Partial = topCounts(count("partial", func(s *Shot, m map[string]int) {
		if s.Partial {
			m["yes"]++
		} else {
			m["no"]++
		}
	}), 2)
	if g.multi {
		f.Workspaces = topCounts(count("workspace", func(s *Shot, m map[string]int) { m[s.Workspace]++ }), 100)
	}
	return f
}

// indexBodies reads the text of each kept page into the search.
func (g *Gallery) indexBodies() {
	defer close(g.bodyDone)
	for _, s := range g.shots {
		if !s.HasBody {
			continue
		}
		if text, err := pageText(s.htmlFile, 64<<10); err == nil {
			s.body = strings.ToLower(text)
		}
		g.bodyIndexed.Add(1)
	}
}

// pageText is the visible text of an HTML file, whitespace squeezed, at
// most max bytes.
func pageText(path string, max int) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 4<<20))
	if err != nil {
		return "", err
	}
	z := html.NewTokenizer(bytes.NewReader(raw))
	var b strings.Builder
	skip := 0
	for b.Len() < max {
		switch z.Next() {
		case html.ErrorToken:
			return squeeze(b.String(), max), nil
		case html.StartTagToken:
			if n, _ := z.TagName(); string(n) == "script" || string(n) == "style" || string(n) == "noscript" {
				skip++
			}
		case html.EndTagToken:
			if n, _ := z.TagName(); (string(n) == "script" || string(n) == "style" || string(n) == "noscript") && skip > 0 {
				skip--
			}
		case html.TextToken:
			if skip == 0 {
				b.Write(z.Text())
				b.WriteByte(' ')
			}
		}
	}
	return squeeze(b.String(), max), nil
}

func squeeze(s string, max int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > max {
		s = s[:max]
		for !utf8.ValidString(s) {
			s = s[:len(s)-1]
		}
	}
	return s
}
