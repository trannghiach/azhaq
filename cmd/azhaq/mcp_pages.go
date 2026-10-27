package main

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/url"
	"slices"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

// azhaq_export returns an export a page at a time, and every page is a
// document a client can parse on its own: an OpenAPI description with
// some of the paths, an introspection result or SDL with some of the
// definitions, a Burp options file with some of the scope, an HTML report
// or a GraphML graph with some of the rows, whole lines. offset counts
// those units, never bytes, so no page cuts one.

// maxInline bounds a page of an export; one unit larger than that is a
// page alone.
const maxInline = 16 << 10

// exportUnits is an export cut into the units its pages hold whole.
type exportUnits struct {
	unit  string   // what a unit is, plural: "paths", "lines"
	names []string // each unit as a page's head names it
	// page is a document holding units lo to hi-1, the whole export when
	// it holds them all. Its size grows with hi.
	page func(lo, hi int) []byte
}

// splitExport cuts an export by its format; one it cannot read is paged
// by lines, and the reason is given.
func splitExport(format string, raw []byte) (*exportUnits, error) {
	var u *exportUnits
	var err error
	switch format {
	case "openapi":
		u, err = openAPIUnits(raw)
	case "graphql":
		u, err = introspectionUnits(raw)
	case "sdl":
		u = sdlUnits(raw)
	case "burp":
		u, err = burpUnits(raw)
	case "html":
		u, err = htmlUnits(raw)
	case "graphml":
		u, err = xmlUnits(raw, "graph", "nodes and edges")
	default:
		u = lineUnits(raw)
	}
	if err != nil {
		return lineUnits(raw), err
	}
	return u, nil
}

// exportPart is what azhaq_export returns: where the export was written,
// how many units it has, and the page from offset on, with the offset of
// the next one.
func exportPart(path, format string, raw []byte, offset int) string {
	u, err := splitExport(format, raw)
	n := len(u.names)
	head := fmt.Sprintf("wrote %s on the server's machine (%d bytes, %s: %s)", path, len(raw), format, count(n, u.unit))
	if err != nil {
		head += fmt.Sprintf("; not read as %s (%v), so paged by lines", format, err)
	}
	if offset == 0 && (len(raw) <= maxInline || n <= 1) {
		return head + "\n" + string(raw) // all of it, as written
	}
	if offset >= n {
		return head + fmt.Sprintf("; offset %d is past its end", offset)
	}
	hi, page := u.fit(offset, maxInline)
	if hi-offset == 1 {
		head += fmt.Sprintf("; this page holds %s %d of %d (%s)", singular[u.unit], offset, n, clip(u.names[offset]))
	} else {
		head += fmt.Sprintf("; this page holds %s %d to %d of %d (%s to %s)", u.unit, offset, hi-1, n, clip(u.names[offset]), clip(u.names[hi-1]))
	}
	if hi < n {
		head += fmt.Sprintf(". For the rest call azhaq_export again with offset %d, or ask a narrower question (format urls, hosts or targets; azhaq_query), or read the file where the server runs", hi)
	} else {
		head += ", the last"
	}
	return head + "\n" + string(page)
}

// fit is the page from lo that holds the most units within max bytes,
// and where it ends; a unit that alone passes max is a page alone.
func (u *exportUnits) fit(lo, max int) (int, []byte) {
	n := len(u.names)
	good, page := lo+1, u.page(lo, lo+1)
	if len(page) > max {
		return good, page
	}
	bad := n + 1 // the first end known not to fit
	for step := 2; good < n && bad > n; step *= 2 {
		hi := min(lo+step, n)
		if p := u.page(lo, hi); len(p) <= max {
			good, page = hi, p
		} else {
			bad = hi
		}
	}
	for bad <= n && bad-good > 1 {
		mid := (good + bad) / 2
		if p := u.page(lo, mid); len(p) <= max {
			good, page = mid, p
		} else {
			bad = mid
		}
	}
	return good, page
}

// singular names one unit of each kind.
var singular = map[string]string{"paths": "path", "definitions": "definition", "scope entries": "scope entry", "rows": "row", "nodes and edges": "node or edge", "lines": "line"}

func count(n int, unit string) string {
	if n == 1 {
		return "1 " + singular[unit]
	}
	return fmt.Sprintf("%d %s", n, unit)
}

func clip(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if utf8.RuneCountInString(s) > 60 {
		s = string([]rune(s)[:60]) + "…"
	}
	return s
}

func lineUnits(raw []byte) *exportUnits {
	var lines []string
	if text := strings.TrimSuffix(string(raw), "\n"); text != "" {
		lines = strings.Split(text, "\n")
	}
	return &exportUnits{unit: "lines", names: lines, page: func(lo, hi int) []byte {
		return []byte(strings.Join(lines[lo:hi], "\n") + "\n")
	}}
}

// readJSON keeps numbers as written.
func readJSON(raw []byte) (map[string]any, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var v map[string]any
	if err := d.Decode(&v); err != nil {
		return nil, err
	}
	if v == nil {
		return nil, errors.New("not a JSON object")
	}
	return v, nil
}

// compactJSON is a page of a JSON export: compact, since a client pays
// for every byte, and with <, > and & as they are.
func compactJSON(v any) []byte {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
	return b.Bytes()
}

// openAPIUnits pages an OpenAPI description by its paths: each page is
// the description with some of them, whole, and the components they
// refer to.
func openAPIUnits(raw []byte) (*exportUnits, error) {
	doc, err := readJSON(raw)
	if err != nil {
		return nil, err
	}
	paths, ok := doc["paths"].(map[string]any)
	if !ok {
		return nil, errors.New("no paths")
	}
	names := slices.Sorted(maps.Keys(paths))
	comps, _ := doc["components"].(map[string]any)
	return &exportUnits{unit: "paths", names: names, page: func(lo, hi int) []byte {
		pg := map[string]any{}
		for k, v := range doc {
			if k != "paths" && k != "components" {
				pg[k] = v
			}
		}
		sub := map[string]any{}
		for _, p := range names[lo:hi] {
			sub[p] = paths[p]
		}
		pg["paths"] = sub
		switch {
		case comps == nil:
		case lo == 0 && hi == len(names):
			pg["components"] = comps
		default:
			if c := usedComponents(pg, comps); len(c) > 0 {
				pg["components"] = c
			}
		}
		return compactJSON(pg)
	}}, nil
}

// usedComponents are the components a page refers to, directly or through
// other components, so that each page's $refs resolve. Security schemes
// are named by requirements, not referred to: they go whole.
func usedComponents(pg map[string]any, comps map[string]any) map[string]any {
	out := map[string]any{}
	if ss, ok := comps["securitySchemes"]; ok {
		out["securitySchemes"] = ss
	}
	seen := map[[2]string]bool{}
	queue := []any{pg}
	for len(queue) > 0 {
		v := queue[0]
		queue = queue[1:]
		refsIn(v, func(ref string) {
			sec, name, ok := componentRef(ref)
			if !ok || seen[[2]string{sec, name}] {
				return
			}
			entries, _ := comps[sec].(map[string]any)
			c, ok := entries[name]
			if !ok {
				return
			}
			seen[[2]string{sec, name}] = true
			m, _ := out[sec].(map[string]any)
			if m == nil {
				m = map[string]any{}
				out[sec] = m
			}
			m[name] = c
			queue = append(queue, c)
		})
	}
	return out
}

// refsIn calls fn with every reference in v: each $ref, and the schemas a
// discriminator maps to, by reference or by name.
func refsIn(v any, fn func(string)) {
	switch v := v.(type) {
	case map[string]any:
		for k, x := range v {
			switch s, isStr := x.(string); {
			case k == "$ref" && isStr:
				fn(s)
			case k == "mapping":
				m, _ := x.(map[string]any)
				for _, y := range m {
					if s, ok := y.(string); ok && strings.HasPrefix(s, "#") {
						fn(s)
					} else if ok {
						fn("#/components/schemas/" + s)
					}
				}
			default:
				refsIn(x, fn)
			}
		}
	case []any:
		for _, x := range v {
			refsIn(x, fn)
		}
	}
}

// componentRef reads #/components/SECTION/NAME[/…] as a JSON pointer.
func componentRef(ref string) (string, string, bool) {
	rest, ok := strings.CutPrefix(ref, "#/components/")
	if !ok {
		return "", "", false
	}
	parts := strings.SplitN(rest, "/", 3)
	if len(parts) < 2 {
		return "", "", false
	}
	unescape := func(s string) string {
		if u, err := url.PathUnescape(s); err == nil {
			s = u
		}
		return strings.ReplaceAll(strings.ReplaceAll(s, "~1", "/"), "~0", "~")
	}
	return unescape(parts[0]), unescape(parts[1]), true
}

// introspectionUnits pages a GraphQL introspection result by its
// definitions, types then directives, each page an introspection result
// of its own; with several endpoints, keyed by endpoint as the export is.
func introspectionUnits(raw []byte) (*exportUnits, error) {
	doc, err := readJSON(raw)
	if err != nil {
		return nil, err
	}
	type endpoint struct {
		url        string
		schema     map[string]any
		types, dir []any
	}
	read := func(u string, v any) (endpoint, error) {
		res, _ := v.(map[string]any)
		data, _ := res["data"].(map[string]any)
		sc, ok := data["__schema"].(map[string]any)
		if !ok {
			return endpoint{}, errors.New("no data.__schema")
		}
		ts, _ := sc["types"].([]any)
		ds, _ := sc["directives"].([]any)
		return endpoint{url: u, schema: sc, types: ts, dir: ds}, nil
	}
	var eps []endpoint
	keyed := doc["data"] == nil
	if keyed {
		for _, u := range slices.Sorted(maps.Keys(doc)) {
			ep, err := read(u, doc[u])
			if err != nil {
				return nil, fmt.Errorf("%s: %w", u, err)
			}
			eps = append(eps, ep)
		}
	} else {
		ep, err := read("", doc)
		if err != nil {
			return nil, err
		}
		eps = append(eps, ep)
	}
	type unit struct{ ep, i int } // i past the types: a directive
	var units []unit
	var names []string
	nameOf := func(v any) string {
		m, _ := v.(map[string]any)
		s, _ := m["name"].(string)
		return s
	}
	// The directives first, as SDL has them: a page then always holds
	// types, which a reader of an introspection result expects.
	for e, ep := range eps {
		for i, d := range ep.dir {
			units = append(units, unit{e, len(ep.types) + i})
			names = append(names, "@"+nameOf(d))
		}
		for i, t := range ep.types {
			units = append(units, unit{e, i})
			names = append(names, nameOf(t))
		}
	}
	return &exportUnits{unit: "definitions", names: names, page: func(lo, hi int) []byte {
		types, dirs := make([][]any, len(eps)), make([][]any, len(eps))
		held := map[int]bool{}
		for _, u := range units[lo:hi] {
			held[u.ep] = true
			if ep := eps[u.ep]; u.i < len(ep.types) {
				types[u.ep] = append(types[u.ep], ep.types[u.i])
			} else {
				dirs[u.ep] = append(dirs[u.ep], ep.dir[u.i-len(ep.types)])
			}
		}
		result := func(e int) map[string]any {
			sc := maps.Clone(eps[e].schema)
			sc["types"], sc["directives"] = orEmpty(types[e]), orEmpty(dirs[e])
			return map[string]any{"data": map[string]any{"__schema": sc}}
		}
		if !keyed {
			return compactJSON(result(0))
		}
		out := map[string]any{}
		for e, ep := range eps {
			if held[e] {
				out[ep.url] = result(e)
			}
		}
		return compactJSON(out)
	}}, nil
}

func orEmpty(xs []any) []any {
	if xs == nil {
		return []any{}
	}
	return xs
}

// sdlUnits pages a GraphQL schema by its definitions. Definitions are
// separated by a blank line; a blank line inside a """ description is
// part of it. Each endpoint's schema starts with the comments that say
// where it was read, repeated on every page that holds some of it.
func sdlUnits(raw []byte) *exportUnits {
	var blocks [][]string
	var cur []string
	in := false // inside a """ block string
	for _, l := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n") {
		if l == "" && !in {
			if len(cur) > 0 {
				blocks, cur = append(blocks, cur), nil
			}
			continue
		}
		cur = append(cur, l)
		if strings.TrimSpace(l) == `"""` {
			in = !in
		}
	}
	if len(cur) > 0 {
		blocks = append(blocks, cur)
	}
	type section struct {
		head string
		defs []string
	}
	var secs []section
	type unit struct{ sec, i int }
	var units []unit
	var names []string
	for _, b := range blocks {
		if len(b) == 2 && strings.HasPrefix(b[0], "# ") && strings.HasPrefix(b[1], "# read by introspection") {
			secs = append(secs, section{head: strings.Join(b, "\n")})
			continue
		}
		if len(secs) == 0 {
			secs = append(secs, section{})
		}
		s := len(secs) - 1
		units = append(units, unit{s, len(secs[s].defs)})
		secs[s].defs = append(secs[s].defs, strings.Join(b, "\n"))
		names = append(names, sdlName(b))
	}
	return &exportUnits{unit: "definitions", names: names, page: func(lo, hi int) []byte {
		var parts []string
		last := -1
		for _, u := range units[lo:hi] {
			if u.sec != last && secs[u.sec].head != "" {
				parts = append(parts, secs[u.sec].head)
			}
			last = u.sec
			parts = append(parts, secs[u.sec].defs[u.i])
		}
		return []byte(strings.Join(parts, "\n\n") + "\n")
	}}
}

// sdlName names a definition by its first line past its description:
// "type User", "directive @auth", "schema".
func sdlName(block []string) string {
	in := false
	for _, l := range block {
		if strings.TrimSpace(l) == `"""` {
			in = !in
			continue
		}
		if in {
			continue
		}
		f := strings.Fields(l)
		if len(f) > 1 && f[1] != "{" {
			name, _, _ := strings.Cut(f[1], "(")
			return f[0] + " " + name
		}
		if len(f) > 0 {
			return f[0]
		}
	}
	return ""
}

// burpUnits pages a Burp project options file by its scope entries, the
// included then the excluded, each page an options file of its own.
func burpUnits(raw []byte) (*exportUnits, error) {
	doc, err := readJSON(raw)
	if err != nil {
		return nil, err
	}
	target, _ := doc["target"].(map[string]any)
	sc, ok := target["scope"].(map[string]any)
	if !ok {
		return nil, errors.New("no target.scope")
	}
	inc, _ := sc["include"].([]any)
	exc, _ := sc["exclude"].([]any)
	var names []string
	for _, lists := range []struct {
		word string
		list []any
	}{{"include", inc}, {"exclude", exc}} {
		for _, e := range lists.list {
			m, _ := e.(map[string]any)
			h, _ := m["host"].(string)
			names = append(names, lists.word+" "+h)
		}
	}
	return &exportUnits{unit: "scope entries", names: names, page: func(lo, hi int) []byte {
		var i, x []any
		for k := lo; k < hi; k++ {
			if k < len(inc) {
				i = append(i, inc[k])
			} else {
				x = append(x, exc[k-len(inc)])
			}
		}
		s := maps.Clone(sc)
		s["include"], s["exclude"] = orEmpty(i), orEmpty(x)
		t := maps.Clone(target)
		t["scope"] = s
		pg := maps.Clone(doc)
		pg["target"] = t
		return compactJSON(pg)
	}}, nil
}

// htmlUnits pages the HTML report by its rows (and groups of screenshots):
// each page is the report with some of them; a section whose rows are all
// on other pages is left out.
func htmlUnits(raw []byte) (*exportUnits, error) {
	doc, err := html.Parse(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	var body *html.Node
	for n := range doc.Descendants() {
		if n.Type == html.ElementNode && n.DataAtom == atom.Body {
			body = n
			break
		}
	}
	if body == nil {
		return nil, errors.New("no body")
	}
	// A section is an h2 and what follows it up to the next one.
	var secs [][]*html.Node
	for c := body.FirstChild; c != nil; c = c.NextSibling {
		if c.Type == html.ElementNode && c.DataAtom == atom.H2 || len(secs) == 0 {
			secs = append(secs, nil)
		}
		secs[len(secs)-1] = append(secs[len(secs)-1], c)
	}
	var rows []*html.Node
	var secOf []int
	var names []string
	for s, nodes := range secs {
		for _, n := range nodes {
			for r := range htmlRows(n) {
				rows, secOf = append(rows, r), append(secOf, s)
				names = append(names, htmlText(r))
			}
		}
	}
	type cut struct{ n, parent, next *html.Node }
	return &exportUnits{unit: "rows", names: names, page: func(lo, hi int) []byte {
		held := map[int]bool{}
		for i := lo; i < hi; i++ {
			held[secOf[i]] = true
		}
		var cuts []cut
		detach := func(n *html.Node) {
			cuts = append(cuts, cut{n, n.Parent, n.NextSibling})
			n.Parent.RemoveChild(n)
		}
		for s, nodes := range secs {
			if !held[s] && slices.Contains(secOf, s) {
				for _, n := range nodes {
					detach(n)
				}
			}
		}
		for i, r := range rows {
			if (i < lo || i >= hi) && held[secOf[i]] {
				detach(r)
			}
		}
		var b bytes.Buffer
		_ = html.Render(&b, doc)
		b.WriteByte('\n')
		for _, c := range slices.Backward(cuts) {
			c.parent.InsertBefore(c.n, c.next)
		}
		return b.Bytes()
	}}, nil
}

// htmlRows are the units under n: table rows with cells, and groups of
// screenshots.
func htmlRows(n *html.Node) func(func(*html.Node) bool) {
	return func(yield func(*html.Node) bool) {
		var walk func(*html.Node) bool
		walk = func(n *html.Node) bool {
			if n.Type == html.ElementNode {
				switch {
				case n.DataAtom == atom.Tr && hasChild(n, atom.Td):
					return yield(n)
				case n.DataAtom == atom.Div && hasClass(n, "group"):
					return yield(n)
				}
			}
			for c := n.FirstChild; c != nil; c = c.NextSibling {
				if !walk(c) {
					return false
				}
			}
			return true
		}
		walk(n)
	}
}

func hasChild(n *html.Node, a atom.Atom) bool {
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if c.Type == html.ElementNode && c.DataAtom == a {
			return true
		}
	}
	return false
}

func hasClass(n *html.Node, class string) bool {
	for _, a := range n.Attr {
		if a.Key == "class" && slices.Contains(strings.Fields(a.Val), class) {
			return true
		}
	}
	return false
}

// htmlText is the text of a row's first cell, or of a group's first
// caption.
func htmlText(n *html.Node) string {
	for d := range n.Descendants() {
		if d.Type == html.ElementNode && (d.DataAtom == atom.Td || d.DataAtom == atom.Figcaption) {
			n = d
			break
		}
	}
	var b strings.Builder
	for d := range n.Descendants() {
		if d.Type == html.TextNode {
			b.WriteString(d.Data)
		}
	}
	return b.String()
}

// xmlUnits pages an XML document by the children of its element named
// parent (graph in GraphML: nodes and edges): each page is the document
// with some of them. What comes before and after them is on every page.
func xmlUnits(raw []byte, parent, unit string) (*exportUnits, error) {
	d := xml.NewDecoder(bytes.NewReader(raw))
	type span struct{ from, to int64 }
	var spans []span
	var names []string
	depth, inside, done := 0, -1, false // inside: the depth of parent's children while it is open
	var prev, from int64
	for {
		tok, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		off := d.InputOffset()
		switch t := tok.(type) {
		case xml.StartElement:
			if depth == inside {
				from = prev
				names = append(names, xmlName(t))
			}
			depth++
			if t.Name.Local == parent && inside < 0 && !done {
				inside = depth
			}
		case xml.EndElement:
			depth--
			if depth == inside {
				spans = append(spans, span{from, off})
			}
			if depth == inside-1 {
				inside, done = -1, true // the first one only
			}
		}
		prev = off
	}
	if len(spans) == 0 {
		return &exportUnits{unit: unit, page: func(int, int) []byte { return raw }}, nil
	}
	head, tail := raw[:spans[0].from], raw[spans[len(spans)-1].to:]
	sep := []byte("\n")
	if len(spans) > 1 {
		sep = raw[spans[0].to:spans[1].from]
	}
	return &exportUnits{unit: unit, names: names, page: func(lo, hi int) []byte {
		var b bytes.Buffer
		b.Write(head)
		for i := lo; i < hi; i++ {
			if i > lo {
				b.Write(sep)
			}
			b.Write(raw[spans[i].from:spans[i].to])
		}
		b.Write(tail)
		return b.Bytes()
	}}, nil
}

// xmlName names an element by its id, or an edge by its ends.
func xmlName(t xml.StartElement) string {
	attr := map[string]string{}
	for _, a := range t.Attr {
		attr[a.Name.Local] = a.Value
	}
	switch {
	case attr["source"] != "" && attr["target"] != "":
		return attr["source"] + " → " + attr["target"]
	case attr["id"] != "":
		return t.Name.Local + " " + attr["id"]
	}
	return t.Name.Local
}
