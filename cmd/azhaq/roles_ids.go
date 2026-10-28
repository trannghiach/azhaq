package main

import (
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/trannghiach/azhaq/internal/normalize"
)

// Filling routes such as /books/v1/{book_title} with identifiers, so that
// every role asks for every role's objects: values the roles' JSON
// answers held, and values given with -id.

// runSeen is what one role's run saw besides answers: the values its
// JSON answers held, by field and by the URL that held them, and GET
// routes with path parameters.
type runSeen struct {
	ids       map[string][]string            // field → values
	lists     map[string]map[string][]string // URL → field → values its answer held
	objects   map[string][]listObject        // URL → the items of its answer that name their owner
	templates map[string]bool
	writes    map[string][]writeOp // route → the writes it takes, besides GET
	kept      map[string]bool      // what ids and lists hold already
}

func newRunSeen() runSeen {
	return runSeen{ids: map[string][]string{}, lists: map[string]map[string][]string{}, objects: map[string][]listObject{},
		templates: map[string]bool{}, writes: map[string][]writeOp{}, kept: map[string]bool{}}
}

// add keeps the values one answer held.
func (s runSeen) add(u string, ids map[string][]string) {
	if len(ids) == 0 {
		return
	}
	list := s.lists[u]
	if list == nil {
		list = map[string][]string{}
		s.lists[u] = list
	}
	for k, vs := range ids {
		for _, v := range vs {
			if key := u + "\x00" + k + "\x00" + v; len(list[k]) < maxFieldVals && !s.kept[key] {
				s.kept[key] = true
				list[k] = append(list[k], v)
			}
			if key := "\x00" + k + "\x00" + v; len(s.ids[k]) < maxFieldVals && !s.kept[key] {
				s.kept[key] = true
				s.ids[k] = append(s.ids[k], v)
			}
		}
	}
}

// listed is every value the answer at u held, in any field.
func (s runSeen) listed(u string) map[string]bool {
	out := map[string]bool{}
	for _, vs := range s.lists[u] {
		for _, v := range vs {
			out[v] = true
		}
	}
	return out
}

// givenID is an identifier given with -id [ROLE:]NAME=VALUE.
type givenID struct {
	role, name, value string
	used              bool // it filled a route
}

// parseIDs reads -id: NAME is a path parameter (book_title), a JSON field
// that holds such values (basket_id, BasketId) or a route
// (/rest/basket/{id}); ROLE, when given, is the role whose own object
// VALUE names.
func parseIDs(specs []string, roles []role) ([]givenID, error) {
	var out []givenID
	for _, s := range specs {
		left, value, ok := strings.Cut(s, "=")
		left, value = strings.TrimSpace(left), strings.TrimSpace(value)
		if !ok || left == "" || value == "" {
			return nil, usagef("-id %q: want [ROLE:]NAME=VALUE, for example -id 'alice:book_title=My book'", s)
		}
		g := givenID{name: left, value: value}
		if who, name, ok := strings.Cut(left, ":"); ok && !strings.ContainsAny(who, "/{") && !strings.HasPrefix(name, "//") {
			if !slices.ContainsFunc(roles, func(r role) bool { return r.name == who }) {
				return nil, usagef("-id %q: no role is named %s", s, who)
			}
			g.role, g.name = who, strings.TrimSpace(name)
		}
		if g.name == "" {
			return nil, usagef("-id %q: want [ROLE:]NAME=VALUE", s)
		}
		out = append(out, g)
	}
	return out, nil
}

// route is a GET route with path parameters, read for filling.
type route struct {
	template string
	param    string   // the first parameter, without braces
	parent   string   // the route up to that parameter: the list its objects come from
	nouns    []string // the kind of object it names, folded, plural and singular: basketitems, basketitem
	names    []string // field names (folded) that hold values of param and say so
	short    string   // the one of names a session keeps it under: bid for a basket
	rivalled string   // a short name another kind's noun shares (bid for books beside a basket): no one's, its values only tried
}

// genericParams say only that the parameter is an identifier.
var genericParams = map[string]bool{"id": true, "uuid": true, "guid": true, "key": true, "slug": true, "pk": true}

// versionSeg: a path segment that names no kind of object.
var versionSeg = regexp.MustCompile(`^(v\d+(\.\d+)*|api|rest)$`)

func newRoute(t string) (route, bool) {
	phs := placeholder.FindAllString(t, -1)
	if len(phs) == 0 {
		return route{}, false
	}
	r := route{template: t, param: strings.Trim(phs[0], "{}")}
	before := t[:strings.Index(t, phs[0])]
	seg := ""
	if p, err := url.Parse(before); err == nil && strings.HasSuffix(p.Path, "/") && strings.Trim(p.Path, "/") != "" {
		if u, err := normalize.URL(strings.TrimSuffix(before, "/")); err == nil {
			r.parent = u
		}
		path := strings.Trim(p.Path, "/")
		seg = path[strings.LastIndex(path, "/")+1:]
	}
	n := norm(r.param)
	if !genericParams[n] {
		r.names = append(r.names, n)
	}
	if seg != "" && !versionSeg.MatchString(norm(seg)) {
		// /rest/basket/{id}: BasketId; /api/Addresss/{id}: AddressId; and
		// the short name a session keeps it under: bid for a basket, not
		// for a BasketItem.
		var fields []string
		r.nouns, fields, r.short = nounFields(seg, n)
		if r.short != "" {
			fields = append(fields, r.short)
		}
		for _, f := range fields {
			if !slices.Contains(r.names, f) {
				r.names = append(r.names, f)
			}
		}
	}
	return r, true
}

// nounFields reads the kind of object a path segment (BasketItems,
// basket) or a reference field's stem (Basket of BasketId) names: its
// folded forms, plural and singular (basketitems, basketitem), the
// fields that hold identifiers of such objects under the name n
// (basketitemid), and a short name of the initials of its words (biid:
// bid is a basket's). Initials say little of the kind on their own:
// shortNouns says which a short name stands for.
func nounFields(s, n string) (nouns, fields []string, short string) {
	ws := words(s)
	if len(ws) == 0 {
		return nil, nil, ""
	}
	f := strings.Join(ws, "")
	nouns = []string{f}
	add := func(x string) {
		if len(x) > 1 && !slices.Contains(nouns, x) {
			nouns = append(nouns, x)
		}
	}
	switch {
	case strings.HasSuffix(f, "ies"):
		add(strings.TrimSuffix(f, "ies") + "y")
	case strings.HasSuffix(f, "s"):
		add(strings.TrimSuffix(f, "s")) // users, Addresss
		for _, x := range []string{"sses", "xes", "ches", "shes"} {
			if strings.HasSuffix(f, x) {
				add(strings.TrimSuffix(f, "es")) // addresses
			}
		}
	}
	for _, x := range nouns {
		fields = append(fields, x+n)
	}
	if n == "id" && len(f) > 2 {
		for _, w := range ws {
			short += w[:1]
		}
		short += n
	}
	return nouns, fields, short
}

// refWords are the words of the kind a reference field points at: basket
// for BasketId, basket item for basket_item_id; nil for one that names no
// kind in three letters or more (bid, uid).
func refWords(field string) []string {
	ws := words(field)
	n := len(ws)
	switch {
	case n > 1 && ws[n-1] == "id":
		ws = ws[:n-1]
	case n > 0 && strings.HasSuffix(ws[n-1], "id"):
		ws[n-1] = strings.TrimSuffix(ws[n-1], "id") // basketid
	default:
		return nil
	}
	if len(strings.Join(ws, "")) < 3 {
		return nil
	}
	return ws
}

// shortNouns says which noun each short name stands for: bid for basket,
// when basket is a route's noun and no other noun of the routes or of the
// answers' reference fields has those initials. A short name several
// nouns share (books beside a basket, or a BrandId) stands for none and
// maps to "". A noun that runs on from another, read as one word
// (basketitems from basket), is that noun's compound, not a rival. A
// short name only a reference field's noun has is left out: a field
// alone never tells what a session's short name is.
func shortNouns(templates map[string]bool, seen map[string]runSeen) map[string]string {
	rivals := map[string]map[string]bool{} // short name → nouns with those initials
	routed := map[string]bool{}
	add := func(noun, short string) {
		if noun == "" || short == "" {
			return
		}
		if rivals[short] == nil {
			rivals[short] = map[string]bool{}
		}
		rivals[short][noun] = true
	}
	for t := range templates {
		if rt, ok := newRoute(t); ok && rt.short != "" {
			add(rt.noun(), rt.short)
			routed[rt.noun()] = true
		}
	}
	for _, s := range seen {
		for k := range s.ids {
			if ws := refWords(k); ws != nil && refField(norm(k)) {
				nouns, _, short := nounFields(strings.Join(ws, "_"), "id")
				add(nouns[len(nouns)-1], short)
			}
		}
	}
	out := map[string]string{}
	for short, nouns := range rivals {
		var left []string
		for n := range nouns {
			compound := false
			for m := range nouns {
				compound = compound || len(short) == len("bid") && len(m) > 2 && len(m) < len(n) && strings.HasPrefix(n, m)
			}
			if !compound {
				left = append(left, n)
			}
		}
		switch {
		case len(left) > 1:
			out[short] = ""
		case len(left) == 1 && routed[left[0]]:
			out[short] = left[0]
		}
	}
	return out
}

// noun is the route's kind of object, singular.
func (r route) noun() string {
	if len(r.nouns) == 0 {
		return ""
	}
	return r.nouns[len(r.nouns)-1]
}

// apart keeps the route's short name only when it stands for the route's
// noun (shortNouns): bid is the basket's, not basketitems' beside it, nor
// the books' or the basket's when both are routes. One several nouns
// share is kept as rivalled.
func (r *route) apart(shorts map[string]string) {
	if r.short == "" {
		return
	}
	noun, ok := shorts[r.short]
	if ok && noun == r.noun() {
		return
	}
	if ok && noun == "" {
		r.rivalled = r.short
	}
	r.names = slices.DeleteFunc(r.names, func(n string) bool { return n == r.short })
	r.short = ""
}

// about: a list at u holds objects of the route's kind: its own list, or
// one whose last segment names the same kind (/api/me/books for
// /books/v1/{book_title}).
func (r route) about(u string) bool {
	if u == r.parent {
		return true
	}
	p, err := url.Parse(u)
	if err != nil {
		return false
	}
	path := strings.Trim(p.Path, "/")
	seg := path[strings.LastIndex(path, "/")+1:]
	if seg == "" || versionSeg.MatchString(norm(seg)) {
		return false
	}
	nouns, _, _ := nounFields(seg, "")
	return slices.ContainsFunc(nouns, func(n string) bool { return slices.Contains(r.nouns, n) })
}

// path is the route without its scheme and host.
func (r route) path() string {
	return pathOf(r.template)
}

// pathOf is a URL without its scheme and host.
func pathOf(u string) string {
	if p, err := url.Parse(u); err == nil && p.Path != "" {
		return p.Path
	}
	return u
}

// takes: the folded field name holds values of the route's parameter.
func (r route) takes(n string) bool {
	return n == norm(r.param) || slices.Contains(r.names, n)
}

// wants: an -id NAME meant for this route.
func (r route) wants(name string) bool {
	if strings.ContainsAny(name, "/{") {
		if name == r.template {
			return true
		}
		p, err := url.Parse(r.template)
		return err == nil && strings.HasSuffix(p.Path, "/"+strings.TrimPrefix(name, "/"))
	}
	n := norm(strings.Trim(name, "{}"))
	return n == norm(r.param) || slices.Contains(r.names, n)
}

// fill makes the URL of the object v names; other parameters take the
// first value pool holds for them.
func (r route) fill(v string, pool map[string][]string) (string, bool) {
	phs := placeholder.FindAllString(r.template, -1)
	u := strings.Replace(r.template, phs[0], url.PathEscape(v), 1)
	for _, ph := range phs[1:] {
		vs := slices.Clone(valuesFor(strings.Trim(ph, "{}"), pool))
		if len(vs) == 0 {
			return "", false
		}
		sortValues(vs)
		u = strings.Replace(u, ph, url.PathEscape(vs[0]), 1)
	}
	return u, true
}

// Where a candidate value came from.
const (
	fromNamed = 1 << iota // a field the parameter is named after (book_title, BasketId)
	fromList              // the list the route's objects come from (/api/Addresss for /api/Addresss/{id})
	fromAny               // an identifier field of any answer
)

// candidates are the values one role's answers hold for the route's
// parameter.
func (r route) candidates(s runSeen) map[string]int {
	out := map[string]int{}
	for k, vs := range s.ids {
		if slices.Contains(r.names, norm(k)) {
			for _, v := range vs {
				out[v] |= fromNamed
			}
		}
	}
	idLike := genericParams[norm(r.param)] || strings.HasSuffix(strings.ToLower(r.param), "id")
	for k, vs := range s.lists[r.parent] {
		if n := norm(k); n == norm(r.param) || slices.Contains(r.names, n) || idLike && n == "id" {
			for _, v := range vs {
				out[v] |= fromList
			}
		}
	}
	for _, v := range valuesFor(r.param, s.ids) {
		out[v] |= fromAny
	}
	return out
}

// instance is an object URL made by filling a route with a value one of
// the roles' answers held, or one given with -id.
type instance struct {
	template string
	value    string   // the identifier filled in
	holders  []string // the roles whose answers held it
	owner    string   // the role whose own object it is, when that is known
	by       string   // what says it is the owner's
	sure     sureness // how surely by says so
	told     told     // what the object's own answer said of its owner
	given    bool     // given with -id
	rank     int      // replay order: given, a role's own, then the rest
}

// told is what an object's own answer said of whose it is.
type told int

const (
	toldNone     told = iota // nothing, or nothing all its readers agree on
	toldConfirms             // it names the owner what filled the route named
	toldNames                // it names the owner, in place of what filled the route
)

// sureness is how surely what filled a route names the object's owner,
// weakest first.
type sureness int

const (
	shortName sureness = iota - 1 // a short name alone (bid): the object's answer must bear it out
	hinted                        // a list item's fields, or the role's answers alone: the object's answer settles it
	proved                        // an identifier the session holds by its full name, or the role's own list: the answer may not undo it
)

// Objects tried per route: a few of each role's own, a few of the rest.
const (
	perOwner = 5
	perRoute = 6
)

// instances fills each route with identifiers: every value given with
// -id for it, a few of each role's own objects, and a few values more
// than one role saw. Values are taken in order (numbers by value), so the
// same answers give the same URLs.
//
// A value is a role's own when who the role is says so (an identifier its
// session holds under a name of the route's kind, or a list item of that
// kind whose fields name the role), when its list (/api/Addresss for
// /api/Addresss/{id}) held it and the same list read by another role did
// not, or when a field named after the parameter held it and no other
// role's answers held it anywhere. Each says why in the instance's by,
// and how surely in its sure; settleOwners lets the object's answer
// confirm it, or undo what it may. A short name several kinds share
// (bid, with books beside a basket) names no one's object: the session's
// values under it are tried on each such route, as no one's.
func instances(roles []role, templates map[string]bool, seen map[string]runSeen, answers map[string]map[string]answer, given []givenID, who map[string]identity) map[string]instance {
	out := map[string]instance{}
	add := func(u string, in instance) {
		if old, ok := out[u]; ok && old.rank <= in.rank {
			return
		}
		out[u] = in
	}
	held := map[string]map[string]bool{} // role → every value its answers held
	for _, r := range roles {
		set := map[string]bool{}
		for _, vs := range seen[r.name].ids {
			for _, v := range vs {
				set[v] = true
			}
		}
		held[r.name] = set
	}
	lists := map[string]map[string]bool{} // role and URL → every value the answer held
	listed := func(name, u string) map[string]bool {
		k := name + "\x00" + u
		if _, ok := lists[k]; !ok {
			lists[k] = seen[name].listed(u)
		}
		return lists[k]
	}
	// elsewhere: another role's answers hold v (in its list at parent, when
	// parent is given).
	elsewhere := func(owner, v, parent string) bool {
		for _, r := range roles {
			switch {
			case r.name == owner:
			case parent == "" && held[r.name][v], parent != "" && listed(r.name, parent)[v]:
				return true
			}
		}
		return false
	}
	// othersList: another role read the list too.
	othersList := func(owner, parent string) bool {
		for _, r := range roles {
			if a, ok := answers[r.name][parent]; ok && r.name != owner && reads(a) && len(a.Keys) > 0 {
				return true
			}
		}
		return false
	}
	var routes []route
	for _, t := range sortedKeys(templates) {
		if rt, ok := newRoute(t); ok {
			routes = append(routes, rt)
		}
	}
	shorts := shortNouns(templates, seen)
	for _, rt := range routes {
		t := rt.template
		rt.apart(shorts)
		for i := range given {
			g := &given[i]
			if !rt.wants(g.name) {
				continue
			}
			pool := seen[g.role].ids
			if g.role == "" && len(roles) > 0 {
				pool = seen[roles[0].name].ids
			}
			if u, ok := rt.fill(g.value, pool); ok {
				g.used = true
				in := instance{template: t, value: g.value, owner: g.role, given: true}
				if g.role != "" {
					in.holders = []string{g.role}
					in.by = "given with -id " + g.role + ":" + g.name + "=" + g.value
				}
				add(u, in)
			}
		}
		known := ownedBy(rt, roles, who, seen)
		shared := map[string][]string{}
		for _, r := range roles {
			var named, own []string
			by, sure := map[string]string{}, map[string]sureness{}
			for v, c := range known {
				if c.owner == r.name {
					named = append(named, v)
					by[v], sure[v] = c.by, c.sure
				}
			}
			cands := rt.candidates(seen[r.name])
			if rt.rivalled != "" {
				for _, v := range who[r.name].own[rt.rivalled] {
					cands[v] |= fromAny
				}
			}
			for v, from := range cands {
				if known[v].owner != "" {
					continue // whose it is, who the roles are tells
				}
				switch {
				case from&fromList != 0 && othersList(r.name, rt.parent) && !elsewhere(r.name, v, rt.parent):
					own = append(own, v)
					by[v], sure[v] = "in "+r.name+"'s "+pathOf(rt.parent)+" and not the other roles'", proved
				case from&fromNamed != 0 && !elsewhere(r.name, v, ""):
					own = append(own, v)
					by[v] = "in " + r.name + "'s answers alone"
				default:
					shared[v] = append(shared[v], r.name)
				}
			}
			// Those who the role is names first: they are surely its own.
			sortValues(named)
			sortValues(own)
			own = append(named, own...)
			for _, v := range own[:min(len(own), perOwner)] {
				if u, ok := rt.fill(v, seen[r.name].ids); ok {
					add(u, instance{template: t, value: v, holders: []string{r.name}, owner: r.name, by: by[v], sure: sure[v], rank: 1})
				}
			}
		}
		vs := make([]string, 0, len(shared))
		for v := range shared {
			vs = append(vs, v)
		}
		sortValues(vs)
		n := 0
		for _, v := range vs {
			if n == perRoute {
				break
			}
			if u, ok := rt.fill(v, seen[shared[v][0]].ids); ok {
				add(u, instance{template: t, value: v, holders: shared[v], rank: 3})
				n++
			}
		}
	}
	return out
}

// sortValues orders identifiers: numbers by value first, then the rest.
func sortValues(vs []string) {
	sort.SliceStable(vs, func(i, j int) bool {
		a, aErr := strconv.ParseFloat(vs[i], 64)
		b, bErr := strconv.ParseFloat(vs[j], 64)
		switch {
		case aErr == nil && bErr == nil && a != b:
			return a < b
		case aErr == nil && bErr != nil:
			return true
		case aErr != nil && bErr == nil:
			return false
		}
		return vs[i] < vs[j]
	})
}

// valuesFor finds values for a path parameter: a field of the same name,
// else for an id-like name, the id fields.
func valuesFor(name string, pool map[string][]string) []string {
	if vs := pool[name]; len(vs) > 0 {
		return vs
	}
	for k, vs := range pool {
		if strings.EqualFold(k, name) {
			return vs
		}
	}
	if l := strings.ToLower(name); l == "id" || strings.HasSuffix(l, "id") || strings.HasSuffix(l, "_id") {
		return pool["id"]
	}
	return nil
}
