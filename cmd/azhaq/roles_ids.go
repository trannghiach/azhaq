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
	templates map[string]bool
	kept      map[string]bool // what ids and lists hold already
}

func newRunSeen() runSeen {
	return runSeen{ids: map[string][]string{}, lists: map[string]map[string][]string{}, templates: map[string]bool{}, kept: map[string]bool{}}
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
	names    []string // field names (folded) that hold values of param and say so
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
		seg = norm(path[strings.LastIndex(path, "/")+1:])
	}
	n := norm(r.param)
	if !genericParams[n] {
		r.names = append(r.names, n)
	}
	if seg != "" && !versionSeg.MatchString(seg) {
		// /rest/basket/{id}: BasketId; /api/Addresss/{id}: AddressId.
		for _, s := range []string{seg, strings.TrimSuffix(seg, "s"), strings.TrimSuffix(seg, "ies") + "y"} {
			if len(s) > 1 && !slices.Contains(r.names, s+n) {
				r.names = append(r.names, s+n)
			}
		}
	}
	return r, true
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
	given    bool     // given with -id
	rank     int      // replay order: given, a role's own, then the rest
}

// Objects tried per route: a few of each role's own, a few of the rest.
const (
	perOwner = 3
	perRoute = 3
)

// instances fills each route with identifiers: every value given with
// -id for it, a few values each role's answers alone held (the role's own
// objects), and a few values more than one role saw. Values are taken in
// order (numbers by value), so the same answers give the same URLs.
//
// A value is a role's own when its list (/api/Addresss for
// /api/Addresss/{id}) held it and the same list read by another role did
// not, or when a field named after the parameter held it and no other
// role's answers held it anywhere.
func instances(roles []role, templates map[string]bool, seen map[string]runSeen, answers map[string]map[string]answer, given []givenID) map[string]instance {
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
	for _, t := range sortedKeys(templates) {
		rt, ok := newRoute(t)
		if !ok {
			continue
		}
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
				}
				add(u, in)
			}
		}
		shared := map[string][]string{}
		for _, r := range roles {
			var own []string
			for v, from := range rt.candidates(seen[r.name]) {
				switch {
				case from&fromList != 0 && othersList(r.name, rt.parent) && !elsewhere(r.name, v, rt.parent),
					from&fromNamed != 0 && !elsewhere(r.name, v, ""):
					own = append(own, v)
				default:
					shared[v] = append(shared[v], r.name)
				}
			}
			sortValues(own)
			for _, v := range own[:min(len(own), perOwner)] {
				if u, ok := rt.fill(v, seen[r.name].ids); ok {
					add(u, instance{template: t, value: v, holders: []string{r.name}, owner: r.name, rank: 1})
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
