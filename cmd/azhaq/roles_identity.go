package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/trannghiach/azhaq/internal/browser"
)

// Who each role is, so that its own objects are known without -id: the
// claims of the tokens its session carries, its "/me" answers, and, for a
// role that signed in with Chrome, what the login answered and left in
// the browser's storage.

// identity is what tells one role apart: the values naming the user, and
// the identifiers of objects its session names (a basket id), with where
// the session holds each.
type identity struct {
	who   map[string]bool     // alice, alice@x.test, 37
	own   map[string][]string // folded field → values: userid → 37, bid → 18
	from  map[string]origin   // folded field and value → where it was read
	kinds map[string]string   // short name → the noun the routes say it stands for: bid → basket (shortNouns)
}

// origin is where a role's identifier was read: the field as spelled
// (data.id, authentication.bid) in a token's claims, a login answer, the
// browser's storage or a "/me" answer.
type origin struct {
	key, where string
	claim      bool
}

func newIdentity() identity {
	return identity{who: map[string]bool{}, own: map[string][]string{}, from: map[string]origin{}}
}

func (id identity) keep(field, v string) {
	if !slices.Contains(id.own[field], v) && len(id.own[field]) < maxFieldVals {
		id.own[field] = append(id.own[field], v)
	}
}

// note keeps v under field, read at o.
func (id identity) note(field, v string, o origin) {
	id.keep(field, v)
	if _, ok := id.from[field+"\x00"+v]; !ok && id.from != nil {
		id.from[field+"\x00"+v] = o
	}
}

// source says where role name's session holds v under field: "bid claim
// of alice's token", "authentication.bid in alice's login answer".
func (id identity) source(name, field, v string) string {
	o, ok := id.from[field+"\x00"+v]
	if !ok {
		return field + " of " + name + "'s session"
	}
	if o.claim {
		return o.key + " claim of " + name + "'s " + o.where
	}
	return o.key + " in " + name + "'s " + o.where
}

// whence is source for a value that names the user, under any field.
func (id identity) whence(name, v string) string {
	for _, f := range sortedKeys(mapKeys(id.own)) {
		if slices.Contains(id.own[f], v) {
			return id.source(name, f, v)
		}
	}
	return name + "'s session"
}

// userFields hold the values that name the user.
var userFields = []string{"userid", "username", "email"}

// userKey is the one of userFields a field (folded) naming the user is
// kept under: sub, uid and user are userid, login is username, a mail
// field holding an address is email; "" for others (owner, createdBy).
func userKey(n, v string) string {
	switch {
	case n == "sub" || n == "uid" || n == "userid" || n == "user":
		return "userid"
	case n == "username" || n == "login" || n == "preferredusername" || n == "upn" || n == "nickname":
		return "username"
	case strings.Contains(n, "mail") && strings.Contains(v, "@"):
		return "email"
	}
	return ""
}

// kind are the values the session holds of the kind field (as spelled)
// points at, each with the field it was kept under: the user's, for an
// owner field (UserId, owner, email); for a reference field, those of the
// kind it names in full (basketId and basket_id for BasketId, not
// BookId), and those under a short name the routes say stands for that
// kind (bid, when basket is the only noun with its initials).
func (id identity) kind(field string, owner bool) map[string]string {
	out := map[string]string{}
	keys := userFields
	if !owner {
		ws := refWords(field)
		if ws == nil {
			return out
		}
		var nouns []string
		nouns, keys, _ = nounFields(strings.Join(ws, "_"), "id")
		for _, k := range sortedKeys(mapKeys(id.kinds)) {
			if slices.Contains(nouns, id.kinds[k]) {
				keys = append(keys, k)
			}
		}
	}
	for _, k := range keys {
		for _, v := range id.own[k] {
			if _, ok := out[v]; !ok {
				out[v] = k
			}
		}
	}
	return out
}

// idShape is the form of an identifier, for telling one of the same kind
// apart: an email, a number, a UUID or a hash; "" for names, which are
// spelled too many ways to tell apart.
func idShape(v string) string {
	switch {
	case strings.Contains(v, "@"):
		return "email"
	case strings.Trim(v, "0123456789") == "":
		return "number"
	case opaqueKey.MatchString(v):
		return "opaque"
	}
	return ""
}

var jwtValue = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*`)

// claims are the claims of a JSON Web Token, or nil.
func claims(token string) map[string]any {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return nil
	}
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return nil
	}
	return m
}

// learnHeaders reads the tokens a role's requests carry: in an
// Authorization header, a cookie, any header.
func (id identity) learnHeaders(h http.Header) {
	for _, vs := range h {
		for _, v := range vs {
			for _, t := range jwtValue.FindAllString(v, 4) {
				id.learn(origin{}, "", "", t, 0)
			}
		}
	}
}

// learnSession reads what a Chrome login left: the JSON answers of the
// requests the form sent, and each storage entry (bid → 18, token → a
// JSON Web Token, user → {"id":…}).
func (id identity) learnSession(s browser.Session) {
	for _, body := range s.Answers {
		var v any
		if json.Unmarshal(body, &v) == nil {
			id.learn(origin{where: "login answer"}, "", "", v, 0)
		}
	}
	for i := 0; i+1 < len(s.Storage); i += 2 {
		store, key, _ := strings.Cut(s.Storage[i], ".")
		id.learn(origin{where: store}, "", key, s.Storage[i+1], 0)
	}
}

// learnAnswer reads a role's own "/me" answer at u: the fields that hold
// one value (a list of users is not who the role is).
func (id identity) learnAnswer(u string, fields map[string][]string) {
	for _, k := range sortedKeys(mapKeys(fields)) {
		if vs := fields[k]; len(vs) == 1 {
			id.learn(origin{where: pathOf(u) + " answer"}, "", k, vs[0], 0)
		}
	}
}

// userObjects name objects that stand for the user: their id is the
// user's.
// A session or authentication object's id is the session's, often the
// credential itself: never an identifier to fill routes with or print.
var userObjects = map[string]bool{"": true, "data": true, "user": true, "me": true, "profile": true, "account": true, "identity": true,
	"claims": true, "currentuser": true, "principal": true, "payload": true, "result": true}

// credentialObjects hold a session rather than describe the user.
var credentialObjects = map[string]bool{"session": true, "sessions": true, "authentication": true, "auth": true, "token": true,
	"tokens": true, "credentials": true, "credential": true, "oauth": true}

// noiseIDs are identifier fields that name no object of the user's.
var noiseIDs = map[string]bool{"requestid": true, "traceid": true, "correlationid": true, "clientid": true, "appid": true,
	"sessionid": true, "sid": true, "jti": true, "kid": true, "deviceid": true, "messageid": true, "roleid": true, "groupid": true}

// learn reads value x, found under key k in an object named parent, at o.
func (id identity) learn(o origin, parent, k string, x any, depth int) {
	if depth > 6 {
		return
	}
	switch t := x.(type) {
	case map[string]any:
		for _, ck := range sortedKeys(mapKeys(t)) {
			id.learn(o, k, ck, t[ck], depth+1)
		}
		return
	case string:
		s := strings.TrimSpace(t)
		if jwtValue.MatchString(s) && depth < 4 {
			if m := claims(jwtValue.FindString(s)); m != nil {
				in := origin{where: "token", claim: true}
				if o.where != "" {
					in.where = "token in " + o.where
				}
				id.learn(in, "", "", m, depth+1)
			}
			return
		}
		if strings.HasPrefix(s, "{") {
			var m map[string]any
			if json.Unmarshal([]byte(s), &m) == nil {
				id.learn(o, parent, k, m, depth)
			}
			return
		}
	}
	s, ok := scalarString(x)
	if !ok || len(s) > 64 || strings.ContainsAny(s, "/?# ") || s == "0.0.0.0" || sensitiveField(k) != "" {
		return
	}
	n := norm(k)
	if credentialObjects[norm(parent)] && (n == "id" || n == "key" || n == "value" || n == "secret") {
		return // a session's id is its credential, not a record of the user's
	}
	o.key = k
	if parent != "" {
		o.key = parent + "." + k
	}
	switch {
	case n == "id" && userObjects[norm(parent)]:
		id.who[s] = true
		id.note("userid", s, o)
		if norm(parent) == "account" {
			id.note("accountid", s, o) // what an accountId points at
		}
	case n == "id":
		id.note(norm(parent)+"id", s, o) // basket: {"id": 18} is a basket id
	case userKey(n, s) != "":
		id.who[s] = true
		id.note(userKey(n, s), s, o)
	case strings.HasSuffix(n, "id") && len(n) > 2 && !noiseIDs[n]:
		id.note(n, s, o)
	}
}

// meLike: an endpoint that answers who the session is: /me, /whoami,
// /users/current, /userinfo.
func meLike(u string) bool {
	p, err := url.Parse(u)
	if err != nil {
		return false
	}
	path := strings.TrimRight(strings.ToLower(p.Path), "/")
	switch norm(path[strings.LastIndex(path, "/")+1:]) {
	case "me", "whoami", "self", "myself", "current", "currentuser", "userinfo", "profile", "account", "myaccount", "authme":
		return true // not /session or /auth: what they answer is the session, its id the credential
	}
	return false
}

// identities are who each signed-in role is: the tokens its session
// carries, what its Chrome login left (logins), and the "/me" answers it
// reads unlike the anonymous role; and what kind of object the short
// names its session keeps stand for, by the routes the runs found.
func identities(roles []role, answers map[string]map[string]answer, seen map[string]runSeen, logins map[string]browser.Session) map[string]identity {
	out := map[string]identity{}
	templates := map[string]bool{}
	for _, s := range seen {
		for t := range s.templates {
			templates[t] = true
		}
	}
	shorts := shortNouns(templates, seen)
	anon := ""
	for _, r := range roles {
		if r.anonymous() {
			anon = r.name
			break
		}
	}
	for _, r := range roles {
		if r.anonymous() {
			continue
		}
		id := newIdentity()
		id.kinds = shorts
		id.learnHeaders(r.session)
		if s, ok := logins[r.name]; ok {
			id.learnSession(s)
		}
		urls := make([]string, 0, len(answers[r.name]))
		for u := range answers[r.name] {
			urls = append(urls, u)
		}
		sort.Strings(urls)
		for _, u := range urls {
			a := answers[r.name][u]
			if !meLike(u) || !reads(a) {
				continue
			}
			if b, ok := answers[anon][u]; anon != "" && ok && reads(b) && b.Hash == a.Hash {
				continue // what everyone gets is no one's identity
			}
			id.learnAnswer(u, seen[r.name].lists[u])
		}
		out[r.name] = id
	}
	return out
}

// ownership is whose object an identifier names, what says so, and how
// surely.
type ownership struct {
	owner, by string
	sure      sureness
}

// ownedBy are the values of the route's parameter that name a role's own
// object, by who the roles are, with what says so. Only an identifier of
// the route's kind of object counts: one the role's session holds under a
// name of that kind (basketId, or bid for /rest/basket/{id}, not for
// /api/BasketItems/{id}), or one of a list item of that kind whose own
// fields name the role (a book whose user is alice, a BasketItem of
// alice's basket). An item of another kind lends its owner only to the
// object its owner or reference field points at (the UserId of an
// address: the user), not to the others it names (a basket item's
// ProductId). A value that names several roles' objects is no one's. A
// short name (bid) is a guess the object's answer must bear out.
func ownedBy(rt route, roles []role, who map[string]identity, seen map[string]runSeen) map[string]ownership {
	out := map[string]ownership{}
	claim := func(v, name, by string, sure sureness) {
		if old, ok := out[v]; ok {
			switch {
			case old.owner != name:
				out[v] = ownership{}
			case sure == proved && old.sure != proved:
				out[v] = ownership{name, by, sure} // its full name after a short one: orderid after oid
			}
			return
		}
		out[v] = ownership{name, by, sure}
	}
	for _, r := range roles {
		id, ok := who[r.name]
		if !ok {
			continue
		}
		for _, f := range sortedKeys(mapKeys(id.own)) {
			if !rt.takes(f) {
				continue
			}
			sure := proved
			if f == rt.short {
				sure = shortName
			}
			for _, v := range id.own[f] {
				claim(v, r.name, id.source(r.name, f, v)+" → "+rt.path(), sure)
			}
		}
	}
	generic := genericParams[norm(rt.param)]
	for _, r := range roles {
		s := seen[r.name]
		for _, u := range sortedKeys(mapKeys(s.objects)) {
			kind := rt.about(u)
			for i := range s.objects[u] {
				o := &s.objects[u][i]
				v, field := "", ""
				switch {
				case !generic && o.fields[norm(rt.param)] != "":
					v, field = o.fields[norm(rt.param)], norm(rt.param)
				case kind && o.fields["id"] != "":
					v, field = o.fields["id"], "id" // /books/v1/{id} from the items of /books/v1
				default:
					for _, n := range rt.names {
						if o.fields[n] != "" {
							v, field = o.fields[n], n
							break
						}
					}
				}
				if v == "" {
					continue
				}
				// The field holding v is the item's own key (book_title
				// in an item without an id), or the item is of another
				// kind and v one it points at.
				only := field
				if kind || !ownerField(field) && !refField(field) && o.fields["id"] == "" {
					only = ""
				}
				if owner, why, _, _ := whose(o, roles, who, "", only); owner != "" {
					claim(v, owner, "item of "+pathOf(u)+": "+why, hinted)
				}
			}
		}
	}
	return out
}

// whose says whose object o is by its own fields (only that one, when
// only is set): an owner field that names a role (UserId 29, owner alice,
// email), or a field that points at an object a role's session names
// (BasketId 8: alice's basket, by her bid). For claimed, a field whose
// value is not that role's, while the role's session holds values of the
// same kind and shape, says the object is someone else's. known: the
// fields told; owner is "" when they name several roles or no role.
// strong: a field names the owner by an identifier its session holds
// under the field's own name (holds).
func whose(o *listObject, roles []role, who map[string]identity, claimed, only string) (owner, by string, known, strong bool) {
	if o == nil {
		return "", "", false, false
	}
	named := map[string]string{}
	sure := map[string]bool{}
	against := ""
	for _, n := range sortedKeys(mapKeys(o.fields)) {
		isOwner := ownerField(n)
		if only != "" && n != only || !isOwner && !refField(n) {
			continue
		}
		v, f := o.fields[n], o.spelled(n)
		for _, r := range roles {
			id, ok := who[r.name]
			if !ok || sure[r.name] {
				continue
			}
			if why, s := id.holds(r.name, f, v, isOwner); why != "" {
				if named[r.name] == "" || s {
					named[r.name], sure[r.name] = why, s
				}
			} else if r.name == claimed && against == "" && named[r.name] == "" {
				against = id.denies(r.name, f, v, isOwner)
			}
		}
	}
	switch {
	case len(named) == 1:
		for name, why := range named {
			return name, why, true, sure[name]
		}
	case len(named) > 1:
		return "", "", true, false
	case against != "":
		return "", against, true, false
	}
	return "", "", false, false
}

// holds says why v, in field (as spelled), is the role's: in an owner
// field, it names the user; in a reference field, the session names that
// object. "" when it is not. strong: the session holds v under the
// field's own name (UserId: its user id; email: its email; BasketId: its
// basketId, not its bid), not merely some identifier of the user's that
// a number of another kind can equal.
func (id identity) holds(name, field, v string, owner bool) (why string, strong bool) {
	if owner {
		for _, x := range []string{v, strings.ToLower(v)} {
			if id.who[x] {
				k := userKey(norm(field), x)
				return fmt.Sprintf("%s %s names %s (%s)", field, v, name, id.whence(name, x)), k != "" && slices.Contains(id.own[k], x)
			}
		}
		return "", false
	}
	if k, ok := id.kind(field, false)[v]; ok {
		_, short := id.kinds[k]
		return fmt.Sprintf("%s %s is %s's %s (%s)", field, v, name, nounWords(field), id.source(name, k, v)), !short
	}
	return "", false
}

// denies says why v, in field, is not the role's: its session holds
// values of that kind and shape, and v is none of them. "" when that
// cannot be told.
func (id identity) denies(name, field, v string, owner bool) string {
	sh := idShape(v)
	if sh == "" {
		return ""
	}
	var mine []string
	for x := range id.kind(field, owner) {
		if idShape(x) == sh {
			if strings.EqualFold(x, v) {
				return ""
			}
			mine = append(mine, x)
		}
	}
	if len(mine) == 0 {
		return ""
	}
	sortValues(mine)
	mine = mine[:min(len(mine), 3)]
	if owner {
		return fmt.Sprintf("%s %s does not name %s (%s)", field, v, name, strings.Join(mine, ", "))
	}
	return fmt.Sprintf("%s %s is not %s's %s (%s)", field, v, name, nounWords(field), strings.Join(mine, ", "))
}

// nounWords is the kind of object a reference field points at, in words:
// basket for BasketId, basket item for basket_item_id.
func nounWords(field string) string {
	if ws := refWords(field); ws != nil {
		return strings.Join(ws, " ")
	}
	return "object"
}

// settleOwners lets each object's own answer say whose it is (UserId,
// owner, BasketId), as far as what filled its route allows: BasketItem 8
// of basket 5 is not alice's though her basket is 8. The answers of every
// role that reads it must agree. An answer may confirm the owner or name
// one. It may undo an owner a list item or the answers alone told, and
// must bear out one a short name alone told (bid), or that owner goes.
// One proved (an identifier the session holds by its full name, the
// role's own list) it never clears, and hands to another role only by an
// identifier that role's session holds under the field's own name (its
// email, its user id as UserId; not an accountId that equals it): a user
// in two organisations, an account number like a user id. An object given
// with -id stays the role's it was given as; an answer that names that role
// confirms it.
func settleOwners(roles []role, made map[string]instance, answers map[string]map[string]answer, who map[string]identity) {
	for _, u := range sortedKeys(mapKeys(made)) {
		in := made[u]
		owner, by, known, strong, n := "", "", false, false, 0
		agree := true
		for _, r := range roles {
			a, ok := answers[r.name][u]
			if !ok || !reads(a) || a.self == nil {
				continue
			}
			o, b, k, s := whose(a.self, roles, who, in.owner, "")
			if n > 0 && (o != owner || k != known) {
				agree = false
			}
			if n == 0 {
				owner, by, known, strong = o, b, k, s
			}
			n++
		}
		told := n > 0 && agree && known
		if in.given {
			if told && owner != "" && owner == in.owner {
				in.by += "; the answer's " + by
				in.told = toldConfirms
				made[u] = in
			}
			continue
		}
		switch {
		case told && owner != "" && owner == in.owner:
			if in.by != "" {
				in.by += "; "
			}
			in.by += "the answer's " + by
			in.told = toldConfirms
		case told && owner != "" && (in.owner == "" || in.sure != proved || strong):
			in.owner, in.by, in.told = owner, "the answer's "+by, toldNames
		case in.owner != "" && in.sure == shortName:
			in.owner, in.by = "", "" // a guess the answer does not bear out
		case told && owner == "" && in.sure == hinted:
			in.owner, in.by = "", ""
		default:
			continue
		}
		made[u] = in
	}
}

func mapKeys[V any](m map[string]V) map[string]bool {
	out := make(map[string]bool, len(m))
	for k := range m {
		out[k] = true
	}
	return out
}
