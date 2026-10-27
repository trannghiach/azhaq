package main

import (
	"encoding/base64"
	"encoding/json"
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
// the identifiers of objects its session names (a basket id).
type identity struct {
	who map[string]bool     // alice, alice@x.test, 37
	own map[string][]string // folded field → values: userid → 37, bid → 18
}

func newIdentity() identity {
	return identity{who: map[string]bool{}, own: map[string][]string{}}
}

// names: one of vs names the user.
func (id identity) names(vs []string) bool {
	for _, v := range vs {
		if id.who[v] {
			return true
		}
	}
	return false
}

func (id identity) keep(field, v string) {
	if !slices.Contains(id.own[field], v) && len(id.own[field]) < maxFieldVals {
		id.own[field] = append(id.own[field], v)
	}
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
				id.learn("", "", t, 0)
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
			id.learn("", "", v, 0)
		}
	}
	for i := 0; i+1 < len(s.Storage); i += 2 {
		_, key, _ := strings.Cut(s.Storage[i], ".")
		id.learn("", key, s.Storage[i+1], 0)
	}
}

// learnAnswer reads a role's own "/me" answer: the fields that hold one
// value (a list of users is not who the role is).
func (id identity) learnAnswer(fields map[string][]string) {
	for k, vs := range fields {
		if len(vs) == 1 {
			id.learn("", k, vs[0], 0)
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

// learn reads value x, found under key k in an object named parent.
func (id identity) learn(parent, k string, x any, depth int) {
	if depth > 6 {
		return
	}
	switch t := x.(type) {
	case map[string]any:
		for ck, cv := range t {
			id.learn(k, ck, cv, depth+1)
		}
		return
	case string:
		s := strings.TrimSpace(t)
		if jwtValue.MatchString(s) && depth < 4 {
			if m := claims(jwtValue.FindString(s)); m != nil {
				id.learn("", "", m, depth+1)
			}
			return
		}
		if strings.HasPrefix(s, "{") {
			var m map[string]any
			if json.Unmarshal([]byte(s), &m) == nil {
				id.learn(parent, k, m, depth)
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
	switch {
	case n == "id" && userObjects[norm(parent)]:
		id.who[s] = true
		id.keep("userid", s)
	case n == "id":
		id.keep(norm(parent)+"id", s) // basket: {"id": 18} is a basket id
	case n == "sub" || n == "uid" || n == "userid" || n == "user":
		id.who[s] = true
		id.keep("userid", s)
	case n == "username" || n == "login" || n == "preferredusername" || n == "upn" || n == "nickname":
		id.who[s] = true
		id.keep("username", s)
	case strings.Contains(n, "mail") && strings.Contains(s, "@"):
		id.who[s] = true
		id.keep("email", s)
	case strings.HasSuffix(n, "id") && len(n) > 2 && !noiseIDs[n]:
		id.keep(n, s)
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
// reads unlike the anonymous role.
func identities(roles []role, answers map[string]map[string]answer, seen map[string]runSeen, logins map[string]browser.Session) map[string]identity {
	out := map[string]identity{}
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
			id.learnAnswer(seen[r.name].lists[u])
		}
		out[r.name] = id
	}
	return out
}

// ownedBy are the values of the route's parameter that name a role's own
// object, by who the roles are: an identifier its session holds (bid 18
// for /rest/basket/{id}), or the identifier of a list item whose owner
// field names the role (the book_title of a book whose user is alice). A
// value that names several roles' objects is no one's ("").
func ownedBy(rt route, roles []role, who map[string]identity, seen map[string]runSeen) map[string]string {
	out := map[string]string{}
	claim := func(v, name string) {
		if old, ok := out[v]; ok && old != name {
			name = ""
		}
		out[v] = name
	}
	for _, r := range roles {
		id, ok := who[r.name]
		if !ok {
			continue
		}
		for f, vs := range id.own {
			if rt.takes(f) {
				for _, v := range vs {
					claim(v, r.name)
				}
			}
		}
	}
	generic := genericParams[norm(rt.param)]
	for _, r := range roles {
		s := seen[r.name]
		for _, u := range sortedKeys(mapKeys(s.objects)) {
			for _, o := range s.objects[u] {
				v := ""
				switch {
				case !generic && o.fields[norm(rt.param)] != "":
					v = o.fields[norm(rt.param)]
				case u == rt.parent && o.fields["id"] != "":
					v = o.fields["id"] // /books/v1/{id} from the items of /books/v1
				default:
					for _, n := range rt.names {
						if o.fields[n] != "" {
							v = o.fields[n]
							break
						}
					}
				}
				if v == "" {
					continue
				}
				owner := ""
				for _, c := range roles {
					if id, ok := who[c.name]; ok && id.names(o.owners) {
						if owner != "" {
							owner = "\x00" // two roles: no one's
							break
						}
						owner = c.name
					}
				}
				if owner != "" && owner != "\x00" {
					claim(v, owner)
				}
			}
		}
	}
	return out
}

func mapKeys[V any](m map[string]V) map[string]bool {
	out := make(map[string]bool, len(m))
	for k := range m {
		out[k] = true
	}
	return out
}
