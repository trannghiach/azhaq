package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/trannghiach/azhaq/internal/collectors/httpcol"
)

// answer is how an endpoint answered one session.
type answer struct {
	Status    int      `json:"status"`
	Length    int      `json:"length"`
	Hash      string   `json:"hash,omitempty"`
	Keys      []string `json:"keys,omitempty"`      // a JSON answer's field paths: data.user.email, data[].id
	Error     bool     `json:"error,omitempty"`     // a JSON answer shaped like an error: {"status":"error"}, {"error":…}
	Sensitive []string `json:"sensitive,omitempty"` // fields holding passwords, secrets, keys, tokens
	Title     string   `json:"title,omitempty"`
	Location  string   `json:"location,omitempty"` // where a redirect sends the role

	nested  bool            // Keys are nested paths read from the body, not the stored top-level fields
	top     []string        // the top-level fields, as the run stores them
	secrets []secret        // the values of the sensitive fields
	held    map[string]bool // the scalar values of the answer (a few hundred), to see an object's identifier in it
	flags   map[string]bool // paths of list items' fields that only hold true or false (data[].liked)
	self    *listObject     // the object the answer is about: its fields say whose it is
	toLogin bool            // a redirect to a sign-in page
	toRoot  bool            // a redirect to the front page
}

// reads: the role got the endpoint's data, not a refusal shaped as data.
func reads(a answer) bool { return a.Status >= 200 && a.Status < 300 && !a.Error }

// refused: any 4xx, a success status around an error, or a redirect to a
// sign-in page.
func refused(a answer) bool {
	return a.Status >= 400 && a.Status < 500 || a.Status >= 200 && a.Status < 300 && a.Error || a.toLogin
}

// bareLocation is a redirect's target without its query, fragment or
// path parameters: a role's redirect can carry its credentials
// (#access_token=…, ?ticket=ST-…, ;jsessionid=…), and roles prints only
// what tells where the role was sent.
func bareLocation(loc string) string {
	if i := strings.IndexAny(loc, "?#;"); i >= 0 {
		return loc[:i]
	}
	return loc
}

// answerOf summarizes a response the way roles compares them.
func answerOf(status int, body []byte, contentType string) answer {
	a, _ := readAnswer(status, body, contentType)
	return a
}

// readAnswer is answerOf with what a JSON body held (nil for others).
func readAnswer(status int, body []byte, contentType string) (answer, *jsonFacts) {
	sum := sha256.Sum256(body)
	a := answer{Status: status, Length: len(body), Hash: hex.EncodeToString(sum[:8])}
	a.top = httpcol.JSONKeys(body, contentType)
	a.Keys = a.top
	f := inspect(body, contentType)
	if f != nil {
		f.apply(&a)
	} else {
		a.Error = errorKeys(a.top)
	}
	return a, f
}

// storedAnswer is an answer as the run's database has it: no body, the
// top-level fields only.
func storedAnswer(status, length int, hash string, keys []string, title string) answer {
	return answer{Status: status, Length: length, Hash: hash, Keys: keys, top: keys, Title: title, Error: errorKeys(keys)}
}

// jsonFacts is what roles reads in a JSON answer besides its status and
// hash.
type jsonFacts struct {
	paths   []string            // field paths, nested
	isError bool                // shaped like an error
	secrets []secret            // values of fields that hold credentials
	ids     map[string][]string // short scalar values by field name, at any depth: what routes are filled with
	held    map[string]bool     // the first few hundred scalar values
	flags   map[string]bool     // paths under a list whose values are all true or false
	objects []listObject        // the list items that say whose they are
	self    *listObject         // the object the answer is about
}

// listObject is a JSON object's short scalar fields by folded name
// ({"book_title":"b1","user":"alice"}), and its owner and reference
// fields (UserId, BasketId) as the answer spells them.
type listObject struct {
	fields map[string]string
	spell  map[string]string
}

// spelled is a field's name as the answer spells it.
func (o *listObject) spelled(n string) string {
	if s := o.spell[n]; s != "" {
		return s
	}
	return n
}

// secret is one value of a sensitive field.
type secret struct {
	field string // the field's name, as the answer spells it
	token bool   // a session token: the session's own unless another session reads the same value
	sum   string // a hash of the value
}

const (
	maxPaths     = 256  // field paths kept per answer
	maxElems     = 500  // elements read of an array
	maxFieldVals = 1000 // values kept per field
	maxHeld      = 512  // scalar values kept per answer
	maxDepth     = 16
)

// inspect reads a JSON answer: nil when the body is not JSON.
func inspect(body []byte, contentType string) *jsonFacts {
	if !strings.Contains(strings.ToLower(contentType), "json") {
		return nil
	}
	var v any
	if json.Unmarshal(body, &v) != nil {
		return nil
	}
	f := &jsonFacts{ids: map[string][]string{}, held: map[string]bool{}}
	paths := map[string]bool{}
	seen := map[string]bool{} // field and value already kept
	kinds := map[string]int{} // path → 1: a boolean seen, 2: anything else
	var walk func(x any, path string, depth int)
	walk = func(x any, path string, depth int) {
		if depth > maxDepth {
			return
		}
		switch t := x.(type) {
		case map[string]any:
			keys := make([]string, 0, len(t))
			for k := range t {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				p := pathKey(k)
				if path != "" {
					p = path + "." + p
				}
				if len(paths) < maxPaths {
					paths[p] = true
				}
				switch c := t[k].(type) {
				case map[string]any, []any:
					walk(c, p, depth+1)
					kinds[p] |= 2
				case bool:
					kinds[p] |= 1
				default:
					f.scalar(k, c, seen)
					kinds[p] |= 2
				}
			}
			if strings.HasSuffix(path, "[]") && len(f.objects) < maxElems {
				if o, ok := ownedObject(t); ok {
					f.objects = append(f.objects, o)
				}
			}
		case []any:
			for i, e := range t {
				if i == maxElems {
					break
				}
				switch e.(type) {
				case map[string]any, []any:
					walk(e, path+"[]", depth+1)
				default:
					if s, ok := scalarString(e); ok && len(f.held) < maxHeld {
						f.held[s] = true
					}
				}
			}
		}
	}
	walk(v, "", 0)
	if m, ok := selfOf(v); ok {
		o := objectOf(m)
		f.self = &o
	}
	f.paths = sortedKeys(paths)
	f.isError = errorShaped(v)
	for p, k := range kinds {
		if k == 1 && strings.Contains(p, "[]") {
			if f.flags == nil {
				f.flags = map[string]bool{}
			}
			f.flags[p] = true
		}
	}
	return f
}

// ownedObject is a list item that may say whose it is: it has an owner
// field (owner, user, UserId, email, createdBy…) or points at an object
// it belongs to (BasketId).
func ownedObject(m map[string]any) (listObject, bool) {
	o := objectOf(m)
	return o, len(o.spell) > 0
}

// objectOf reads an object's short scalar fields.
func objectOf(m map[string]any) listObject {
	o := listObject{fields: map[string]string{}, spell: map[string]string{}}
	for k, x := range m {
		s, ok := scalarString(x)
		if !ok || len(s) > 64 {
			continue
		}
		n := norm(k)
		o.fields[n] = s
		if ownerField(n) || refField(n) {
			o.spell[n] = k
		}
	}
	return o
}

// selfOf is the object an answer is about: the answer, or the object its
// envelope carries ({"status":"success","data":{…}}).
func selfOf(v any) (map[string]any, bool) {
	m, ok := v.(map[string]any)
	if !ok {
		return nil, false
	}
	for k := range m {
		if !envelope[norm(k)] {
			return m, true
		}
	}
	for _, k := range []string{"data", "result"} {
		if in, ok := m[k].(map[string]any); ok {
			return in, true
		}
	}
	return nil, false
}

// refField: a field (folded) that points at an object of another kind,
// one the object belongs to (BasketId, cartId, accountId), not at its
// user.
func refField(n string) bool {
	return len(n) > 2 && strings.HasSuffix(n, "id") && !ownerField(n) && !noiseIDs[n]
}

// ownerField: a field (folded) that says which user an object is. An
// account, customer or member is not the user: its number can equal a
// user id by chance, so accountId is a reference to an account.
func ownerField(n string) bool {
	switch n {
	case "owner", "ownerid", "ownername", "owneremail", "user", "userid", "username", "useremail", "email", "createdby", "createdbyid",
		"author", "authorid", "authoremail", "creator", "creatorid", "uid", "login", "uploadedby", "postedby", "submittedby":
		return true
	}
	return false
}

// scalar keeps one field's value: as an identifier, as a secret, as a
// value the answer holds.
func (f *jsonFacts) scalar(k string, x any, seen map[string]bool) {
	s, ok := scalarString(x)
	if !ok {
		return
	}
	if len(f.held) < maxHeld {
		f.held[s] = true
	}
	if len(s) <= 64 && !strings.ContainsAny(s, "/?#") && len(f.ids[k]) < maxFieldVals && !seen[k+"\x00"+s] {
		seen[k+"\x00"+s] = true
		f.ids[k] = append(f.ids[k], s)
	}
	if class := sensitiveField(k); class != "" && !masked(s) && !seen["\x01"+k+"\x00"+s] {
		seen["\x01"+k+"\x00"+s] = true
		sum := sha256.Sum256([]byte(s))
		f.secrets = append(f.secrets, secret{field: k, token: class == "token", sum: hex.EncodeToString(sum[:8])})
	}
}

// apply puts what the body held on the answer.
func (f *jsonFacts) apply(a *answer) {
	a.Keys, a.nested = f.paths, true
	a.Error = f.isError
	a.secrets, a.held, a.flags, a.self = f.secrets, f.held, f.flags, f.self
	a.Sensitive = nil
	for _, s := range f.secrets {
		if !slices.Contains(a.Sensitive, s.field) {
			a.Sensitive = append(a.Sensitive, s.field)
		}
	}
	sort.Strings(a.Sensitive)
}

// scalarString is a string or number value as text; "" and other types
// are not values.
func scalarString(x any) (string, bool) {
	switch t := x.(type) {
	case string:
		s := strings.TrimSpace(t)
		return s, s != ""
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64), true
	}
	return "", false
}

// opaqueKey: a field named by data (an id, a hash), not by the schema.
var opaqueKey = regexp.MustCompile(`^(\d+|[0-9a-fA-F-]{16,})$`)

// pathKey is a field's name in a path; fields named by data are one
// field.
func pathKey(k string) string {
	if opaqueKey.MatchString(k) {
		return "*"
	}
	return k
}

// masked: a value replaced by stars, not the secret itself.
func masked(s string) bool {
	return strings.Contains(s, "****") || strings.Contains(s, "••••") || strings.Contains(strings.ToLower(s), "xxxx")
}

// envelope names the fields of an answer about the request rather than
// an object: an object with a status of its own ({"id":5,"status":"failed"})
// is data.
var envelope = map[string]bool{"status": true, "statuscode": true, "httpstatus": true, "code": true, "message": true, "msg": true,
	"messages": true, "data": true, "error": true, "errors": true, "errormessage": true, "errordescription": true, "errorcode": true,
	"detail": true, "details": true, "result": true, "results": true, "success": true, "ok": true, "reason": true, "title": true,
	"type": true, "timestamp": true, "path": true, "instance": true, "requestid": true, "traceid": true, "fault": true,
	"help": true, "documentationurl": true, "moreinfo": true}

// errorShaped: a JSON answer that says it failed, whatever its status:
// {"status":"error"}, {"success":false}, {"status":403}, or an error and
// no data.
func errorShaped(v any) bool {
	m, ok := v.(map[string]any)
	if !ok {
		return false
	}
	for k := range m {
		if !envelope[norm(k)] {
			return false
		}
	}
	for k, x := range m {
		switch n := norm(k); n {
		case "status", "result":
			if s, ok := x.(string); ok && failWord(s) {
				return true
			}
			if v, ok := x.(float64); ok && n == "status" && v >= 400 && v < 600 {
				return true
			}
		case "statuscode", "httpstatus":
			if v, ok := x.(float64); ok && v >= 400 && v < 600 {
				return true
			}
		case "success", "ok":
			if b, ok := x.(bool); ok && !b {
				return true
			}
		case "error", "errors", "errormessage", "fault":
			if truthy(x) && !truthy(m["data"]) && !truthy(m["result"]) && !truthy(m["results"]) {
				return true
			}
		}
	}
	return false
}

func failWord(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "error", "fail", "failed", "failure", "unauthorized", "unauthorised", "forbidden", "denied", "access denied":
		return true
	}
	return false
}

func truthy(x any) bool {
	switch t := x.(type) {
	case nil:
		return false
	case bool:
		return t
	case string:
		return t != ""
	case []any:
		return len(t) > 0
	case map[string]any:
		return len(t) > 0
	}
	return true
}

// errorKeys: the top-level fields of an error ({"error","message"}), for
// an answer whose body roles did not read.
func errorKeys(keys []string) bool {
	isErr := false
	for _, k := range keys {
		n := norm(k)
		switch {
		case n == "error" || n == "errors" || n == "errormessage" || n == "errordescription":
			isErr = true
		case n == "data" || n == "result" || n == "results" || !envelope[n]:
			return false
		}
	}
	return isErr
}

// sensitiveField says whether a field holds a credential or a personal
// secret: "token" for session tokens, "secret" for passwords, keys, card
// numbers and the like, "" for neither. Translation keys
// (LABEL_PASSWORD), settings (passwordLength), labels (forgotPassword)
// and pagination tokens (nextPageToken) are not.
func sensitiveField(k string) string {
	if k == strings.ToUpper(k) && strings.ContainsAny(k, "_-.") {
		return "" // a translation key or a constant
	}
	n := norm(k)
	if n == "" || strings.Contains(n, "csrf") || strings.Contains(n, "xsrf") {
		return ""
	}
	if ws := words(k); len(ws) > 1 {
		switch ws[0] {
		case "label", "placeholder", "hint", "tooltip", "msg", "message", "text", "title", "button", "btn", "link", "error",
			"invalid", "forgot", "confirm", "repeat", "show", "hide", "enter", "new", "change", "has", "is", "require", "min", "max":
			return ""
		}
	}
	suffix := func(xs ...string) bool {
		for _, x := range xs {
			if strings.HasSuffix(n, x) {
				return true
			}
		}
		return false
	}
	switch {
	case n == "pass" || suffix("password", "passwd", "passphrase", "passwordhash", "passwordsalt", "passworddigest", "pwd", "pwdhash", "passhash"):
		return "secret"
	case suffix("secret", "apikey", "privatekey", "secretkey", "accesskey", "signingkey", "encryptionkey", "masterkey"):
		return "secret"
	case n == "ssn" || strings.Contains(n, "socialsecurity"):
		return "secret"
	case suffix("cardnumber", "creditcard", "ccnumber", "ccnum", "cardnum") || n == "cvv" || n == "cvc" || n == "cvv2" || n == "cardcvv" || n == "cardcvc":
		return "secret"
	case n == "otp" || n == "totp" || suffix("otpcode", "recoverycode", "recoverycodes", "backupcode", "backupcodes", "securityanswer"):
		return "secret"
	case suffix("token") || n == "jwt" || n == "sessionid" || n == "sessid":
		for _, x := range []string{"page", "next", "continuation", "cursor", "sync"} {
			if strings.Contains(n, x) {
				return ""
			}
		}
		return "token"
	}
	return ""
}

// words splits a field name into lower-case words: lastPasswordChange
// and last_password_change are last, password, change.
func words(k string) []string {
	var out []string
	var cur []rune
	prev := rune(0)
	for _, r := range k {
		lower, upper, digit := r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9'
		switch {
		case !lower && !upper && !digit:
			if len(cur) > 0 {
				out, cur = append(out, strings.ToLower(string(cur))), nil
			}
		case upper && prev >= 'a' && prev <= 'z' && len(cur) > 0:
			out, cur = append(out, strings.ToLower(string(cur))), []rune{r}
		default:
			cur = append(cur, r)
		}
		prev = r
	}
	if len(cur) > 0 {
		out = append(out, strings.ToLower(string(cur)))
	}
	return out
}

// norm folds a field or parameter name: BasketId, basket_id and basketid
// are one name.
func norm(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// fieldsDiffer: two JSON answers with different fields. Fields under an
// array one of them has empty are not a difference: that is data. Nor is
// a flag only one role's list items carry (data[].liked: true): how the
// list is shown to that role, not what it may read.
func fieldsDiffer(a, b answer) bool {
	if !a.nested || !b.nested {
		x, y := a.top, b.top
		if !a.nested {
			x = a.Keys
		}
		if !b.nested {
			y = b.Keys
		}
		return !slices.Equal(x, y)
	}
	return missing(a.Keys, b.Keys, a.flags) || missing(b.Keys, a.Keys, b.flags)
}

// missing: a path of a that b lacks, under no array b has empty, and not
// one of a's list flags.
func missing(a, b []string, flags map[string]bool) bool {
	has := map[string]bool{}
	for _, p := range b {
		has[p] = true
	}
	for _, p := range a {
		if has[p] || flags[p] || emptyArray(p, b) {
			continue
		}
		return true
	}
	return false
}

// emptyArray: p lies under an array (data[].id) of which b holds no
// element's field.
func emptyArray(p string, b []string) bool {
	for i := strings.Index(p, "[]"); i >= 0; {
		prefix := p[:i+2]
		if !slices.ContainsFunc(b, func(q string) bool { return strings.HasPrefix(q, prefix) }) {
			return true
		}
		j := strings.Index(p[i+2:], "[]")
		if j < 0 {
			break
		}
		i += 2 + j
	}
	return false
}
