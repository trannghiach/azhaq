package gqlcol

import (
	"context"
	"encoding/json"
	"regexp"
	"sort"
	"strings"
)

// Recovering a schema without introspection, as clairvoyance does: a
// server that validates a query names in its errors the fields it has
// ("Did you mean …"), their types ("of type "[UserObject]" must have a
// sub selection") and their required arguments; a field asked for that
// draws no "Cannot query field" is one it has.
//
// Every document asked carries a field no schema has, so it never passes
// validation and nothing in it runs: a mutation asked for by name is
// named, never executed.
//
// Three kinds of word go in the queue: "client", harvested from GraphQL
// operations the map already found in HTML and scripts on the endpoint's
// origin (fetch.CachedOrigin, webextract.GraphQLWords) -- the words most
// likely to be real, since the client code asks for them; "probe", the
// built-in wordlist and -graphql-wordlist, and the derived words their
// and the recovered names' parts recombine into; and "suggestion", a name
// a validation error names outright ("Did you mean pastes?"), which a
// probe word merely triggered.

var (
	unknownField = regexp.MustCompile(`^Cannot query field "([^"]+)" on type "([^"]+)"\.?(?:\s*Did you mean (.+?)\?)?\s*$`)
	quotedName   = regexp.MustCompile(`"([A-Za-z_][A-Za-z0-9_]*)"`)
	needsFields  = regexp.MustCompile(`^Field "([^"]+)" of type "([^"]+)" must have a (?:sub selection|selection of subfields)`)
	needsArg     = regexp.MustCompile(`^Field "([^"]+)" argument "([^"]+)" of type "([^"]+)" is required`)
	noFields     = regexp.MustCompile(`^Field "([^"]+)" must not have a selection since type "([^"]+)" has no subfields`)
)

// poison is the field no schema has: it fails every document it is in.
const poison = "azhaqNoSuchField9z"

// maxRecover bounds the documents asked per operation type, across every
// phase (client words, the wordlist, derived words); batchWords bounds
// the probe words asked in one of them.
const (
	maxRecover = 48
	batchWords = 60
)

// maxDeriveRounds bounds how many times derived words are generated from
// what is known so far and tried: each round a field was found in can
// reveal a neighbour the first round's words did not include.
const maxDeriveRounds = 3

// rootWords are names root fields often have.
var rootWords = strings.Fields(`
me viewer node nodes user users currentUser account accounts profile profiles admin admins
login logout signin signup register authenticate auth token tokens refreshToken session sessions
createUser updateUser deleteUser editUser removeUser addUser resetPassword changePassword forgotPassword
post posts createPost updatePost deletePost comment comments createComment deleteComment
product products order orders cart carts basket item items checkout payment payments invoice invoices
file files upload uploadFile download document documents image images media
search find lookup query list all
setting settings config configuration preferences flags featureFlags
health status version info debug system diagnostics metrics logs auditLogs audit
message messages notification notifications event events task tasks job jobs report reports
organization organizations org orgs team teams group groups member members role roles permission permissions
project projects repository repositories issue issues ticket tickets customer customers employee employees
address addresses card cards wallet wallets transaction transactions transfer transfers
secret secrets key keys apiKey apiKeys webhook webhooks integration integrations
`)

// deriveVerbs and deriveNouns are generic words common across GraphQL
// schemas, recombined with each other and with the parts of names already
// recovered: "paste"/"pastes" known plus "delete" and "all" can name
// "deleteAllPastes", a field neither a plain wordlist nor a suggestion
// (nothing probed is close enough to it) would reach on its own.
var (
	deriveVerbs = strings.Fields(`get list all create update delete remove add edit change
		import export upload download reset find search save send invite accept reject approve run`)
	deriveNouns = strings.Fields(`user users account accounts session sessions token tokens
		post posts comment comments file files order orders item items product products
		message messages notification notifications event events task tasks job jobs report reports
		log logs setting settings system health diagnostics metric metrics audit
		key keys secret secrets role roles permission permissions`)
)

// maxDeriveWords bounds the candidates one derive round returns: the pool
// of parts recombines fast, and most of it is never worth trying.
const maxDeriveWords = 4000

// camelPart splits a camelCase or PascalCase name into lowercase parts:
// "deleteAllPastes" -> delete, all, pastes; "systemHealth" -> system,
// health.
var camelPart = regexp.MustCompile(`[A-Z]+[a-z0-9]*|[a-z0-9]+`)

func camelParts(name string) []string {
	var out []string
	for _, p := range camelPart.FindAllString(name, -1) {
		out = append(out, strings.ToLower(p))
	}
	return out
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// deriveWords makes candidate root field names from the parts of names
// already recovered, the built-in verbs and nouns, and extra (the
// user's -graphql-wordlist), recombined pairwise and with an "All" infix
// (deleteAllPastes, getAllUsers): CRUD conventions a plain wordlist of
// whole names does not spell out.
func deriveWords(known, extra []string) []string {
	pool := map[string]bool{}
	for _, n := range known {
		for _, p := range camelParts(n) {
			pool[p] = true
		}
	}
	for _, w := range deriveVerbs {
		pool[w] = true
	}
	for _, w := range deriveNouns {
		pool[w] = true
	}
	for _, w := range extra {
		pool[strings.ToLower(w)] = true
	}
	parts := make([]string, 0, len(pool))
	for p := range pool {
		parts = append(parts, p)
	}
	sort.Strings(parts)

	seen := map[string]bool{}
	var out []string
	add := func(w string) bool {
		if !seen[w] {
			seen[w] = true
			out = append(out, w)
		}
		return len(out) < maxDeriveWords
	}
outer:
	for _, a := range parts {
		if !add(a) { // the part alone, too: a known type name may be a field
			break outer
		}
		for _, b := range parts {
			if a == b {
				continue
			}
			if !add(a+capitalize(b)) || !add(a+"All"+capitalize(b)) {
				break outer
			}
		}
	}
	return out
}

// queuedWord is one probe word waiting to be asked, and how it was found:
// "client", "probe" (the wordlist or a derived word) or "suggestion"
// (named outright by a validation error, never queued as such -- only
// produced on recField.how).
type queuedWord struct{ word, from string }

// recoveredType is one operation type's fields as the errors gave them.
type recoveredType struct {
	name   string               // Query, Mutations…, as the server calls it
	fields map[string]*recField // the fields it has
	how    map[string]string    // field name -> "client", "probe" or "suggestion"
	errors int                  // validation errors read to learn them
	tried  int                  // probe words asked, every phase together
}

type recField struct {
	typ  string            // its type, when an error said it
	args map[string]string // its required arguments and their types
}

// recoverType asks for root fields of one operation type ("query",
// "mutation") by name, a batch per document, following the names the
// errors suggest, then words derived from what is known, and gives what
// the server has; nil when it does not answer like a validating GraphQL
// server. clientWords are field, argument and type names the map found in
// the endpoint's own HTML and scripts; extra is the user's
// -graphql-wordlist, added to the built-in wordlist and the derive pool;
// seen are the fields recovered for the other root types.
func (s *Schema) recoverType(ctx context.Context, raw, op string, clientWords, extra, seen []string) (*recoveredType, error) {
	rt := &recoveredType{fields: map[string]*recField{}, how: map[string]string{}}
	tried := map[string]bool{}
	queuedOnce := map[string]bool{}
	var queue []queuedWord
	push := func(w, from string) {
		if w == "" || queuedOnce[w] {
			return
		}
		queuedOnce[w] = true
		queue = append(queue, queuedWord{w, from})
	}
	for _, w := range clientWords {
		push(w, "client")
	}
	for _, w := range rootWords {
		push(w, "probe")
	}
	for _, w := range extra {
		push(w, "probe")
	}

	sawErrors := false
	deriveRounds := 0
	for sent := 0; sent < maxRecover; {
		if len(queue) == 0 {
			if deriveRounds >= maxDeriveRounds {
				break
			}
			deriveRounds++
			added := 0
			// Parts of names known anywhere (the other root types, the client's
			// code) name fields here too: pastes in Query, deleteAllPastes in Mutation.
			for _, w := range deriveWords(append(append(rt.names(), seen...), clientWords...), extra) {
				if !queuedOnce[w] {
					push(w, "probe")
					added++
				}
			}
			if added == 0 {
				break
			}
			continue
		}
		var batch []queuedWord
		for len(queue) > 0 && len(batch) < batchWords {
			w := queue[0]
			queue = queue[1:]
			if !tried[w.word] {
				tried[w.word] = true
				batch = append(batch, w)
			}
		}
		if len(batch) == 0 {
			continue
		}
		sent++
		from := make(map[string]string, len(batch))
		words := make([]string, len(batch))
		for i, b := range batch {
			words[i] = b.word
			from[b.word] = b.from
		}
		_, data, err := s.post(ctx, raw, op+" { "+poison+" "+strings.Join(words, " ")+" }")
		if err != nil {
			return nil, err
		}
		var res struct {
			Errors []struct {
				Message string `json:"message"`
			} `json:"errors"`
		}
		if json.Unmarshal(data, &res) != nil || len(res.Errors) == 0 {
			// Not a validating GraphQL answer, or a document with a field no
			// schema has went through: nothing here is to be trusted.
			return nil, nil
		}
		unknown := map[string]bool{}
		rt.errors += len(res.Errors)
		for _, e := range res.Errors {
			m := strings.TrimSpace(e.Message)
			if g := unknownField.FindStringSubmatch(m); g != nil {
				sawErrors = true
				unknown[g[1]] = true
				if g[2] != "" && rt.name == "" && g[1] == poison {
					rt.name = g[2]
				}
				for _, sg := range quotedName.FindAllStringSubmatch(g[3], -1) {
					rt.field(sg[1])
					rt.how[sg[1]] = "suggestion"
					push(sg[1], "probe") // asked again for its type
				}
				continue
			}
			if g := needsFields.FindStringSubmatch(m); g != nil {
				rt.field(g[1]).typ = g[2]
				continue
			}
			if g := noFields.FindStringSubmatch(m); g != nil {
				rt.field(g[1]).typ = g[2]
				continue
			}
			if g := needsArg.FindStringSubmatch(m); g != nil {
				f := rt.field(g[1])
				if f.args == nil {
					f.args = map[string]string{}
				}
				f.args[g[2]] = g[3]
			}
		}
		if !unknown[poison] {
			// The server did not complain of a field no schema has: it does
			// not validate, or says nothing of fields; stop asking.
			return nil, nil
		}
		for _, w := range batch {
			if !unknown[w.word] {
				rt.field(w.word)
				if rt.how[w.word] == "" {
					rt.how[w.word] = from[w.word]
				}
			}
		}
	}
	if !sawErrors || len(rt.fields) == 0 {
		return nil, nil
	}
	rt.tried = len(tried)
	return rt, nil
}

func (rt *recoveredType) field(name string) *recField {
	f := rt.fields[name]
	if f == nil {
		f = &recField{}
		rt.fields[name] = f
	}
	return f
}

// names are the type's fields, sorted.
func (rt *recoveredType) names() []string {
	out := make([]string, 0, len(rt.fields))
	for n := range rt.fields {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// signatures are the fields as SDL says them, with what is known:
// uploadPaste(content: String!, filename: String!): UploadPaste.
func (rt *recoveredType) signatures() []string {
	var out []string
	for _, n := range rt.names() {
		f := rt.fields[n]
		sig := n
		if len(f.args) > 0 {
			var args []string
			for a, t := range f.args {
				args = append(args, a+": "+t)
			}
			sort.Strings(args)
			sig += "(" + strings.Join(args, ", ") + ")"
		}
		if f.typ != "" {
			sig += ": " + f.typ
		}
		out = append(out, sig)
	}
	return out
}

// counts is the number of fields found each way: client, probe or
// suggestion.
func (rt *recoveredType) counts() map[string]int {
	c := map[string]int{}
	for name := range rt.fields {
		c[rt.how[name]]++
	}
	return c
}

// typeNames are the object types the errors named, without list and
// non-null marks.
func typeNames(rts ...*recoveredType) []string {
	seen := map[string]bool{}
	for _, rt := range rts {
		if rt == nil {
			continue
		}
		for _, f := range rt.fields {
			if t := strings.Trim(f.typ, "[]!"); t != "" {
				seen[t] = true
			}
		}
	}
	out := make([]string, 0, len(seen))
	for t := range seen {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}
