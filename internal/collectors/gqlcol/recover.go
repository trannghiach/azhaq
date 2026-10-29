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

var (
	unknownField = regexp.MustCompile(`^Cannot query field "([^"]+)" on type "([^"]+)"\.?(?:\s*Did you mean (.+?)\?)?\s*$`)
	quotedName   = regexp.MustCompile(`"([A-Za-z_][A-Za-z0-9_]*)"`)
	needsFields  = regexp.MustCompile(`^Field "([^"]+)" of type "([^"]+)" must have a (?:sub selection|selection of subfields)`)
	needsArg     = regexp.MustCompile(`^Field "([^"]+)" argument "([^"]+)" of type "([^"]+)" is required`)
	noFields     = regexp.MustCompile(`^Field "([^"]+)" must not have a selection since type "([^"]+)" has no subfields`)
)

// poison is the field no schema has: it fails every document it is in.
const poison = "azhaqNoSuchField9z"

// maxRecover bounds the documents asked per operation type.
const maxRecover = 24

// rootWords are names root fields often have.
var rootWords = strings.Fields(`
me viewer node nodes user users currentUser account accounts profile profiles admin admins
login logout signin signup register authenticate auth token tokens refreshToken session sessions
createUser updateUser deleteUser editUser removeUser addUser resetPassword changePassword forgotPassword
post posts createPost updatePost deletePost comment comments createComment deleteComment
paste pastes createPaste editPaste deletePaste uploadPaste importPaste
product products order orders cart carts basket item items checkout payment payments invoice invoices
file files upload uploadFile download document documents image images media
search find lookup query list all
setting settings config configuration preferences flags featureFlags
health systemHealth status version info debug systemDiagnostics systemUpdate diagnostics metrics logs auditLogs audit
message messages notification notifications event events task tasks job jobs report reports
organization organizations org orgs team teams group groups member members role roles permission permissions
project projects repository repositories issue issues ticket tickets customer customers employee employees
address addresses card cards wallet wallets transaction transactions transfer transfers
secret secrets key keys apiKey apiKeys webhook webhooks integration integrations
`)

// recoveredType is one operation type's fields as the errors gave them.
type recoveredType struct {
	name   string               // Query, Mutations…, as the server calls it
	fields map[string]*recField // the fields it has
	errors int                  // validation errors read to learn them
}

type recField struct {
	typ  string            // its type, when an error said it
	args map[string]string // its required arguments and their types
}

// recoverType asks for root fields of one operation type ("query",
// "mutation") by name, a batch per document, following the names the
// errors suggest, and gives what the server has; nil when it does not
// answer like a validating GraphQL server.
func (s *Schema) recoverType(ctx context.Context, raw, op string) (*recoveredType, error) {
	rt := &recoveredType{fields: map[string]*recField{}}
	tried := map[string]bool{}
	queue := append([]string(nil), rootWords...)
	sawErrors := false
	for asked := 0; asked < maxRecover && len(queue) > 0; asked++ {
		var batch []string
		for len(queue) > 0 && len(batch) < 60 {
			w := queue[0]
			queue = queue[1:]
			if !tried[w] {
				tried[w] = true
				batch = append(batch, w)
			}
		}
		if len(batch) == 0 {
			break
		}
		_, data, err := s.post(ctx, raw, op+" { "+poison+" "+strings.Join(batch, " ")+" }")
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
					if !tried[sg[1]] {
						queue = append(queue, sg[1]) // asked again for its type
					}
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
			if !unknown[w] {
				rt.field(w)
			}
		}
	}
	if !sawErrors || len(rt.fields) == 0 {
		return nil, nil
	}
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
