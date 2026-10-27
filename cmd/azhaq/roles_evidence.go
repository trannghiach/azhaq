package main

import (
	"bytes"
	"compress/gzip"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/trannghiach/azhaq/internal/fetch"
	"github.com/trannghiach/azhaq/internal/normalize"
	"github.com/trannghiach/azhaq/internal/webextract"
	"github.com/trannghiach/azhaq/store"
)

// Evidence: the answers behind the rows roles lists, kept in roles.db in
// -dir with the request that got each (its session as placeholders), and
// azhaq roles show, which prints one row's answers side by side.

const (
	maxKeptBody  = 256 << 10 // of each body, kept
	maxKeptTotal = 128 << 20 // of all bodies, gzipped, held until the listed rows are known
	evidenceFile = "roles.db"
)

// Confidence that a row's object is its owner's.
const (
	confProved = "proved" // what filled the route (the session, the owner's own list, -id) and the object's answer both say so
	confLikely = "likely" // one of them says so
	confGuess  = "guess"  // initials, or the owner's answers alone
)

// bodyKeep holds the bodies of the answers by hash, gzipped and cut, until
// the listed rows are known. Bodies the same for several roles are kept
// once.
type bodyKeep struct {
	mu   sync.Mutex
	m    map[string]keptBody
	size int
}

type keptBody struct {
	gz    []byte
	ctype string
	cut   bool
}

// bodies is where roles keeps bodies while it runs; nil keeps none.
var bodies *bodyKeep

func newBodyKeep() *bodyKeep { return &bodyKeep{m: map[string]keptBody{}} }

// keepBody keeps body under hash, the hash of the whole body.
func keepBody(hash, ctype string, body []byte) {
	k := bodies
	if k == nil || hash == "" {
		return
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if _, ok := k.m[hash]; ok || k.size >= maxKeptTotal {
		return
	}
	cut := len(body) > maxKeptBody
	if cut {
		body = body[:maxKeptBody]
	}
	var buf bytes.Buffer
	w, _ := gzip.NewWriterLevel(&buf, gzip.BestSpeed)
	_, _ = w.Write(body)
	_ = w.Close()
	k.m[hash] = keptBody{gz: buf.Bytes(), ctype: ctype, cut: cut}
	k.size += buf.Len()
}

// keptBodyOf is the body kept under hash.
func keptBodyOf(hash string) (body []byte, ctype string, cut, ok bool) {
	k := bodies
	if k == nil || hash == "" {
		return nil, "", false, false
	}
	k.mu.Lock()
	kb, ok := k.m[hash]
	k.mu.Unlock()
	if !ok {
		return nil, "", false, false
	}
	r, err := gzip.NewReader(bytes.NewReader(kb.gz))
	if err != nil {
		return nil, "", false, false
	}
	defer r.Close()
	body, err = io.ReadAll(r)
	return body, kb.ctype, kb.cut, err == nil
}

// keepRunBodies keeps the bodies a role's run got, from the process cache
// the run filled: nothing is sent.
func keepRunBodies(got map[string]answer, raw map[string]string) {
	if bodies == nil {
		return
	}
	for u, a := range got {
		if c := webextract.ClassifyURL(u); a.Hash == "" || c == "asset" || c == "script" {
			continue
		}
		res, ok := fetch.Cached(raw[u])
		if !ok {
			continue
		}
		if sum := sha256.Sum256(res.Body); hex.EncodeToString(sum[:8]) == a.Hash {
			keepBody(a.Hash, contentType(res), res.Body)
		}
	}
}

// redactor takes out of a kept body what must not be kept: the values of
// sensitive fields, JSON Web Tokens, and every value a role sent (its
// headers, cookies, the credential after Bearer). Each is replaced by a
// tag keyed for this run alone, so two answers holding the same secret
// still show the same tag, and the tag tells nothing of the secret.
type redactor struct {
	key  []byte
	sent []string // longest first
}

func newRedactor(roles []role) *redactor {
	rd := &redactor{key: make([]byte, 32)}
	_, _ = rand.Read(rd.key)
	seen := map[string]bool{}
	for _, r := range roles {
		h := r.session
		if h == nil {
			h = headerOf(r.headers)
		}
		for k, vs := range h {
			if plainHeader(k) {
				continue
			}
			for _, v := range vs {
				parts := []string{v}
				for _, p := range strings.FieldsFunc(v, func(r rune) bool { return r == ';' || r == ' ' || r == ',' }) {
					if _, val, ok := strings.Cut(p, "="); ok {
						p = val
					}
					parts = append(parts, p)
				}
				for _, p := range parts {
					if len(p) >= 6 && !seen[p] {
						seen[p] = true
						rd.sent = append(rd.sent, p)
					}
				}
			}
		}
	}
	slices.SortFunc(rd.sent, func(a, b string) int { return len(b) - len(a) })
	return rd
}

func (rd *redactor) tag(v string) string {
	m := hmac.New(sha256.New, rd.key)
	m.Write([]byte(v))
	return "[redacted " + hex.EncodeToString(m.Sum(nil))[:8] + "]"
}

var (
	shellVar     = regexp.MustCompile(`\$([A-Z0-9_]+)`)
	jsonPair     = regexp.MustCompile(`"((?:[^"\\]|\\.){1,64})"\s*:\s*("(?:[^"\\]|\\.)*"|-?\d[\d.eE+-]*)`)
	jsonPairOpen = regexp.MustCompile(`"((?:[^"\\]|\\.){1,64})"\s*:\s*"(?:[^"\\]|\\.)*$`)
)

// body is a kept body, its secrets taken out.
func (rd *redactor) body(b []byte) []byte {
	s := jsonPair.ReplaceAllStringFunc(string(b), func(m string) string {
		sub := jsonPair.FindStringSubmatch(m)
		v := strings.Trim(sub[2], `"`)
		if sensitiveField(sub[1]) == "" || v == "" || masked(v) {
			return m
		}
		return m[:len(m)-len(sub[2])] + `"` + rd.tag(v) + `"`
	})
	// A secret the cut left open at the end.
	if loc := jsonPairOpen.FindStringSubmatchIndex(s); loc != nil && sensitiveField(s[loc[2]:loc[3]]) != "" {
		s = s[:loc[3]+1] + `: "` + rd.tag(s[loc[3]:]) + `"`
	}
	s = jwtValue.ReplaceAllStringFunc(s, rd.tag)
	for _, v := range rd.sent {
		if strings.Contains(s, v) {
			s = strings.ReplaceAll(s, v, rd.tag(v))
		}
	}
	return []byte(s)
}

// plainHeader: a header that says how to answer, not who asks.
func plainHeader(k string) bool {
	switch http.CanonicalHeaderKey(k) {
	case "Accept", "Accept-Language", "User-Agent", "Content-Type", "X-Requested-With":
		return true
	}
	return false
}

// envName is the shell variable a role's credential is given in:
// ALICE_TOKEN.
func envName(roleName, what string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(roleName + "_" + what) {
		if r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	s := b.String()
	if s[0] >= '0' && s[0] <= '9' {
		s = "ROLE_" + s
	}
	return s
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// curlLine is the request as curl sends it, with the role's session as
// shell variables (-H "Authorization: Bearer $ALICE_TOKEN", -b
// "$BOB_COOKIE"), never its values. vars are the variables it names.
func curlLine(method, u string, r role, ctype string, body []byte) (line string, vars []string) {
	parts := []string{"curl -sS -i"}
	if method != "" && method != http.MethodGet {
		parts = append(parts, "-X "+method)
	}
	parts = append(parts, shellQuote(u))
	h := r.session
	if h == nil {
		h = headerOf(r.headers)
	}
	for _, k := range sortedKeys(mapKeys(h)) {
		v := h.Get(k)
		switch ck := http.CanonicalHeaderKey(k); {
		case v == "":
		case plainHeader(ck):
			if ck != "User-Agent" && ck != "Accept" {
				parts = append(parts, "-H "+shellQuote(ck+": "+v))
			}
		case ck == "Cookie":
			name := envName(r.name, "COOKIE")
			vars = append(vars, name)
			parts = append(parts, `-b "$`+name+`"`)
		case ck == "Authorization":
			scheme, _, ok := strings.Cut(v, " ")
			what := "AUTHORIZATION"
			switch strings.ToLower(scheme) {
			case "bearer":
				what = "TOKEN"
			case "basic":
				what = "BASIC"
			}
			name := envName(r.name, what)
			vars = append(vars, name)
			if ok && what != "AUTHORIZATION" {
				parts = append(parts, `-H "Authorization: `+scheme+` $`+name+`"`)
			} else {
				parts = append(parts, `-H "Authorization: $`+name+`"`)
			}
		default:
			name := envName(r.name, ck)
			vars = append(vars, name)
			parts = append(parts, `-H "`+ck+`: $`+name+`"`)
		}
	}
	if body != nil || method == http.MethodPut || method == http.MethodPatch || method == http.MethodPost {
		if ctype != "" {
			parts = append(parts, "-H "+shellQuote("Content-Type: "+ctype))
		}
		parts = append(parts, "--data-raw "+shellQuote(string(body)))
	}
	return strings.Join(parts, " "), vars
}

// explain fills the evidence and confidence of each row that says a role
// reads or writes another role's object.
func explain(rows []roleRow, made map[string]instance, roles []role, who map[string]identity) {
	for i := range rows {
		row := &rows[i]
		switch row.Verdict {
		case verdictCross, verdictAnyID:
			in := made[row.URL]
			row.Confidence = confidenceOf(in)
			row.Evidence = readEvidence(*row)
			if row.Verdict == verdictAnyID {
				row.Confidence = confGuess
			}
		case verdictWriteCross, verdictWriteAnyone:
			if in, ok := made[row.URL]; ok && in.owner == row.Owner {
				row.Confidence = confidenceOf(in)
			} else {
				row.Confidence = harConfidence(*row, roles, who)
			}
			row.Evidence = writeEvidence(*row)
		}
	}
}

// confidenceOf says how surely an object is its owner's: what filled its
// route said so from the owner's session (an identifier it holds, its
// initials, a list item naming the owner by it), the owner's own list or
// -id; and the object's own answer confirms it.
func confidenceOf(in instance) string {
	filled := in.given || in.sure == proved || in.sure == shortName || strings.HasPrefix(in.by, "item of ")
	if in.told == toldNames {
		filled = false // the answer named the owner; what filled the route did not
	}
	switch {
	case filled && in.told == toldConfirms:
		return confProved
	case filled && in.sure != shortName, in.told != toldNone:
		return confLikely
	}
	return confGuess
}

// harConfidence: a write from the owner's HAR is likely the owner's own
// object's when its body or URL names an object of the owner's session
// (its BasketId, its user id); else a guess, as many writes are anyone's
// to send (a review, a feedback).
func harConfidence(row roleRow, roles []role, who map[string]identity) string {
	var v any
	if json.Unmarshal(row.reqBody, &v) == nil {
		if m, ok := v.(map[string]any); ok {
			o := objectOf(m)
			if owner, _, _, _ := whose(&o, roles, who, "", ""); owner == row.Owner {
				return confLikely
			}
		}
	}
	return confGuess
}

// readEvidence says in one line why a cross read is one: who got what the
// owner got, what says whose it is, and the control.
func readEvidence(row roleRow) string {
	oa := row.Answers[row.Owner]
	same := true
	for _, n := range row.Readers {
		same = same && row.Answers[n].Hash == oa.Hash
	}
	how := fmt.Sprintf("the same body, %s", size(oa.Length))
	if !same {
		how = "the same fields around " + row.value
	}
	who := strings.Join(row.Readers, " and ")
	parts := []string{fmt.Sprintf("%s got %s's answer (%s)", who, row.Owner, how)}
	if row.OwnerBy != "" {
		parts = append(parts, shortBy(row.OwnerBy))
	}
	if c := row.Control; c != nil {
		var ns []string
		for _, n := range row.Readers {
			if a, ok := c.Answers[n]; ok {
				ns = append(ns, fmt.Sprintf("%d", a.Status))
			}
		}
		switch {
		case len(c.Alike) > 0:
			parts = append(parts, fmt.Sprintf("a made-up %s got %s alike (%s): the route answers any identifier", c.Value, strings.Join(c.Alike, " and "), strings.Join(ns, ", ")))
		case len(ns) > 0:
			parts = append(parts, fmt.Sprintf("a made-up %s got %s", c.Value, strings.Join(dedupe(ns), ", ")))
		}
	}
	if len(row.mutual) > 0 {
		parts = append(parts, "both ways: "+row.Owner+" reads "+strings.Join(row.mutual, " and ")+"'s too")
	}
	return strings.Join(parts, "; ")
}

func dedupe(xs []string) []string {
	var out []string
	for _, x := range xs {
		if !slices.Contains(out, x) {
			out = append(out, x)
		}
	}
	return out
}

// writeEvidence says in one line who was let to write the owner's object.
func writeEvidence(row roleRow) string {
	var let []string
	for _, n := range row.Readers {
		let = append(let, fmt.Sprintf("%s %d", n, row.Answers[n].Status))
	}
	s := fmt.Sprintf("%s let (%s)", strings.Join(row.Readers, " and "), strings.Join(let, ", "))
	if a, ok := row.Answers[row.Owner]; ok && a.Status != 0 {
		s += fmt.Sprintf(" as %s was (%d)", row.Owner, a.Status)
	}
	return s + "; " + row.OwnerBy
}

// saveEvidence writes the listed rows and every answer behind them to
// roles.db in dir: each body as kept (cut at 256 KB, secrets taken out),
// and the request as curl sends it.
func saveEvidence(dir string, roles []role, rows []roleRow) error {
	ev, err := store.OpenEvidence(filepath.Join(dir, evidenceFile))
	if err != nil {
		return err
	}
	defer ev.Close()
	rd := newRedactor(roles)
	var out []store.EvidenceRow
	names := make([]string, len(roles))
	for i, r := range roles {
		names[i] = r.name
	}
	for _, row := range rows {
		raw, err := json.Marshal(row)
		if err != nil {
			return err
		}
		er := store.EvidenceRow{URL: row.URL, Method: row.Method, Row: raw}
		reqBody := row.reqBody
		if reqBody != nil {
			reqBody = rd.body(reqBody)
		}
		add := func(r role, kind, asked string, a answer) {
			line, _ := curlLine(row.Method, asked, r, row.reqType, reqBody)
			ea := store.EvidenceAnswer{Role: r.name, Kind: kind, Asked: asked, Status: a.Status, Curl: line}
			if b, ctype, cut, ok := keptBodyOf(a.Hash); ok {
				ea.Body, ea.ContentType, ea.Truncated = rd.body(b), ctype, cut
			}
			er.Answers = append(er.Answers, ea)
		}
		for _, r := range roles {
			if a, ok := row.Answers[r.name]; ok && a.Status != 0 {
				add(r, "answer", row.URL, a)
			}
		}
		if c := row.Control; c != nil {
			for _, r := range roles {
				if a, ok := c.Answers[r.name]; ok {
					add(r, "control", c.URL, a)
				}
			}
		}
		out = append(out, er)
	}
	return ev.Save(names, out)
}

// cmdRolesShow prints one row a roles run listed: per role, its status,
// how its answer differs from the owner's field by field, and the request
// as curl sends it with the role's session as a shell variable.
//
//	azhaq roles show -dir azhaq-roles-… https://app/rest/basket/6
func cmdRolesShow(args []string) error {
	fs := newFlags("roles show")
	dir := fs.String("dir", "", "the -dir of the roles run (it holds "+evidenceFile+")")
	method := fs.String("method", "", "the method of a write row (-replay-writes); a read's row by default")
	asJSON := fs.Bool("json", false, "one JSON object: the row, and each answer with its curl line and its differences")
	bodyOf := fs.String("body", "", "print the answer ROLE got, as kept (secrets taken out), and nothing else")
	if err := parse(fs, args); err != nil {
		return err
	}
	if *dir == "" || fs.NArg() != 1 {
		return usagef("usage: azhaq roles show -dir DIR URL [-method M]")
	}
	ev, err := store.OpenEvidenceExisting(filepath.Join(*dir, evidenceFile))
	if err != nil {
		return usagef("%v: give the -dir of a roles run", err)
	}
	defer ev.Close()
	m := strings.ToUpper(*method)
	if m == http.MethodGet {
		m = ""
	}
	u := fs.Arg(0)
	er, ok, err := ev.Row(u, m)
	if err == nil && !ok {
		if n, nerr := normalize.URL(u); nerr == nil && n != u {
			u = n
			er, ok, err = ev.Row(u, m)
		}
	}
	if err != nil {
		return err
	}
	if !ok {
		keys, _ := ev.Keys()
		var near []string
		for _, k := range keys {
			if strings.Contains(k, pathOf(u)) || len(near) < 5 && len(keys) <= 5 {
				near = append(near, k)
			}
		}
		verb := m
		if verb == "" {
			verb = http.MethodGet
		}
		msg := fmt.Sprintf("no row for %s %s in %s", verb, u, filepath.Join(*dir, evidenceFile))
		if len(near) > 0 {
			msg += "; it holds " + strings.Join(near[:min(len(near), 10)], ", ")
		}
		return exitErr{code: exitError, msg: msg}
	}
	var row roleRow
	_ = json.Unmarshal(er.Row, &row)
	if *bodyOf != "" {
		for _, a := range er.Answers {
			if a.Role == *bodyOf && a.Kind == "answer" {
				_, err := os.Stdout.Write(a.Body)
				return err
			}
		}
		return exitErr{code: exitError, msg: fmt.Sprintf("no answer of %s kept for %s", *bodyOf, u)}
	}
	order := ev.Roles()
	sortAnswers(er.Answers, order)
	base := baseAnswer(row, er.Answers)
	type shown struct {
		Role        string     `json:"role"`
		Kind        string     `json:"kind"`
		Asked       string     `json:"url"`
		Status      int        `json:"status"`
		Length      int        `json:"length"`
		ContentType string     `json:"content_type,omitempty"`
		Truncated   bool       `json:"truncated,omitempty"`
		Curl        string     `json:"curl"`
		SameAs      string     `json:"same_as,omitempty"`
		Against     string     `json:"against,omitempty"`
		Diff        []diffLine `json:"diff,omitempty"`
		More        int        `json:"diff_more,omitempty"`
	}
	var list []shown
	var vars []string
	for _, a := range er.Answers {
		s := shown{Role: a.Role, Kind: a.Kind, Asked: a.Asked, Status: a.Status, Length: len(a.Body), ContentType: a.ContentType, Truncated: a.Truncated, Curl: a.Curl}
		for _, v := range shellVar.FindAllStringSubmatch(a.Curl, -1) {
			if !slices.Contains(vars, v[1]) {
				vars = append(vars, v[1])
			}
		}
		if base != nil && (a.Role != base.Role || a.Kind != base.Kind) && a.Body != nil {
			if bytes.Equal(a.Body, base.Body) {
				s.SameAs = base.Role
			} else {
				s.Against = base.Role
				s.Diff, s.More = jsonDiff(base.Body, a.Body, 20)
			}
		}
		list = append(list, s)
	}
	if *asJSON {
		return json.NewEncoder(os.Stdout).Encode(struct {
			URL     string          `json:"url"`
			Method  string          `json:"method,omitempty"`
			Row     json.RawMessage `json:"row"`
			Answers []shown         `json:"answers"`
			Vars    []string        `json:"vars,omitempty"`
		}{er.URL, er.Method, er.Row, list, vars})
	}
	verb := er.Method
	if verb == "" {
		verb = http.MethodGet
	}
	fmt.Printf("%s %s\n  [%s]", verb, er.URL, row.label())
	if row.Confidence != "" {
		fmt.Printf(" %s", row.Confidence)
	}
	fmt.Println()
	if row.Evidence != "" {
		fmt.Printf("  evidence: %s\n", row.Evidence)
	}
	if row.OwnerBy != "" {
		fmt.Printf("  owner_by: %s\n", row.OwnerBy)
	}
	if row.SessionSuspect {
		fmt.Println("  session_suspect: an answer was asked after its role's session last proved alive")
	}
	for _, s := range list {
		fmt.Println()
		who := s.Role
		switch {
		case s.Kind == "control":
			who += " (made-up identifier)"
		case s.Role == row.Owner:
			who += " (owner)"
		}
		info := []string{fmt.Sprintf("%d", s.Status)}
		if s.Kind == "answer" {
			info = append(info, size(s.Length))
		}
		if s.ContentType != "" {
			info = append(info, s.ContentType)
		}
		if s.Truncated {
			info = append(info, "cut at 256 KB")
		}
		if s.Length == 0 && s.Kind == "answer" && s.Status != 0 {
			info = append(info, "body not kept")
		}
		fmt.Printf("%s  %s\n", who, strings.Join(info, "  "))
		fmt.Printf("  %s\n", s.Curl)
		switch {
		case s.SameAs != "":
			fmt.Printf("  the same body as %s's\n", s.SameAs)
		case s.Against != "" && len(s.Diff) == 0 && s.More == 0:
			fmt.Printf("  not JSON both: the body differs from %s's\n", s.Against)
		case s.Against != "":
			fmt.Printf("  against %s's:\n", s.Against)
			for _, d := range s.Diff {
				fmt.Printf("    %s\n", d)
			}
			if s.More > 0 {
				fmt.Printf("    … %d more\n", s.More)
			}
		}
	}
	if len(vars) > 0 {
		fmt.Printf("\nset %s to the sessions the roles sent (roles keeps none of them)\n", strings.Join(vars, ", "))
	}
	return nil
}

// sortAnswers puts the answers in the roles' order, the controls last.
func sortAnswers(as []store.EvidenceAnswer, order []string) {
	idx := func(n string) int {
		if i := slices.Index(order, n); i >= 0 {
			return i
		}
		return len(order)
	}
	sort.SliceStable(as, func(i, j int) bool {
		if as[i].Kind != as[j].Kind {
			return as[i].Kind == "answer"
		}
		return idx(as[i].Role) < idx(as[j].Role)
	})
}

// baseAnswer is what the other answers are compared with: the owner's,
// else the first role's that reads it.
func baseAnswer(row roleRow, as []store.EvidenceAnswer) *store.EvidenceAnswer {
	for i := range as {
		if as[i].Kind == "answer" && as[i].Role == row.Owner && as[i].Body != nil {
			return &as[i]
		}
	}
	for i := range as {
		if as[i].Kind == "answer" && ok2xx(as[i].Status) && as[i].Body != nil {
			return &as[i]
		}
	}
	return nil
}

// diffLine is one field that differs: in the base only (-), in the other
// only (+), or with another value (~).
type diffLine struct {
	Op    string `json:"op"`
	Path  string `json:"path"`
	Base  string `json:"base,omitempty"`
	Other string `json:"other,omitempty"`
}

func (d diffLine) String() string {
	switch d.Op {
	case "-":
		return "- " + d.Path + "  " + d.Base
	case "+":
		return "+ " + d.Path + "  " + d.Other
	}
	return "~ " + d.Path + "  " + d.Base + " → " + d.Other
}

// jsonDiff compares two JSON bodies field by field: at most limit lines,
// and how many more. Nil when either is not JSON.
func jsonDiff(base, other []byte, limit int) ([]diffLine, int) {
	var a, b any
	if json.Unmarshal(base, &a) != nil || json.Unmarshal(other, &b) != nil {
		return nil, 0
	}
	fa, fb := map[string]string{}, map[string]string{}
	flatten(a, "", fa)
	flatten(b, "", fb)
	keys := mapKeys(fa)
	for k := range fb {
		keys[k] = true
	}
	var out []diffLine
	more := 0
	for _, k := range sortedKeys(keys) {
		x, inA := fa[k]
		y, inB := fb[k]
		var d diffLine
		switch {
		case inA && !inB:
			d = diffLine{Op: "-", Path: k, Base: x}
		case inB && !inA:
			d = diffLine{Op: "+", Path: k, Other: y}
		case x != y:
			d = diffLine{Op: "~", Path: k, Base: x, Other: y}
		default:
			continue
		}
		if len(out) == limit {
			more++
			continue
		}
		out = append(out, d)
	}
	return out, more
}

// flatten puts each leaf of a JSON value under its path: data.items[0].id.
func flatten(v any, path string, out map[string]string) {
	if len(out) > 20000 {
		return
	}
	switch t := v.(type) {
	case map[string]any:
		if len(t) == 0 {
			out[path] = "{}"
		}
		for _, k := range sortedKeys(mapKeys(t)) {
			p := k
			if path != "" {
				p = path + "." + k
			}
			flatten(t[k], p, out)
		}
	case []any:
		if len(t) == 0 {
			out[path] = "[]"
		}
		for i, e := range t {
			flatten(e, fmt.Sprintf("%s[%d]", path, i), out)
		}
	default:
		raw, _ := json.Marshal(t)
		s := string(raw)
		if len(s) > 80 {
			s = s[:77] + "…"
		}
		out[path] = s
	}
}
