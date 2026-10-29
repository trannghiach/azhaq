package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/trannghiach/azhaq/internal/normalize"
	"github.com/trannghiach/azhaq/store"
)

// azhaq report: each finding azhaq roles listed, written up from the
// evidence it kept in roles.db. Nothing is asked of the target and nothing
// is said that the row or its answers do not hold: what is missing is
// named in the report.

// Classes of a report, by the verdict of the row.
const (
	classRead     = "bola_read"
	classWrite    = "bola_write"
	classExposure = "excessive_data_exposure"
)

// classOf is the bug class a verdict is, and its name; empty for a verdict
// report writes nothing for.
func classOf(verdict string) (class, label string) {
	switch verdict {
	case verdictCross:
		return classRead, "Broken object level authorization"
	case verdictWriteCross, verdictWriteAnyone:
		return classWrite, "Broken object level authorization (write)"
	case verdictWriteUnread:
		return classWrite, "Broken object level authorization (write accepted, not read back)"
	case verdictAnyoneSecrets:
		return classExposure, "Excessive data exposure"
	}
	return "", ""
}

type reportDoc struct {
	Title       string        `json:"title"`
	Class       string        `json:"class"`
	Method      string        `json:"method"`
	URL         string        `json:"url"`
	Route       string        `json:"route"`
	Verdict     string        `json:"verdict"`
	Confidence  string        `json:"confidence"` // "unrated" for a row roles gives none
	Summary     string        `json:"summary"`
	Severity    reportSeverty `json:"severity_guess"`
	Variables   []string      `json:"variables,omitempty"` // the session values the curl lines name
	Steps       []reportStep  `json:"steps"`
	Evidence    []reportAns   `json:"evidence"`
	OwnerReason string        `json:"owner_reason"` // the row's owner_by, as kept
	Impact      string        `json:"impact"`
	Remediation string        `json:"remediation"`
	Notes       reportNotes   `json:"notes"`
	Missing     []string      `json:"missing,omitempty"` // what the evidence store does not hold for this report
}

type reportSeverty struct {
	Level  string `json:"level"`
	Reason string `json:"reason"`
}

type reportStep struct {
	N      int    `json:"n"`
	Text   string `json:"text"`
	Curl   string `json:"curl,omitempty"`
	Expect string `json:"expect,omitempty"`
}

type reportAns struct {
	Role        string        `json:"role"`
	Kind        string        `json:"kind"` // owner, reader, other, control
	Request     string        `json:"request"`
	Status      int           `json:"status"`
	Length      int           `json:"length"`
	ContentType string        `json:"content_type,omitempty"`
	BodyKept    bool          `json:"body_kept"`
	Truncated   bool          `json:"truncated,omitempty"`
	SameAs      string        `json:"same_as,omitempty"`
	Fields      []reportField `json:"fields,omitempty"`
	FieldsMore  int           `json:"fields_more,omitempty"`
	Text        string        `json:"text,omitempty"` // a body that is not JSON: its start
}

type reportField struct {
	Path  string `json:"path"`
	Value string `json:"value"`
}

type reportNotes struct {
	Confidence     string   `json:"confidence"`
	ConfidenceWhy  string   `json:"confidence_why,omitempty"`
	BothWays       bool     `json:"both_ways"`
	FoundBy        []string `json:"found_by,omitempty"`
	Run            string   `json:"run"`
	SessionSuspect bool     `json:"session_suspect,omitempty"`
	Redacted       bool     `json:"redacted,omitempty"`
}

// cmdReport writes up the findings a roles run listed:
//
//	azhaq report -dir azhaq-roles-… [-url URL [-method M]] [-format md|json] [-o FILE] [-redact]
func cmdReport(args []string) error {
	fs := newFlags("report")
	dir := fs.String("dir", "", "the -dir of the roles run (it holds "+evidenceFile+")")
	target := fs.String("url", "", "write up this one row (its URL as roles lists it); every cross-role finding by default")
	method := fs.String("method", "", "the method of a write row (-replay-writes); a read's row by default")
	format := fs.String("format", "md", "md or json")
	out := fs.String("o", "", "FILE for the reports (one file, or a directory with a report per file); without -url, DIR/reports; with -url, standard output")
	redact := fs.Bool("redact", false, "also mask hosts and identifiers (a report to share outside the engagement)")
	if err := parse(fs, args); err != nil {
		return err
	}
	if *dir == "" || fs.NArg() != 0 {
		return usagef("usage: azhaq report -dir DIR [-url URL] [-method M] [-format md|json] [-o FILE] [-redact]")
	}
	if *format != "md" && *format != "json" {
		return usagef("-format is md or json, not %q", *format)
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

	var rows []store.EvidenceRow
	if *target != "" {
		er, ok, err := loadEvidenceRow(ev, *target, m)
		if err != nil {
			return err
		}
		if !ok {
			return exitErr{code: exitError, msg: fmt.Sprintf("no row for %s in %s", *target, filepath.Join(*dir, evidenceFile))}
		}
		var row roleRow
		if err := json.Unmarshal(er.Row, &row); err != nil {
			return err
		}
		if c, _ := classOf(row.Verdict); c == "" {
			return exitErr{code: exitError, msg: fmt.Sprintf("%s is [%s]: report writes up a role reading or writing another role's object, or sensitive fields anyone reads", *target, row.Verdict)}
		}
		rows = append(rows, er)
	} else {
		keys, err := ev.Keys()
		if err != nil {
			return err
		}
		for _, k := range keys {
			verb, u, _ := strings.Cut(k, " ")
			if verb == http.MethodGet {
				verb = ""
			}
			er, ok, err := ev.Row(u, verb)
			if err != nil || !ok {
				continue
			}
			var row roleRow
			if json.Unmarshal(er.Row, &row) == nil {
				if c, _ := classOf(row.Verdict); c != "" {
					rows = append(rows, er)
				}
			}
		}
	}
	order := ev.Roles()
	saved, savedOK := ev.SavedAt()
	docs := make([]reportDoc, 0, len(rows))
	for _, er := range rows {
		d, err := buildReport(er, order, saved, savedOK, *redact)
		if err != nil {
			return err
		}
		docs = append(docs, d)
	}
	sortReports(docs)
	if len(docs) == 0 {
		fmt.Fprintf(os.Stderr, "azhaq report: no row in %s is a role reading or writing another role's object, or sensitive fields anyone reads\n", filepath.Join(*dir, evidenceFile))
		return nil
	}
	return emitReports(docs, *format, *out, *dir, *target != "")
}

// loadEvidenceRow reads one row as roles show does: by its URL, or by the
// URL normalized.
func loadEvidenceRow(ev *store.Evidence, u, method string) (store.EvidenceRow, bool, error) {
	er, ok, err := ev.Row(u, method)
	if err == nil && !ok {
		if n, nerr := normalize.URL(u); nerr == nil && n != u {
			er, ok, err = ev.Row(n, method)
		}
	}
	return er, ok, err
}

var confRank = map[string]int{confProved: 0, confLikely: 1, confGuess: 2}

// sortReports: proved first, then likely, guess, and the rows roles gives
// no confidence last; within one, by verdict and URL.
func sortReports(ds []reportDoc) {
	rank := func(c string) int {
		if r, ok := confRank[c]; ok {
			return r
		}
		return len(confRank)
	}
	sort.SliceStable(ds, func(i, j int) bool {
		a, b := ds[i], ds[j]
		if ra, rb := rank(a.Confidence), rank(b.Confidence); ra != rb {
			return ra < rb
		}
		if va, vb := verdictOrder[a.Verdict], verdictOrder[b.Verdict]; va != vb {
			return va < vb
		}
		return a.URL+" "+a.Method < b.URL+" "+b.Method
	})
}

// emitReports writes the reports where -o says and lists them. One report
// with -url goes to standard output, the list to standard error.
func emitReports(docs []reportDoc, format, out, dir string, single bool) error {
	render := func(d reportDoc) ([]byte, error) {
		if format == "json" {
			var b bytes.Buffer
			enc := json.NewEncoder(&b)
			enc.SetEscapeHTML(false)
			enc.SetIndent("", "  ")
			err := enc.Encode(d)
			return b.Bytes(), err
		}
		return []byte(d.markdown()), nil
	}
	ext := map[string]string{"md": ".md", "json": ".json"}[format]
	list := func(path string, d reportDoc) {
		fmt.Printf("  %s  [%s] %s\n", path, d.Confidence, d.Title)
	}
	asDir := out != "" && (strings.HasSuffix(out, "/") || isDir(out))
	switch {
	case out == "" && single:
		b, err := render(docs[0])
		if err != nil {
			return err
		}
		_, err = os.Stdout.Write(b)
		return err
	case out != "" && !asDir:
		var all [][]byte
		for _, d := range docs {
			b, err := render(d)
			if err != nil {
				return err
			}
			all = append(all, b)
		}
		sep := "\n---\n\n"
		if format == "json" {
			sep = ""
		}
		body := bytes.Join(all, []byte(sep))
		if format == "json" && !single {
			body = []byte("[" + strings.Join(splitJSONLines(all), ",") + "]\n")
		}
		if err := os.WriteFile(out, body, 0o644); err != nil {
			return err
		}
		fmt.Printf("azhaq report: %s in %s\n", plural(len(docs), "report"), out)
		for _, d := range docs {
			list(out, d)
		}
		return nil
	}
	to := out
	if to == "" {
		to = filepath.Join(dir, "reports")
	}
	if err := os.MkdirAll(to, 0o755); err != nil {
		return err
	}
	fmt.Printf("azhaq report: %s in %s\n", plural(len(docs), "report"), to)
	for i, d := range docs {
		b, err := render(d)
		if err != nil {
			return err
		}
		p := filepath.Join(to, fmt.Sprintf("%02d-%s-%s%s", i+1, d.Confidence, reportSlug(d), ext))
		if err := os.WriteFile(p, b, 0o644); err != nil {
			return err
		}
		list(p, d)
	}
	return nil
}

func isDir(p string) bool { st, err := os.Stat(p); return err == nil && st.IsDir() }

func splitJSONLines(all [][]byte) []string {
	out := make([]string, len(all))
	for i, b := range all {
		out[i] = strings.TrimSpace(string(b))
	}
	return out
}

var slugCut = regexp.MustCompile(`[^a-z0-9]+`)

// reportSlug names a report's file by its method and route, never by the
// identifier of the object.
func reportSlug(d reportDoc) string {
	s := strings.Trim(slugCut.ReplaceAllString(strings.ToLower(d.Method+" "+d.Route), "-"), "-")
	if len(s) > 60 {
		s = strings.Trim(s[:60], "-")
	}
	return s
}

// ---- building a report

var (
	rptVersionSeg = regexp.MustCompile(`^(v\d+|api)$`)
	rptIDSeg      = regexp.MustCompile(`(?i)^(\d+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{16,})$`)
	idKeyWords    = []string{"username", "user", "owner", "email", "login", "slug", "handle", "account", "sub", "uuid", "guid"}
)

// idField: a field name that holds an identifier of a person or an object.
func idField(k string, params map[string]bool) bool {
	n := strings.ToLower(strings.Map(func(r rune) rune {
		if r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, k))
	return n != "" && (params[n] || n == "id" || strings.HasSuffix(n, "id") || slices.Contains(idKeyWords, n))
}

// masker takes hosts and identifiers out of what a report says. Off, it
// changes nothing.
type masker struct {
	on     bool
	hosts  map[string]string // host, and host:port → its placeholder
	ph     map[string]string // identifier → placeholder
	order  []string          // identifiers, in the order met
	roles  map[string]bool   // role names stay: they are the reader's own labels
	params map[string]bool   // path parameter names, normalized
}

func newMasker(on bool, roles []string) *masker {
	m := &masker{on: on, hosts: map[string]string{}, ph: map[string]string{}, roles: map[string]bool{}, params: map[string]bool{}}
	for _, r := range roles {
		m.roles[r] = true
	}
	return m
}

func (m *masker) addHost(u string) {
	p, err := url.Parse(u)
	if err != nil || p.Host == "" {
		return
	}
	if _, ok := m.hosts[p.Host]; ok {
		return
	}
	ph := "<host>"
	if n := len(distinctValues(m.hosts)); n > 0 {
		ph = fmt.Sprintf("<host-%d>", n+1)
	}
	if v, ok := m.hosts[p.Hostname()]; ok {
		ph = v // the same name on another port
	}
	m.hosts[p.Host] = ph
	m.hosts[p.Hostname()] = ph
}

func distinctValues(m map[string]string) map[string]bool {
	out := map[string]bool{}
	for _, v := range m {
		out[v] = true
	}
	return out
}

func (m *masker) addID(v string) {
	if v == "" || m.roles[v] {
		return
	}
	if _, ok := m.ph[v]; !ok {
		m.ph[v] = fmt.Sprintf("<id-%d>", len(m.order)+1)
		m.order = append(m.order, v)
	}
}

// textID: an identifier safe to look for in running text (a short number
// would hit every other number).
func textID(v string) bool {
	if _, err := strconv.Atoi(v); err == nil {
		return len(v) >= 4
	}
	return len(v) >= 2
}

// collect takes the identifiers of a JSON body: the values of the fields
// that name a person or an object.
func (m *masker) collect(body []byte) {
	var v any
	if json.Unmarshal(body, &v) != nil {
		return
	}
	var walk func(any)
	walk = func(v any) {
		switch t := v.(type) {
		case map[string]any:
			for _, k := range sortedKeys(mapKeys(t)) {
				switch x := t[k].(type) {
				case string:
					if idField(k, m.params) {
						m.addID(x)
					}
				case float64:
					if idField(k, m.params) {
						m.addID(strconv.FormatFloat(x, 'f', -1, 64))
					}
				default:
					walk(x)
				}
			}
		case []any:
			for _, e := range t {
				walk(e)
			}
		}
	}
	walk(v)
}

// route aligns an object URL with the template it fills: each {name}
// gives an identifier, and the name of a parameter.
func (m *masker) route(objURL, tmpl string) {
	if tmpl == "" {
		return
	}
	a, b := strings.Split(pathOf(objURL), "/"), strings.Split(pathOf(tmpl), "/")
	if len(a) != len(b) {
		return
	}
	for i, s := range b {
		if strings.HasPrefix(s, "{") && strings.HasSuffix(s, "}") {
			m.params[strings.ToLower(strings.Map(func(r rune) rune {
				if r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
					return r
				}
				return -1
			}, s))] = true
			m.addID(a[i])
			if u, err := url.PathUnescape(a[i]); err == nil {
				m.addID(u)
			}
		}
	}
}

func replaceToken(s, v, to string) string {
	word := func(b byte) bool {
		return b >= '0' && b <= '9' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b == '_'
	}
	var b strings.Builder
	for {
		i := strings.Index(s, v)
		if i < 0 {
			b.WriteString(s)
			return b.String()
		}
		end := i + len(v)
		if (i > 0 && word(s[i-1])) || (end < len(s) && word(s[end])) {
			b.WriteString(s[:end])
		} else {
			b.WriteString(s[:i])
			b.WriteString(to)
		}
		s = s[end:]
	}
}

// text is s with the hosts, the identifiers and any token masked.
func (m *masker) text(s string) string {
	if !m.on {
		return s
	}
	s = jwtValue.ReplaceAllString(s, "<token>")
	hs := make([]string, 0, len(m.hosts))
	for h := range m.hosts {
		hs = append(hs, h)
	}
	slices.SortFunc(hs, func(a, b string) int { return len(b) - len(a) })
	for _, h := range hs {
		s = strings.ReplaceAll(s, h, m.hosts[h])
	}
	ids := slices.Clone(m.order)
	slices.SortFunc(ids, func(a, b string) int { return len(b) - len(a) })
	for _, v := range ids {
		if textID(v) {
			s = replaceToken(s, v, m.ph[v])
		}
	}
	return s
}

// value is a field's value as shown: an identifier field's value is its
// placeholder when masking.
func (m *masker) value(key, raw string) string {
	if m.on && idField(key, m.params) {
		v := raw
		if u, err := strconv.Unquote(raw); err == nil {
			v = u
		}
		if p, ok := m.ph[v]; ok {
			return `"` + p + `"`
		}
		return `"<id>"`
	}
	return m.text(raw)
}

// pathOf is a URL's path as shown: with masking, its identifiers are
// placeholders, and the segments that look like one are {id}.
func (m *masker) pathOf(u string) string {
	p := pathOf(u)
	if !m.on {
		return p
	}
	segs := strings.Split(m.text(p), "/")
	for i, s := range segs {
		if rptIDSeg.MatchString(s) {
			segs[i] = "{id}"
		}
	}
	return strings.Join(segs, "/")
}

// routeOf is the route as shown: the template when there is one, else the
// path.
func (m *masker) routeOf(u, tmpl string) string {
	if tmpl != "" {
		return pathOf(tmpl)
	}
	return m.pathOf(u)
}

// noun is what the route's objects are, from its path: /books/v1/{title}
// → book.
func noun(route string) string {
	segs := strings.Split(route, "/")
	for i := len(segs) - 1; i >= 0; i-- {
		s := segs[i]
		if s == "" || strings.HasPrefix(s, "{") || rptVersionSeg.MatchString(s) || rptIDSeg.MatchString(s) || strings.HasPrefix(s, "<") {
			continue
		}
		switch {
		case strings.HasSuffix(s, "ies") && len(s) > 4:
			return s[:len(s)-3] + "y"
		case strings.HasSuffix(s, "s") && !strings.HasSuffix(s, "ss") && len(s) > 2:
			return s[:len(s)-1]
		}
		return s
	}
	return "object"
}

func joinNames(ns []string) string {
	switch len(ns) {
	case 0:
		return ""
	case 1:
		return ns[0]
	}
	return strings.Join(ns[:len(ns)-1], ", ") + " and " + ns[len(ns)-1]
}

func verbOf(class string, n int) string {
	switch {
	case class == classWrite && n == 1:
		return "writes"
	case class == classWrite:
		return "write"
	case n == 1:
		return "reads"
	}
	return "read"
}

// possessive: alice's
func possessive(n string) string {
	if strings.HasSuffix(n, "s") {
		return n + "'"
	}
	return n + "'s"
}

func confidenceWhy(c string) string {
	switch c {
	case confProved:
		return "what filled the route and the object's own answer both say it is the owner's"
	case confLikely:
		return "one of the two says it is the owner's: what filled the route, or the object's own answer"
	case confGuess:
		return "only the owner's answers, or initials, say it is the owner's, or the route answers any identifier"
	}
	return ""
}

const noRun = "the run date is not recorded in this evidence store (it was written by an older azhaq)"

// buildReport is the report of one listed row, from what the row and its
// answers hold.
func buildReport(er store.EvidenceRow, order []string, saved time.Time, savedOK, redact bool) (reportDoc, error) {
	var row roleRow
	if err := json.Unmarshal(er.Row, &row); err != nil {
		return reportDoc{}, fmt.Errorf("row %s: %w", er.URL, err)
	}
	class, label := classOf(row.Verdict)
	if class == "" {
		return reportDoc{}, fmt.Errorf("row %s is [%s]: nothing to report", er.URL, row.Verdict)
	}
	sortAnswers(er.Answers, order)
	mk := newMasker(redact, order)
	if redact {
		mk.addHost(row.URL)
		mk.addHost(row.From)
		for _, a := range er.Answers {
			mk.addHost(a.Asked)
		}
		mk.route(row.URL, row.From)
		if row.Control != nil {
			mk.addID(row.Control.Value)
		}
		for _, a := range er.Answers {
			mk.collect(a.Body)
		}
	}

	verb := er.Method
	if verb == "" {
		verb = http.MethodGet
	}
	route := mk.routeOf(row.URL, row.From)
	objPath := mk.pathOf(row.URL)
	d := reportDoc{Class: class, Method: verb, URL: mk.text(row.URL), Route: route, Verdict: row.Verdict, Confidence: row.Confidence, OwnerReason: mk.text(row.OwnerBy)}
	if d.Confidence == "" {
		d.Confidence = "unrated"
	}
	owner := row.Owner
	readers := row.Readers
	if class == classExposure {
		owner = ""
	}

	// Title.
	switch class {
	case classExposure:
		d.Title = fmt.Sprintf("%s: anyone reads %s via %s %s", label, joinNames(row.Sensitive), verb, route)
		if len(row.Sensitive) == 0 {
			d.Title = fmt.Sprintf("%s: anyone reads sensitive fields via %s %s", label, verb, route)
		}
	case classWrite:
		who := joinNames(readers)
		if row.Verdict == verdictWriteAnyone || who == "" {
			d.Title = fmt.Sprintf("%s: anyone writes %s %s via %s %s", label, possessive(owner), noun(route), verb, route)
			break
		}
		d.Title = fmt.Sprintf("%s: %s %s %s %s via %s %s", label, who, verbOf(class, len(readers)), possessive(owner), noun(route), verb, route)
	default:
		d.Title = fmt.Sprintf("%s: %s %s %s %s via %s %s", label, joinNames(readers), verbOf(class, len(readers)), possessive(owner), noun(route), verb, route)
	}

	// The answers, owner and readers first, the controls last.
	var answers, controls []store.EvidenceAnswer
	for _, a := range er.Answers {
		if a.Kind == "control" {
			controls = append(controls, a)
		} else {
			answers = append(answers, a)
		}
	}
	missing := func(s string) { d.Missing = append(d.Missing, s) }
	byRole := map[string]*store.EvidenceAnswer{}
	for i := range answers {
		byRole[answers[i].Role] = &answers[i]
	}
	vars := []string{}
	addVars := func(curl string) {
		for _, v := range shellVar.FindAllStringSubmatch(curl, -1) {
			if !slices.Contains(vars, v[1]) {
				vars = append(vars, v[1])
			}
		}
	}

	conv := func(a store.EvidenceAnswer, kind string) reportAns {
		ra := reportAns{Role: a.Role, Kind: kind, Request: mk.text(a.Curl), Status: a.Status, Length: a.Length, ContentType: a.ContentType, BodyKept: a.Body != nil, Truncated: a.Truncated}
		addVars(a.Curl)
		if a.Curl == "" {
			missing(fmt.Sprintf("the request %s sent is not in the evidence store", a.Role))
		}
		switch {
		case a.Body == nil && a.Length > 0:
			missing(fmt.Sprintf("the body %s got (%s) was not kept: only its status and length are held", a.Role, byteSize(a.Length)))
		case a.Body == nil:
		default:
			ra.Fields, ra.FieldsMore, ra.Text = bodyFields(a.Body, row.Sensitive, 12, mk)
			if a.Truncated {
				missing(fmt.Sprintf("the body %s got is cut at 256 KB: fields past the cut are not shown", a.Role))
			}
		}
		return ra
	}
	var ownerAns *store.EvidenceAnswer
	if owner != "" {
		ownerAns = byRole[owner]
	}
	if owner != "" && ownerAns == nil {
		missing(fmt.Sprintf("no answer of %s (the owner) is held for this row", owner))
	}
	same := func(a *store.EvidenceAnswer, base *store.EvidenceAnswer) bool {
		if a.Body != nil && base.Body != nil {
			return bytes.Equal(a.Body, base.Body)
		}
		ha, hb := row.Answers[a.Role].Hash, row.Answers[base.Role].Hash
		return ha != "" && ha == hb
	}
	var base *store.EvidenceAnswer
	for i := range answers {
		a := &answers[i]
		kind := "other"
		switch {
		case a.Role == owner:
			kind = "owner"
		case slices.Contains(readers, a.Role):
			kind = "reader"
		}
		ra := conv(*a, kind)
		if base == nil && (kind == "owner" || class == classExposure && ok2xx(a.Status)) {
			base = a
		} else if base != nil && same(a, base) && ok2xx(a.Status) {
			ra.SameAs = base.Role
		}
		d.Evidence = append(d.Evidence, ra)
	}
	rank := map[string]int{"owner": 0, "reader": 1, "other": 2}
	sort.SliceStable(d.Evidence, func(i, j int) bool { return rank[d.Evidence[i].Kind] < rank[d.Evidence[j].Kind] })
	for _, a := range controls {
		d.Evidence = append(d.Evidence, conv(a, "control"))
	}
	if class != classExposure && owner == "" {
		missing("the row names no owner")
	}
	var controlled []string
	for _, a := range controls {
		controlled = append(controlled, fmt.Sprintf("%s %d", a.Role, a.Status))
	}
	if len(controls) == 0 && class == classRead {
		missing("no control was asked for this row: the evidence store holds no answer for a made-up identifier, so the report cannot say whether the route answers any identifier")
	}
	if row.Control != nil && len(row.Control.Alike) > 0 {
		missing("the route answered a made-up identifier like a real object for " + joinNames(row.Control.Alike) + ": this weakens the finding")
	}
	if class != classExposure && row.OwnerBy == "" {
		missing("the row holds no reason why the object is the owner's")
	}
	if class == classWrite {
		missing("the owner's reads of the object before and after the write are not kept in the evidence store, only what the row says of them")
	}

	// Summary: two sentences.
	d.Summary = summaryOf(row, class, verb, objPath, answers, owner, controlled, controls, mk)

	d.Severity = severityOf(row, class)
	d.Variables = vars

	// Steps.
	n := 0
	step := func(text, curl, expect string) {
		n++
		d.Steps = append(d.Steps, reportStep{N: n, Text: text, Curl: mk.text(curl), Expect: expect})
	}
	if len(vars) > 0 {
		step("Sign in with each account you control and put its session credential in "+joinNames(vars)+" (azhaq keeps no credential; the commands below name these variables only).", "", "")
	} else {
		step("Use the accounts you control; no credential is needed for the requests below beyond what the commands show.", "", "")
	}
	for _, ra := range d.Evidence {
		if ra.Kind == "control" {
			continue
		}
		var text string
		switch {
		case ra.Kind == "owner" && class == classWrite:
			text = fmt.Sprintf("As %s, the owner, send the write to its own object.", ra.Role)
		case ra.Kind == "owner":
			text = fmt.Sprintf("As %s, the owner, request the object: this is its own view.", ra.Role)
		case class == classWrite:
			text = fmt.Sprintf("As %s, send the same write to %s's object.", ra.Role, owner)
		case class == classExposure:
			text = fmt.Sprintf("As %s, request the route.", ra.Role)
		case ra.Kind == "other":
			text = fmt.Sprintf("For comparison, as %s, request the same object.", ra.Role)
		default:
			text = fmt.Sprintf("As %s, request %s's object.", ra.Role, owner)
		}
		step(text, ra.Request, expectOf(ra))
	}
	for _, ra := range d.Evidence {
		if ra.Kind == "control" {
			step(fmt.Sprintf("Control: as %s, request a made-up identifier on the same route.", ra.Role), ra.Request, expectOf(ra))
		}
	}

	d.Impact, d.Remediation = impactOf(class, row, owner)
	run := noRun
	if savedOK {
		run = saved.UTC().Format("2006-01-02 15:04 UTC")
	}
	d.Notes = reportNotes{Confidence: d.Confidence, ConfidenceWhy: confidenceWhy(row.Confidence), BothWays: row.BothWays, FoundBy: row.FoundBy, Run: run, SessionSuspect: row.SessionSuspect, Redacted: redact}
	return d, nil
}

func expectOf(a reportAns) string {
	s := fmt.Sprintf("%d, %s", a.Status, byteSize(a.Length))
	if a.SameAs != "" {
		s += ", the same body as " + a.SameAs + "'s"
	}
	return s
}

// bodyFields are the fields of a JSON body worth showing: the sensitive
// ones first, then the others in order, at most limit. A body that is not
// JSON gives its start.
func bodyFields(body []byte, sensitive []string, limit int, mk *masker) (fields []reportField, more int, text string) {
	var v any
	if json.Unmarshal(body, &v) != nil {
		s := strings.TrimSpace(string(body))
		if len(s) > 160 {
			s = s[:160] + "…"
		}
		return nil, 0, mk.text(strings.Join(strings.Fields(s), " "))
	}
	flat := map[string]string{}
	flatten(v, "", flat)
	var first, rest []string
	for _, k := range sortedKeys(mapKeys(flat)) {
		if slices.Contains(sensitive, lastKey(k)) {
			first = append(first, k)
		} else {
			rest = append(rest, k)
		}
	}
	all := append(first, rest...)
	for i, k := range all {
		if i == limit {
			more = len(all) - limit
			break
		}
		p := mk.text(k)
		fields = append(fields, reportField{Path: p, Value: mk.value(lastKey(k), flat[k])})
	}
	return fields, more, ""
}

// lastKey is the field name a path ends in: data.items[0].id → id.
func lastKey(path string) string {
	if i := strings.LastIndex(path, "."); i >= 0 {
		path = path[i+1:]
	}
	if i := strings.Index(path, "["); i >= 0 {
		path = path[:i]
	}
	return path
}

func summaryOf(row roleRow, class, verb, route string, answers []store.EvidenceAnswer, owner string, controlled []string, controls []store.EvidenceAnswer, mk *masker) string {
	get := func(role string) string {
		for _, a := range answers {
			if a.Role == role {
				return fmt.Sprintf("%d with %s", a.Status, byteSize(a.Length))
			}
		}
		return "an answer not held in the evidence store"
	}
	var s1 string
	switch class {
	case classRead:
		rs := joinNames(row.Readers)
		got := make([]string, 0, len(row.Readers))
		for _, r := range row.Readers {
			got = append(got, get(r))
		}
		same := ""
		if oa, ok := row.Answers[owner]; ok && oa.Hash != "" {
			eq := true
			for _, r := range row.Readers {
				eq = eq && row.Answers[r].Hash == oa.Hash
			}
			if eq {
				same = fmt.Sprintf(", the same body %s got", owner)
			} else {
				same = fmt.Sprintf(", an answer roles matched to %s's object", owner)
			}
		}
		s1 = fmt.Sprintf("%s requested %s %s, which holds %s's object, and got %s%s", rs, verb, route, owner, joinNames(got), same)
		if len(row.Sensitive) > 0 {
			s1 += " (sensitive fields: " + strings.Join(row.Sensitive, ", ") + ")"
		}
	case classWrite:
		rs := joinNames(row.Readers)
		if row.Verdict == verdictWriteAnyone || rs == "" {
			rs = "A role with no more access than anyone (" + joinNames(row.Readers) + ")"
		}
		got := make([]string, 0, len(row.Readers))
		for _, r := range row.Readers {
			got = append(got, get(r))
		}
		s1 = fmt.Sprintf("%s sent %s %s, a write to %s's object, and got %s", rs, verb, route, owner, joinNames(got))
	default:
		var ok []string
		for _, a := range answers {
			if ok2xx(a.Status) {
				ok = append(ok, a.Role)
			}
		}
		s1 = fmt.Sprintf("%s %s answers 2xx to %s with the sensitive fields %s", verb, route, joinNames(ok), strings.Join(row.Sensitive, ", "))
	}
	var s2 string
	switch class {
	case classExposure:
		s2 = "azhaq roles lists it because the anonymous role reads them; it gives no confidence for this kind of row, which is about fields, not about whose object it is."
	case classWrite:
		s2 = "azhaq roles rates it " + row.Confidence + ": it lists a write only when the owner's object, read as the owner before and after, changed the way the write asks."
	default:
		s2 = "azhaq roles rates it " + row.Confidence + " (" + confidenceWhy(row.Confidence) + ")"
		switch {
		case row.Control != nil && len(row.Control.Alike) > 0:
			s2 += "; the route also answered a made-up identifier like a real object for " + joinNames(row.Control.Alike)
		case len(controls) > 0:
			s2 += "; a made-up identifier on the same route got " + joinNames(controlled)
		default:
			s2 += "; no control was asked, so it is not shown that the route refuses an identifier that is nobody's"
		}
		s2 += "."
	}
	return s1 + ". " + s2
}

// severityOf is a guess from the class and what the row holds: sensitive
// fields read and a write each raise it.
func severityOf(row roleRow, class string) reportSeverty {
	levels := []string{"low", "medium", "high", "critical"}
	lvl := 1
	var why []string
	switch class {
	case classRead:
		why = append(why, "a role reads another role's object (medium to start)")
	case classWrite:
		why = append(why, "a role writes another role's object (medium to start)")
	case classExposure:
		why = append(why, "sensitive fields come back to a role with no more access than anyone (medium to start)")
	}
	if len(row.Sensitive) > 0 {
		lvl++
		why = append(why, "raised: the answer holds sensitive fields ("+strings.Join(row.Sensitive, ", ")+")")
	}
	if class == classWrite {
		lvl++
		why = append(why, "raised: it is a write, so data changes or is lost, not only read")
		if row.Verdict == verdictWriteAnyone {
			lvl++
			why = append(why, "raised: the anonymous role can write")
		}
	}
	if class != classExposure && row.Confidence == confGuess {
		why = append(why, "not lowered or raised for the confidence, which is a guess: check the object is the owner's first")
	}
	lvl = min(lvl, len(levels)-1)
	return reportSeverty{Level: levels[lvl], Reason: strings.Join(why, "; ")}
}

func impactOf(class string, row roleRow, owner string) (impact, remediation string) {
	switch class {
	case classWrite:
		impact = "An account can change or delete another account's data by sending the owner's identifier in the request: the server does not check that the object belongs to the session that writes it."
		remediation = "Check on the server, for every route that takes an identifier, that the object belongs to the session (or that the session's role may write it) before changing it, and refuse with 403 or 404 otherwise. Take the owner from the session, not from the request."
	case classExposure:
		impact = "Anyone who can reach the route reads the sensitive fields it returns"
		if len(row.Sensitive) > 0 {
			impact += " (" + strings.Join(row.Sensitive, ", ") + ")"
		}
		impact += ", signed in or not, which can be used to take over accounts or read other people's data."
		remediation = "Do not return fields that hold secrets, or return them only to the role that owns them; require a session on the route; mask or drop the values in debug and listing endpoints."
	default:
		impact = "An account can read another account's data by changing the identifier in the request: the server does not check that the object belongs to the session that asks for it"
		if len(row.Sensitive) > 0 {
			impact += ", including its sensitive fields (" + strings.Join(row.Sensitive, ", ") + ")"
		}
		impact += "."
		remediation = "Check on the server, for every route that takes an identifier, that the object belongs to the session (or that the session's role may read it), and refuse with 403 or 404 otherwise. Take the owner from the session, not from the request; unguessable identifiers do not replace the check."
	}
	return impact, remediation
}

// ---- Markdown

func (d reportDoc) markdown() string {
	var b strings.Builder
	w := func(f string, a ...any) { fmt.Fprintf(&b, f, a...) }
	w("# %s\n\n", d.Title)
	w("## Summary\n\n%s\n\n", d.Summary)
	w("## Severity (a guess)\n\n**%s**, guessed from the class and the fields, not rated: %s.\n\n", d.Severity.Level, d.Severity.Reason)
	w("## Steps to reproduce\n\n")
	for _, s := range d.Steps {
		w("%d. %s\n", s.N, s.Text)
		if s.Curl != "" {
			w("\n   ```sh\n   %s\n   ```\n", s.Curl)
		}
		if s.Expect != "" {
			w("\n   Expected: %s.\n", s.Expect)
		}
		w("\n")
	}
	w("## Evidence\n\n")
	for _, a := range d.Evidence {
		w("### %s\n\n", evidenceHeading(a))
		w("Request:\n\n```sh\n%s\n```\n\n", a.Request)
		resp := fmt.Sprintf("%d, %s", a.Status, byteSize(a.Length))
		if a.ContentType != "" {
			resp += ", " + a.ContentType
		}
		w("Response: %s.", resp)
		if a.SameAs != "" {
			w(" The body is the same as %s's.", a.SameAs)
		}
		w("\n\n")
		switch {
		case a.SameAs != "" && d.Class == classExposure:
			w("The fields are those of %s's body above.\n\n", a.SameAs)
		case !a.BodyKept:
			w("The body was not kept: only its status and length are in the evidence store.\n\n")
		case a.Text != "":
			w("The body is not JSON; it starts: `%s`\n\n", strings.ReplaceAll(a.Text, "`", "'"))
		case len(a.Fields) == 0:
			w("The body holds no fields.\n\n")
		default:
			for _, f := range a.Fields {
				w("- `%s`: `%s`\n", f.Path, f.Value)
			}
			if a.FieldsMore > 0 {
				w("- … %d more fields\n", a.FieldsMore)
			}
			if a.Truncated {
				w("\nThe body is cut at 256 KB; fields past the cut are not shown.\n")
			}
			w("\n")
		}
	}
	w("Secrets in the kept bodies are taken out by azhaq roles.\n\n")
	if !slices.ContainsFunc(d.Evidence, func(a reportAns) bool { return a.Kind == "control" }) {
		if d.Class == classRead {
			w("### Control\n\nNo control was asked for this row, and the evidence store holds no answer for a made-up identifier. The report therefore does not show that the route refuses an identifier that is nobody's.\n\n")
		} else {
			w("### Control\n\nNone is held: azhaq roles asks a made-up identifier only for a role reading another role's object.\n\n")
		}
	}
	w("## Why the object is the owner's\n\n")
	switch {
	case d.Class == classExposure:
		w("Not applicable: this finding is about fields that come back to anyone, not about whose object it is.\n\n")
	case d.OwnerReason == "":
		w("The row holds no reason why the object is the owner's.\n\n")
	default:
		w("> %s\n\n", d.OwnerReason)
	}
	w("## Impact\n\n%s\n\n", d.Impact)
	w("## Remediation\n\n%s\n\n", d.Remediation)
	w("## Notes\n\n")
	conf := d.Notes.Confidence
	if d.Notes.ConfidenceWhy != "" {
		conf += ": " + d.Notes.ConfidenceWhy
	} else if conf == "unrated" {
		conf += ": azhaq roles gives no confidence for this kind of row"
	}
	w("- Confidence: %s.\n", conf)
	switch {
	case d.Class == classExposure:
	case d.Notes.BothWays:
		w("- Both ways: yes, the owner also reads one of its readers' objects on the same route.\n")
	default:
		w("- Both ways: no, the run did not find the owner reading its readers' objects on this route.\n")
	}
	if d.Notes.SessionSuspect {
		w("- Session suspect: an answer was asked after its role's session last proved alive; ask it again before sending.\n")
	}
	if len(d.Notes.FoundBy) > 0 {
		w("- Found by the runs of: %s.\n", strings.Join(d.Notes.FoundBy, ", "))
	}
	if strings.HasPrefix(d.Notes.Run, "the run date") {
		w("- Found by azhaq roles; %s.\n", d.Notes.Run)
	} else {
		w("- Found by azhaq roles, run %s.\n", d.Notes.Run)
	}
	if d.Notes.Redacted {
		w("- Hosts and identifiers are masked (`<host>`, `<id-N>`); role names are the tester's own labels and stay. Identifiers that no kept body names in an identifier field are not masked.\n")
	}
	if len(d.Missing) > 0 {
		w("- Missing from the evidence store:\n")
		for _, m := range d.Missing {
			w("  - %s.\n", m)
		}
	}
	return b.String()
}

func evidenceHeading(a reportAns) string {
	switch a.Kind {
	case "owner":
		return a.Role + " (owner)"
	case "reader":
		return a.Role + " (reader)"
	case "control":
		return "Control: " + a.Role + ", a made-up identifier"
	}
	return a.Role
}
