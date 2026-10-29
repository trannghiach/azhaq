package hunt

import (
	"strings"
	"testing"
	"time"

	"github.com/trannghiach/azhaq/engine"
	"github.com/trannghiach/azhaq/types"
)

var now = time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)

func urlRow(key, role, cov string, status int, mod func(*engine.MapEntry)) engine.MapEntry {
	r := engine.MapEntry{
		Entity:   types.Entity{ID: key, Type: types.TypeURL, Key: key, FirstSeen: now.Add(-30 * 24 * time.Hour)},
		Scope:    "target",
		Coverage: cov,
		Role:     role,
		Status:   status,
	}
	if mod != nil {
		mod(&r)
	}
	return r
}

func build(rows ...engine.MapEntry) []Row {
	return Build(Input{DB: "w.db", Rows: rows, Now: now, Since: 7 * 24 * time.Hour})
}

func find(rows []Row, key string) *Row {
	for i := range rows {
		if rows[i].Key == key {
			return &rows[i]
		}
	}
	return nil
}

func has(r *Row, signal string) bool {
	if r == nil {
		return false
	}
	for _, x := range r.Reasons {
		if x.Signal == signal {
			return true
		}
	}
	return false
}

func TestScoringTable(t *testing.T) {
	const o = "http://t.test"
	cases := []struct {
		name   string
		row    engine.MapEntry
		signal string
		score  int
	}{
		{"admin path answers", urlRow(o+"/admin", "page", "visited", 200, nil), "path-admin", 40},
		{"admin path refused is still there", urlRow(o+"/admin", "forbidden", "visited", 403, nil), "path-admin", 30 + weights["gated"]},
		{"admin path not requested weighs half", urlRow(o+"/admin", "page", "hint", 0, nil), "path-admin", 20},
		{"debug word with underscore", urlRow(o+"/x/_debug", "api", "visited", 200, nil), "path-debug", 50},
		{"hyphenated api-docs word", urlRow(o+"/v2/api-docs", "api", "visited", 200, nil), "path-doc", 15 + weights["api-description"]},
		{"kdbx served", urlRow(o+"/ftp/a.kdbx", "page", "visited", 200, nil), "exposed-file", 70},
		{"bak refused", urlRow(o+"/ftp/a.bak", "page", "visited", 403, nil), "exposed-file", 55*fileUnseen/100 + weights["gated"]},
		{"git directory", urlRow(o+"/.git/HEAD", "page", "visited", 200, nil), "exposed-file", 70},
		{"directory listing", urlRow(o+"/files/", "page", "visited", 200, func(r *engine.MapEntry) { r.Title = "Index of /files" }), "listing", 55},
		{"listing directory title", urlRow(o+"/ftp", "page", "visited", 200, func(r *engine.MapEntry) { r.Title = "listing directory /ftp" }), "listing", 55},
		{"graphql by proof", urlRow(o+"/graphql", "api", "visited", 400, func(r *engine.MapEntry) { r.Proof = "status=400 role=graphql" }), "graphql", 40},
		{"graphql schema read", urlRow(o+"/graphql", "api", "visited", 200, func(r *engine.MapEntry) {
			r.Ops = []engine.Op{{Method: "POST", Source: "graphql"}}
		}), "graphql", 45},
		{"id in the path", urlRow(o+"/obj/{id}", "api", "hint", 0, func(r *engine.MapEntry) { r.Methods = []string{"GET"} }), "object-id", 35},
		{"id in a write-only path", urlRow(o+"/obj/{id}", "api", "hint", 0, func(r *engine.MapEntry) { r.Methods = []string{"PUT"} }), "object-id", objectWriteOnly + unauthWriteDry},
		{"redirect parameter", urlRow(o+"/go?next=x", "page", "visited", 200, func(r *engine.MapEntry) { r.Params = []string{"next"} }), "param-redirect", 30 + weights["input"]},
		{"command parameter the engine lacks", urlRow(o+"/t", "page", "visited", 200, func(r *engine.MapEntry) { r.Params = []string{"ip"} }), "param-command", 40 + weights["input"]},
		{"unauthenticated write answered", urlRow(o+"/api/x", "api", "visited", 200, func(r *engine.MapEntry) { r.Methods = []string{"GET", "POST"} }), "unauth-write", 25},
		{"upload form", urlRow(o+"/up", "page", "visited", 200, func(r *engine.MapEntry) {
			r.Forms = []engine.MapForm{{Method: "POST", Action: o + "/up", Files: []string{"f"}}}
		}), "upload", 35},
		{"state-changing GET left alone", urlRow(o+"/wipe", "page", "skipped", 0, func(r *engine.MapEntry) {
			r.Proof = "skipped=looks like a GET would change something word=wipe"
		}), "state-change", 30},
		{"password in a GET form", urlRow(o+"/pw", "page", "visited", 200, func(r *engine.MapEntry) {
			r.Forms = []engine.MapForm{{Method: "GET", Action: o + "/pw", Fields: []string{"password_new"}}}
		}), "password-in-url", 30 + weights["input"]},
		{"source map", urlRow(o+"/a.js.map", "sourcemap", "visited", 200, nil), "sourcemap", 45},
		{"server error", urlRow(o+"/boom", "page", "visited", 500, func(r *engine.MapEntry) { r.Title = "TypeError" }), "server-error", 20},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rows := build(c.row)
			if len(rows) != 1 {
				t.Fatalf("got %d rows, want 1: %+v", len(rows), rows)
			}
			if !has(&rows[0], c.signal) {
				t.Errorf("no %s reason in %+v", c.signal, rows[0].Reasons)
			}
			if rows[0].Score != c.score {
				t.Errorf("score %d, want %d (%+v)", rows[0].Score, c.score, rows[0].Reasons)
			}
		})
	}
}

func TestWritesNeedNoSession(t *testing.T) {
	post := func(r *engine.MapEntry) { r.Methods = []string{"POST"} }
	for name, r := range map[string]engine.MapEntry{
		"refused without a session": urlRow("http://t.test/w", "auth", "visited", 401, post),
		"a run that held a cookie":  urlRow("http://t.test/w", "page", "visited", 200, func(r *engine.MapEntry) { post(r); r.Proof = "status=200 auth=cookie" }),
		"a description asks":        urlRow("http://t.test/w", "api", "visited", 200, func(r *engine.MapEntry) { post(r); r.Ops = []engine.Op{{Method: "POST", Auth: true}} }),
	} {
		if rows := build(r); has(find(rows, r.Entity.Key), "unauth-write") {
			t.Errorf("%s: ranked as an unauthenticated write", name)
		}
	}
}

func TestExclusions(t *testing.T) {
	const o = "http://t.test"
	word := func(r *engine.MapEntry) { r.Title = "Index of /" } // a signal that would rank it
	for name, r := range map[string]engine.MapEntry{
		"script":          urlRow(o+"/admin/app.js", "script", "visited", 200, word),
		"script by name":  urlRow(o+"/debug/main.js", "page", "visited", 200, word),
		"image":           urlRow(o+"/admin/logo.png", "asset", "hint", 0, word),
		"stylesheet":      urlRow(o+"/static/admin.css", "asset", "visited", 200, word),
		"font":            urlRow(o+"/debug.woff2", "asset", "visited", 200, word),
		"catch-all page":  urlRow(o+"/admin/anything", "page", "catchall", 200, word),
		"gone":            urlRow(o+"/admin/old", "page", "gone", 404, word),
		"plain page":      urlRow(o+"/about", "page", "visited", 200, nil),
		"static html app": urlRow(o+"/", "app", "visited", 200, nil),
	} {
		if rows := build(r); len(rows) != 0 {
			t.Errorf("%s ranked: %+v", name, rows)
		}
	}
}

func TestNewAloneNeverRanks(t *testing.T) {
	old := urlRow("http://t.test/old", "page", "visited", 200, nil)
	fresh := func(key string) engine.MapEntry {
		return urlRow(key, "page", "visited", 200, func(r *engine.MapEntry) { r.Entity.FirstSeen = now.Add(-time.Hour) })
	}
	rows := build(old, fresh("http://t.test/fresh"), fresh("http://t.test/admin"))
	if len(rows) != 1 || rows[0].Key != "http://t.test/admin" {
		t.Fatalf("rows: %+v", rows)
	}
	if !has(&rows[0], "new") {
		t.Errorf("a fresh row beside older ones carries the new bonus: %+v", rows[0].Reasons)
	}
	// With nothing older, "new" tells nothing and is not added.
	if rows := build(fresh("http://t.test/admin")); has(&rows[0], "new") {
		t.Errorf("first run: every row is new, none is flagged: %+v", rows[0].Reasons)
	}
	// The bonus never lifts a row over one with more evidence only by itself.
	a := urlRow("http://t.test/admin", "page", "visited", 200, nil)
	b := fresh("http://t.test/debug")
	got := build(a, b, old)
	if got[0].Key != "http://t.test/debug" { // debug 50 + new 5 over admin 40
		t.Errorf("order: %v", []string{got[0].Key, got[1].Key})
	}
}

func TestGroupKey(t *testing.T) {
	for in, want := range map[string]string{
		"http://t.test/rest/basket/6":                          "http://t.test/rest/basket/{n}",
		"http://t.test/rest/basket/7":                          "http://t.test/rest/basket/{n}",
		"http://t.test/books/v1/%7Bbook_title%7D":              "http://t.test/books/v1/{book_title}",
		"http://t.test/ftp/":                                   "http://t.test/ftp",
		"http://t.test/":                                       "http://t.test/",
		"http://t.test/fi/?page=a.php":                         "http://t.test/fi/?page={v}",
		"http://t.test/fi/?page=b.php":                         "http://t.test/fi/?page={v}",
		"http://t.test/s?b=1&a=2":                              "http://t.test/s?a={v}&b={v}",
		"http://t.test/u/550e8400-e29b-41d4-a716-446655440000": "http://t.test/u/{uuid}",
	} {
		if got := GroupKey(in, false); got != want {
			t.Errorf("GroupKey(%q) = %q, want %q", in, got, want)
		}
	}
	if got := GroupKey("http://t.test/#/administration", true); got != "http://t.test/#/administration" {
		t.Errorf("a client route keeps its fragment: %q", got)
	}
}

func TestOneRowPerTemplate(t *testing.T) {
	const o = "http://t.test"
	rows := build(
		urlRow(o+"/rest/basket/6", "api", "visited", 200, nil),
		urlRow(o+"/rest/basket/7", "api", "visited", 200, nil),
		urlRow(o+"/rest/basket/8", "api", "visited", 200, nil),
		urlRow(o+"/fi/?page=a.php", "page", "visited", 200, nil),
		urlRow(o+"/fi/?page=b.php", "page", "visited", 200, nil),
		urlRow(o+"/fi/?page=c", "page", "visited", 200, nil),
	)
	if r := find(rows, o+"/rest/basket/{n}"); r == nil || len(rows) != 2 {
		t.Fatalf("one row for the basket template, one for fi: %+v", rows)
	}
	if find(rows, o+"/fi/?page={v}") == nil {
		t.Errorf("fi rows folded under their template: %+v", rows)
	}
	// A route seen once shows its own URL.
	if r := build(urlRow(o+"/app/redirect?url=", "page", "visited", 200, func(r *engine.MapEntry) { r.Params = []string{"url"} })); r[0].Key != o+"/app/redirect?url=" {
		t.Errorf("single instance key: %q", r[0].Key)
	}
	// /ftp and /ftp/ are one route.
	rows = build(
		urlRow(o+"/ftp", "page", "visited", 200, func(r *engine.MapEntry) { r.Title = "listing directory /ftp" }),
		urlRow(o+"/ftp/", "page", "visited", 200, func(r *engine.MapEntry) { r.Title = "listing directory /ftp/" }),
	)
	if len(rows) != 1 || len(rows[0].Reasons) != 1 {
		t.Errorf("slash variants fold, with one reason per signal: %+v", rows)
	}
}

func TestOrderingTies(t *testing.T) {
	rows := []Row{
		{Key: "d", Score: 50, scope: "fanout", signals: 3},
		{Key: "c", Score: 50, scope: "target", signals: 1},
		{Key: "b", Score: 50, scope: "target", signals: 2},
		{Key: "a", Score: 50, scope: "target", signals: 2},
		{Key: "z", Score: 60, scope: "fanout", signals: 1},
	}
	sortRows(rows)
	var got []string
	for _, r := range rows {
		got = append(got, r.Key)
	}
	// score; then target before fan-out; then more signals; then key
	if want := "z a b c d"; strings.Join(got, " ") != want {
		t.Errorf("order %v, want %s", got, want)
	}
}

func TestScoreIsTheSumOfSignals(t *testing.T) {
	r := build(urlRow("http://t.test/admin/setup", "page", "visited", 200, nil))
	if len(r) != 1 || r[0].Score != 80 || r[0].signals != 2 {
		t.Errorf("admin 40 + config 40: %+v", r)
	}
	// A signal counts once, at its highest weight.
	r = build(urlRow("http://t.test/admin/internal/console", "page", "visited", 200, nil))
	if r[0].Score != 40 || len(r[0].Reasons) != 1 {
		t.Errorf("one admin signal at its strongest word: %+v", r)
	}
}

func TestRolesRankFirst(t *testing.T) {
	const o = "http://t.test"
	rows := Build(Input{DB: "w.db", Now: now, Since: time.Hour,
		Rows: []engine.MapEntry{
			urlRow(o+"/books/v1/{b}", "api", "hint", 0, func(r *engine.MapEntry) { r.Methods = []string{"GET"} }),
			urlRow(o+"/.git/HEAD", "page", "visited", 200, nil),
		},
		Roles: []RoleRow{
			{URL: o + "/books/v1/mine", Template: o + "/books/v1/{b}", Verdict: "reads another role's object", Evidence: "bob got alice's answer", Confidence: "proved"},
			{URL: o + "/other", Verdict: "same for every role"},
		}})
	if rows[0].Key != o+"/books/v1/{b}" || !has(&rows[0], "cross-role") {
		t.Fatalf("a proved cross-role read leads: %+v", rows)
	}
	d := rows[0].Reasons[0].Detail
	if !strings.Contains(d, "bob got alice's answer") || !strings.Contains(d, "(proved)") {
		t.Errorf("the reason quotes evidence and confidence: %q", d)
	}
	if want := "azhaq roles show -dir DIR " + o + "/books/v1/mine"; rows[0].Next != want {
		t.Errorf("next = %q, want %q", rows[0].Next, want)
	}
	if find(rows, o+"/other") != nil {
		t.Error("a verdict that is not a cross-role one adds no row")
	}
	// Confidence scales the weight.
	w := func(conf string) int {
		r := Build(Input{Now: now, Roles: []RoleRow{{URL: o + "/x", Verdict: "reads another role's object", Confidence: conf}}})
		return r[0].Score
	}
	if !(w("proved") > w("likely") && w("likely") > w("guess")) {
		t.Errorf("confidence order: %d %d %d", w("proved"), w("likely"), w("guess"))
	}
	if w("proved") <= 60 {
		t.Error("cross-role verdicts outweigh the 60-90 band of open findings")
	}
	// A write verdict names the method.
	r := Build(Input{Now: now, Roles: []RoleRow{{URL: o + "/x", Method: "PUT", Verdict: "writes another role's object", Confidence: "proved"}}})
	if !strings.HasSuffix(r[0].Next, "-method PUT") {
		t.Errorf("next for a write: %q", r[0].Next)
	}
}

func TestSecretsTakeoversHosts(t *testing.T) {
	rows := Build(Input{DB: "w.db", Now: now,
		Rows: []engine.MapEntry{
			{Entity: types.Entity{Type: types.TypeHostname, Key: "staging.t.test"}, Scope: "target", Role: "live"},
			{Entity: types.Entity{Type: types.TypeHostname, Key: "www.t.test"}, Scope: "target", Role: "live"},
			{Entity: types.Entity{Type: types.TypeHostname, Key: "dev.gone.test"}, Scope: "target", Role: "dead"},
		},
		Secrets:   []Secret{{Kind: "aws-key", Severity: "high", Where: "http://t.test/main.js"}, {Kind: "jwt", Severity: "info", Where: "http://t.test/main.js"}},
		Takeovers: []Takeover{{Host: "old.t.test", Strong: true, Detail: "s3 takeover"}, {Host: "x.t.test", Detail: "dangling"}}})
	got := map[string]int{}
	for _, r := range rows {
		got[r.Key] = r.Score
	}
	for key, want := range map[string]int{"http://t.test/main.js": 70, "old.t.test": takeoverStrong, "x.t.test": weights["takeover"], "staging.t.test": 30} {
		if got[key] != want {
			t.Errorf("%s scored %d, want %d (%v)", key, got[key], want, got)
		}
	}
	if len(got) != 4 {
		t.Errorf("only rows with a signal: %v", got)
	}
	if r := find(rows, "old.t.test"); r.Type != "Hostname" || r.Next != "azhaq show -db w.db old.t.test" {
		t.Errorf("takeover row: %+v", r)
	}
}

func TestNextCommands(t *testing.T) {
	const o = "http://t.test"
	rows := build(
		urlRow(o+"/rest/basket/{id}", "api", "hint", 0, func(r *engine.MapEntry) { r.Methods = []string{"GET"} }),
		urlRow(o+"/page", "page", "visited", 200, func(r *engine.MapEntry) { r.Params = []string{"zz"} }),
		urlRow(o+"/.git/HEAD", "page", "visited", 200, nil),
	)
	want := map[string]string{
		o + "/rest/basket/{id}": "azhaq roles -role anon -role 'user=Authorization: Bearer …' -- -url " + o + "/",
		o + "/page":             "azhaq params -u " + o + "/page -w WORDLIST",
		o + "/.git/HEAD":        "azhaq show -db w.db " + o + "/.git/HEAD",
	}
	for k, n := range want {
		if r := find(rows, k); r == nil || r.Next != n {
			t.Errorf("%s: next %v, want %q", k, r, n)
		}
	}
	if got := quote("http://t.test/a?b={v}"); got != "'http://t.test/a?b={v}'" {
		t.Errorf("quote: %s", got)
	}
}

func TestReadRoles(t *testing.T) {
	in := `{"url":"http://t/x","verdict":"reads another role's object","confidence":"proved","readers":["bob"]}

{"type":"summary","command":"roles"}
{"url":"http://t/y","verdict":"signed-in only"}
`
	rs, err := ReadRoles(strings.NewReader(in))
	if err != nil || len(rs) != 2 || rs[0].Readers[0] != "bob" {
		t.Fatalf("%v %+v", err, rs)
	}
	if _, err := ReadRoles(strings.NewReader("not json\n")); err == nil {
		t.Error("a line that is not JSON is an error naming the line")
	}
}
