package gallery

import (
	"bytes"
	"context"
	"encoding/json"
	"image"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/trannghiach/azhaq/store"
	"github.com/trannghiach/azhaq/types"
)

type srv struct {
	t  *testing.T
	ts *httptest.Server
	g  *Gallery
}

func newSrv(t *testing.T, paths ...string) *srv {
	t.Helper()
	g, err := Open(paths, nil)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(g.Handler("127.0.0.1:0"))
	t.Cleanup(func() { ts.Close(); g.Close() })
	return &srv{t, ts, g}
}

func (s *srv) get(path string, v any) (int, time.Duration) {
	s.t.Helper()
	t0 := time.Now()
	r, err := http.Get(s.ts.URL + path)
	if err != nil {
		s.t.Fatal(err)
	}
	defer r.Body.Close()
	raw, _ := io.ReadAll(r.Body)
	d := time.Since(t0)
	if v != nil && r.StatusCode == 200 {
		if err := json.Unmarshal(raw, v); err != nil {
			s.t.Fatalf("%s: %v: %s", path, err, raw)
		}
	}
	return r.StatusCode, d
}

func (s *srv) list(q string) List {
	s.t.Helper()
	var l List
	if code, _ := s.get("/api/shots?"+q, &l); code != 200 {
		s.t.Fatalf("%s: %d", q, code)
	}
	return l
}

func count(rows []fixShot, f func(fixShot) bool) int {
	n := 0
	for _, r := range rows {
		if f(r) {
			n++
		}
	}
	return n
}

func TestAPITwoThousand(t *testing.T) {
	dir := t.TempDir()
	rows, db := makeWorkspace(t, dir, "big.db", 2000)
	s := newSrv(t, db)

	// The first page and a filter, within the budgets.
	var best time.Duration = time.Hour
	var first List
	for i := 0; i < 5; i++ {
		var l List
		_, d := s.get("/api/shots", &l)
		best, first = min(best, d), l
	}
	if first.Total != 2000 || len(first.Shots) != 48 || first.Limit != 48 {
		t.Fatalf("first page: total %d, %d shots, limit %d", first.Total, len(first.Shots), first.Limit)
	}
	if best > 500*time.Millisecond {
		t.Errorf("first page took %v", best)
	}
	best = time.Hour
	for i := 0; i < 5; i++ {
		var l List
		_, d := s.get("/api/shots?status=500&tech=nginx&q=title:portal", &l)
		best = min(best, d)
	}
	if best > 200*time.Millisecond {
		t.Errorf("a filter took %v", best)
	}
	t.Logf("first page %v ms in handler, filter best %v", first.TookMS, best)

	// Status, technology, title, host and partial agree with the rows.
	want := count(rows, func(r fixShot) bool { return r.Status == 500 })
	if got := s.list("status=500&limit=1").Total; got != want || want == 0 {
		t.Errorf("status=500: %d, want %d", got, want)
	}
	if got, want := s.list("status=4xx&limit=1").Total, count(rows, func(r fixShot) bool { return r.Status/100 == 4 }); got != want {
		t.Errorf("status=4xx: %d, want %d", got, want)
	}
	if got, want := s.list("status=301,302&limit=1").Total, count(rows, func(r fixShot) bool { return r.Status == 301 || r.Status == 302 }); got != want {
		t.Errorf("status=301,302: %d, want %d", got, want)
	}
	if got, want := s.list("tech=apache&limit=1").Total, count(rows, func(r fixShot) bool { return r.has("Apache") }); got != want || want == 0 {
		t.Errorf("tech=apache: %d, want %d", got, want)
	}
	if a, b := s.list("tech=nginx:1.25.3&limit=1").Total, s.list("tech=nginx&limit=1").Total; a != b || a == 0 {
		t.Errorf("tech=nginx:1.25.3 lists %d, tech=nginx %d", a, b)
	}
	if got, want := s.list("tech=Apache&tech=PHP&limit=1").Total, count(rows, func(r fixShot) bool { return r.has("Apache") && r.has("PHP") }); got != want {
		t.Errorf("tech=Apache&tech=PHP: %d, want %d", got, want)
	}
	if got, want := s.list("title=sign+in&limit=1").Total, count(rows, func(r fixShot) bool { return r.Title == "Sign in to Acme" }); got != want || want == 0 {
		t.Errorf("title: %d, want %d", got, want)
	}
	if got, want := s.list("host=h5.example&limit=1").Total, count(rows, func(r fixShot) bool { return strings.HasPrefix(r.Host, "h5.example") }); got != want || want == 0 {
		t.Errorf("host: %d, want %d", got, want)
	}
	if got, want := s.list("partial=yes&limit=1").Total, count(rows, func(r fixShot) bool { return r.Partial }); got != want || want == 0 {
		t.Errorf("partial=yes: %d, want %d", got, want)
	}
	if got, want := s.list("partial=no&limit=1").Total, count(rows, func(r fixShot) bool { return !r.Partial }); got != want {
		t.Errorf("partial=no: %d, want %d", got, want)
	}

	// Search: free text reads the URL, the title and the kept body; the
	// operators each read their own field.
	if got, want := s.list("q=marker14&limit=5").Total, count(rows, func(r fixShot) bool { return strings.Contains(r.Body, "marker14") }); got != want || want < 2 {
		t.Errorf("body search for marker14: %d results, want %d", got, want)
	}
	if got := s.list("q=marker1400+marker1401&limit=5").Total; got != 0 {
		t.Errorf("two words of different pages: %d", got)
	}
	if got, want := s.list("q=body:welcome&limit=1").Total, count(rows, func(r fixShot) bool { return r.Body != "" }); got != want {
		t.Errorf("body:welcome: %d, want %d", got, want)
	}
	if got := s.list("q=hidden&limit=1").Total; got != 0 {
		t.Errorf("a script's text is searched: %d", got)
	}
	if got, want := s.list("q=%22sign+in%22+tech:nginx&limit=1").Total, count(rows, func(r fixShot) bool { return r.Title == "Sign in to Acme" && r.has("nginx") }); got != want || want == 0 {
		t.Errorf("phrase and tech: %d, want %d", got, want)
	}
	if got, want := s.list("q=header:%22sid%3D17%3B%22&limit=1").Total, 1; got != want {
		t.Errorf("header:sid=17: %d, want %d", got, want)
	}
	if got, want := s.list("q=status:404+-title:portal&limit=1").Total, count(rows, func(r fixShot) bool { return r.Status == 404 && !strings.Contains(strings.ToLower(r.Title), "portal") }); got != want {
		t.Errorf("status and not title: %d, want %d", got, want)
	}
	if got, want := s.list("q=url:h96.example&limit=1").Total, count(rows, func(r fixShot) bool { return strings.HasPrefix(r.Host, "h96.example") }); got != want || want == 0 {
		t.Errorf("url:: %d, want %d", got, want)
	}
	if got := s.list("q=p:" + url.QueryEscape(first.Shots[0].Hash[:6]) + "&limit=1").Total; got == 0 {
		t.Errorf("p: prefix found nothing")
	}

	// Groups: 40 patterns, pages of a pattern share a group.
	var gr struct {
		Total  int        `json:"total"`
		Groups []GroupRow `json:"groups"`
	}
	s.get("/api/groups?min=1&limit=5000", &gr)
	if gr.Total > 60 || gr.Total < 30 {
		t.Errorf("%d groups for 40 patterns", gr.Total)
	}
	sum := 0
	for i, g := range gr.Groups {
		sum += g.Size
		if i > 0 && g.Size > gr.Groups[i-1].Size {
			t.Errorf("groups not by size")
		}
	}
	if sum != 2000 {
		t.Errorf("groups hold %d pages", sum)
	}
	g0 := gr.Groups[0]
	if got := s.list("group=0&limit=500"); got.Total != g0.Size || got.Shots[0].GroupSize != g0.Size {
		t.Errorf("group 0 lists %d, has %d", got.Total, g0.Size)
	}
	if got := s.list("collapse=1&limit=1"); got.Total != gr.Total {
		t.Errorf("collapse lists %d, groups %d", got.Total, gr.Total)
	}
	if got := s.list("collapse=1&limit=3&sort=group"); got.Shots[0].GroupMatches != g0.Size {
		t.Errorf("group matches %d", got.Shots[0].GroupMatches)
	}

	// Paging and order: pages follow each other and cover the set once.
	seen := map[string]bool{}
	for off := 0; off < 2000; off += 200 {
		l := s.list("limit=200&offset=" + strconv.Itoa(off))
		for _, sh := range l.Shots {
			if seen[sh.ID] {
				t.Fatalf("page repeats %s", sh.URL)
			}
			seen[sh.ID] = true
		}
	}
	if len(seen) != 2000 {
		t.Errorf("pages cover %d", len(seen))
	}
	if l := s.list("offset=1990&limit=48"); len(l.Shots) != 10 {
		t.Errorf("last page has %d", len(l.Shots))
	}
	if l := s.list("offset=5000"); len(l.Shots) != 0 || l.Total != 2000 {
		t.Errorf("past the end: %d", len(l.Shots))
	}
	asc, desc := s.list("sort=title&limit=500"), s.list("sort=title&order=desc&limit=500")
	if !sort.SliceIsSorted(asc.Shots, func(i, j int) bool { return strings.ToLower(asc.Shots[i].Title) < strings.ToLower(asc.Shots[j].Title) }) {
		t.Errorf("sort=title is not ordered")
	}
	if desc.Shots[0].Title < desc.Shots[len(desc.Shots)-1].Title {
		t.Errorf("order=desc is not reversed")
	}
	if l := s.list("sort=status&limit=500"); l.Shots[0].Status > l.Shots[499].Status {
		t.Errorf("sort=status is not ordered")
	}

	// Facets count under the other filters.
	var fc Facets
	s.get("/api/facets?status=500", &fc)
	nginx := 0
	for _, c := range fc.Tech {
		if c.Value == "nginx" {
			nginx = c.Count
		}
	}
	if want := count(rows, func(r fixShot) bool { return r.Status == 500 && r.has("nginx") }); nginx != want {
		t.Errorf("nginx facet %d, want %d", nginx, want)
	}
	total := 0
	for _, c := range fc.Status {
		total += c.Count
	}
	if total != 2000 { // a facet is counted under the other filters, not its own
		t.Errorf("status facet sums to %d", total)
	}

	// Bad input is refused, not guessed.
	for _, q := range []string{"limit=0", "limit=9999", "offset=-1", "sort=bogus", "partial=maybe", "group=x"} {
		if code, _ := s.get("/api/shots?"+q, nil); code != 400 {
			t.Errorf("%s: %d", q, code)
		}
	}
	if code, _ := s.get("/api/shots/nope", nil); code != 404 {
		t.Errorf("unknown page: %d", code)
	}
	var st Stats
	s.get("/api/stats", &st)
	if st.Pages != 2000 || st.Statuses["500"] != want || st.Body.Kept != count(rows, func(r fixShot) bool { return r.Body != "" }) || !st.Body.Ready && st.Body.Indexed > st.Body.Kept {
		t.Errorf("stats: %+v", st)
	}
}

func TestDetailAndImages(t *testing.T) {
	dir := t.TempDir()
	rows, db := makeWorkspace(t, dir, "d.db", 50)
	// A page whose picture is gone, and one whose record names a file that
	// is not a picture.
	if err := os.Remove(filepath.Join(dir, "d.db_1.png")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "d.db_2.png"), []byte("secret text, not a picture"), 0o644); err != nil {
		t.Fatal(err)
	}
	s := newSrv(t, db)
	var l List
	s.get("/api/shots?limit=500", &l)
	by := map[string]ShotView{}
	for _, sh := range l.Shots {
		by[sh.URL] = sh
	}
	var d Detail
	var body Shot
	for _, sh := range l.Shots {
		if sh.HasBody {
			body = *sh.Shot
			break
		}
	}
	if code, _ := s.get("/api/shots/"+body.ID, &d); code != 200 {
		t.Fatal(code)
	}
	var rec struct {
		Headers []struct{ Key, Value string }
		TLS     struct{ Protocol string }
		Console []struct{ Type, Value string }
		Network []struct{ URL string }
	}
	if err := json.Unmarshal(d.Record, &rec); err != nil {
		t.Fatal(err)
	}
	if len(rec.Headers) != 2 || rec.TLS.Protocol != "TLS 1.3" || len(rec.Console) != 1 || len(rec.Network) != 2 {
		t.Errorf("record: %s", d.Record)
	}
	if !strings.Contains(d.BodyText, "welcome marker") || strings.Contains(d.BodyText, "hidden") {
		t.Errorf("body text %q", d.BodyText)
	}
	if !strings.HasPrefix(d.ShowCommand, "azhaq show -db ") || !strings.HasSuffix(d.ShowCommand, " "+body.URL) {
		t.Errorf("show command %q", d.ShowCommand)
	}
	if d.GroupSize > 1 && len(d.Members) != min(d.GroupSize-1, 24) {
		t.Errorf("%d members of a group of %d", len(d.Members), d.GroupSize)
	}
	var show struct {
		Command string
		Entity  struct{ Type, Key string }
		Obs     []struct{ Collector, Kind string } `json:"observations"`
	}
	if code, _ := s.get("/api/shots/"+body.ID+"/show", &show); code != 200 || show.Entity.Key != body.URL || len(show.Obs) != 1 || show.Obs[0].Kind != "screenshot" {
		t.Errorf("show: %d %+v", code, show)
	}

	// Images.
	var th struct{ n int }
	_ = th
	r, err := http.Get(s.ts.URL + "/img/" + body.ID + "/thumb")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(r.Body)
	r.Body.Close()
	cfg, format, err := image.DecodeConfig(bytes.NewReader(raw))
	if err != nil || format != "jpeg" || cfg.Width > thumbWidth || cfg.Width == 0 || r.Header.Get("Content-Type") != "image/jpeg" {
		t.Errorf("thumb: %v %s %dx%d", err, format, cfg.Width, cfg.Height)
	}
	full, _ := http.Get(s.ts.URL + "/img/" + body.ID + "/full")
	rawFull, _ := io.ReadAll(full.Body)
	full.Body.Close()
	disk, _ := os.ReadFile(filepath.Join(dir, "d.db_0.png"))
	if body.URL != rowsURL(rows, 0) {
		disk, _ = os.ReadFile(findFile(t, dir, body.URL, rows))
	}
	if !bytes.Equal(rawFull, disk) {
		t.Errorf("full picture differs from the file")
	}
	for _, u := range []string{rowsURL(rows, 1), rowsURL(rows, 2)} {
		sh := by[u]
		for _, kind := range []string{"thumb", "full"} {
			if code, _ := s.get("/img/"+sh.ID+"/"+kind, nil); code != 404 {
				t.Errorf("%s of %s: %d", kind, u, code)
			}
		}
	}
	if by[rowsURL(rows, 1)].HasFile {
		t.Errorf("a missing picture is listed as present")
	}
	// The gaps are said.
	var st Stats
	s.get("/api/stats", &st)
	if st.NoFile != 2 || !slices.ContainsFunc(st.Warnings, func(w Warning) bool { return w.Partial && strings.Contains(w.Message, "picture file is not on disk") }) {
		t.Errorf("missing files not said: %+v", st.Warnings)
	}
}

func rowsURL(rows []fixShot, i int) string { return rows[i].URL }

func findFile(t *testing.T, dir, page string, rows []fixShot) string {
	for i, r := range rows {
		if r.URL == page {
			return filepath.Join(dir, "d.db_"+strconv.Itoa(i)+".png")
		}
	}
	t.Fatal("no row")
	return ""
}

func TestHostGuard(t *testing.T) {
	_, db := makeWorkspace(t, t.TempDir(), "g.db", 5)
	g, err := Open([]string{db}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	h := g.Handler("127.0.0.1:7180")
	for host, want := range map[string]int{"127.0.0.1:7180": 200, "localhost:7180": 200, "[::1]:7180": 200, "evil.example:7180": 403, "10.0.0.5:7180": 403} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/api/stats", nil)
		r.Host = host
		h.ServeHTTP(w, r)
		if w.Code != want {
			t.Errorf("Host %s: %d, want %d", host, w.Code, want)
		}
		if want == 200 && !strings.Contains(w.Header().Get("Content-Security-Policy"), "default-src 'none'") {
			t.Errorf("no CSP on %s", host)
		}
	}
	w := httptest.NewRecorder()
	post := httptest.NewRequest("POST", "/api/stats", nil)
	post.Host = "127.0.0.1:7180"
	h.ServeHTTP(w, post)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST: %d", w.Code)
	}
	// Bound to another address, the guard is off: the user chose it.
	w = httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/stats", nil)
	r.Host = "gallery.lan:7180"
	g.Handler("0.0.0.0:7180").ServeHTTP(w, r)
	if w.Code != 200 {
		t.Errorf("0.0.0.0: %d", w.Code)
	}
}

// The gallery reads the workspace and its pictures and opens no
// connection: the pages' URLs point at a listener that counts, the
// default transport and resolver fail the test, and every endpoint is
// asked.
func TestMakesNoOutgoingConnection(t *testing.T) {
	var hits atomic.Int64
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	go func() {
		for {
			c, err := target.Accept()
			if err != nil {
				return
			}
			hits.Add(1)
			c.Close()
		}
	}()
	oldT, oldR := http.DefaultTransport, net.DefaultResolver
	http.DefaultTransport = roundTripFail{t, &hits}
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
		hits.Add(1)
		t.Errorf("a name was resolved through %s", addr)
		return nil, io.EOF
	}}
	defer func() { http.DefaultTransport, net.DefaultResolver = oldT, oldR }()

	dir := t.TempDir()
	rows, db := makeWorkspace(t, dir, "o.db", 60)
	// Re-point the pages at the counting listener and at an unresolvable name.
	_ = rows
	g, err := Open([]string{db}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i, sh := range g.shots {
		if i%2 == 0 {
			sh.URL, sh.FinalURL = "http://"+target.Addr().String()+"/p"+strconv.Itoa(i), "http://"+target.Addr().String()+"/"
		} else {
			sh.URL = "https://nxdomain-" + strconv.Itoa(i) + ".invalid/"
		}
		sh.index()
	}
	ts := httptest.NewServer(g.Handler("127.0.0.1:0"))
	defer ts.Close()
	defer g.Close()
	ids := []string{}
	for _, sh := range g.shots {
		ids = append(ids, sh.ID)
	}
	paths := []string{"/", "/app.js", "/app.css", "/api/", "/api/shots?limit=200", "/api/shots?q=p&collapse=1", "/api/facets", "/api/groups", "/api/failed", "/api/stats"}
	for _, id := range ids {
		paths = append(paths, "/api/shots/"+id, "/api/shots/"+id+"/show", "/img/"+id+"/thumb", "/img/"+id+"/full")
	}
	for _, p := range paths {
		r, err := http.Get(ts.URL + p)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, r.Body)
		r.Body.Close()
		if r.StatusCode != 200 {
			t.Errorf("%s: %d", p, r.StatusCode)
		}
	}
	time.Sleep(50 * time.Millisecond)
	if n := hits.Load(); n != 0 {
		t.Errorf("%d outgoing connections", n)
	}
}

type roundTripFail struct {
	t    *testing.T
	hits *atomic.Int64
}

func (r roundTripFail) RoundTrip(req *http.Request) (*http.Response, error) {
	// The test's own requests go to the httptest server on loopback; any
	// other host is the gallery reaching out.
	if h := req.URL.Hostname(); h != "127.0.0.1" {
		r.hits.Add(1)
		r.t.Errorf("request to %s", req.URL)
		return nil, io.EOF
	}
	return (&http.Transport{}).RoundTrip(req)
}

// The page and its script ask for nothing outside this server, and the
// package has no client code: the source and the assets are searched.
func TestNothingExternalInTheSource(t *testing.T) {
	for _, name := range []string{"index.html", "app.js", "app.css"} {
		raw, err := uiFiles.ReadFile("ui/" + name)
		if err != nil {
			t.Fatal(err)
		}
		for _, bad := range []string{"http://", "https://", "//cdn", "@import", "@font-face", "innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function", "setAttribute(\"style", "style=", "XMLHttpRequest", "WebSocket", "EventSource", "sendBeacon", "import("} {
			// The page's text may show the scheme; a request may not.
			for _, line := range strings.Split(string(raw), "\n") {
				if !strings.Contains(line, bad) {
					continue
				}
				if bad == "http://" || bad == "https://" {
					if strings.Contains(line, "/^https?") || strings.Contains(line, "location.origin") {
						continue
					}
				}
				t.Errorf("%s: %q in %q", name, bad, strings.TrimSpace(line))
			}
		}
	}
	files, _ := filepath.Glob("*.go")
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		raw, _ := os.ReadFile(f)
		for _, bad := range []string{"http.Get", "http.Post", "http.Client", "http.DefaultClient", "http.NewRequest", "net.Dial", "net.Lookup", "DefaultTransport", "internal/fetch", "internal/browser\""} {
			if bytes.Contains(raw, []byte(bad)) {
				t.Errorf("%s uses %s", f, bad)
			}
		}
	}
}

func TestWorkspaces(t *testing.T) {
	dir := t.TempDir()
	a, dbA := makeWorkspace(t, dir, "a.db", 30)
	b, dbB := makeWorkspace(t, dir, "b.db", 20)
	_ = a
	_ = b
	notWS := filepath.Join(dir, "roles.db") // some other sqlite file
	other, err := os.Create(notWS)
	if err != nil {
		t.Fatal(err)
	}
	other.Close()
	broken := filepath.Join(dir, "broken.db")
	if err := os.WriteFile(broken, []byte("this is not sqlite at all, just text padding padding padding padding"), 0o644); err != nil {
		t.Fatal(err)
	}
	s := newSrv(t, dbA, dbB, notWS, broken)
	var st Stats
	s.get("/api/stats", &st)
	if st.Pages != 50 || len(st.Workspaces) != 2 {
		t.Errorf("merged %d pages from %d workspaces", st.Pages, len(st.Workspaces))
	}
	if l := s.list("workspace=a.db&limit=1"); l.Total != 30 {
		t.Errorf("workspace a: %d", l.Total)
	}
	var fc Facets
	s.get("/api/facets", &fc)
	if len(fc.Workspaces) != 2 {
		t.Errorf("workspace facet %+v", fc.Workspaces)
	}
	var skipped, partial int
	for _, w := range st.Warnings {
		if strings.Contains(w.Message, "skipped") {
			skipped++
			if w.Partial {
				partial++
			}
		}
	}
	if skipped != 2 || partial != 1 { // the empty file is a note; the unreadable one is partial
		t.Errorf("skipped %d, partial %d: %+v", skipped, partial, st.Warnings)
	}
	if _, err := Open([]string{broken}, nil); err == nil {
		t.Errorf("a single unreadable workspace opened")
	}
	// Pages of the same URL in two workspaces are two pages; a URL shot
	// twice in one workspace is one, the newer.
	if l := s.list("q=h1.example.test:8000&limit=10"); l.Total != 2 {
		t.Errorf("same URL in two workspaces: %d", l.Total)
	}
}

func TestParseSearch(t *testing.T) {
	got := parseSearch(`login title:"Sign in" -tech:nginx body:x p:ab "two words" status:2xx`)
	want := []term{{"", "login", false}, {"title", "sign in", false}, {"tech", "nginx", true}, {"body", "x", false}, {"p", "ab", false}, {"", "two words", false}, {"status", "2xx", false}}
	if !slices.Equal(got, want) {
		t.Errorf("%+v", got)
	}
}

func TestFailedPages(t *testing.T) {
	dir := t.TempDir()
	rows, db := makeWorkspace(t, dir, "f.db", 5)
	st, err := store.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	add := func(key, kind, field, msg string, at time.Time) {
		ent, err := st.UpsertEntity(types.TypeURL, key, at)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(map[string]string{field: msg})
		if _, err := st.AddObservation(ent.ID, types.Observation{Collector: "azhaq-shots", Source: key, Kind: kind, Payload: raw, ObservedAt: at}); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().Add(time.Hour)
	add("https://down.example.test/", "error", "error", "navigate: net::ERR_CONNECTION_REFUSED", now)
	add("https://teapot.example.test/", "note", "note", "screenshot of https://teapot.example.test/ not taken: it answers 418", now)
	add("https://chosen.example.test/", "error", "error", "not requested: out of scope", now)
	add(rows[0].URL, "error", "error", "an old failure of a page a later run took", time.Now().Add(-time.Hour))
	st.Close()
	s := newSrv(t, db)
	var f struct {
		Total  int
		Failed []Failed
	}
	s.get("/api/failed", &f)
	if f.Total != 2 || f.Failed[0].URL != "https://down.example.test/" || f.Failed[0].Kind != "error" || !strings.Contains(f.Failed[0].Reason, "ERR_CONNECTION_REFUSED") || f.Failed[1].Kind != "note" {
		t.Errorf("failed: %+v", f)
	}
	if s.get("/api/failed?kind=note", &f); f.Total != 1 {
		t.Errorf("kind=note: %d", f.Total)
	}
	if s.get("/api/failed?q=teapot", &f); f.Total != 1 {
		t.Errorf("q=teapot: %d", f.Total)
	}
	if code, _ := s.get("/api/failed?kind=x", nil); code != 400 {
		t.Errorf("kind=x: %d", code)
	}
	var stt Stats
	s.get("/api/stats", &stt)
	if stt.Failed != 2 || stt.Pages != 5 {
		t.Errorf("stats %d failed, %d pages", stt.Failed, stt.Pages)
	}
}

// A partial page says what it lacks: the assets of hosts outside the
// scope that were blocked, or the images that did not load.
func TestPartialShotsSayWhy(t *testing.T) {
	dir := t.TempDir()
	_, p := makeWorkspace(t, dir, "w.db", 60)
	s := newSrv(t, p)
	l := s.list("partial=yes&limit=100")
	var blocked, unloaded int
	for _, v := range l.Shots {
		switch {
		case v.PartialWhy == "3 off-scope assets blocked: cdn.example.test":
			blocked++
		case v.PartialWhy == "2 of 9 images, styles and scripts not loaded":
			unloaded++
		default:
			t.Errorf("%s: partial_why %q", v.URL, v.PartialWhy)
		}
	}
	if blocked == 0 || unloaded == 0 || blocked+unloaded != l.Total {
		t.Errorf("%d blocked, %d unloaded of %d partial pages", blocked, unloaded, l.Total)
	}
	for _, v := range s.list("partial=no&limit=100").Shots {
		if v.PartialWhy != "" {
			t.Errorf("%s is whole but says %q", v.URL, v.PartialWhy)
		}
	}
}
