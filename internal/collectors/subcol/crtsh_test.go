package subcol

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

// fakePG is a database/sql driver that records what it is sent and
// answers a SELECT with its rows.
type fakePG struct {
	mu    sync.Mutex
	execs []string
	query string
	args  []driver.NamedValue
	rows  []string
	err   error
}

func (f *fakePG) Open(string) (driver.Conn, error) { return &fakeConn{f}, nil }

type fakeConn struct{ f *fakePG }

func (c *fakeConn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("not used") }
func (c *fakeConn) Close() error                        { return nil }
func (c *fakeConn) Begin() (driver.Tx, error)           { return nil, errors.New("not used") }

func (c *fakeConn) ExecContext(_ context.Context, q string, _ []driver.NamedValue) (driver.Result, error) {
	c.f.mu.Lock()
	defer c.f.mu.Unlock()
	c.f.execs = append(c.f.execs, q)
	return driver.ResultNoRows, nil
}

func (c *fakeConn) QueryContext(_ context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	c.f.mu.Lock()
	defer c.f.mu.Unlock()
	c.f.query, c.f.args = q, args
	if c.f.err != nil {
		return nil, c.f.err
	}
	return &fakeRows{rows: c.f.rows}, nil
}

type fakeRows struct {
	rows []string
	i    int
}

func (r *fakeRows) Columns() []string { return []string{"name_value"} }
func (r *fakeRows) Close() error      { return nil }
func (r *fakeRows) Next(dest []driver.Value) error {
	if r.i >= len(r.rows) {
		return io.EOF
	}
	dest[0] = r.rows[r.i]
	r.i++
	return nil
}

type fakeDriverConnector struct{ f *fakePG }

func (c fakeDriverConnector) Connect(context.Context) (driver.Conn, error) {
	return &fakeConn{c.f}, nil
}
func (c fakeDriverConnector) Driver() driver.Driver { return c.f }

// The lookup is crt.sh's statement with the domain as its one argument,
// under a statement_timeout of the budget, LIMIT 10000 when asked for a
// page; each row's NAME_VALUE is split into names, and the rows are counted.
func TestCrtshStatement(t *testing.T) {
	f := &fakePG{rows: []string{"a.example.org\nb.example.org", "*.example.org"}}
	db := sql.OpenDB(fakeDriverConnector{f})
	defer db.Close()
	names, rows, err := namesFromDB(context.Background(), db, "example.org", 25*time.Second, 0)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"a.example.org", "b.example.org", "*.example.org"}; !slices.Equal(names, want) {
		t.Errorf("names %v, want %v", names, want)
	}
	if rows != 2 {
		t.Errorf("%d rows counted, want 2", rows)
	}
	if len(f.execs) != 1 || f.execs[0] != "SET statement_timeout = 25000;" {
		t.Errorf("setup statements %q", f.execs)
	}
	for _, want := range []string{"SELECT DISTINCT cai.NAME_VALUE", "certificate_and_identities", "plainto_tsquery('certwatch', $1)", "ILIKE ('%' || $1 || '%')"} {
		if !strings.Contains(f.query, want) {
			t.Errorf("statement lacks %q: %s", want, f.query)
		}
	}
	if strings.Contains(strings.ToUpper(f.query), "LIMIT") {
		t.Errorf("statement is limited when no limit was asked: %s", f.query)
	}
	if _, _, err := namesFromDB(context.Background(), db, "example.org", time.Second, 10000); err != nil || !strings.HasSuffix(strings.TrimSpace(f.query), "LIMIT 10000") {
		t.Errorf("a page is asked with subfinder's LIMIT 10000: %v: %s", err, f.query)
	}
	if len(f.args) != 1 || f.args[0].Value != "example.org" {
		t.Errorf("arguments %v", f.args)
	}
	f.err = errors.New("pq: too many connections")
	if _, _, err := namesFromDB(context.Background(), db, "example.org", time.Second, 0); err == nil {
		t.Error("a failed query gave no error")
	}
}

type rtFunc func(*http.Request) (*http.Response, error)

func (f rtFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// session answers every request from body; asked counts them.
func crtshSession(status int, body string, asked *int) *subscraping.Session {
	c := New(Options{Client: &http.Client{Transport: rtFunc(func(r *http.Request) (*http.Response, error) {
		*asked++
		return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Request: r, Header: http.Header{}}, nil
	})}})
	return &subscraping.Session{Client: c.opts.Client, RequestLimiter: c.limiter, Timeout: 5}
}

func runCrtsh(t *testing.T, q func(context.Context, string, *url.URL, time.Duration, int) ([]string, int, error), sess *subscraping.Session) ([]string, string, error) {
	t.Helper()
	old := crtshQuery
	crtshQuery = q
	defer func() { crtshQuery = old }()
	n := &rowNote{}
	ctx, cancel := context.WithTimeout(context.WithValue(context.Background(), noteKey{}, n), 30*time.Second)
	defer cancel()
	names, err := crtshSource().collect(ctx, "example.org", nil, sess)
	return names, n.text, err
}

func TestCrtshDatabaseFirst(t *testing.T) {
	var asked int
	var gotVia *url.URL
	var gotBudget time.Duration
	var gotLimit int
	names, note, err := runCrtsh(t, func(_ context.Context, d string, via *url.URL, b time.Duration, limit int) ([]string, int, error) {
		gotVia, gotBudget, gotLimit = via, b, limit
		return []string{"a." + d}, 1, nil
	}, crtshSession(200, `[]`, &asked))
	if err != nil || !slices.Equal(names, []string{"a.example.org"}) {
		t.Fatalf("names %v, err %v", names, err)
	}
	if asked != 0 || note != "" || gotVia != nil {
		t.Errorf("the JSON API was asked %d times, note %q, via %v", asked, note, gotVia)
	}
	if gotLimit != 10000 {
		t.Errorf("the first question had LIMIT %d, want subfinder's 10000", gotLimit)
	}
	if gotBudget < 3*time.Second || gotBudget > 8*time.Second {
		t.Errorf("the limited query got %s of the source's 30 s: a few seconds, the rest is the JSON API's", gotBudget)
	}
}

// page is n distinct names of example.org, as a database page of n rows.
func page(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = "h" + strconv.Itoa(i) + ".example.org"
	}
	return out
}

// A full page (10000 rows, the limit) has more behind it: the database is
// asked again without the limit, in a share of the time left, and the note
// says so. A page that is not full is the whole answer.
func TestCrtshFullPageIsAskedAgain(t *testing.T) {
	var limits []int
	var budgets []time.Duration
	var asked int
	names, note, err := runCrtsh(t, func(_ context.Context, d string, _ *url.URL, b time.Duration, limit int) ([]string, int, error) {
		limits, budgets = append(limits, limit), append(budgets, b)
		if limit > 0 {
			return page(crtshLimit), crtshLimit, nil
		}
		return page(crtshLimit + 5), crtshLimit + 5, nil
	}, crtshSession(200, `[]`, &asked))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(limits, []int{10000, 0}) {
		t.Errorf("limits asked %v, want the page then the rest", limits)
	}
	if len(budgets) == 2 && (budgets[0] > 8*time.Second || budgets[1] <= budgets[0] || budgets[0]+budgets[1] > 30*time.Second) {
		t.Errorf("budgets %v of the source's 30 s", budgets)
	}
	seen := map[string]bool{}
	for _, n := range names {
		seen[n] = true
	}
	if len(seen) != crtshLimit+5 {
		t.Errorf("%d distinct names, want %d", len(seen), crtshLimit+5)
	}
	if asked != 0 || !strings.Contains(note, "without the limit") {
		t.Errorf("JSON API asked %d times, note %q", asked, note)
	}
	// 9999 rows is not full.
	limits = nil
	names, note, _ = runCrtsh(t, func(_ context.Context, _ string, _ *url.URL, _ time.Duration, limit int) ([]string, int, error) {
		limits = append(limits, limit)
		return page(9999), 9999, nil
	}, crtshSession(200, `[]`, new(int)))
	if len(limits) != 1 || len(names) != 9999 || note != "" {
		t.Errorf("a page of 9999 rows: asked %v, %d names, note %q", limits, len(names), note)
	}
}

// When the query for the rest fails, the JSON API gives it; when that fails
// too, the page stays the answer and the note says there may be more.
func TestCrtshFullPageRestFallsBack(t *testing.T) {
	q := func(_ context.Context, _ string, _ *url.URL, _ time.Duration, limit int) ([]string, int, error) {
		if limit > 0 {
			return page(crtshLimit), crtshLimit, nil
		}
		return nil, 0, errors.New("pq: canceling statement due to statement timeout")
	}
	var asked int
	json := `[{"common_name":"only-json.example.org","name_value":"only-json.example.org"}]`
	names, note, err := runCrtsh(t, q, crtshSession(200, json, &asked))
	slices.Sort(names)
	if len(names) > 0 {
		names = slices.Compact(names)
	}
	if err != nil || len(names) != crtshLimit+1 || asked != 1 || !strings.Contains(note, "JSON API gave the rest") || !strings.Contains(note, "statement timeout") {
		t.Errorf("JSON rest: %d names, err %v, asked %d, note %q", len(names), err, asked, note)
	}
	names, note, err = runCrtsh(t, q, crtshSession(404, "", new(int)))
	if err != nil || len(names) != crtshLimit || !strings.Contains(note, "may be more names") {
		t.Errorf("neither: %d names, err %v, note %q", len(names), err, note)
	}
}

// A database that does not answer the limited query leaves most of the
// source's time to the JSON API: the query is cut at a quarter of it.
func TestCrtshSlowDatabaseLeavesTimeForJSON(t *testing.T) {
	var qdl time.Time
	var jsonLeft time.Duration
	c := New(Options{Client: &http.Client{Transport: rtFunc(func(r *http.Request) (*http.Response, error) {
		dl, _ := r.Context().Deadline()
		jsonLeft = time.Until(dl)
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`[{"common_name":"j.example.org","name_value":"j.example.org"}]`)), Request: r, Header: http.Header{}}, nil
	})}})
	sess := &subscraping.Session{Client: c.opts.Client, RequestLimiter: c.limiter, Timeout: 5}
	old := crtshQuery
	crtshQuery = func(ctx context.Context, _ string, _ *url.URL, _ time.Duration, _ int) ([]string, int, error) {
		qdl, _ = ctx.Deadline()
		<-ctx.Done() // never answers
		return nil, 0, ctx.Err()
	}
	defer func() { crtshQuery = old }()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	start := time.Now()
	names, err := crtshSource().collect(ctx, "example.org", nil, sess)
	if err != nil || len(names) == 0 || names[0] != "j.example.org" {
		t.Fatalf("names %v, err %v", names, err)
	}
	if took := qdl.Sub(start); took > 2500*time.Millisecond {
		t.Errorf("the limited query was given %s of 8 s", took)
	}
	if jsonLeft < 5*time.Second {
		t.Errorf("the JSON API had %s left of 8 s", jsonLeft)
	}
}

func TestCrtshFallsBackToJSON(t *testing.T) {
	json := `[{"common_name":"c.example.org","name_value":"x.example.org\ny.example.org"}]`
	for name, q := range map[string]func(context.Context, string, *url.URL, time.Duration, int) ([]string, int, error){
		"error": func(context.Context, string, *url.URL, time.Duration, int) ([]string, int, error) {
			return nil, 0, errors.New("connection refused")
		},
		"nothing": func(context.Context, string, *url.URL, time.Duration, int) ([]string, int, error) { return nil, 0, nil },
	} {
		var asked int
		names, note, err := runCrtsh(t, q, crtshSession(200, json, &asked))
		if err != nil || !slices.Equal(names, []string{"c.example.org", "x.example.org", "y.example.org"}) {
			t.Errorf("%s: names %v, err %v", name, names, err)
		}
		if asked != 1 || !strings.Contains(note, "JSON API") {
			t.Errorf("%s: JSON API asked %d times, note %q", name, asked, note)
		}
	}
	// Neither answers: the JSON API's error is the source's.
	_, _, err := runCrtsh(t, func(context.Context, string, *url.URL, time.Duration, int) ([]string, int, error) {
		return nil, 0, errors.New("down")
	},
		crtshSession(404, "", new(int)))
	if err == nil {
		t.Error("both failed and the source reported no error")
	}
}

// An HTTP proxy cannot carry PostgreSQL: the database is not tried, the
// JSON API goes through the proxy, and the note says so. SOCKS5 carries both.
func TestCrtshProxy(t *testing.T) {
	via := func(raw string) *http.Client {
		u, _ := url.Parse(raw)
		return &http.Client{Transport: &retryTransport{next: &http.Transport{Proxy: http.ProxyURL(u)}}}
	}
	if u, err := crtshProxy(via("socks5://127.0.0.1:9050")); err != nil || u == nil || u.Host != "127.0.0.1:9050" {
		t.Errorf("socks5: %v, %v", u, err)
	}
	if u, err := crtshProxy(via("http://127.0.0.1:8080")); err == nil || u != nil || !strings.Contains(err.Error(), "http proxy") {
		t.Errorf("http: %v, %v", u, err)
	}
	if u, err := crtshProxy(&http.Client{Transport: &http.Transport{}}); err != nil || u != nil {
		t.Errorf("none: %v, %v", u, err)
	}
	called := false
	old := crtshQuery
	crtshQuery = func(context.Context, string, *url.URL, time.Duration, int) ([]string, int, error) {
		called = true
		return nil, 0, nil
	}
	defer func() { crtshQuery = old }()
	if _, _, err := crtshDatabase(context.Background(), "example.org", via("http://127.0.0.1:8080"), crtshLimitedShare, crtshLimit); err == nil || called {
		t.Errorf("an http proxy: err %v, database asked %v", err, called)
	}
}

// Through a SOCKS5 proxy the database is asked for crt.sh's PostgreSQL
// port by name, so the proxy resolves it; here the proxy only notes it
// and refuses.
func TestCrtshThroughSocks(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	asked := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		b := make([]byte, 262)
		if _, err := io.ReadFull(c, b[:3]); err != nil { // version, one method
			return
		}
		_, _ = c.Write([]byte{5, 0})
		if _, err := io.ReadFull(c, b[:5]); err != nil || b[3] != 3 { // domain name
			return
		}
		n := int(b[4])
		if _, err := io.ReadFull(c, b[5:5+n+2]); err != nil {
			return
		}
		asked <- string(b[5:5+n]) + ":" + strconv.Itoa(int(b[5+n])<<8|int(b[6+n]))
		_, _ = c.Write([]byte{5, 2, 0, 1, 0, 0, 0, 0, 0, 0})
	}()
	via, _ := url.Parse("socks5://" + ln.Addr().String())
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, _, err := queryCrtsh(ctx, "example.org", via, 5*time.Second, crtshLimit); err == nil {
		t.Error("a refused connection gave no error")
	}
	select {
	case got := <-asked:
		if got != "crt.sh:5432" {
			t.Errorf("the proxy was asked for %s, want crt.sh:5432", got)
		}
	default:
		t.Error("the proxy was not asked")
	}
}
