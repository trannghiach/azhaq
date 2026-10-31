package subcol

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/trannghiach/azhaq/internal/egress"
)

// crtshStatement is subfinder's lookup; crtshLimit is its "LIMIT 10000"
// (it drops it only with -all), which keeps crt.sh's query to seconds.
// A full page is asked again without the limit, within the source's time.
const crtshStatement = `SELECT DISTINCT cai.NAME_VALUE
FROM certificate_and_identities cai
WHERE plainto_tsquery('certwatch', $1) @@ identities(cai.CERTIFICATE)
	AND cai.NAME_VALUE ILIKE ('%' || $1 || '%')`

const crtshLimit = 10000

// crtshQuery is crtshDatabase's lookup, up to limit rows (0: all of them);
// it gives the names, and how many rows they came from. Tests replace it.
var crtshQuery = queryCrtsh

// The parts of the source's remaining time the database may use. The
// limited query answers in seconds or not at all, so it gets a quarter and
// leaves most of the time to the JSON API; the query for the rest of a
// full page is slow by nature and gets most of what is left.
const (
	crtshLimitedShare = 0.25
	crtshRestShare    = 0.6
)

// crtshDatabase asks crt.sh's PostgreSQL for the names of domain, up to
// limit rows, in share of the time the source has left. It is a lookup of
// a public source, not target traffic, and goes where the other sources
// go: through the source proxy when that is SOCKS5; an HTTP proxy cannot
// carry PostgreSQL, so the caller is told to use the JSON API.
func crtshDatabase(ctx context.Context, domain string, client *http.Client, share float64, limit int) ([]string, int, error) {
	via, err := crtshProxy(client)
	if err != nil {
		return nil, 0, err
	}
	budget := 30 * time.Second
	if dl, ok := ctx.Deadline(); ok {
		budget = time.Until(dl)
	}
	budget = time.Duration(float64(budget) * share)
	if budget < time.Second {
		return nil, 0, errors.New("too little time left for it")
	}
	qctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	countCall(ctx)
	return crtshQuery(qctx, domain, via, budget, limit)
}

// crtshProxy is the SOCKS5 proxy the source requests go through, nil for
// none, or an error when the proxy is one PostgreSQL cannot pass.
func crtshProxy(client *http.Client) (*url.URL, error) {
	var tr http.RoundTripper
	if client != nil {
		tr = client.Transport
	}
	if rt, ok := tr.(*retryTransport); ok {
		tr = rt.next
	}
	var fn func(*http.Request) (*url.URL, error)
	switch t := egress.Unwrap(tr).(type) {
	case *http.Transport:
		fn = t.Proxy
	case nil:
		fn = http.ProxyFromEnvironment
	}
	if fn == nil {
		return nil, nil
	}
	u, err := fn(&http.Request{URL: &url.URL{Scheme: "https", Host: "crt.sh", Path: "/"}})
	if err != nil || u == nil {
		return nil, nil
	}
	switch u.Scheme {
	case "socks5", "socks5h":
		return u, nil
	}
	return nil, fmt.Errorf("an %s proxy cannot carry PostgreSQL (use a socks5 proxy to use it)", u.Scheme)
}

// queryCrtsh connects to crt.sh's database, directly or through a SOCKS5
// proxy, and returns the names the certificates there hold for domain.
func queryCrtsh(ctx context.Context, domain string, via *url.URL, budget time.Duration, limit int) ([]string, int, error) {
	dsn := fmt.Sprintf("host=crt.sh user=guest dbname=certwatch sslmode=disable binary_parameters=yes connect_timeout=%d", max(1, int(budget/time.Second)))
	db, err := egress.OpenSourceDB(dsn, via)
	if err != nil {
		return nil, 0, err
	}
	defer db.Close()
	return namesFromDB(ctx, db, domain, budget, limit)
}

// namesFromDB runs the lookup on one connection, whose statement_timeout
// is the budget, and splits each NAME_VALUE into its names; it also says
// how many rows it read.
func namesFromDB(ctx context.Context, db *sql.DB, domain string, budget time.Duration, limit int) ([]string, int, error) {
	conn, err := db.Conn(ctx)
	if err != nil {
		return nil, 0, err
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, fmt.Sprintf("SET statement_timeout = %d;", budget.Milliseconds())); err != nil {
		return nil, 0, err
	}
	stmt := crtshStatement
	if limit > 0 {
		stmt += fmt.Sprintf("\nLIMIT %d", limit)
	}
	rows, err := conn.QueryContext(ctx, stmt, domain)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var names []string
	n := 0
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return names, n, err
		}
		n++
		names = append(names, strings.Split(v, "\n")...)
	}
	return names, n, rows.Err()
}
