package subcol

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/lib/pq"
	"golang.org/x/net/proxy"

	"github.com/trannghiach/azhaq/internal/fetch"
)

// crtshStatement has no LIMIT: it lists at least what subfinder lists,
// which drops its own limit only with -all. The source's time bounds it.
const crtshStatement = `SELECT DISTINCT cai.NAME_VALUE
FROM certificate_and_identities cai
WHERE plainto_tsquery('certwatch', $1) @@ identities(cai.CERTIFICATE)
	AND cai.NAME_VALUE ILIKE ('%' || $1 || '%')`

// crtshQuery is crtshDatabase's lookup; tests replace it.
var crtshQuery = queryCrtsh

// sqlShare is the part of a source's time the database may use, so that
// the JSON API still has some when the database hangs.
const sqlShare = 0.6

// crtshDatabase asks crt.sh's PostgreSQL for the names of domain. It is
// a lookup of a public source, not target traffic, and goes where the
// other sources go: through the source proxy when that is SOCKS5; an
// HTTP proxy cannot carry PostgreSQL, so the caller is told to use the
// JSON API.
func crtshDatabase(ctx context.Context, domain string, client *http.Client) ([]string, error) {
	via, err := crtshProxy(client)
	if err != nil {
		return nil, err
	}
	budget := 30 * time.Second
	if dl, ok := ctx.Deadline(); ok {
		budget = time.Until(dl)
	}
	budget = time.Duration(float64(budget) * sqlShare)
	if budget < time.Second {
		return nil, errors.New("too little time left for it")
	}
	qctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	countCall(ctx)
	return crtshQuery(qctx, domain, via, budget)
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
	switch t := tr.(type) {
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
func queryCrtsh(ctx context.Context, domain string, via *url.URL, budget time.Duration) ([]string, error) {
	dsn := fmt.Sprintf("host=crt.sh user=guest dbname=certwatch sslmode=disable binary_parameters=yes connect_timeout=%d", max(1, int(budget/time.Second)))
	c, err := pq.NewConnector(dsn)
	if err != nil {
		return nil, err
	}
	d, err := crtshDialer(via)
	if err != nil {
		return nil, err
	}
	c.Dialer(d)
	db := sql.OpenDB(c)
	defer db.Close()
	return namesFromDB(ctx, db, domain, budget)
}

// namesFromDB runs the lookup on one connection, whose statement_timeout
// is the budget, and splits each NAME_VALUE into its names.
func namesFromDB(ctx context.Context, db *sql.DB, domain string, budget time.Duration) ([]string, error) {
	conn, err := db.Conn(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, fmt.Sprintf("SET statement_timeout = %d;", budget.Milliseconds())); err != nil {
		return nil, err
	}
	rows, err := conn.QueryContext(ctx, crtshStatement, domain)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return names, err
		}
		names = append(names, strings.Split(v, "\n")...)
	}
	return names, rows.Err()
}

// pgDialer connects as the run's HTTP client does (the resolver's
// addresses), or through a SOCKS5 proxy.
type pgDialer struct{ via proxy.ContextDialer }

func crtshDialer(via *url.URL) (*pgDialer, error) {
	if via == nil {
		return &pgDialer{}, nil
	}
	d, err := proxy.FromURL(via, &net.Dialer{Timeout: 10 * time.Second})
	if err != nil {
		return nil, err
	}
	cd, ok := d.(proxy.ContextDialer)
	if !ok {
		return nil, errors.New("the proxy dialer takes no context")
	}
	return &pgDialer{via: cd}, nil
}

func (d *pgDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if d.via != nil {
		return d.via.DialContext(ctx, network, addr)
	}
	return fetch.Dial(ctx, network, addr)
}

func (d *pgDialer) Dial(network, addr string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, addr)
}

func (d *pgDialer) DialTimeout(network, addr string, timeout time.Duration) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return d.DialContext(ctx, network, addr)
}
