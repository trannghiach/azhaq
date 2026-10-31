package egress

import (
	"context"
	"database/sql"
	"errors"
	"net"
	"net/url"
	"time"

	"github.com/lib/pq"
	"golang.org/x/net/proxy"

	"github.com/trannghiach/azhaq/internal/ledger"
)

// OpenSourceDB opens a PostgreSQL database that is a third-party source
// (crt.sh's public one), directly or through a SOCKS5 proxy. Each
// connection is held to the kill file and recorded as a source's.
func OpenSourceDB(dsn string, via *url.URL) (*sql.DB, error) {
	c, err := pq.NewConnector(dsn)
	if err != nil {
		return nil, err
	}
	d := &sourceDialer{}
	if via != nil {
		pd, err := proxy.FromURL(via, &net.Dialer{Timeout: 10 * time.Second})
		if err != nil {
			return nil, err
		}
		cd, ok := pd.(proxy.ContextDialer)
		if !ok {
			return nil, errors.New("the proxy dialer takes no context")
		}
		d.via = cd
	}
	c.Dialer(d)
	return sql.OpenDB(c), nil
}

type sourceDialer struct{ via proxy.ContextDialer }

func (d *sourceDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if d.via == nil {
		return DialSource(ctx, network, addr)
	}
	if err := Current().Killed(); err != nil {
		return nil, err
	}
	ledger.TCPAs(ctx, ledger.ClassSource, "", addr)
	return d.via.DialContext(ctx, network, addr)
}

func (d *sourceDialer) Dial(network, addr string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, addr)
}

func (d *sourceDialer) DialTimeout(network, addr string, timeout time.Duration) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return d.DialContext(ctx, network, addr)
}
