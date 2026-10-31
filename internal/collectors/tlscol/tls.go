package tlscol

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"strings"
	"time"

	"github.com/trannghiach/azhaq/catalog"
	"github.com/trannghiach/azhaq/internal/egress"
	"github.com/trannghiach/azhaq/internal/ledger"
	"github.com/trannghiach/azhaq/internal/neterr"
	"github.com/trannghiach/azhaq/internal/normalize"
	"github.com/trannghiach/azhaq/internal/timing"
	"github.com/trannghiach/azhaq/types"
)

const Name = "azhaq-tls"

type Collector struct {
	Port string
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

func New() *Collector {
	return &Collector{Port: "443"}
}

func Register(cat *catalog.Catalog) {
	cat.MustRegister(New())
}

func (c *Collector) Name() string { return Name }

// Info: this collector sends requests to the target, and for a hostname
// waits for DNS so names that do not resolve are never probed.
func (c *Collector) Info() catalog.Info {
	return catalog.Info{Kind: catalog.Touch, After: "azhaq-dns"}
}

func (c *Collector) Inputs() []types.SeedType {
	return []types.SeedType{types.TypeHostname, types.TypeIPAddress}
}

// Skip: an address is read when it came from a network (-asn, -cidr).
func (c *Collector) Skip(seed types.Seed) bool {
	return seed.Type == types.TypeIPAddress && seed.Keys["from"] != "prefix"
}

func (c *Collector) Outputs() []string { return []string{"certificate"} }

func (c *Collector) Run(ctx context.Context, seed types.Seed, emit func(types.Observation) error) (types.RunMeta, error) {
	host := normalize.Hostname(seed.Key())
	if host == "" {
		return types.RunMeta{Status: types.StatusError, Error: "empty host"}, nil
	}
	isIP := net.ParseIP(host) != nil
	if isIP && seed.Type != types.TypeIPAddress {
		return types.RunMeta{Status: types.StatusOK}, nil
	}
	serverName := host
	if isIP {
		serverName = "" // no SNI: the certificate the address serves by default
	}
	port := c.Port
	if port == "" {
		port = "443"
	}
	addr := net.JoinHostPort(host, port)
	if err := egress.Killed(); err != nil {
		return types.RunMeta{Status: types.StatusCapped}, err
	}
	dctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	hs := timing.Start(ctx, "tls.handshake", host)
	defer hs()

	var conn net.Conn
	var err error
	if c.Dial != nil {
		ledger.TCP(ctx, host, addr)
		conn, err = c.Dial(dctx, "tcp", addr)
	} else {
		conn, err = egress.DialTLS(dctx, host, addr, &tls.Config{
			ServerName:         serverName,
			InsecureSkipVerify: true, // observe the presented cert
			MinVersion:         tls.VersionTLS12,
		}, 8*time.Second)
	}
	if err != nil {
		if neterr.UnknownHost(err) || isIP {
			return types.RunMeta{Status: types.StatusOK}, nil // most addresses of a network serve no TLS
		}
		return types.RunMeta{Status: types.StatusError, Error: err.Error()}, err
	}
	defer conn.Close()

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		if tc, ok := conn.(interface{ ConnectionState() tls.ConnectionState }); ok {
			return c.emitState(host, tc.ConnectionState(), emit)
		}
		return types.RunMeta{Status: types.StatusError, Error: "not tls"}, nil
	}
	if err := tlsConn.HandshakeContext(dctx); err != nil {
		return types.RunMeta{Status: types.StatusError, Error: err.Error()}, err
	}
	return c.emitState(host, tlsConn.ConnectionState(), emit)
}

func (c *Collector) emitState(host string, st tls.ConnectionState, emit func(types.Observation) error) (types.RunMeta, error) {
	if len(st.PeerCertificates) == 0 {
		return types.RunMeta{Status: types.StatusError, Error: "no peer cert"}, nil
	}
	cert := st.PeerCertificates[0]
	var sans []string
	for _, n := range cert.DNSNames {
		sans = append(sans, normalize.Hostname(n))
	}
	payload, _ := json.Marshal(map[string]any{
		"fqdn":      host,
		"subject":   cert.Subject.String(),
		"issuer":    cert.Issuer.String(),
		"not_after": cert.NotAfter.UTC().Format(time.RFC3339),
		"dns_names": sans,
		"version":   st.Version,
	})
	err := emit(types.Observation{
		Collector:  Name,
		Source:     host + ":443",
		Kind:       "certificate",
		Payload:    payload,
		Confidence: 0.95,
		ObservedAt: time.Now().UTC(),
	})
	var hints []types.Seed
	if net.ParseIP(host) != nil {
		// An address found by network: its certificate names the service.
		for _, n := range sans {
			n = strings.TrimPrefix(n, "*.")
			if n != "" && normalize.SharedSuffix(n) == "" && len(hints) < 20 {
				hints = append(hints, types.Seed{Type: types.TypeHostname, Keys: map[string]string{"fqdn": n, "from": "prefix"}})
			}
		}
		return types.RunMeta{Status: types.StatusOK, EmitCount: 1, NextHints: hints}, err
	}
	for _, n := range sans {
		if n == "" || n == host || n[0] == '*' {
			continue
		}
		// Default / CDN certs list unrelated names. Stay on this site.
		if !normalize.SameSite(host, n) {
			continue
		}
		hints = append(hints, types.Seed{Type: types.TypeHostname, Keys: map[string]string{"fqdn": n}})
	}
	return types.RunMeta{Status: types.StatusOK, EmitCount: 1, NextHints: hints}, err
}
