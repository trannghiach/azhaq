package dnsr

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
)

// Transports of a resolver.
const (
	NetUDP = "udp"
	NetTCP = "tcp"
	NetDoT = "dot"
	NetDoH = "doh"
)

// Server is a resolver and how to reach it. Key is its spelling in a Pool
// and in the results: host:port for plain UDP, otherwise tcp:host:port,
// dot:host:port or doh:URL (with :get for GET; POST is the default).
type Server struct {
	Key  string
	Net  string
	Addr string // host:port; the URL for DoH
	GET  bool   // DoH by GET
}

// ParseResolver reads one resolver:
//
//	1.1.1.1  1.1.1.1:5353  [2606:4700::1111]:53  ::1     UDP, port 53 unless given
//	udp:HOST[:PORT]  tcp:HOST[:PORT]                      the transport named
//	dot:HOST[:PORT]                                       DNS over TLS, port 853
//	doh:https://HOST/PATH[:get|:post]                     DNS over HTTPS, POST unless :get
//
// A host name, not an address, needs a port or a prefix: a bare word is
// more likely a mistyped file name than a resolver.
func ParseResolver(s string) (Server, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Server{}, fmt.Errorf("empty resolver")
	}
	netw, rest := NetUDP, s
	prefixed := false
	if len(s) > 4 && s[3] == ':' {
		switch strings.ToLower(s[:3]) {
		case "udp", "tcp", "dot", "doh":
			netw, rest, prefixed = strings.ToLower(s[:3]), s[4:], true
		}
	}
	if netw == NetDoH {
		return parseDoH(s, rest)
	}
	host, port, err := net.SplitHostPort(rest)
	if err != nil {
		host, port = strings.Trim(rest, "[]"), "53"
		if netw == NetDoT {
			port = "853"
		}
		if net.ParseIP(host) == nil && !prefixed {
			return Server{}, fmt.Errorf("%q is neither a file nor a resolver: an address (1.1.1.1), HOST:PORT, or udp:, tcp:, dot:, doh: and an address", s)
		}
	}
	if host == "" || port == "" || strings.ContainsAny(host, "/ \t") {
		return Server{}, fmt.Errorf("%q is not a resolver address", s)
	}
	addr := net.JoinHostPort(host, port)
	key := addr
	if netw != NetUDP {
		key = netw + ":" + addr
	}
	return Server{Key: key, Net: netw, Addr: addr}, nil
}

func parseDoH(orig, rest string) (Server, error) {
	get := false
	switch {
	case strings.HasSuffix(rest, ":get"):
		rest, get = strings.TrimSuffix(rest, ":get"), true
	case strings.HasSuffix(rest, ":post"):
		rest = strings.TrimSuffix(rest, ":post")
	case strings.HasSuffix(rest, ":jsonapi"):
		return Server{}, fmt.Errorf("%q: the JSON API of DoH is not supported; give the RFC 8484 URL with :get or :post", orig)
	}
	u, err := url.Parse(rest)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return Server{}, fmt.Errorf("%q: doh: wants a URL such as doh:https://dns.example/dns-query", orig)
	}
	key := "doh:" + rest
	if get {
		key += ":get"
	}
	return Server{Key: key, Net: NetDoH, Addr: rest, GET: get}, nil
}

// ParseResolvers reads a resolver specification: the name of a file with
// one resolver per line (blank lines and # comments skipped), or resolvers
// separated by commas. This is the one place resolvers are read; every
// command that takes -resolvers goes through it. The keys come back in
// order, once each, ready for Options.Resolvers.
func ParseResolvers(spec string) ([]string, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, nil
	}
	var entries []string
	if fi, err := os.Stat(spec); err == nil && !fi.IsDir() {
		f, err := os.Open(spec)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			if l := strings.TrimSpace(sc.Text()); l != "" && !strings.HasPrefix(l, "#") {
				entries = append(entries, l)
			}
		}
		if err := sc.Err(); err != nil {
			return nil, err
		}
		if len(entries) == 0 {
			return nil, fmt.Errorf("%s holds no resolvers", spec)
		}
	} else {
		entries = strings.Split(spec, ",")
	}
	var out []string
	seen := map[string]bool{}
	for _, e := range entries {
		if strings.TrimSpace(e) == "" {
			continue
		}
		s, err := ParseResolver(e)
		if err != nil {
			return nil, err
		}
		if !seen[s.Key] {
			seen[s.Key] = true
			out = append(out, s.Key)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no resolvers in %q", spec)
	}
	return out, nil
}

// dotConn wraps c, a connection to a DoT resolver, in TLS.
func dotConn(ctx context.Context, c net.Conn, addr string, cfg *tls.Config) (net.Conn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	var tc *tls.Config
	if cfg != nil {
		tc = cfg.Clone()
	} else {
		tc = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	if tc.ServerName == "" {
		tc.ServerName = host
	}
	conn := tls.Client(c, tc)
	if err := conn.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	return conn, nil
}
