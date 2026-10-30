package portscan

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"net"
	"strconv"
	"time"

	"github.com/trannghiach/azhaq/internal/ledger"
)

// maxProbes is how many more connects an open port that said nothing may
// cost to find out what it serves: the TLS handshake, the requests of the
// protocols usual on its number and the ladder of the others. The GET for
// a web page's body is counted apart (at most two).
const maxProbes = 24

// ladderLimit: by default, after this many open ports of one address that
// no probe could name, the rest of that address's silent ports are not run
// down the ladder (a firewall or tarpit that accepts every connect would
// cost thousands of connects for nothing). Scanner.Unnamed changes it; the
// report says how many were skipped.
const ladderLimit = 6

// target is what a request is built for.
type target struct {
	host string
	port int
}

// A protocol is what a service answers to a harmless request of its own,
// written from the protocol's public specification (named where it is
// declared). Nothing here logs in, writes or changes state.
type protocol struct {
	name     string
	ports    []int // usual TCP ports: the request goes there first
	tlsPorts []int // usual ports of the TLS-wrapped variant
	// request is sent to a port that waits to be asked; nil for a
	// protocol read only from what a port says.
	request func(t target) []byte
	// frame says how many bytes the whole answer has (0: not known yet,
	// -1: not this protocol's), so the read stops when it is complete.
	frame func(b []byte) int
	// read reads an answer (or a greeting) and fills in what it says;
	// false when it is not this protocol's.
	read func(r []byte, o *Open) bool
	// deepen asks once more on the same connection for a version the
	// first answer does not give.
	deepen func(s *Scanner, c net.Conn, o *Open)
	// passive: read is strict enough to try on any greeting or answer.
	passive bool
}

var protocols []*protocol

func register(ps ...*protocol) { protocols = append(protocols, ps...) }

func protocolNamed(name string) *protocol {
	for _, p := range protocols {
		if p.name == name {
			return p
		}
	}
	return nil
}

// protocolsOn lists the protocols with a request whose usual port this is.
func protocolsOn(port int, secure bool) []*protocol {
	var out []*protocol
	for _, p := range protocols {
		ports := p.ports
		if secure {
			ports = p.tlsPorts
		}
		for _, q := range ports {
			if q == port && p.request != nil {
				out = append(out, p)
			}
		}
	}
	return out
}

// The ladder: the order a port that is none of its usual protocols is asked
// in, the likeliest first. How the HEAD ended says too little to reorder
// it: a DNS server may hold the connection or drop it on its idle timer.
var ladderOrder = []string{
	"redis", "postgresql", "mongodb", "memcached", "mqtt", "amqp", "dns", "ldap", "smb", "mssql", "kafka", "rdp",
	"zookeeper", "cassandra", "oracle-tns", "sip", "rtsp", "socks5", "x11", "stomp", "xmpp",
}

func ladder() []*protocol {
	var out []*protocol
	for _, n := range ladderOrder {
		if p := protocolNamed(n); p != nil {
			out = append(out, p)
		}
	}
	return out
}

// ident is one open port's identification: the connects it may still make.
type ident struct {
	s        *Scanner
	ctx      context.Context
	o        *Open
	host, ip string
	left     int
	tried    map[string]bool
	rtt      time.Duration // the shortest connect seen: how long a quiet answer is worth waiting for
}

// dial opens a connection of the identification: paced, counted against the
// run's budget and written to the ledger like any connect.
func (id *ident) dial(secure bool) (net.Conn, error) {
	if id.left <= 0 {
		return nil, errors.New("probes spent")
	}
	id.left--
	t0 := time.Now()
	c, err := id.s.dial(id.ctx, id.host, id.ip, id.o.Port, secure)
	if d := time.Since(t0); err == nil && !secure && (id.rtt == 0 || d < id.rtt) {
		id.rtt = d
	}
	return c, err
}

// patience is how long a request on a fresh connection is waited on:
// twenty round trips, but at least half a second (a JVM service is slow to
// its first answer) and at most the banner wait.
func (id *ident) patience(floor time.Duration) time.Duration {
	w := 20 * id.rtt
	if w < floor {
		w = floor
	}
	return min(w, id.s.Timeout+id.s.Banner)
}

// dial is a paced, counted and recorded connect to a port; secure wraps it
// in a TLS handshake.
func (s *Scanner) dial(ctx context.Context, host, ip string, port int, secure bool) (net.Conn, error) {
	return s.dialWait(ctx, host, ip, port, secure, s.Timeout+s.Banner)
}

// dialWait is dial with a bound on the TLS handshake.
func (s *Scanner) dialWait(ctx context.Context, host, ip string, port int, secure bool, handshake time.Duration) (net.Conn, error) {
	if err := s.wait(ctx, ip); err != nil {
		return nil, err
	}
	if s.Take != nil {
		if err := s.Take(); err != nil {
			s.noteStop(err)
			return nil, err
		}
	}
	if host == "" {
		host = ip
	}
	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	ledger.TCP(ctx, host, addr)
	d := s.dialer(ip)
	if !secure {
		return d.DialContext(ctx, "tcp", addr)
	}
	cfg := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10}
	if net.ParseIP(host) == nil {
		cfg.ServerName = host
	}
	hctx, cancel := context.WithTimeout(ctx, handshake)
	defer cancel()
	return (&tls.Dialer{NetDialer: &d, Config: cfg}).DialContext(hctx, "tcp", addr)
}

// talk writes req (when there is one) and reads the answer until frame
// says it is whole, the port closes, or nothing more comes. The first byte
// may take until wait; after that a pause of a fifth of a second ends it.
func (s *Scanner) talk(conn net.Conn, req []byte, frame func([]byte) int, wait time.Duration) []byte {
	_ = conn.SetDeadline(time.Now().Add(wait))
	if len(req) > 0 {
		if _, err := conn.Write(req); err != nil {
			return nil
		}
	}
	var buf []byte
	tmp := make([]byte, 4096)
	for len(buf) < 1<<16 {
		n, err := conn.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if err != nil || n == 0 {
			break
		}
		if frame != nil {
			need := frame(buf)
			if need < 0 || need > 0 && len(buf) >= need {
				break
			}
			if need > 0 {
				continue // a longer answer is on its way
			}
		}
		_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	}
	return buf
}

// try asks p on conn and reads the answer; it says whether p recognised it.
func (id *ident) try(conn net.Conn, p *protocol) bool {
	s := id.s
	id.tried[p.name] = true
	reply := s.talk(conn, p.request(target{id.host, id.o.Port}), p.frame, id.patience(500*time.Millisecond))
	return id.accept(conn, p, reply)
}

// accept applies p's reader to an answer and, on a match, takes what it says.
func (id *ident) accept(conn net.Conn, p *protocol, reply []byte) bool {
	if len(reply) == 0 {
		return false
	}
	o := *id.o
	if !p.read(reply, &o) {
		return false
	}
	if o.Service == "" {
		o.Service = p.name
	}
	if o.Banner == "" && isText(reply) {
		o.Banner = printable(reply)
	}
	*id.o = o
	if p.deepen != nil && conn != nil {
		p.deepen(id.s, conn, id.o)
	}
	return true
}

// passive reads an answer with every protocol that is strict enough to
// tell from a single answer.
func (id *ident) passive(reply []byte) bool { return passiveRead(reply, id.o) }

// bannerOf is what to show of an answer: its first printable line, or for
// a binary one, its first bytes in hex.
func bannerOf(b []byte) string {
	p := printable(b)
	if p == "(binary)" {
		return "(binary) " + hex.EncodeToString(b[:min(len(b), 16)])
	}
	return p
}

// identify asks a port that said nothing what it serves. A port on its
// usual number is asked its own protocol first, on the connection already
// open. Then an HTTP HEAD (with a GET for the page of one whose HEAD is
// refused); then, for an answer that is not text, a TLS handshake on a
// second connection (the greeting inside is read before any request); and
// last the ladder of protocols that wait to be asked, each on a connection
// of its own. Every connect is paced, counted and recorded, and an open
// port costs at most maxProbes more.
func (s *Scanner) identify(ctx context.Context, o *Open, conn net.Conn, host, ip string, rtt time.Duration) {
	if host == "" {
		host = ip
	}
	id := &ident{s: s, ctx: ctx, o: o, host: host, ip: ip, left: maxProbes, tried: map[string]bool{}, rtt: rtt}
	for _, p := range protocolsOn(o.Port, false) {
		if id.try(conn, p) {
			return
		}
		// What it was sent may have left it mid-message: a fresh connection.
		if c, err := id.dial(false); err == nil {
			defer c.Close()
			conn = c
		} else {
			return
		}
	}
	head := s.ask(conn, host, o.Port, 80)
	wantTLS := true
	if status, banner, ok := httpAnswer(head); ok {
		o.Service, o.Banner = "http", banner
		s.webProduct(ctx, o, head, status, host, ip, false)
		if status != 400 {
			return
		}
	} else if icyAnswer(head, o) {
		return
	} else if _, product, _ := greetingProduct(head, printable(head)); product != "" {
		// A greeting that came late, in reply to the HEAD.
		o.Banner = printable(head)
		s.greeted(o, head)
		return
	} else if id.passive(head) {
		return
	} else if len(head) > 0 {
		// Kept, binary or not: a TLS alert, another protocol's complaint.
		o.Banner = bannerOf(head)
		// A text answer that is not HTTP is another protocol's: not TLS.
		wantTLS = !isText(head)
	}
	if wantTLS && id.tls() {
		return
	}
	// A port whose service greets first and said nothing, twice, is not
	// asked the ladder: it is a greeter that is slow, not one that waits.
	if speaksFirst(o.Port) {
		return
	}
	if !s.ladderAllowed(ip) {
		return
	}
	named := false
	defer func() {
		if !named && o.Service == "" {
			s.ladderFailed(ip)
		}
	}()
	for _, p := range ladder() {
		if id.left <= 0 || ctx.Err() != nil {
			return
		}
		if id.tried[p.name] || p.request == nil {
			continue
		}
		c, err := id.dial(false)
		if err != nil {
			return
		}
		ok := id.try(c, p)
		c.Close()
		if ok {
			named = true
			return
		}
	}
}

// ladderAllowed says whether this address's silent ports are still run down
// the ladder; ladderFailed counts one that no probe could name.
func (s *Scanner) ladderAllowed(ip string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	limit := ladderLimit
	switch {
	case s.Unnamed < 0:
		return true
	case s.Unnamed > 0:
		limit = s.Unnamed
	}
	if s.unnamed[ip] >= limit {
		s.skipped[ip]++
		return false
	}
	return true
}

func (s *Scanner) ladderFailed(ip string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.unnamed == nil {
		s.unnamed, s.skipped = map[string]int{}, map[string]int{}
	}
	s.unnamed[ip]++
}

func isText(b []byte) bool {
	t := printable(b)
	return t != "" && t != "(binary)"
}

// icyAnswer reads a SHOUTcast or Icecast stream's status line, which is HTTP
// in all but its name.
func icyAnswer(head []byte, o *Open) bool {
	if !bytes.HasPrefix(head, []byte("ICY ")) {
		return false
	}
	o.Service, o.Banner = "icy", printable(head)
	o.Product, o.Version = headerProduct(head)
	return true
}

// dialTLS is dial(true) with a handshake that waits only as long as a
// plain port is worth: a TLS server answers a ClientHello at once.
func (id *ident) dialTLS() (net.Conn, error) {
	if id.left <= 0 {
		return nil, errors.New("probes spent")
	}
	id.left--
	return id.s.dialWait(id.ctx, id.host, id.ip, id.o.Port, true, id.patience(time.Second))
}

// tls tries a handshake and, inside it, the greeting, then the HEAD (or the
// protocol the port is usually wrapped in). It says whether the port speaks
// TLS.
func (id *ident) tls() bool {
	s, o := id.s, id.o
	c, err := id.dialTLS()
	if err != nil {
		return false
	}
	defer c.Close()
	o.TLS = true
	o.Service, o.Banner = "tls", ""
	if certs := c.(*tls.Conn).ConnectionState().PeerCertificates; len(certs) > 0 {
		o.SubjectCN = certs[0].Subject.CommonName
		o.SubjectAN = append(o.SubjectAN, certs[0].DNSNames...)
		for _, a := range certs[0].IPAddresses {
			o.SubjectAN = append(o.SubjectAN, a.String())
		}
	}
	// A service that greets first (IMAPS, POP3S, SMTPS) says so inside.
	// It speaks as soon as the handshake ends, so a short wait is enough, and
	// an HTTPS port, which does not, loses little by it.
	greeting := s.talk(c, nil, nil, min(max(3*id.rtt, 150*time.Millisecond), s.Banner))
	if len(greeting) > 0 {
		o.Banner = bannerOf(greeting)
		s.greeted(o, greeting)
		if svc := bannerService(o.Banner); svc != "" {
			o.Service = svc
		} else if id.passive(greeting) {
			return true
		}
		if o.Service != "tls" {
			return true
		}
	}
	if hinted := protocolsOn(o.Port, true); len(hinted) > 0 {
		for _, p := range hinted {
			if id.try(c, p) {
				return true
			}
			c.Close()
			c2, err := id.dialTLS()
			if err != nil {
				return true
			}
			defer c2.Close()
			c = c2
		}
	}
	head := s.ask(c, id.host, o.Port, 443)
	if status, banner, ok := httpAnswer(head); ok {
		o.Service, o.Banner = "https", banner
		s.webProduct(id.ctx, o, head, status, id.host, id.ip, true)
	} else if len(head) > 0 && id.passive(head) {
		return true
	}
	return true
}

// noteStop keeps the error that stopped a probe (the run's request budget is
// spent) so the scan reports it, though the port that met it goes on as it was.
func (s *Scanner) noteStop(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stop == nil {
		s.stop = err
	}
}
