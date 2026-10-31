package portscan

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"maps"
	"net"
	"strconv"
	"sync"
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
	left     *probeBudget // shared by the forks that ask beside each other
	tried    map[string]bool
	rtt      time.Duration // the shortest connect seen: how long a quiet answer is worth waiting for
	// shook is called once a TLS handshake of this identification succeeded.
	shook func()
}

// probeBudget is what a port's identification may still connect, and whether
// the port stopped accepting (a plain connect failed).
type probeBudget struct {
	mu   sync.Mutex
	n    int
	dead bool
}

var errProbesSpent = errors.New("probes spent")

func (b *probeBudget) take() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.n <= 0 || b.dead {
		return false
	}
	b.n--
	return true
}

func (b *probeBudget) fail() {
	b.mu.Lock()
	b.dead = true
	b.mu.Unlock()
}

func (b *probeBudget) spent() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.n <= 0 || b.dead
}

// fork is an identification that asks beside this one: its own copy of what
// is known so far, the same budget of connects.
func (id *ident) fork(ctx context.Context) *ident {
	o := *id.o
	return &ident{s: id.s, ctx: ctx, o: &o, host: id.host, ip: id.ip, left: id.left, tried: maps.Clone(id.tried), rtt: id.rtt}
}

// guard closes conn when the identification is cancelled, so a read that
// waits on it ends; the caller stops the guard when it is done with conn.
func (id *ident) guard(conn net.Conn) (stop func() bool) {
	return context.AfterFunc(id.ctx, func() { _ = conn.Close() })
}

// dial opens a connection of the identification: paced, counted against the
// run's budget and written to the ledger like any connect.
func (id *ident) dial(secure bool) (net.Conn, error) {
	if err := id.ctx.Err(); err != nil {
		return nil, err
	}
	if !id.left.take() {
		return nil, errProbesSpent
	}
	t0 := time.Now()
	c, err := id.s.dial(id.ctx, id.host, id.ip, id.o.Port, secure)
	if err != nil && !secure && id.ctx.Err() == nil {
		id.left.fail() // the port no longer accepts: the rest would be refused too
	}
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
	defer id.guard(conn)()
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

// askOwn sends a port that an answer named, but not its product, the named
// protocol's own request on a fresh connection: an AMQP broker answers the
// HEAD with its version header, and says product and version only to AMQP.
func (id *ident) askOwn() {
	if id.o.Product != "" {
		return
	}
	for _, p := range protocols {
		if p.name != id.o.Service || p.request == nil || id.tried[p.name] {
			continue
		}
		if c, err := id.dial(false); err == nil {
			id.try(c, p)
			c.Close()
		}
		return
	}
}

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
// of its own, a few at a time (climb). A HEAD that stays unanswered for a
// while is waited on while the handshake and the ladder are asked beside it
// (speculate), and what it answers still goes first. Every connect is paced,
// counted and recorded, and an open port costs at most maxProbes more.
func (s *Scanner) identify(ctx context.Context, o *Open, conn net.Conn, host, ip string, rtt time.Duration) {
	if host == "" {
		host = ip
	}
	id := &ident{s: s, ctx: ctx, o: o, host: host, ip: ip, left: &probeBudget{n: maxProbes}, tried: map[string]bool{}, rtt: rtt}
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
	// The HEAD is asked on its own goroutine so its silence can be waited
	// out beside other probes.
	hctx, stopHead := context.WithCancel(ctx)
	defer stopHead()
	headc := make(chan []byte, 1)
	go func() {
		stop := context.AfterFunc(hctx, func() { _ = conn.Close() })
		h := s.ask(conn, host, o.Port, 80)
		stop()
		headc <- h
	}()
	var head []byte
	var sp *speculation
	defer func() {
		if sp != nil {
			sp.stop()
		}
	}()
	if wait := id.patience(500 * time.Millisecond); 2*wait <= s.Timeout+s.Banner {
		t := time.NewTimer(wait)
		select {
		case head = <-headc:
		case <-t.C:
			sp = id.speculate()
			select {
			case head = <-headc:
			case r := <-sp.done:
				sp.res, sp.got = r, true
				if r.win > 0 {
					// A protocol of the ladder named it, and no HTTP server
					// is also that: the HEAD's wait is not worth the rest.
					stopHead()
					<-headc
					adopt(o, r.o, true)
					return
				}
				head = <-headc
			}
		}
		t.Stop()
	} else {
		head = <-headc
	}
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
		id.askOwn()
		return
	} else if len(head) > 0 {
		// Kept, binary or not: a TLS alert, another protocol's complaint.
		o.Banner = bannerOf(head)
		// A text answer that is not HTTP is another protocol's: not TLS.
		wantTLS = !isText(head)
	}
	if sp != nil {
		r := sp.result()
		switch {
		case r.win == 0 && wantTLS:
			adopt(o, r.o, false)
			return
		case r.win > 0:
			adopt(o, r.o, true)
			return
		case r.win < 0 && r.ladder:
			if o.Service == "" {
				s.ladderFailed(ip)
			}
			return
		}
		// What was asked beside the HEAD does not apply (the handshake
		// answered, but the HEAD's answer was text of another protocol; or
		// the ladder was left out): go on as if it had not been asked.
		if r.win < 0 && !r.ladder && wantTLS {
			wantTLS = false // the handshake was asked and failed
		}
	}
	if wantTLS && id.tls() {
		return
	}
	// A port whose service greets first and said nothing, twice, is not
	// asked the ladder: it is a greeter that is slow, not one that waits.
	if speaksFirst(o.Port) {
		return
	}
	id.ladder()
}

// adopt takes what a fork found. A protocol of the ladder keeps the banner
// an earlier answer left when it names none of its own.
func adopt(o *Open, found Open, keepBanner bool) {
	b := o.Banner
	*o = found
	if keepBanner && o.Banner == "" {
		o.Banner = b
	}
}

// probe is one connection of the identification that may name the port.
type probe struct {
	run func(sub *ident) bool
	tls bool // the handshake: see race
	// wait is how long the probe holds back, unless it is called off first,
	// when it is asked in a window with the handshake.
	wait time.Duration
}

// laneMax is how many connections one open port's identification may have
// asking at once, its own included. The others are taken from the scan's
// workers only while some are free, so a sweep is not starved by it.
const laneMax = 12

// borrow takes up to n of the scan's workers if they are free; release gives
// them back.
func (s *Scanner) borrow(n int) int {
	got := 0
	for got < n {
		select {
		case s.conns <- struct{}{}:
			got++
		default:
			return got
		}
	}
	return got
}

func (s *Scanner) release(n int) {
	for ; n > 0; n-- {
		<-s.conns
	}
}

// stopped says the run's budget was spent on a probe of this scan.
func (s *Scanner) stopped() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stop != nil
}

// ladderProbes are the protocols of the ladder not yet asked, in its order.
func (id *ident) ladderProbes() []probe {
	var out []probe
	for _, p := range ladder() {
		if id.tried[p.name] || p.request == nil {
			continue
		}
		out = append(out, probe{run: func(sub *ident) bool {
			c, err := sub.dial(false)
			if err != nil {
				return false
			}
			defer c.Close()
			return sub.try(c, p)
		}})
	}
	return out
}

// ladder runs the protocols that wait to be asked down the list until one
// answers, unless this address has too many ports no probe could name.
func (id *ident) ladder() {
	s := id.s
	if !s.ladderOpen(id.ip) {
		s.ladderSkip(id.ip)
		return
	}
	if id.climb(id.ladderProbes(), []int{3, 6, laneMax}) < 0 && id.o.Service == "" {
		s.ladderFailed(id.ip)
	}
}

// climb asks the probes in order, a window of them at a time (widths gives
// the first widths, the last repeats): a window is only as wide as the free
// workers allow, and a probe that names the port ends the climb. The first
// window is narrow so a likely answer costs few connects, the later ones
// wide so a port that says nothing to any is done in a few waits, not one
// per protocol. It returns the index of the probe that named the port
// (what it found is in id.o), or -1.
func (id *ident) climb(ps []probe, widths []int) int {
	s := id.s
	lanes := 1 + s.borrow(laneMax-1)
	defer s.release(lanes - 1)
	for k, i := 0, 0; i < len(ps); k++ {
		if id.ctx.Err() != nil || id.left.spent() || s.stopped() {
			return -1
		}
		w := min(widths[min(k, len(widths)-1)], lanes, len(ps)-i)
		if win := id.race(ps[i : i+w]); win >= 0 {
			return i + win
		}
		i += w
	}
	return -1
}

// race asks the probes at once, each in a fork of its own. Among the
// probes of the ladder the first in the list that names the port wins, as it
// would down the list: a later probe is called off when an earlier one
// names it, and an earlier one is waited for. The handshake is not part of
// that order: a probe of the ladder that names the port calls it off, and a
// handshake that succeeds calls off the ladder, since a port is not both.
func (id *ident) race(ps []probe) int {
	if len(ps) == 1 {
		sub := id.fork(id.ctx)
		if !ps[0].run(sub) {
			return -1
		}
		*id.o = *sub.o
		return 0
	}
	type outcome struct {
		named bool
		o     Open
	}
	out := make([]outcome, len(ps))
	cancels := make([]context.CancelFunc, len(ps))
	subs := make([]*ident, len(ps))
	for i := range ps {
		var ctx context.Context
		ctx, cancels[i] = context.WithCancel(id.ctx)
		subs[i] = id.fork(ctx)
	}
	hasTLS := false
	for _, p := range ps {
		hasTLS = hasTLS || p.tls
	}
	var mu sync.Mutex
	callOff := func(keep func(j int) bool) {
		for j, cancel := range cancels {
			if !keep(j) {
				cancel()
			}
		}
	}
	var wg sync.WaitGroup
	for i := range ps {
		if ps[i].tls {
			subs[i].shook = func() {
				mu.Lock()
				defer mu.Unlock()
				callOff(func(j int) bool { return ps[j].tls })
			}
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if w := ps[i].wait; w > 0 && hasTLS {
				t := time.NewTimer(w)
				defer t.Stop()
				select {
				case <-t.C:
				case <-subs[i].ctx.Done():
					return
				}
			}
			ok := ps[i].run(subs[i])
			mu.Lock()
			defer mu.Unlock()
			out[i] = outcome{ok, *subs[i].o}
			if ok {
				callOff(func(j int) bool { return j == i || ps[i].tls == ps[j].tls && j < i })
			}
		}()
	}
	wg.Wait()
	for _, cancel := range cancels {
		cancel()
	}
	win := -1
	for i, r := range out {
		if r.named && (win < 0 || ps[i].tls && !ps[win].tls) {
			win = i
		}
	}
	if win >= 0 {
		*id.o = out[win].o
	}
	return win
}

// speculation is the handshake and the ladder asked beside a HEAD that has
// not answered yet. probes[0] is the handshake.
type speculation struct {
	cancel context.CancelFunc
	done   chan specResult
	res    specResult
	got    bool // res holds the result
}

type specResult struct {
	win    int  // the probe that named the port: 0 the handshake, above it the ladder, -1 none
	o      Open // what it found
	ladder bool // the ladder was asked
}

func (id *ident) speculate() *speculation {
	ctx, cancel := context.WithCancel(id.ctx)
	sp := &speculation{cancel: cancel, done: make(chan specResult, 1)}
	sid := id.fork(ctx)
	ps := []probe{{tls: true, run: func(sub *ident) bool { return sub.tls() }}}
	ladder := !speaksFirst(id.o.Port) && id.s.ladderOpen(id.ip)
	if ladder {
		// The handshake gets a head start: a TLS server has shaken hands
		// before the first of these connects, and calls them off.
		grace := min(max(8*id.rtt, 250*time.Millisecond), id.patience(500*time.Millisecond))
		for _, p := range sid.ladderProbes() {
			p.wait = grace
			ps = append(ps, p)
		}
	}
	go func() {
		win := sid.climb(ps, []int{laneMax})
		sp.done <- specResult{win: win, o: *sid.o, ladder: ladder}
	}()
	return sp
}

// result waits for what the speculation found.
func (sp *speculation) result() specResult {
	if !sp.got {
		sp.res, sp.got = <-sp.done, true
	}
	return sp.res
}

// stop calls the speculation off and waits until its connections are shut.
func (sp *speculation) stop() {
	sp.cancel()
	sp.result()
}

// ladderOpen says whether this address's silent ports are still run down the
// ladder; ladderSkip counts one that was not, ladderFailed one that no probe
// could name.
func (s *Scanner) ladderOpen(ip string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	limit := ladderLimit
	switch {
	case s.Unnamed < 0:
		return true
	case s.Unnamed > 0:
		limit = s.Unnamed
	}
	return s.unnamed[ip] < limit
}

func (s *Scanner) ladderSkip(ip string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.skipped == nil {
		s.unnamed, s.skipped = map[string]int{}, map[string]int{}
	}
	s.skipped[ip]++
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
	if err := id.ctx.Err(); err != nil {
		return nil, err
	}
	if !id.left.take() {
		return nil, errProbesSpent
	}
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
	defer id.guard(c)()
	if id.shook != nil {
		id.shook()
	}
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
			defer id.guard(c2)()
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
