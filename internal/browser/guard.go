package browser

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"sync"
	"time"

	"golang.org/x/net/proxy"

	"github.com/trannghiach/azhaq/internal/egress"
	"github.com/trannghiach/azhaq/internal/fetch"
	"github.com/trannghiach/azhaq/internal/ledger"
)

// guard is a SOCKS5 proxy on loopback that Chrome makes every connection
// through. The Fetch domain pauses requests, not connections: a WebSocket,
// a preconnect or Chrome's own services (updates, sign-in, time) reaching
// for a host outside the scope stop here instead. Chrome cannot
// authenticate to a SOCKS proxy: on Linux the guard relays only for the
// processes of the Chrome it was started for (peers), elsewhere for any
// local process, to hosts in the scope.
type guard struct {
	ln      net.Listener
	allowed func(host string) bool
	peers   peers
	ctx     context.Context
	stop    context.CancelFunc
	via     *url.URL // the proxy for Chrome's connections when it is not the environment's

	mu     sync.Mutex
	closed bool
	wg     sync.WaitGroup // connections being handled
	denied map[string]int // host → connections refused for being outside the scope
}

// refuse counts a connection to a host outside the scope.
func (g *guard) refuse(host string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.denied == nil {
		g.denied = map[string]int{}
	}
	g.denied[host]++
}

// Denied is how many connections Chrome opened to hosts outside the scope,
// all refused, and the hosts, sorted.
func (g *guard) Denied() (n int, hosts []string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for h, c := range g.denied {
		n += c
		hosts = append(hosts, h)
	}
	slices.Sort(hosts)
	return n, hosts
}

func newGuard(allowed func(string) bool) (*guard, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	g := &guard{ln: ln, allowed: allowed}
	g.ctx, g.stop = context.WithCancel(context.Background())
	go g.serve()
	return g, nil
}

func (g *guard) addr() string { return g.ln.Addr().String() }

// chrome names the browser process whose processes the guard relays for.
func (g *guard) chrome(pid int) { g.peers.set(pid) }

// close stops the guard and the connections it relays, and waits for them.
func (g *guard) close() {
	g.mu.Lock()
	g.closed = true
	g.mu.Unlock()
	g.stop()
	_ = g.ln.Close()
	g.wg.Wait()
}

func (g *guard) serve() {
	for {
		c, err := g.ln.Accept()
		if err != nil {
			return
		}
		g.mu.Lock()
		if g.closed {
			g.mu.Unlock()
			_ = c.Close()
			return
		}
		g.wg.Add(1)
		g.mu.Unlock()
		go func() {
			defer g.wg.Done()
			stop := context.AfterFunc(g.ctx, func() { _ = c.Close() })
			defer stop()
			g.handle(c)
		}()
	}
}

// SOCKS5 replies (RFC 1928).
const (
	socksOK         = 0
	socksNotAllowed = 2
	socksNoCommand  = 7
	socksNoAddress  = 8
)

func (g *guard) handle(c net.Conn) {
	defer c.Close()
	if !g.peers.owns(c) {
		return // not Chrome's
	}
	_ = c.SetDeadline(time.Now().Add(15 * time.Second))
	// Room for a TLS record: a ClientHello is read whole.
	r := bufio.NewReaderSize(c, 5+1<<14)
	reply := func(code byte) { _, _ = c.Write([]byte{5, code, 0, 1, 0, 0, 0, 0, 0, 0}) }

	head := make([]byte, 2) // version, number of methods
	if _, err := io.ReadFull(r, head); err != nil || head[0] != 5 {
		return
	}
	if _, err := io.ReadFull(r, make([]byte, head[1])); err != nil {
		return
	}
	if _, err := c.Write([]byte{5, 0}); err != nil { // no authentication
		return
	}
	req := make([]byte, 4) // version, command, reserved, address type
	if _, err := io.ReadFull(r, req); err != nil || req[0] != 5 {
		return
	}
	var host string
	switch req[3] {
	case 1, 4:
		ip := make([]byte, 4)
		if req[3] == 4 {
			ip = make([]byte, 16)
		}
		if _, err := io.ReadFull(r, ip); err != nil {
			return
		}
		host = net.IP(ip).String()
	case 3:
		n, err := r.ReadByte()
		if err != nil {
			return
		}
		name := make([]byte, n)
		if _, err := io.ReadFull(r, name); err != nil {
			return
		}
		host = string(name)
	default:
		reply(socksNoAddress)
		return
	}
	port := make([]byte, 2)
	if _, err := io.ReadFull(r, port); err != nil {
		return
	}
	if req[1] != 1 { // CONNECT only
		reply(socksNoCommand)
		return
	}
	addr := net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(port))))
	if !g.allowed(host) {
		g.refuse(host)
		reply(socksNotAllowed)
		return
	}
	// Connected once Chrome has said what it sends: its first bytes tell
	// TLS from plain HTTP (which proxy of the environment, as the run's
	// own requests), and a WebSocket's handshake, which no paused request
	// counted, from the rest. A preconnect Chrome never uses reaches
	// nothing.
	reply(socksOK)
	_ = c.SetDeadline(time.Time{})
	tls, ws, err := sniff(r)
	if err != nil {
		return
	}
	if ws {
		if egress.Take() != nil {
			return // the budget is spent
		}
		if egress.Pace(g.ctx) != nil {
			egress.Refund() // never sent
			return
		}
	}
	scheme := "http"
	if tls {
		scheme = "https"
	}
	p, err := upstream(scheme, addr, g.via)
	if err != nil {
		if ws {
			egress.Refund()
		}
		return
	}
	if p != nil && p.Scheme == "http" && !tls && !ws {
		// An HTTP proxy is asked for each plain request, as the run's own
		// requests are, not for a tunnel it cannot read.
		g.forward(c, r, p, addr)
		return
	}
	ctx, cancel := context.WithTimeout(g.ctx, 10*time.Second)
	up, err := dialOut(ctx, p, addr)
	cancel()
	if err != nil {
		if ws {
			egress.Refund()
		}
		return
	}
	if ws {
		// A WebSocket handshake is no paused request: the connection is
		// the entry, once there is one to send it on.
		wsScheme := "ws"
		if tls {
			wsScheme = "wss"
		}
		ledger.Chrome(g.ctx, http.MethodGet, wsScheme+"://"+addr+wsPath(r, tls))
	}
	defer up.Close()
	stop := context.AfterFunc(g.ctx, func() { _ = up.Close() })
	defer stop()
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(up, r)
		closeWrite(up)
		close(done)
	}()
	_, _ = io.Copy(c, up)
	closeWrite(c)
	<-done
}

// sniff waits for the client's first bytes and says whether they open TLS,
// and whether they open a WebSocket: a plain request asking for the
// upgrade, or a TLS ClientHello offering HTTP/1.1 only, which Chrome sends
// for a WebSocket alone (its other connections offer h2 too).
func sniff(r *bufio.Reader) (tls, ws bool, err error) {
	first, err := r.Peek(1)
	if err != nil {
		return false, false, err
	}
	if first[0] == 0x16 { // a TLS handshake record
		alpn, ok := clientALPN(r)
		return true, ok && len(alpn) > 0 && !slices.Contains(alpn, "h2"), nil
	}
	return false, upgrades(peekHead(r)), nil
}

// wsPath is the path and query of a plain WebSocket handshake r starts
// with; one inside TLS shows none.
func wsPath(r *bufio.Reader, tls bool) string {
	if tls {
		return ""
	}
	line, _, _ := bytes.Cut(peekHead(r), []byte("\r\n"))
	f := bytes.Fields(line)
	if len(f) < 2 || !bytes.HasPrefix(f[1], []byte("/")) {
		return ""
	}
	return string(f[1])
}

// peekHead is the header of the request r starts with, as far as r's
// buffer holds it.
func peekHead(r *bufio.Reader) []byte {
	for {
		b, err := r.Peek(r.Buffered())
		if i := bytes.Index(b, []byte("\r\n\r\n")); i >= 0 {
			return b[:i]
		}
		if err != nil || len(b) >= r.Size() {
			return b
		}
		if _, err := r.Peek(len(b) + 1); err != nil {
			b, _ = r.Peek(r.Buffered())
			return b
		}
	}
}

// upgrades says whether a request's header asks for a WebSocket.
func upgrades(head []byte) bool {
	for _, line := range bytes.Split(head, []byte("\r\n"))[1:] {
		name, value, ok := bytes.Cut(line, []byte(":"))
		if ok && bytes.EqualFold(bytes.TrimSpace(name), []byte("upgrade")) {
			for _, v := range bytes.Split(value, []byte(",")) {
				if bytes.EqualFold(bytes.TrimSpace(v), []byte("websocket")) {
					return true
				}
			}
		}
	}
	return false
}

// clientALPN is the protocols the TLS ClientHello r starts with offers
// (RFC 7301), and whether one was read.
func clientALPN(r *bufio.Reader) ([]string, bool) {
	rec, err := r.Peek(5)
	if err != nil {
		return nil, false
	}
	n := int(binary.BigEndian.Uint16(rec[3:5]))
	if rec, err = r.Peek(5 + n); err != nil {
		return nil, false
	}
	p := rec[5:]
	if len(p) < 4 || p[0] != 1 { // client_hello
		return nil, false
	}
	p = p[4:]
	skip := func(n int) bool {
		if len(p) < n {
			return false
		}
		p = p[n:]
		return true
	}
	vec := func(size int) bool { // skips a vector with a length of size bytes
		if len(p) < size {
			return false
		}
		n := 0
		for _, c := range p[:size] {
			n = n<<8 | int(c)
		}
		return skip(size) && skip(n)
	}
	if !skip(2+32) || !vec(1) || !vec(2) || !vec(1) || len(p) < 2 { // version, random, session, suites, compression
		return nil, false
	}
	exts := p[2:]
	if n := int(binary.BigEndian.Uint16(p)); n < len(exts) {
		exts = exts[:n]
	}
	for len(exts) >= 4 {
		typ, n := binary.BigEndian.Uint16(exts), int(binary.BigEndian.Uint16(exts[2:]))
		if len(exts) < 4+n {
			return nil, false
		}
		body := exts[4 : 4+n]
		exts = exts[4+n:]
		if typ != 16 || len(body) < 2 {
			continue
		}
		var out []string
		for list := body[2:]; len(list) > 0; {
			l := int(list[0])
			if len(list) < 1+l {
				return nil, false
			}
			out = append(out, string(list[1:1+l]))
			list = list[1+l:]
		}
		return out, true
	}
	return nil, true
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
		return
	}
	_ = c.Close()
}

// upstream is the proxy Chrome's connection to addr goes through, as the
// run's own requests to a scheme://addr URL would: the one -chrome-proxy
// (via) names, else -proxy's or the environment's; nil for none.
func upstream(scheme, addr string, via *url.URL) (*url.URL, error) {
	if via != nil {
		return via, nil
	}
	return egress.ProxyFor(&http.Request{URL: &url.URL{Scheme: scheme, Host: addr}})
}

// dialOut connects to addr through the proxy p (Burp, a SOCKS tunnel), or
// directly when there is none, a name through the run's resolver.
func dialOut(ctx context.Context, p *url.URL, addr string) (net.Conn, error) {
	if p == nil {
		return fetch.Dial(ctx, "tcp", addr)
	}
	switch p.Scheme {
	case "socks5", "socks5h":
		pd, err := proxy.FromURL(p, runDialer{})
		if err != nil {
			return nil, err
		}
		if cd, ok := pd.(proxy.ContextDialer); ok {
			return cd.DialContext(ctx, "tcp", addr)
		}
		return pd.Dial("tcp", addr)
	case "http":
		return connectVia(ctx, p, addr)
	}
	return nil, fmt.Errorf("proxy %s: Chrome's connections go through http and socks5 proxies only", p.Redacted())
}

// forward relays the plain HTTP requests Chrome sends on c to the HTTP
// proxy p, each as the absolute URI a proxy reads (what the run's own
// client sends it): a CONNECT tunnel would hide the request from the proxy,
// and many proxies refuse one to any port but 443.
func (g *guard) forward(c net.Conn, r *bufio.Reader, p *url.URL, addr string) {
	at := p.Host
	if p.Port() == "" {
		at = net.JoinHostPort(p.Hostname(), "80")
	}
	ctx, cancel := context.WithTimeout(g.ctx, 10*time.Second)
	up, err := fetch.Dial(ctx, "tcp", at)
	cancel()
	if err != nil {
		return
	}
	defer up.Close()
	stop := context.AfterFunc(g.ctx, func() { _ = up.Close() })
	defer stop()
	from := bufio.NewReader(up)
	for {
		req, err := http.ReadRequest(r)
		if err != nil {
			return
		}
		req.URL.Scheme = "http"
		if req.Host == "" {
			req.Host = addr
		}
		if u := p.User; u != nil {
			pass, _ := u.Password()
			req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(u.Username()+":"+pass)))
		}
		if err := req.WriteProxy(up); err != nil {
			return
		}
		res, err := http.ReadResponse(from, req)
		if err != nil {
			return
		}
		err = res.Write(c)
		res.Body.Close()
		if err != nil || res.Close || req.Close {
			return
		}
	}
}

// runDialer reaches a proxy as the run's HTTP client does.
type runDialer struct{}

func (runDialer) Dial(network, addr string) (net.Conn, error) {
	return fetch.Dial(context.Background(), network, addr)
}

func (runDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return fetch.Dial(ctx, network, addr)
}

// connectVia opens a tunnel to addr through an HTTP proxy.
func connectVia(ctx context.Context, p *url.URL, addr string) (net.Conn, error) {
	at := p.Host
	if p.Port() == "" {
		at = net.JoinHostPort(p.Hostname(), "80")
	}
	c, err := fetch.Dial(ctx, "tcp", at)
	if err != nil {
		return nil, err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}
	req := &http.Request{Method: http.MethodConnect, URL: &url.URL{Opaque: addr}, Host: addr, Header: http.Header{}}
	if u := p.User; u != nil {
		pass, _ := u.Password()
		req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(u.Username()+":"+pass)))
	}
	if err := req.Write(c); err != nil {
		c.Close()
		return nil, err
	}
	r := bufio.NewReader(c)
	res, err := http.ReadResponse(r, req)
	if err != nil {
		c.Close()
		return nil, err
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		c.Close()
		return nil, errors.New("proxy " + p.Redacted() + ": CONNECT " + addr + ": " + res.Status)
	}
	_ = c.SetDeadline(time.Time{})
	if r.Buffered() > 0 {
		return &bufConn{Conn: c, r: r}, nil
	}
	return c, nil
}

// bufConn is a connection whose first bytes were read into r.
type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufConn) Read(p []byte) (int, error) { return c.r.Read(p) }
