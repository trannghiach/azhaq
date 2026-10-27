package browser

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"golang.org/x/net/proxy"
)

// guard is a SOCKS5 proxy on loopback that Chrome makes every connection
// through. The Fetch domain pauses requests, not connections: a WebSocket,
// a preconnect or Chrome's own services (updates, sign-in, time) reaching
// for a host outside the scope stop here instead.
type guard struct {
	ln      net.Listener
	allowed func(host string) bool
}

func newGuard(allowed func(string) bool) (*guard, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	g := &guard{ln: ln, allowed: allowed}
	go g.serve()
	return g, nil
}

func (g *guard) addr() string { return g.ln.Addr().String() }

func (g *guard) close() { _ = g.ln.Close() }

func (g *guard) serve() {
	for {
		c, err := g.ln.Accept()
		if err != nil {
			return
		}
		go g.handle(c)
	}
}

// SOCKS5 replies (RFC 1928).
const (
	socksOK          = 0
	socksFailure     = 1
	socksNotAllowed  = 2
	socksUnreachable = 4
	socksNoCommand   = 7
	socksNoAddress   = 8
)

func (g *guard) handle(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(15 * time.Second))
	r := bufio.NewReader(c)
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
		reply(socksNotAllowed)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	up, err := dialOut(ctx, addr)
	cancel()
	if err != nil {
		reply(socksUnreachable)
		return
	}
	defer up.Close()
	reply(socksOK)
	_ = c.SetDeadline(time.Time{})
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

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
		return
	}
	_ = c.Close()
}

// dialOut connects to addr as Chrome would have: through the proxy the
// environment names, if any (Burp, a SOCKS tunnel), or directly.
func dialOut(ctx context.Context, addr string) (net.Conn, error) {
	d := &net.Dialer{Timeout: 10 * time.Second}
	scheme := "https"
	if _, port, _ := net.SplitHostPort(addr); port == "80" {
		scheme = "http"
	}
	p, err := http.ProxyFromEnvironment(&http.Request{URL: &url.URL{Scheme: scheme, Host: addr}})
	if err != nil {
		return nil, err
	}
	if p == nil {
		return d.DialContext(ctx, "tcp", addr)
	}
	switch p.Scheme {
	case "socks5", "socks5h":
		pd, err := proxy.FromURL(p, d)
		if err != nil {
			return nil, err
		}
		if cd, ok := pd.(proxy.ContextDialer); ok {
			return cd.DialContext(ctx, "tcp", addr)
		}
		return pd.Dial("tcp", addr)
	case "http":
		return connectVia(ctx, d, p, addr)
	}
	return nil, fmt.Errorf("proxy %s: Chrome's connections go through http and socks5 proxies only", p.Redacted())
}

// connectVia opens a tunnel to addr through an HTTP proxy.
func connectVia(ctx context.Context, d *net.Dialer, p *url.URL, addr string) (net.Conn, error) {
	at := p.Host
	if p.Port() == "" {
		at = net.JoinHostPort(p.Hostname(), "80")
	}
	c, err := d.DialContext(ctx, "tcp", at)
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
