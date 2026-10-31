package main

import (
	"net"
	"testing"
	"time"
)

// lab starts a listener that runs fn on each connection; it returns the port.
func lab(t *testing.T, fn func(c net.Conn)) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); fn(c) }()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

// What each lab daemon says when it serves (a reply the protocol defines),
// by lab port: a greeting, or the answer to what the check asks.
var serviceSays = map[int]func(c net.Conn){
	16379: asked("+PONG\r\n"),
	13306: says("\x4a\x00\x00\x00\x0a8.0.35\x00"),
	15432: asked("N"),
	17017: quiet,
	11883: asked("\x20\x02\x00\x00"),
	15682: asked("\x01\x00\x00\x00\x00\x01\x00\x0a\x00\x0a"),
	21211: asked("VERSION 1.6.21\r\n"),
	12222: says("SSH-2.0-OpenSSH_9.6\r\n"),
	10021: says("220 ftp ready\r\n"),
	10025: says("220 mailpit ESMTP\r\n"),
	18825: asked("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"),
	10389: asked("\x30\x0c\x02\x01\x01\x61\x07\x0a\x01\x00\x04\x00\x04\x00"),
	10445: quiet,
	19200: asked("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"),
	10053: func(c net.Conn) {
		b := make([]byte, 64)
		if n, _ := c.Read(b); n >= 4 {
			c.Write([]byte{0, 12, b[2], b[3], 0x81, 0x05, 0, 1, 0, 0, 0, 0}) // REFUSED
		}
	},
}

func says(s string) func(net.Conn) {
	return func(c net.Conn) { c.Write([]byte(s)); time.Sleep(time.Second) }
}
func asked(s string) func(net.Conn) {
	return func(c net.Conn) {
		if n, _ := c.Read(make([]byte, 64)); n > 0 {
			c.Write([]byte(s))
		}
		time.Sleep(time.Second)
	}
}
func quiet(c net.Conn) { time.Sleep(time.Second) }

// A daemon that is up is serving; docker's proxy, which accepts and closes
// while the container starts, is not, for any of the lab's protocols.
func TestServingNeedsTheDaemonNotTheProxy(t *testing.T) {
	proxy := lab(t, func(c net.Conn) {})
	for _, s := range serviceTruth {
		r, ok := readyBy[s.port]
		if !ok {
			t.Errorf("%d %s has no readiness check", s.port, s.what)
			continue
		}
		says, ok := serviceSays[s.port]
		if !ok {
			t.Fatalf("%d %s: the test has no reply for it", s.port, s.what)
		}
		if !servingAs(lab(t, says), r) {
			t.Errorf("%d %s: a daemon that answers is not taken as serving", s.port, s.what)
		}
		if servingAs(proxy, r) {
			t.Errorf("%d %s: a connection that is accepted and closed is taken as serving", s.port, s.what)
		}
	}
	// A daemon that answers with the wrong thing, or Elasticsearch still starting.
	if servingAs(lab(t, asked("HTTP/1.1 503 Service Unavailable\r\n\r\n")), readyBy[19200]) {
		t.Error("Elasticsearch answering 503 is taken as serving")
	}
	if servingAs(lab(t, says("HELO\r\n")), readyBy[12222]) {
		t.Error("something that is not an SSH greeting is taken as serving")
	}
}

// The wait ends when the last daemon serves, and names what never did.
func TestWaitServingWaitsForTheDaemons(t *testing.T) {
	started := time.Now().Add(300 * time.Millisecond)
	late := lab(t, func(c net.Conn) {
		if time.Now().Before(started) {
			return // the proxy, before the daemon is up
		}
		c.Write([]byte("SSH-2.0-OpenSSH_9.6\r\n"))
		time.Sleep(time.Second)
	})
	never := lab(t, func(c net.Conn) {})
	old := readyBy
	defer func() { readyBy = old }()
	readyBy = map[int]serviceReady{late: old[12222], never: old[12222]}
	t0 := time.Now()
	not := waitServing(time.Second, 20*time.Millisecond, []int{late, never})
	if len(not) != 1 || not[0] != never {
		t.Fatalf("not serving: %v, want [%d]", not, never)
	}
	if d := time.Since(t0); d < time.Second {
		t.Errorf("gave up after %v, before the wait was over", d)
	}
	t0 = time.Now()
	if not := waitServing(5*time.Second, 20*time.Millisecond, []int{late}); len(not) != 0 || time.Since(t0) > time.Second {
		t.Errorf("a daemon that serves is waited for %v: %v", time.Since(t0), not)
	}
}
