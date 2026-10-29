package portscan

import (
	"context"
	"encoding/binary"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/trannghiach/azhaq/internal/ledger"
)

func TestGreetingProduct(t *testing.T) {
	mysql := func(v string) []byte {
		body := append([]byte{10}, v...)
		body = append(body, 0, 1, 0, 0, 0, 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 0)
		return append([]byte{byte(len(body)), 0, 0, 0}, body...)
	}
	tests := []struct {
		raw                       string
		service, product, version string
	}{
		{"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.20\r\n", "ssh", "OpenSSH", "9.6p1"},
		{"SSH-2.0-dropbear_2022.83\r\n", "ssh", "dropbear", "2022.83"},
		{"SSH-2.0-libssh-0.9.6\r\n", "ssh", "libssh", "0.9.6"},
		{"SSH-2.0-Go\r\n", "ssh", "Go", ""},
		{"220 (vsFTPd 3.0.5)\r\n", "", "vsftpd", "3.0.5"},
		{"220 ProFTPD 1.3.8 Server (Debian) [::ffff:10.0.0.1]\r\n", "", "ProFTPD", "1.3.8"},
		{"220---------- Welcome to Pure-FTPd [privsep] [TLS] ----------\r\n", "", "Pure-FTPd", ""},
		{"220-FileZilla Server 1.8.0\r\n", "", "FileZilla Server", "1.8.0"},
		{"220 mail.example.com ESMTP Postfix (Ubuntu)\r\n", "", "Postfix", ""},
		{"220 mx.example.com ESMTP Exim 4.96 Tue, 28 Oct 2026 10:00:00 +0000\r\n", "", "Exim", "4.96"},
		{"220 host ESMTP Sendmail 8.15.2/8.15.2; Tue, 28 Oct 2026\r\n", "", "Sendmail", "8.15.2"},
		{"+OK Dovecot (Ubuntu) ready.\r\n", "", "Dovecot", ""},
		{"+OK Dovecot 2.3.21 ready.\r\n", "", "Dovecot", "2.3.21"},
		{"* OK [CAPABILITY IMAP4rev1 LITERAL+] Dovecot (Debian) ready.\r\n", "", "Dovecot", ""},
		{"* OK mail Cyrus IMAP 3.4.1 server ready\r\n", "", "Cyrus", "3.4.1"},
		{string(mysql("8.0.35-0ubuntu0.22.04.1")), "mysql", "MySQL", "8.0.35"},
		{string(mysql("5.5.5-10.11.6-MariaDB-0+deb12u1")), "mysql", "MariaDB", "10.11.6"},
		{"220 smtp.example.com ESMTP ready\r\n", "", "", ""},
		{"hello\r\n", "", "", ""},
	}
	for _, tt := range tests {
		service, product, version := greetingProduct([]byte(tt.raw), printable([]byte(tt.raw)))
		if service != tt.service || product != tt.product || version != tt.version {
			t.Errorf("%q: got %q %q %q, want %q %q %q", tt.raw, service, product, version, tt.service, tt.product, tt.version)
		}
	}
}

func TestHeadProduct(t *testing.T) {
	head := func(lines ...string) []byte {
		return []byte("HTTP/1.1 200 OK\r\n" + strings.Join(lines, "\r\n") + "\r\n\r\n")
	}
	tests := []struct {
		name             string
		head             []byte
		product, version string
	}{
		{"werkzeug", head("Server: Werkzeug/2.2.3 Python/3.11.15"), "Werkzeug", "2.2.3"},
		{"apache", head("Server: Apache/2.4.25 (Debian)"), "Apache httpd", "2.4.25"},
		{"nginx", head("Server: nginx/1.25.3"), "nginx", "1.25.3"},
		{"nginx bare", head("Server: nginx"), "nginx", ""},
		{"iis", head("Server: Microsoft-IIS/10.0"), "Microsoft IIS httpd", "10.0"},
		{"jetty", head("Server: Jetty(9.4.51.v20230217)"), "Jetty", "9.4.51.v20230217"},
		{"cups", head("Server: CUPS/2.4 IPP/2.1"), "CUPS", "2.4"},
		{"express", head("X-Powered-By: Express", "Content-Type: text/html"), "Express", ""},
		{"php behind a server", head("Server: Apache/2.4.57", "X-Powered-By: PHP/8.2.12"), "Apache httpd", "2.4.57"},
		{"php alone", head("X-Powered-By: PHP/8.2.12"), "PHP", "8.2.12"},
		{"elasticsearch", head("X-Elastic-Product: Elasticsearch"), "Elasticsearch", ""},
		{"not a product", head("Server: (none)"), "", ""},
		{"no header", head("Content-Type: text/html"), "", ""},
	}
	for _, tt := range tests {
		h, ok := parseHead(tt.head)
		if !ok {
			t.Fatalf("%s: not an HTTP head", tt.name)
		}
		if p, v := headProduct(h); p != tt.product || v != tt.version {
			t.Errorf("%s: got %q %q, want %q %q", tt.name, p, v, tt.product, tt.version)
		}
	}
	if _, ok := parseHead([]byte("-ERR unknown")); ok {
		t.Error("a RESP error parsed as HTTP")
	}
}

func TestBodyProduct(t *testing.T) {
	tests := []struct {
		body             string
		product, version string
	}{
		{"Ollama is running", "Ollama", ""},
		{"Ollama is running\n", "Ollama", ""},
		{`{"name":"n1","cluster_name":"docker-cluster","version":{"number":"8.11.1","build_flavor":"default","lucene_version":"9.8.0"},"tagline":"You Know, for Search"}`, "Elasticsearch", "8.11.1"},
		{`{"name":"n","version":{"distribution":"opensearch","number":"2.11.0","lucene_version":"9.7.0"},"tagline":"The OpenSearch Project: https://opensearch.org/"}`, "OpenSearch", "2.11.0"},
		{`{"version":{"number":"1.2.3"}}`, "", ""}, // someone's API, not Elasticsearch
		{"<html></html>", "", ""},
	}
	for _, tt := range tests {
		if p, v := bodyProduct([]byte(tt.body)); p != tt.product || v != tt.version {
			t.Errorf("%.40q: got %q %q, want %q %q", tt.body, p, v, tt.product, tt.version)
		}
	}
}

func TestMongoHello(t *testing.T) {
	// {ismaster: true, maxWireVersion: 21, ok: 1.0} in an OP_MSG.
	doc := []byte{0, 0, 0, 0}
	doc = append(doc, 0x08)
	doc = append(doc, "ismaster\x00"...)
	doc = append(doc, 1, 0x10)
	doc = append(doc, "maxWireVersion\x00"...)
	doc = append(doc, 21, 0, 0, 0, 0x01)
	doc = append(doc, "ok\x00"...)
	doc = append(doc, make([]byte, 8)...)
	doc = append(doc, 0)
	binary.LittleEndian.PutUint32(doc, uint32(len(doc)))
	msg := make([]byte, 16)
	binary.LittleEndian.PutUint32(msg[12:], 2013)
	msg = append(append(msg, 0, 0, 0, 0, 0), doc...)
	binary.LittleEndian.PutUint32(msg, uint32(len(msg)))

	if v, ok := mongoHello(msg); !ok || v != "7.0" {
		t.Fatalf("got %q %v", v, ok)
	}
	if _, ok := mongoHello([]byte("HTTP/1.1 400 Bad Request\r\n\r\n")); ok {
		t.Fatal("an HTTP answer taken for MongoDB's")
	}
	req := mongoIsMaster()
	if len(req) != 55 || binary.LittleEndian.Uint32(req) != 55 {
		t.Fatalf("isMaster message is %d bytes", len(req))
	}
}

// listen serves each connection with fn, on a free port of 127.0.0.1.
func listen(t *testing.T, fn func(c net.Conn)) int {
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

func scanOne(t *testing.T, port int) Open {
	t.Helper()
	s := &Scanner{Banner: 150 * time.Millisecond, Timeout: time.Second}
	r, err := s.ScanEach(context.Background(), "localhost", "127.0.0.1", []int{port})
	if err != nil || len(r.Open) != 1 {
		t.Fatalf("scan: %v %+v", err, r)
	}
	return r.Open[0]
}

func TestScanNamesProducts(t *testing.T) {
	ssh := listen(t, func(c net.Conn) { c.Write([]byte("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.20\r\n")) })
	my := listen(t, func(c net.Conn) {
		body := append([]byte{10}, "8.0.35\x00"...)
		body = append(body, 1, 0, 0, 0, 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 0)
		c.Write(append([]byte{byte(len(body)), 0, 0, 0}, body...))
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Werkzeug/2.2.3 Python/3.11")
		w.Write([]byte("hi"))
	}))
	defer srv.Close()
	express := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", "Express")
		w.Write([]byte("hi"))
	}))
	defer express.Close()
	port := func(s *httptest.Server) int { return s.Listener.Addr().(*net.TCPAddr).Port }

	if o := scanOne(t, ssh); o.Service != "ssh" || o.Product != "OpenSSH" || o.Version != "9.6p1" {
		t.Errorf("ssh: %+v", o)
	}
	if o := scanOne(t, my); o.Service != "mysql" || o.Product != "MySQL" || o.Version != "8.0.35" || o.Banner != "8.0.35" {
		t.Errorf("mysql: %+v", o)
	}
	if o := scanOne(t, port(srv)); o.Service != "http" || o.Product != "Werkzeug" || o.Version != "2.2.3" {
		t.Errorf("werkzeug: %+v", o)
	}
	if o := scanOne(t, port(express)); o.Service != "http" || o.Product != "Express" || o.Version != "" {
		t.Errorf("express: %+v", o)
	}
}

// Elasticsearch and Ollama say what they are in the body of GET /: a
// second request, counted and recorded like a connect.
func TestScanReadsTheBodyWhenTheHeadsSayNothing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "l.jsonl")
	l, err := ledger.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	ledger.Use(l)
	defer ledger.Use(nil)

	es := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Elastic-Product", "Elasticsearch")
		w.Header().Set("Content-Type", "application/json; charset=UTF-8")
		w.Write([]byte(`{"version":{"number":"8.11.1","lucene_version":"9.8.0"},"tagline":"You Know, for Search"}`))
	}))
	defer es.Close()
	ollama := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte("Ollama is running"))
	}))
	defer ollama.Close()
	page := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html>"))
	}))
	defer page.Close()
	port := func(s *httptest.Server) int { return s.Listener.Addr().(*net.TCPAddr).Port }

	var takes atomic.Int32
	s := &Scanner{Banner: 150 * time.Millisecond, Timeout: time.Second, Take: func() error { takes.Add(1); return nil }}
	r, err := s.ScanEach(context.Background(), "localhost", "127.0.0.1", []int{port(es), port(ollama), port(page)})
	if err != nil {
		t.Fatal(err)
	}
	got := map[int]Open{}
	for _, o := range r.Open {
		got[o.Port] = o
	}
	if o := got[port(es)]; o.Service != "http" || o.Product != "Elasticsearch" || o.Version != "8.11.1" {
		t.Errorf("elasticsearch: %+v", o)
	}
	if o := got[port(ollama)]; o.Service != "http" || o.Product != "Ollama" {
		t.Errorf("ollama: %+v", o)
	}
	if o := got[port(page)]; o.Product != "" {
		t.Errorf("a page named a product: %+v", o)
	}
	l.Close()
	n := 0
	ledger.Read(path, func(e ledger.Entry) error { n++; return nil })
	// Three connects and the three HEADs on them, plus a GET for each of
	// the two JSON and plain-text answers; the HTML page is not asked again.
	if want := 3 + 2; n != want || int(takes.Load()) != want {
		t.Errorf("%d ledger entries, %d takes, want %d", n, takes.Load(), want)
	}
}

func TestScanRedisPostgresMongoOnTheirPorts(t *testing.T) {
	s := &Scanner{Banner: 150 * time.Millisecond, Timeout: time.Second}
	pipe := func(serve func(c net.Conn)) net.Conn {
		a, b := net.Pipe()
		go func() { defer b.Close(); serve(b) }()
		return a
	}
	read := func(c net.Conn) []byte {
		buf := make([]byte, 64)
		n, _ := c.Read(buf)
		return buf[:n]
	}

	o := Open{Port: 6379}
	c := pipe(func(c net.Conn) {
		if string(read(c)) == "PING\r\n" {
			c.Write([]byte("-NOAUTH Authentication required.\r\n"))
		}
	})
	if !s.speak(&o, c) || o.Service != "redis" || o.Product != "Redis" {
		t.Errorf("redis: %+v", o)
	}
	c.Close()

	o = Open{Port: 6379}
	c = pipe(func(c net.Conn) { read(c); c.Write([]byte("+PONG\r\n")) })
	if !s.speak(&o, c) || o.Product != "Redis" || o.Banner != "+PONG" {
		t.Errorf("redis pong: %+v", o)
	}
	c.Close()

	o = Open{Port: 5432}
	c = pipe(func(c net.Conn) {
		if r := read(c); len(r) == 8 && binary.BigEndian.Uint32(r[4:]) == 80877103 {
			c.Write([]byte("N"))
		}
	})
	if !s.speak(&o, c) || o.Service != "postgresql" || o.Product != "PostgreSQL" || o.Version != "" {
		t.Errorf("postgres: %+v", o)
	}
	c.Close()

	// Not PostgreSQL: something that answers with more than one byte.
	o = Open{Port: 5432}
	c = pipe(func(c net.Conn) { read(c); c.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n")) })
	if s.speak(&o, c) || o.Product != "" {
		t.Errorf("a web server taken for postgres: %+v", o)
	}
	c.Close()

	o = Open{Port: 27017}
	c = pipe(func(c net.Conn) { read(c) }) // closes without an answer
	if s.speak(&o, c) || o.Product != "" {
		t.Errorf("silence taken for mongodb: %+v", o)
	}
	c.Close()

	if s.speak(&Open{Port: 8080}, nil) {
		t.Error("an ordinary port was asked a database's question")
	}
}

// Redis answers the HTTP HEAD with an error of its own, PostgreSQL with a
// complaint about the protocol: neither needs another request.
func TestScanFindsRedisAndPostgresOnOtherPorts(t *testing.T) {
	redis := listen(t, func(c net.Conn) {
		c.Read(make([]byte, 512))
		c.Write([]byte("-ERR unknown command `HEAD`, with args beginning with: `/`, `HTTP/1.0`,\r\n"))
	})
	pg := listen(t, func(c net.Conn) {
		buf := make([]byte, 512)
		c.Read(buf)
		msg := "Munsupported frontend protocol 18245.12079: server supports 3.0 to 3.0\x00"
		c.Write(append([]byte("E\x00\x00\x00\x50SFATAL\x00"), msg...))
	})
	if o := scanOne(t, redis); o.Service != "redis" || o.Product != "Redis" {
		t.Errorf("redis: %+v", o)
	}
	if o := scanOne(t, pg); o.Service != "postgresql" || o.Product != "PostgreSQL" {
		t.Errorf("postgres: %+v", o)
	}
}
