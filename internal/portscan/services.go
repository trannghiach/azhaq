package portscan

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"html"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// A greeting signature names a product from the first line a service
// sends: product is fixed, or taken from the group p; v is the version.
type greeting struct {
	re      *regexp.Regexp
	product string
}

var greetings = []greeting{
	{regexp.MustCompile(`(?i)\bvsFTPd (?P<v>\d[\w.]*)`), "vsftpd"},
	{regexp.MustCompile(`(?i)\bProFTPD (?P<v>\d[\w.]*)`), "ProFTPD"},
	{regexp.MustCompile(`(?i)\bPure-FTPd\b`), "Pure-FTPd"},
	{regexp.MustCompile(`(?i)\bFileZilla Server (?:version )?(?P<v>\d[\w.]*)`), "FileZilla Server"},
	{regexp.MustCompile(`(?i)\bMicrosoft FTP Service\b`), "Microsoft ftpd"},
	{regexp.MustCompile(`(?i)\bESMTP Postfix\b`), "Postfix"},
	{regexp.MustCompile(`(?i)\bESMTP Exim (?P<v>\d[\w.]*)`), "Exim"},
	{regexp.MustCompile(`(?i)\bSendmail (?P<v>\d[\w.]*)`), "Sendmail"},
	{regexp.MustCompile(`(?i)\bESMTP OpenSMTPD\b`), "OpenSMTPD"},
	{regexp.MustCompile(`(?i)\bMicrosoft ESMTP MAIL Service, Version: (?P<v>\d[\w.]*)`), "Microsoft Exchange smtpd"},
	{regexp.MustCompile(`(?i)\bESMTP Haraka\b`), "Haraka"},
	{regexp.MustCompile(`(?i)\bMailpit ESMTP\b`), "Mailpit"},
	{regexp.MustCompile(`(?i)\bESMTP MailHog\b`), "MailHog"},
	{regexp.MustCompile(`(?i)\bDovecot\b(?: (?P<v>\d[\d.]*))?`), "Dovecot"},
	{regexp.MustCompile(`(?i)\bCyrus (?:IMAP|POP3)[ -]?(?:v)?(?P<v>\d[\w.]*)`), "Cyrus"},
	{regexp.MustCompile(`(?i)\bCourier-IMAP\b`), "Courier"},
}

// sshRe splits the software of "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.20".
var (
	sshRe     = regexp.MustCompile(`^SSH-\d\.\d+-(\S+)`)
	sshSplit  = regexp.MustCompile(`^(.+?)[_-](\d[\w.+~]*)$`)
	rfbRe     = regexp.MustCompile(`^RFB (\d+)\.(\d+)`)
	mariaTrim = regexp.MustCompile(`^5\.5\.5-`)
	leadVer   = regexp.MustCompile(`^\d+(?:\.\d+)*`)
)

// greetingProduct reads a product and version out of what a port said
// first: raw is the bytes, banner their first printable line.
func greetingProduct(raw []byte, banner string) (service, product, version string) {
	if v, ok := mysqlVersion(raw); ok {
		product, version = "MySQL", leadVer.FindString(v)
		if strings.Contains(v, "MariaDB") {
			product, version = "MariaDB", leadVer.FindString(mariaTrim.ReplaceAllString(v, ""))
		}
		return "mysql", product, version
	}
	if m := sshRe.FindStringSubmatch(banner); m != nil {
		if s := sshSplit.FindStringSubmatch(m[1]); s != nil {
			return "ssh", s[1], s[2]
		}
		return "ssh", m[1], ""
	}
	for _, g := range greetings {
		if m := g.re.FindStringSubmatch(banner); m != nil {
			if i := g.re.SubexpIndex("v"); i > 0 {
				version = m[i]
			}
			return "", g.product, strings.TrimRight(version, ".")
		}
	}
	return "", "", ""
}

// mysqlVersion reads the server version from the handshake MySQL and
// MariaDB send on connect: a 3-byte length, a sequence byte, protocol 10,
// then the version, NUL-ended.
func mysqlVersion(raw []byte) (string, bool) {
	if len(raw) < 7 || raw[3] != 0 || raw[4] != 10 {
		return "", false
	}
	if n := int(raw[0]) | int(raw[1])<<8 | int(raw[2])<<16; n < 2 || n > len(raw)-4 && len(raw) < 256 {
		return "", false
	}
	end := bytes.IndexByte(raw[5:], 0)
	if end < 1 || end > 80 {
		return "", false
	}
	v := raw[5 : 5+end]
	for _, c := range v {
		if c < 0x20 || c >= 0x7f {
			return "", false
		}
	}
	if v[0] < '0' || v[0] > '9' {
		return "", false
	}
	return string(v), true
}

// httpHead is the part of an HTTP answer's head that names a product.
type httpHead struct {
	status                   int
	server, powered, elastic string
	contentType              string
	contentLength            int
}

func parseHead(head []byte) (h httpHead, ok bool) {
	if !bytes.HasPrefix(head, []byte("HTTP/")) {
		return h, false
	}
	h.contentLength = -1
	lines := strings.Split(string(head), "\n")
	if f := strings.Fields(lines[0]); len(f) > 1 {
		h.status, _ = strconv.Atoi(f[1])
	}
	for _, l := range lines[1:] {
		k, v, found := strings.Cut(strings.TrimSpace(l), ":")
		if !found {
			break
		}
		v = printable([]byte(strings.TrimSpace(v)))
		switch strings.ToLower(k) {
		case "server":
			h.server = v
		case "x-powered-by":
			h.powered = v
		case "x-elastic-product":
			h.elastic = v
		case "content-type":
			h.contentType = strings.ToLower(v)
		case "content-length":
			if n, err := strconv.Atoi(v); err == nil {
				h.contentLength = n
			}
		}
	}
	return h, true
}

var tokenName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.\-]{0,39}$`)

// aliases give the name a product is known by, for the Server tokens that
// are not it.
var aliases = map[string]string{
	"apache":            "Apache httpd",
	"microsoft-iis":     "Microsoft IIS httpd",
	"microsoft-httpapi": "Microsoft HTTPAPI httpd",
	"apache-coyote":     "Apache Tomcat/Coyote JSP engine",
	"cups":              "CUPS",
}

// serverProduct reads "Apache/2.4.25 (Debian)", "Werkzeug/2.2.3 Python/3.11"
// or "Jetty(9.4.51.v20230217)": the first token is the product.
func serverProduct(s string) (product, version string) {
	t := strings.Fields(s)
	if len(t) == 0 {
		return "", ""
	}
	name := t[0]
	if i := strings.IndexAny(name, "/("); i > 0 {
		version = strings.TrimRight(name[i+1:], ")")
		name = name[:i]
	}
	if !tokenName.MatchString(name) {
		return "", ""
	}
	if version != "" && (version[0] < '0' || version[0] > '9') {
		version = ""
	}
	if a, ok := aliases[strings.ToLower(name)]; ok {
		name = a
	}
	return name, version
}

// headProduct is the product an HTTP head names: an Elasticsearch product
// header, else the Server header, else X-Powered-By.
func headProduct(h httpHead) (product, version string) {
	if h.elastic != "" {
		return "Elasticsearch", ""
	}
	if p, v := serverProduct(h.server); p != "" {
		return p, v
	}
	return serverProduct(h.powered)
}

// bodyProduct reads the product a GET / body names: Ollama says so in
// plain text, Elasticsearch and OpenSearch give their version in JSON.
func bodyProduct(body []byte) (product, version string) {
	body = bytes.TrimSpace(body)
	if string(body) == "Ollama is running" {
		return "Ollama", ""
	}
	var other struct {
		Etcd    string `json:"etcdserver"`
		GitVer  string `json:"gitVersion"`
		Docker  string `json:"Version"`
		APIVer  string `json:"ApiVersion"`
		Compose []struct {
			Name string `json:"Name"`
		} `json:"Components"`
	}
	if len(body) > 0 && body[0] == '{' && json.Unmarshal(body, &other) == nil {
		switch {
		case other.Etcd != "":
			return "etcd", other.Etcd
		case other.GitVer != "":
			return "Kubernetes", strings.TrimPrefix(other.GitVer, "v")
		case other.Docker != "" && other.APIVer != "":
			return "Docker Engine", other.Docker
		}
	}
	var doc struct {
		Version struct {
			Number       string `json:"number"`
			Distribution string `json:"distribution"`
			Lucene       string `json:"lucene_version"`
		} `json:"version"`
		Tagline string `json:"tagline"`
	}
	if len(body) > 0 && body[0] == '{' && json.Unmarshal(body, &doc) == nil && doc.Version.Number != "" {
		switch {
		case doc.Version.Distribution == "opensearch":
			return "OpenSearch", doc.Version.Number
		case doc.Version.Lucene != "" || strings.Contains(doc.Tagline, "for Search"):
			return "Elasticsearch", doc.Version.Number
		}
	}
	return "", ""
}

// greeted fills in what the first bytes a port sent say.
func (s *Scanner) greeted(o *Open, raw []byte) {
	service, product, version := greetingProduct(raw, o.Banner)
	if product == "" {
		passiveRead(raw, o)
		return
	}
	o.Product, o.Version = product, version
	if service != "" {
		o.Service = service
	} else if tmp := *o; passiveRead(raw, &tmp) {
		*o = tmp // a protocol of its own names it (ManageSieve, behind Dovecot's name)
	}
	if service == "mysql" {
		v, _ := mysqlVersion(raw)
		o.Banner = v // the handshake is binary; its version is what it says
	}
}

// passiveRead reads a greeting or an answer with every protocol strict
// enough to be told from one message.
func passiveRead(raw []byte, o *Open) bool {
	for _, p := range protocols {
		if !p.passive {
			continue
		}
		c := *o
		if p.read(raw, &c) {
			if c.Service == "" {
				c.Service = p.name
			}
			if c.Banner == "" && isText(raw) {
				c.Banner = printable(raw)
			}
			*o = c
			return true
		}
	}
	return false
}

// settle220 tells an FTP server from an SMTP one when the greeting is only
// "220 ...": SMTP answers EHLO with 250, an FTP server answers SYST with
// its system type or a request to log in.
func (s *Scanner) settle220(conn net.Conn, o *Open) {
	r, _ := s.talk(conn, []byte("EHLO azhaq.invalid\r\n"), nil, s.Banner)
	if bytes.HasPrefix(r, []byte("250")) {
		o.Service = "smtp"
		return
	}
	r, _ = s.talk(conn, []byte("SYST\r\n"), nil, s.Banner)
	switch {
	case bytes.HasPrefix(r, []byte("215")), bytes.HasPrefix(r, []byte("530")), bytes.HasPrefix(r, []byte("331")):
		o.Service = "ftp"
	}
}

// webProduct reads the product of an HTTP answer to the HEAD, and when
// the head names none (or only Elasticsearch's header), or the HEAD was
// refused (405, 501) or answered with an error page, asks GET / once more
// for a body that names one, or for an HTML page's title and generator.
// https says the port speaks TLS.
func (s *Scanner) webProduct(ctx context.Context, o *Open, head []byte, status int, host, ip string, https bool) {
	h, ok := parseHead(head)
	if !ok {
		return
	}
	if p, v := headProduct(h); p != "" {
		o.Product, o.Version = p, v
	}
	if o.Product != "" && h.elastic == "" {
		return
	}
	small := h.contentLength < 0 || h.contentLength <= 4096
	typed := strings.Contains(h.contentType, "json") || strings.Contains(h.contentType, "text/plain")
	html := strings.Contains(h.contentType, "text/html")
	switch status {
	case 200, 401:
		if !(typed && small || html && o.Product == "") {
			return
		}
	case 403, 404, 405, 501:
		// The HEAD was refused, or this is an error page: the page itself may say.
	default:
		return
	}
	body := s.getBody(ctx, o.Port, host, ip, https)
	if p, v := bodyProduct(body); p != "" {
		o.Product, o.Version = p, v
		return
	}
	if o.Product != "" {
		return
	}
	if t := pageTitle(body); t != "" {
		o.Title = t
	}
	if p, v := generatorProduct(body); p != "" {
		o.Product, o.Version = p, v
	} else if p, v := titleProduct(o.Title, body); p != "" {
		o.Product, o.Version = p, v
	} else if needsVersionPage(body) {
		if p, v := bodyProduct(s.getPath(ctx, o.Port, host, ip, https, "/version")); p != "" {
			o.Product, o.Version = p, v
		}
	}
}

// titleProducts name an application by its page's title: a product that
// serves a page of its own and puts no name in a header.
var titleProducts = []struct {
	title   *regexp.Regexp
	product string
	version *regexp.Regexp // looked for in the page
}{
	{regexp.MustCompile(`(?i)^mailpit$`), "Mailpit", regexp.MustCompile(`/dist/app\.css\?v(\d[\w.]*)`)},
	{regexp.MustCompile(`(?i)^rabbitmq management$`), "RabbitMQ Management", nil},
	{regexp.MustCompile(`(?i)^grafana$`), "Grafana", nil},
	{regexp.MustCompile(`(?i)\[jenkins\]$`), "Jenkins", nil},
	{regexp.MustCompile(`(?i)^kibana$`), "Kibana", nil},
	{regexp.MustCompile(`(?i)^prometheus time series`), "Prometheus", nil},
	{regexp.MustCompile(`(?i)^portainer$`), "Portainer", nil},
	{regexp.MustCompile(`(?i)^phpmyadmin$`), "phpMyAdmin", nil},
	{regexp.MustCompile(`(?i)^welcome to nginx!?$`), "nginx", nil},
}

var tomcatTitle = regexp.MustCompile(`^Apache Tomcat/(\d[\w.]*)`)

func titleProduct(title string, body []byte) (product, version string) {
	if m := tomcatTitle.FindStringSubmatch(title); m != nil {
		return "Apache Tomcat", m[1]
	}
	for _, t := range titleProducts {
		if !t.title.MatchString(title) {
			continue
		}
		if t.version != nil {
			if m := t.version.FindSubmatch(body); m != nil {
				return t.product, string(m[1])
			}
		}
		return t.product, ""
	}
	return "", ""
}

// needsVersionPage: a Go server's plain 404, or a Kubernetes API's Status
// object, says nothing of itself on /, but etcd, Kubernetes and Docker
// answer /version.
func needsVersionPage(body []byte) bool {
	b := bytes.TrimSpace(body)
	return string(b) == "404 page not found" || bytes.HasPrefix(b, []byte(`{"kind":"Status"`)) ||
		bytes.HasPrefix(b, []byte("{\n  \"kind\": \"Status\""))
}

var (
	titleRe   = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	metaRe    = regexp.MustCompile(`(?is)<meta\b[^>]*>`)
	attrRe    = regexp.MustCompile(`(?is)([a-z][a-z0-9:_-]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))`)
	genNameRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_. \-]{0,39}$`)
	genVerRe  = regexp.MustCompile(`^v?(\d[\w.+~\-]*)$`)
)

// pageTitle is the text of the first <title>: entities decoded, runs of
// white space one space, at most 120 characters.
func pageTitle(body []byte) string {
	m := titleRe.FindSubmatch(body)
	if m == nil {
		return ""
	}
	t := strings.Join(strings.Fields(html.UnescapeString(strings.ToValidUTF8(string(m[1]), ""))), " ")
	if r := []rune(t); len(r) > 120 {
		t = strings.TrimSpace(string(r[:120]))
	}
	return t
}

// generatorProduct reads <meta name="generator" content="WordPress 6.4.2">:
// the product, and its version when the last word is one.
func generatorProduct(body []byte) (product, version string) {
	for _, tag := range metaRe.FindAll(body, -1) {
		var name, content string
		for _, a := range attrRe.FindAllSubmatch(tag, -1) {
			val := string(a[2]) + string(a[3]) + string(a[4])
			switch strings.ToLower(string(a[1])) {
			case "name":
				name = strings.ToLower(strings.TrimSpace(val))
			case "content":
				content = html.UnescapeString(val)
			}
		}
		if name != "generator" {
			continue
		}
		content, _, _ = strings.Cut(content, " (") // "Drupal 10 (https://www.drupal.org)"
		f := strings.Fields(content)
		if len(f) == 0 {
			return "", ""
		}
		if len(f) == 1 && strings.ContainsAny(f[0], "/(") {
			return serverProduct(f[0])
		}
		if m := genVerRe.FindStringSubmatch(f[len(f)-1]); m != nil && len(f) > 1 {
			version, f = m[1], f[:len(f)-1]
		}
		if name := strings.Join(f, " "); genNameRe.MatchString(name) {
			return name, version
		}
		return "", ""
	}
	return "", ""
}

// getBody is GET / on a new connection (paced, counted and recorded as a
// connect), and the first 64 KiB of the body: a page's title can come
// after a long head.
func (s *Scanner) getBody(ctx context.Context, port int, host, ip string, https bool) []byte {
	return s.getPath(ctx, port, host, ip, https, "/")
}

// getPath is GET path on a new connection.
func (s *Scanner) getPath(ctx context.Context, port int, host, ip string, https bool, path string) []byte {
	if host == "" {
		host = ip
	}
	conn, err := s.dial(ctx, host, ip, port, https)
	if err != nil {
		return nil
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(s.Timeout + s.Banner))
	hostHdr := host
	switch {
	case port != map[bool]int{false: 80, true: 443}[https]:
		hostHdr = net.JoinHostPort(host, strconv.Itoa(port))
	case strings.Contains(host, ":"):
		hostHdr = "[" + host + "]"
	}
	req := "GET " + path + " HTTP/1.0\r\nHost: " + hostHdr + "\r\n"
	if s.UserAgent != "" {
		req += "User-Agent: " + s.UserAgent + "\r\n"
	}
	if _, err := conn.Write([]byte(req + "Accept: */*\r\n\r\n")); err != nil {
		return nil
	}
	var resp []byte
	buf := make([]byte, 2048)
	for len(resp) < 64<<10 {
		n, err := conn.Read(buf)
		resp = append(resp, buf[:n]...)
		if err != nil {
			break
		}
	}
	if _, body, ok := bytes.Cut(resp, []byte("\r\n\r\n")); ok {
		return body
	}
	return nil
}

func mongoIsMaster() []byte { return mongoCommand("isMaster") }

// mongoReleases maps maxWireVersion to the release that introduced it.
var mongoReleases = map[int32]string{
	6: "3.6", 7: "4.0", 8: "4.2", 9: "4.4", 13: "5.0", 14: "5.1", 15: "5.2", 16: "5.3",
	17: "6.0", 18: "6.1", 19: "6.2", 20: "6.3", 21: "7.0", 22: "7.1", 23: "7.2", 24: "7.3", 25: "8.0",
}

// mongoHello reads an OP_MSG answer to isMaster: it is MongoDB when it
// says ismaster, and its maxWireVersion names the release (major.minor).
func mongoHello(r []byte) (version string, ok bool) {
	if len(r) < 26 || binary.LittleEndian.Uint32(r[12:]) != 2013 || r[20] != 0 {
		return "", false
	}
	doc := r[21:]
	if len(doc) < 5 {
		return "", false
	}
	wire := int32(-1)
	found := false
	for el := doc[4:]; len(el) > 1; {
		typ := el[0]
		end := bytes.IndexByte(el[1:], 0)
		if end < 0 {
			break
		}
		name, val := string(el[1:1+end]), el[2+end:]
		var size int
		switch typ {
		case 0x01, 0x09, 0x11, 0x12:
			size = 8
		case 0x02:
			if len(val) < 4 {
				return "", false
			}
			size = 4 + int(binary.LittleEndian.Uint32(val))
		case 0x03, 0x04:
			if len(val) < 4 {
				return "", false
			}
			size = int(binary.LittleEndian.Uint32(val))
		case 0x05:
			if len(val) < 4 {
				return "", false
			}
			size = 5 + int(binary.LittleEndian.Uint32(val))
		case 0x07:
			size = 12
		case 0x08:
			size = 1
			if len(val) > 0 && (name == "ismaster" || name == "isWritablePrimary") {
				found = true
			}
		case 0x0a:
		case 0x10:
			size = 4
			if len(val) >= 4 && name == "maxWireVersion" {
				wire = int32(binary.LittleEndian.Uint32(val))
				found = true
			}
		case 0x13:
			size = 16
		default:
			return mongoRelease(wire), found // a type not skipped: stop reading
		}
		if size < 0 || len(val) < size {
			break
		}
		el = val[size:]
	}
	return mongoRelease(wire), found
}

func mongoRelease(wire int32) string { return mongoReleases[wire] }
