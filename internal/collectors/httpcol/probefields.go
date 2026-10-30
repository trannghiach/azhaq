package httpcol

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	jarm "github.com/hdm/jarm-go"
	"github.com/mfonda/simhash"
	"github.com/microcosm-cc/bluemonday"
	"golang.org/x/net/html"
	"golang.org/x/net/html/charset"
	"golang.org/x/net/http2"
	"golang.org/x/text/transform"

	"github.com/trannghiach/azhaq/internal/cpedetect"
	"github.com/trannghiach/azhaq/internal/fetch"
	"github.com/trannghiach/azhaq/internal/fingerprint"
	"github.com/trannghiach/azhaq/internal/normalize"
	"github.com/trannghiach/azhaq/internal/pagekind"
)

// The probe's fields follow httpx v1.12 (MIT, github.com/projectdiscovery/httpx):
// hash names, the title rule, the tls object and the websocket test come
// from it.

// canHaveTitle is httpx's rule: only these content types are read for a title.
func canHaveTitle(contentType string) bool {
	ct, _, _ := strings.Cut(strings.ToLower(contentType), ";")
	switch strings.TrimSpace(ct) {
	case "text/html", "application/xhtml+xml", "application/xml", "application/rss+xml", "application/atom+xml", "application/vnd.wap.xhtml+xml":
		return true
	}
	return false
}

// domTitle is the text of the first <title> element, with httpx's cleaning:
// newlines, tabs and the like are dropped, not turned into spaces.
func domTitle(data []byte) string {
	doc, err := html.Parse(bytes.NewReader(data))
	if err != nil {
		return ""
	}
	var find func(*html.Node) *html.Node
	find = func(n *html.Node) *html.Node {
		if n.Type == html.ElementNode && n.Data == "title" {
			return n
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			if t := find(c); t != nil {
				return t
			}
		}
		return nil
	}
	t := find(doc)
	if t == nil {
		return ""
	}
	var b strings.Builder
	for c := t.FirstChild; c != nil; c = c.NextSibling {
		if c.Type == html.TextNode {
			b.WriteString(c.Data)
		}
	}
	s := strings.TrimSpace(strings.Trim(b.String(), "\n\t\v\f\r"))
	return strings.NewReplacer("\n", "", "\t", "", "\v", "", "\f", "", "\r", "").Replace(s)
}

// decode is the body in UTF-8 when its charset is declared (the header, a
// byte order mark or a <meta>) and is not already UTF-8; httpx does this
// for GBK, Big5 and EUC-KR only.
func decode(body []byte, h http.Header) []byte {
	if len(body) == 0 {
		return body
	}
	enc, name, certain := charset.DetermineEncoding(body[:min(len(body), 4096)], headerGet(h, "Content-Type"))
	if !certain || name == "utf-8" || enc == nil {
		return body
	}
	out, _, err := transform.Bytes(enc.NewDecoder(), body)
	if err != nil {
		return body
	}
	return out
}

// hashes are the body and header digests of -hash, named as httpx names them.
func hashes(kinds []string, body []byte, head string) map[string]any {
	out := map[string]any{}
	for _, k := range kinds {
		k = strings.ToLower(strings.TrimSpace(k))
		sum := func(b []byte) string {
			switch k {
			case "md5":
				s := md5.Sum(b)
				return hex.EncodeToString(s[:])
			case "sha1":
				s := sha1.Sum(b)
				return hex.EncodeToString(s[:])
			case "sha256":
				s := sha256.Sum256(b)
				return hex.EncodeToString(s[:])
			case "sha512":
				s := sha512.Sum512(b)
				return hex.EncodeToString(s[:])
			case "mmh3":
				return fingerprint.Mmh3(b)
			case "simhash":
				return strconv.FormatUint(simhash.Simhash(simhash.NewWordFeatureSet(b)), 10)
			}
			return ""
		}
		if v := sum(body); v != "" {
			out["body_"+k] = v
			out["header_"+k] = sum([]byte(head))
		}
	}
	return out
}

// HashKinds are the digests -hash accepts.
var HashKinds = []string{"md5", "mmh3", "simhash", "sha1", "sha256", "sha512"}

var stripTags = bluemonday.NewPolicy() // allows no element: only text is left
var spaces = regexp.MustCompile(`\s+`)

// preview is the first n characters of the body on one line with its tags
// stripped, as httpx's -bp: the text is HTML-escaped as it is by httpx.
func preview(data []byte, n int) string {
	s := stripTags.Sanitize(string(data))
	s = spaces.ReplaceAllString(strings.ReplaceAll(s, "\n", ""), " ")
	if len(s) > n {
		s = s[:n]
	}
	return strings.TrimSpace(s)
}

// ExtractPresets are the names -ep takes, and what each finds.
var ExtractPresets = map[string]string{
	"url":  `https?://[^\s"'<>\x60)\]]+`,
	"ipv4": `\b(?:(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})\b`,
	"mail": `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`,
}

// websocket is httpx's test: a 101, or headers or a body that name one.
var wsHeader = []*regexp.Regexp{
	regexp.MustCompile(`(?m)^Sec-WebSocket-Accept:\s+.+`),
	regexp.MustCompile(`(?m)^Upgrade:\s+websocket`),
	regexp.MustCompile(`(?m)^Connection:\s+upgrade`),
}

var wsBody = []*regexp.Regexp{
	regexp.MustCompile(`{"socket":true,"socketUrl":"(?:wss?|ws)://.*"}`),
	regexp.MustCompile(`{"sid":"[^"]*","upgrades":\["websocket"\].*}`),
}

func isWebSocket(status int, head string, data []byte) bool {
	if status == 101 {
		return true
	}
	for _, re := range wsHeader {
		if re.MatchString(head) {
			return true
		}
	}
	for _, re := range wsBody {
		if re.Match(data) {
			return true
		}
	}
	return false
}

var tlsVersions = map[uint16]string{tls.VersionTLS10: "tls10", tls.VersionTLS11: "tls11", tls.VersionTLS12: "tls12", tls.VersionTLS13: "tls13"}

// tlsData is httpx's tls object for the handshake of an answer.
func tlsData(raw string, t *fetch.TLSInfo) map[string]any {
	if t == nil || len(t.Certs) == 0 {
		return nil
	}
	cert, err := x509.ParseCertificate(t.Certs[0])
	if err != nil {
		return nil
	}
	host, port := "", "443"
	if u, err := url.Parse(raw); err == nil {
		host = u.Hostname()
		if p := u.Port(); p != "" {
			port = p
		}
	}
	names := append(append([]string(nil), cert.DNSNames...), cert.Subject.CommonName)
	out := map[string]any{
		"host": host, "port": port, "probe_status": true,
		"tls_version": tlsVersions[t.Version], "cipher": tls.CipherSuiteName(t.Cipher),
		"not_before": cert.NotBefore.Format(time.RFC3339Nano), "not_after": cert.NotAfter.Format(time.RFC3339Nano),
		"subject_dn": dn(cert.Subject.String()), "subject_cn": cert.Subject.CommonName,
		"issuer_dn": dn(cert.Issuer.String()), "issuer_cn": cert.Issuer.CommonName,
		"serial":           serial(cert.SerialNumber),
		"fingerprint_hash": map[string]any{"md5": sumHex(md5.Sum(cert.Raw)), "sha1": sumHex(sha1.Sum(cert.Raw)), "sha256": sumHex(sha256.Sum256(cert.Raw))},
		"tls_connection":   "ctls",
	}
	if len(cert.Subject.Organization) > 0 {
		out["subject_org"] = cert.Subject.Organization
	}
	if len(cert.Issuer.Organization) > 0 {
		out["issuer_org"] = cert.Issuer.Organization
	}
	if len(cert.DNSNames) > 0 {
		out["subject_an"] = cert.DNSNames
	}
	if len(cert.EmailAddresses) > 0 {
		out["emails"] = cert.EmailAddresses
	}
	if time.Now().After(cert.NotAfter) {
		out["expired"] = true
	}
	if len(cert.AuthorityKeyId) == 0 || bytes.Equal(cert.AuthorityKeyId, cert.SubjectKeyId) {
		out["self_signed"] = true
	}
	if misMatched(host, names) {
		out["mismatched"] = true
	}
	for _, n := range names {
		if strings.Contains(n, "*.") {
			out["wildcard_certificate"] = true
			break
		}
	}
	if t.ServerName != "" {
		out["sni"] = t.ServerName
	}
	return out
}

func sumHex[A interface{ [16]byte | [20]byte | [32]byte }](a A) string {
	switch v := any(a).(type) {
	case [16]byte:
		return hex.EncodeToString(v[:])
	case [20]byte:
		return hex.EncodeToString(v[:])
	case [32]byte:
		return hex.EncodeToString(v[:])
	}
	return ""
}

// dn separates the parts of a distinguished name with ", ", as httpx prints it.
func dn(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		b.WriteByte(s[i])
		if s[i] == ',' && (i == 0 || s[i-1] != '\\') && i+1 < len(s) && s[i+1] != ' ' {
			b.WriteByte(' ')
		}
	}
	return b.String()
}

// serial is the certificate serial as upper-case hex pairs: 0A:1B.
func serial(n *big.Int) string {
	if n == nil || n.Sign() == 0 {
		return ""
	}
	b := strings.ToUpper(hex.EncodeToString(n.Bytes()))
	var parts []string
	for i := 0; i+1 < len(b); i += 2 {
		parts = append(parts, b[i:i+2])
	}
	return strings.Join(parts, ":")
}

// misMatched: none of the certificate's names is the host (a wildcard
// covers one label).
func misMatched(host string, names []string) bool {
	if host == "" {
		return false
	}
	for _, n := range names {
		n = strings.ToLower(n)
		if n == strings.ToLower(host) {
			return false
		}
		if rest, ok := strings.CutPrefix(n, "*."); ok {
			if _, tail, ok := strings.Cut(strings.ToLower(host), "."); ok && tail == rest {
				return false
			}
		}
	}
	return true
}

// jarmHash is the JARM fingerprint of a TLS server: ten handshakes, each
// counted and paced as a request.
func jarmHash(ctx context.Context, raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" {
		return ""
	}
	port := 443
	if p := u.Port(); p != "" {
		port, _ = strconv.Atoi(p)
	}
	host := u.Hostname()
	var results []string
	for _, probe := range jarm.GetProbes(host, port) {
		if err := fetch.Spend(ctx); err != nil {
			return ""
		}
		c, err := fetch.Dial(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
		if err != nil {
			return ""
		}
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := c.Write(jarm.BuildProbe(probe)); err != nil {
			c.Close()
			return ""
		}
		buf := make([]byte, 1484)
		_, _ = c.Read(buf)
		c.Close()
		ans, err := jarm.ParseServerHello(buf, probe)
		if err != nil {
			return ""
		}
		results = append(results, ans)
	}
	return jarm.RawHashToFuzzyHash(strings.Join(results, ","))
}

// supportsHTTP2 asks once: for h2 over TLS, or for an upgrade to h2c on a
// plain connection.
func (c *Collector) supportsHTTP2(ctx context.Context, raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	if err := fetch.Spend(ctx); err != nil {
		return false
	}
	if u.Scheme == "http" {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
		if err != nil {
			return false
		}
		fetch.ApplyHeaders(req)
		req.Header.Set("Connection", "Upgrade, HTTP2-Settings")
		req.Header.Set("Upgrade", "h2c")
		req.Header.Set("HTTP2-Settings", "AAMAAABkAARAAAAAAAIAAAAA")
		resp, err := noRedirect(c.Client).Do(req)
		if err != nil {
			return false
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return resp.StatusCode == http.StatusSwitchingProtocols
	}
	tr := &http2.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
			conn, err := fetch.Dial(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			host, _, _ := net.SplitHostPort(addr)
			cfg = cfg.Clone()
			cfg.InsecureSkipVerify, cfg.ServerName = true, host
			tc := tls.Client(conn, cfg)
			if err := tc.HandshakeContext(ctx); err != nil {
				conn.Close()
				return nil, err
			}
			return tc, nil
		},
	}
	defer tr.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return false
	}
	fetch.ApplyHeaders(req)
	resp, err := (&http.Client{Transport: tr, Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return false
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.ProtoMajor == 2
}

func noRedirect(c *http.Client) *http.Client {
	cp := *c
	cp.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &cp
}

// supportsPipeline is httpx's test: ten requests written one after another
// on one connection, and at least two answers read back.
func supportsPipeline(ctx context.Context, raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	port := u.Port()
	if port == "" {
		port = map[string]string{"http": "80", "https": "443"}[u.Scheme]
	}
	const n = 10
	for i := 0; i < n; i++ {
		if fetch.Spend(ctx) != nil {
			return false
		}
	}
	conn, err := fetch.Dial(ctx, "tcp", net.JoinHostPort(u.Hostname(), port))
	if err != nil {
		return false
	}
	defer conn.Close()
	if u.Scheme == "https" {
		tc := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, ServerName: u.Hostname(), MinVersion: tls.VersionTLS10})
		if tc.HandshakeContext(ctx) != nil {
			return false
		}
		conn = tc
	}
	req := fmt.Sprintf("GET / HTTP/1.1\nHost: %s\n\n", net.JoinHostPort(u.Hostname(), port))
	for i := 0; i < n; i++ {
		if _, err := conn.Write([]byte(req)); err != nil {
			return false
		}
	}
	got := 0
	buf := make([]byte, 1024)
	for i := 0; i < n; i++ {
		if conn.SetReadDeadline(time.Now().Add(time.Second)) != nil {
			return false
		}
		k, err := conn.Read(buf)
		if err != nil {
			break
		}
		for _, part := range strings.Split(string(buf[:k]), "\n\n") {
			low := strings.ToLower(part)
			if strings.Contains(low, "http/1.1") || strings.Contains(low, "http/1.0") {
				got++
			}
		}
	}
	return got >= 2
}

// isVirtualHost asks again with a Host that cannot exist (a random label
// before the host) and says whether the answer differs: status, length,
// words, lines, or a response less than 85% alike (httpx's test).
func (c *Collector) isVirtualHost(ctx context.Context, raw string, first fetch.Result, firstRaw string, firstLen int) bool {
	var rnd [6]byte
	_, _ = rand.Read(rnd[:])
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	rq := &fetch.Req{Header: http.Header{"Host": {hex.EncodeToString(rnd[:]) + "." + u.Host}}}
	res, _, err := fetch.DoReq(ctx, c.Client, raw, rq)
	if err != nil {
		return false
	}
	last := lastHeader(res)
	n2, err := strconv.Atoi(headerGet(last, "Content-Length"))
	if err != nil || n2 <= 0 {
		n2 = len(res.Body)
	}
	w1, l1 := fingerprint.Stats(first.Body)
	w2, l2 := fingerprint.Stats(res.Body)
	status := func(r fetch.Result) int {
		if k := len(r.Hops); k > 0 {
			return r.Hops[k-1].Status
		}
		return r.Status
	}
	if status(first) != status(res) || firstLen != n2 || w1 != w2 || l1 != l2 {
		return true
	}
	second := ""
	if res.Raw != nil {
		second = res.Raw.Head + string(res.Body)
	}
	return int(dice(firstRaw, second)*100) <= 85
}

// dice is the Sørensen–Dice coefficient of the character pairs of two
// strings, spaces ignored (as the strsim package httpx uses).
func dice(a, b string) float64 {
	a, b = strings.ReplaceAll(a, " ", ""), strings.ReplaceAll(b, " ", "")
	if a == b {
		return 1
	}
	if len(a) < 2 || len(b) < 2 {
		return 0
	}
	pairs := map[string]int{}
	for i := 0; i < len(a)-1; i++ {
		pairs[a[i:i+2]]++
	}
	hit := 0
	for i := 0; i < len(b)-1; i++ {
		if pairs[b[i:i+2]] > 0 {
			pairs[b[i:i+2]]--
			hit++
		}
	}
	return 2 * float64(hit) / float64(len(a)+len(b)-2)
}

var jarmSeen sync.Map // origin → hash, one fingerprint per TLS server

// probeFields adds what httpx reports to the row of an answer and keeps
// the answer itself for the matchers. It returns the observation's source:
// the URL, led by the method when it is not a GET.
func (c *Collector) probeFields(ctx context.Context, row map[string]any, raw, reqURL, final string, res fetch.Result, data []byte, rq *fetch.Req) string {
	sp := c.Spec
	method := res.Method
	if method == "" {
		method = http.MethodGet
	}
	row["method"] = method
	last := lastHeader(res)
	if sp.Follow {
		row["content_type"] = headerGet(last, "Content-Type")
		row["server"] = headerGet(last, "Server")
		row["location"] = headerGet(last, "Location")
	}
	// httpx's length is the header's, else the bytes read.
	if n, err := strconv.Atoi(headerGet(last, "Content-Length")); err == nil && n > 0 {
		row["length"] = n
	} else {
		row["length"] = len(data)
	}
	head := ""
	var tlsInfo *fetch.TLSInfo
	if res.Raw != nil {
		head, tlsInfo = res.Raw.Head, res.Raw.TLS
	}
	status := res.Status
	if n := len(res.Hops); n > 0 {
		status = res.Hops[n-1].Status
	}
	row["elapsed_ns"] = res.Elapsed.Nanoseconds()
	if len(sp.Hashes) > 0 {
		row["hash"] = hashes(sp.Hashes, data, head)
	}
	if sp.Preview > 0 {
		if p := preview(data, sp.Preview); p != "" {
			row["body_preview"] = p
		}
	}
	if len(sp.extract) > 0 {
		whole := head + string(res.Body)
		ex := map[string][]string{}
		for i, re := range sp.extract {
			var uniq []string
			seen := map[string]bool{}
			for _, m := range re.FindAllString(whole, -1) {
				if !seen[m] {
					seen[m] = true
					uniq = append(uniq, m)
				}
			}
			if len(uniq) > 0 {
				ex[sp.Extract[i].Name] = uniq
			}
		}
		if len(ex) > 0 {
			row["extracts"] = ex
		}
	}
	if sp.CPE || sp.WP || sp.KB {
		extras(row, sp, data, res)
	}
	if isWebSocket(status, head, data) {
		row["websocket"] = true
	}
	if sp.SNI != "" {
		row["sni"] = sp.SNI
	}
	if sp.TLS || sp.TLSProbe {
		if t := tlsData(raw, tlsInfo); t != nil {
			row["tls"] = t
		}
	}
	var next []string
	if sp.CSPProbe || sp.EFQDN {
		if csp := cspNames(last, data); csp != nil {
			row["csp"] = csp
			if sp.CSPProbe {
				next = append(next, csp["domains"].([]string)...)
				next = append(next, csp["fqdn"].([]string)...)
			}
		}
	}
	if sp.EFQDN {
		if bd := bodyNames(data); len(bd["body_fqdn"]) > 0 || len(bd["body_domains"]) > 0 {
			row["body_fqdn"], row["body_domains"] = bd["body_fqdn"], bd["body_domains"]
		}
	}
	if sp.TLSProbe {
		if t, ok := row["tls"].(map[string]any); ok {
			for _, n := range strs(t["subject_an"]) {
				next = append(next, strings.TrimPrefix(strings.TrimPrefix(n, "*"), "."))
			}
			if cn, _ := t["subject_cn"].(string); cn != "" {
				next = append(next, strings.TrimPrefix(strings.TrimPrefix(cn, "*"), "."))
			}
		}
	}
	if len(next) > 0 {
		names.Store(reqURL, dedupeStrings(next))
	}
	if sp.JARM && strings.HasPrefix(raw, "https://") {
		origin := originOf(raw)
		v, ok := jarmSeen.Load(origin)
		if !ok {
			v = jarmHash(ctx, raw)
			jarmSeen.Store(origin, v)
		}
		if h := v.(string); h != "" {
			row["jarm_hash"] = h
		}
	}
	if sp.HTTP2 && c.supportsHTTP2(ctx, raw) {
		row["http2"] = true
	}
	if sp.Pipeline && supportsPipeline(ctx, raw) {
		row["pipeline"] = true
	}
	if sp.VHost && c.isVirtualHost(ctx, raw, res, head+string(res.Body), intOfRow(row["length"])) {
		row["vhost"] = true
	}
	source := reqURL
	if method != http.MethodGet || !rq.Plain() {
		source = method + " " + reqURL
		if rq != nil {
			source += " #" + rq.Key("")
		}
	}
	if sp.Evidence {
		ev := &Evidence{Method: method, Head: head, Body: res.Body, Data: data, URL: reqURL, Final: final, Hops: res.Hops, Elapsed: res.Elapsed}
		if res.Raw != nil {
			ev.Request, ev.Chain = res.Raw.Request, res.Raw.Chain
		}
		evidence.Store(source, ev)
	}
	return source
}

func originOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	port := u.Port()
	if port == "" {
		port = map[string]string{"http": "80", "https": "443"}[u.Scheme]
	}
	return u.Scheme + "://" + net.JoinHostPort(u.Hostname(), port)
}

// iconHref is the href the page gave for an icon found at u, as httpx
// reports it: "data:" for an inline one, "/favicon.ico" when the page
// named none.
func iconHref(body []byte, page, u string) string {
	if u == "data:" {
		return u
	}
	base, err := url.Parse(page)
	if err != nil {
		return u
	}
	z := html.NewTokenizer(bytes.NewReader(body))
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			break
		}
		if tt != html.StartTagToken && tt != html.SelfClosingTagToken {
			continue
		}
		tok := z.Token()
		if tok.Data != "link" {
			continue
		}
		var href string
		for _, a := range tok.Attr {
			if a.Key == "href" {
				href = strings.TrimSpace(a.Val)
			}
		}
		if p, err := base.Parse(href); err == nil && href != "" && p.String() == u {
			return href
		}
	}
	if p, err := url.Parse(u); err == nil {
		return p.Path
	}
	return u
}

func intOfRow(v any) int {
	n, _ := v.(int)
	return n
}

var (
	cpeOnce sync.Once
	cpeDet  *cpedetect.CPEDetector
	wpDet   *cpedetect.WordPressDetector
)

func detectors() {
	cpeOnce.Do(func() {
		cpeDet, _ = cpedetect.NewCPEDetector() // the data is embedded: no failure to report
		wpDet, _ = cpedetect.NewWordPressDetector()
	})
}

// extras adds -cpe, -wp and -kb.
func extras(row map[string]any, sp *Spec, data []byte, res fetch.Result) {
	if sp.CPE || sp.WP {
		detectors()
	}
	if sp.CPE && cpeDet != nil {
		title, _ := row["title"].(string)
		fav, _ := row["favicon"].(string)
		var tech []string
		if t, ok := row["tech"].([]string); ok {
			tech = t
		}
		m := cpedetect.EnrichCPEVersions(cpeDet.Detect(title, string(data), fav), tech)
		if len(m) > 0 {
			sort.Slice(m, func(i, j int) bool { return m[i].CPE+m[i].Product < m[j].CPE+m[j].Product })
			row["cpe"] = m
		}
	}
	if sp.WP && wpDet != nil {
		if info := wpDet.Detect(string(data)); info.HasData() {
			row["wordpress"] = info
		}
	}
	if sp.KB {
		kb := map[string]any{"pHash": 0}
		if r, ok := pagekind.Classify(string(data)); ok {
			kb["PageType"] = r.Type
			if r.Forms != nil {
				kb["Forms"] = r.Forms
			}
		}
		row["knowledgebase"] = kb
	}
}

func strs(v any) []string {
	switch x := v.(type) {
	case []string:
		return x
	}
	return nil
}

func dedupeStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

var cspHeaders = []string{"Content-Security-Policy", "Content-Security-Policy-Report-Only", "X-Content-Security-Policy-Report-Only", "X-Webkit-Csp-Report-Only"}

// cspNames are the hosts a Content-Security-Policy (header or <meta>) names:
// the registrable domains and the longer names under them, as httpx's csp.
func cspNames(h http.Header, body []byte) map[string]any {
	domains, fqdns := map[string]bool{}, map[string]bool{}
	add := func(policy string) {
		for _, t := range strings.FieldsFunc(policy, func(r rune) bool { return r == ' ' || r == ';' || r == ',' }) {
			if !strings.Contains(t, ".") && !strings.HasPrefix(t, "http") {
				continue
			}
			host := hostOfToken(t)
			if host == "" || net.ParseIP(host) != nil {
				continue
			}
			apex := normalize.RegistrableDomain(host)
			if apex == "" {
				continue
			}
			domains[apex] = true
			if host != apex {
				fqdns[host] = true
			}
		}
	}
	for _, name := range cspHeaders {
		for _, v := range h.Values(name) {
			add(v)
		}
	}
	z := html.NewTokenizer(bytes.NewReader(body))
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			break
		}
		if tt != html.StartTagToken && tt != html.SelfClosingTagToken {
			continue
		}
		tok := z.Token()
		if tok.Data != "meta" {
			continue
		}
		var equiv, content string
		for _, a := range tok.Attr {
			switch a.Key {
			case "http-equiv":
				equiv = a.Val
			case "content":
				content = a.Val
			}
		}
		if equiv != "" && content != "" {
			add(content)
		}
	}
	if len(domains) == 0 && len(fqdns) == 0 {
		return nil
	}
	return map[string]any{"domains": sortedKeys(domains), "fqdn": sortedKeys(fqdns)}
}

// hostOfToken is the host of a CSP source: quotes and wildcard labels are
// dropped (*.example.com is example.com).
func hostOfToken(t string) string {
	t = strings.Trim(t, `'"`)
	if _, rest, ok := strings.Cut(t, "://"); ok {
		t = rest
	}
	var keep []string
	for _, part := range strings.Split(t, ".") {
		if !strings.Contains(part, "*") {
			keep = append(keep, part)
		}
	}
	u, err := url.Parse("https://" + strings.Join(keep, "."))
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

var hostRE = regexp.MustCompile(`(?i)(?:^|['"/@])([a-z0-9]+[a-z0-9.-]*\.[a-z]{2,})(?:['"/@]|$)`)

// urlAttrs are the attributes that hold a URL.
var urlAttrs = map[string]bool{"href": true, "src": true, "action": true, "formaction": true, "poster": true, "cite": true, "data-url": true, "data-href": true}

// bodyNames are the host names a page names in the attributes that hold URLs
// and in its text, as the names (body_fqdn) and their registrable domains.
// httpx also reads the syntax tree of inline scripts; this reads their text.
func bodyNames(data []byte) map[string][]string {
	domains, fqdns := map[string]bool{}, map[string]bool{}
	note := func(host string) {
		host = strings.ToLower(strings.Trim(host, "."))
		if host == "" || net.ParseIP(host) != nil || !strings.Contains(host, ".") {
			return
		}
		apex := normalize.RegistrableDomain(host)
		if apex == "" {
			return
		}
		domains[apex] = true
		if host != apex {
			fqdns[host] = true
		}
	}
	z := html.NewTokenizer(bytes.NewReader(data))
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			break
		}
		switch tt {
		case html.StartTagToken, html.SelfClosingTagToken:
			tok := z.Token()
			for _, a := range tok.Attr {
				if urlAttrs[a.Key] {
					if u, err := url.Parse(strings.TrimSpace(a.Val)); err == nil && u.Hostname() != "" {
						note(u.Hostname())
					}
				}
			}
		case html.TextToken:
			for _, m := range hostRE.FindAllSubmatch(z.Text(), -1) {
				note(string(m[1]))
			}
		}
	}
	return map[string][]string{"body_fqdn": sortedKeys(fqdns), "body_domains": sortedKeys(domains)}
}
