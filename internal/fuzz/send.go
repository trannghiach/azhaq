package fuzz

import (
	"bufio"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/andybalholm/brotli"

	"github.com/trannghiach/azhaq/internal/fetch"
	"github.com/trannghiach/azhaq/internal/ledger"
)

// Sender sends one request and describes the answer. keepBody says a
// matcher will read the body.
type Sender interface {
	Send(ctx context.Context, req *Request, keepBody bool) (*Response, error)
}

// MaxBody is the most of an answer that is read: ffuf's 5 MB.
const MaxBody = 5 << 20

// HTTPOptions shape the real sender.
type HTTPOptions struct {
	Timeout time.Duration
	Threads int
	Follow  bool                   // -r: follow redirects
	Allow   func(host string) bool // hosts a followed redirect may go to

	Proxy       string // -x: http, https, socks5 or socks5h URL for every request
	ReplayProxy string // -replay-proxy: each match is sent once more through this
	IgnoreBody  bool   // -ignore-body: the body is not read
	Raw         bool   // -raw: the path goes out as written
	SNI         string // -sni: the server name in the TLS hello
	HTTP2       bool   // -http2
	CertFile    string // -cc and -ck: a client certificate
	KeyFile     string
	KeepRaw     bool // keep the request and answer as text, for -od
}

type httpSender struct {
	client *http.Client
	replay *http.Client
	opt    HTTPOptions
}

// Replayer sends a request that matched through the replay proxy. It is the
// user's own proxy: the copy is not a request to the target, so it is not in
// the ledger, the budget or the pace.
type Replayer interface {
	Replay(ctx context.Context, req *Request) error
}

// NewSender sends through internal/fetch: its client (dialer, TLS settings,
// the run's resolver), its default headers, and fetch.Spend before every
// request, which applies the run's request budget and pace.
func NewSender(o HTTPOptions) (Sender, error) {
	tlsConf, err := tlsFor(o)
	if err != nil {
		return nil, err
	}
	base := fetch.Client(nil)
	tr := ledger.Unwrap(base.Transport).(*http.Transport).Clone()
	tr.ResponseHeaderTimeout = o.Timeout
	tr.TLSHandshakeTimeout = o.Timeout
	tr.TLSClientConfig = tlsConf
	tr.ForceAttemptHTTP2 = o.HTTP2
	tr.MaxResponseHeaderBytes = 1 << 20
	// One connection kept per thread: the default keeps two, and a sweep
	// would open a connection for most requests.
	tr.MaxIdleConnsPerHost = max(o.Threads, 2)
	tr.MaxIdleConns = 2 * max(o.Threads, 2)
	if o.Proxy != "" {
		pu, err := url.Parse(o.Proxy)
		if err != nil {
			return nil, err
		}
		tr.Proxy = http.ProxyURL(pu)
	}
	s := &httpSender{opt: o}
	s.client = &http.Client{Transport: ledger.Wrap(tr), Timeout: o.Timeout, CheckRedirect: s.redirects()}
	if o.ReplayProxy != "" {
		pu, err := url.Parse(o.ReplayProxy)
		if err != nil {
			return nil, err
		}
		rt := tr.Clone()
		rt.Proxy = http.ProxyURL(pu)
		rt.ForceAttemptHTTP2 = false
		// No ledger, budget or pace: the proxy is the user's, not a target.
		s.replay = &http.Client{Transport: rt, Timeout: o.Timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	return s, nil
}

// tlsFor is the client's TLS settings: any certificate is taken (the run
// looks at what a server says, not whether it is trusted), and servers as old
// as TLS 1.0 are reached, as ffuf does.
func tlsFor(o HTTPOptions) (*tls.Config, error) {
	c := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10, Renegotiation: tls.RenegotiateOnceAsClient, ServerName: o.SNI}
	if o.CertFile != "" || o.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(o.CertFile, o.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("-cc and -ck: %v", err)
		}
		c.Certificates = []tls.Certificate{cert}
	}
	return c, nil
}

func (s *httpSender) redirects() func(*http.Request, []*http.Request) error {
	if !s.opt.Follow {
		return func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	}
	return func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 || (s.opt.Allow != nil && !s.opt.Allow(req.URL.Hostname())) {
			return http.ErrUseLastResponse
		}
		return nil
	}
}

// newRequest is req as an HTTP request: its headers, the Host header as the
// host asked for, and a default Accept.
func (s *httpSender) newRequest(ctx context.Context, req *Request) (*http.Request, error) {
	method := req.Method
	if method == "" {
		method = http.MethodGet
	}
	target, opaque := req.URL, ""
	if s.opt.Raw {
		target, opaque = splitRaw(req.URL)
	}
	hr, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader([]byte(req.Data)))
	if err != nil {
		return nil, err
	}
	if opaque != "" {
		hr.URL.Opaque = opaque // the request line takes it as written
	}
	for _, h := range req.Headers {
		if h.Name == "Host" {
			hr.Host = h.Value
		}
		hr.Header.Set(h.Name, h.Value)
	}
	if hr.Header.Get("Accept") == "" {
		hr.Header.Set("Accept", "*/*") // not the page-oriented default: answers as ffuf's, which sends none
	}
	fetch.ApplyHeaders(hr)
	return hr, nil
}

// splitRaw cuts "scheme://host/path?q" into the part Go parses and the
// path and query exactly as written.
func splitRaw(raw string) (target, opaque string) {
	i := strings.Index(raw, "://")
	if i < 0 {
		return raw, ""
	}
	rest := raw[i+3:]
	j := strings.IndexAny(rest, "/?")
	if j < 0 {
		return raw, ""
	}
	path := rest[j:]
	if path[0] == '?' {
		path = "/" + path
	}
	return raw[:i+3] + rest[:j] + "/", path
}

func (s *httpSender) Send(ctx context.Context, req *Request, keepBody bool) (*Response, error) {
	var start time.Time
	var first time.Duration
	trace := &httptrace.ClientTrace{
		WroteRequest:         func(httptrace.WroteRequestInfo) { start = time.Now() },
		GotFirstResponseByte: func() { first = time.Since(start) },
	}
	hr, err := s.newRequest(httptrace.WithClientTrace(ctx, trace), req)
	if err != nil {
		return nil, err
	}
	var rawReq []byte
	if s.opt.KeepRaw {
		rawReq, _ = httputil.DumpRequestOut(hr, true)
	}
	if err := fetch.Spend(ctx); err != nil {
		return nil, err
	}
	resp, err := s.client.Do(hr)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	r := &Response{Status: resp.StatusCode, Header: resp.Header, ContentType: resp.Header.Get("Content-Type"), Request: req}
	if n, err := strconv.Atoi(resp.Header.Get("Content-Length")); err == nil {
		r.Length = int64(n)
		if n > MaxBody {
			return r, nil // not read: size only, as ffuf
		}
	}
	if s.opt.IgnoreBody {
		return r, nil
	}
	// Bound what is pulled off the wire: a compressed body is decoded below
	// and must not swell past the cap either.
	resp.Body = struct {
		io.Reader
		io.Closer
	}{io.LimitReader(resp.Body, MaxBody+1), resp.Body}
	if s.opt.KeepRaw {
		raw, _ := httputil.DumpResponse(resp, true)
		r.RawRequest, r.RawResponse = string(rawReq), string(raw)
	}
	body, length, words, lines, ok, err := readCounting(decoded(resp), keepBody)
	if err != nil {
		// Cut off: its size is no answer's, and would pass a size filter.
		return nil, fmt.Errorf("answer cut off after %d bytes: %w", length, err)
	}
	if ok {
		r.Length, r.Words, r.Lines, r.Body = length, words, lines, body
	} else {
		r.RawResponse = "" // cut at the cap: not kept as if it were whole
	}
	r.Duration = int64(first)
	return r, nil
}

// Replay sends req through the replay proxy and drops the answer.
func (s *httpSender) Replay(ctx context.Context, req *Request) error {
	if s.replay == nil {
		return nil
	}
	hr, err := s.newRequest(ctx, req)
	if err != nil {
		return err
	}
	resp, err := s.replay.Do(hr)
	if err != nil {
		return err
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, MaxBody))
	return resp.Body.Close()
}

// decoded is the body of resp as sent: the transport undoes gzip it asked for
// itself, but a request that names its own Accept-Encoding (a browser's, or
// "copy as cURL") gets the body as the server compressed it, and ffuf counts
// the decoded bytes.
func decoded(resp *http.Response) io.Reader {
	br := bufio.NewReader(resp.Body)
	var d io.Reader
	switch strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Encoding"))) {
	case "gzip", "x-gzip":
		if head, _ := br.Peek(2); len(head) == 2 && head[0] == 0x1f && head[1] == 0x8b {
			if zr, err := gzip.NewReader(br); err == nil {
				d = zr
			}
		}
	case "br":
		d = brotli.NewReader(br)
	case "deflate":
		// "deflate" is zlib-wrapped; some servers send the bare stream.
		if head, _ := br.Peek(2); len(head) == 2 && (uint(head[0])<<8|uint(head[1]))%31 == 0 && head[0]&0x0f == 8 {
			if zr, err := zlib.NewReader(br); err == nil {
				d = zr
			}
		} else {
			d = flate.NewReader(br)
		}
	}
	if d == nil {
		return br
	}
	return io.LimitReader(d, MaxBody+1)
}

// readCounting reads up to MaxBody, counting as it goes, and keeps the
// bytes only when asked: words are spaces plus one, lines newlines plus one.
// ok is false when the body was longer than the most read; err says the
// body ended early.
func readCounting(r io.Reader, keep bool) (body []byte, length, words, lines int64, ok bool, err error) {
	buf := make([]byte, 32<<10)
	var spaces, newlines int64
	for {
		n, rerr := r.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			if length+int64(n) > MaxBody {
				return nil, 0, 0, 0, false, nil
			}
			length += int64(n)
			spaces += int64(bytes.Count(chunk, []byte{' '}))
			newlines += int64(bytes.Count(chunk, []byte{'\n'}))
			if keep {
				body = append(body, chunk...)
			}
		}
		if rerr == io.EOF {
			return body, length, spaces + 1, newlines + 1, true, nil
		}
		if rerr != nil {
			return nil, length, 0, 0, false, rerr
		}
	}
}

// RedirectLocation is the Location of a 3xx answer, as sent; absolute
// resolves it against the request URL the way ffuf does, so a redirect to
// the same site compares equal to the URL asked.
func RedirectLocation(r *Response, absolute bool) string {
	loc := ""
	if r.Status >= 300 && r.Status <= 399 {
		loc = r.Header.Get("Location")
	}
	if !absolute || loc == "" {
		return loc
	}
	to, err := url.Parse(loc)
	if err != nil {
		return loc
	}
	base, err := url.Parse(r.Request.URL)
	if err != nil {
		return loc
	}
	if to.IsAbs() && to.Hostname() == base.Hostname() && to.Scheme == base.Scheme && port(to) == port(base) {
		return to.Scheme + "://" + base.Host + to.Path
	}
	return base.ResolveReference(to).String()
}

func port(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	if strings.EqualFold(u.Scheme, "https") {
		return "443"
	}
	return "80"
}
