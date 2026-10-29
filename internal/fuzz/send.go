package fuzz

import (
	"bytes"
	"context"
	"github.com/trannghiach/azhaq/internal/ledger"
	"io"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/trannghiach/azhaq/internal/fetch"
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
}

type httpSender struct {
	client *http.Client
}

// NewSender sends through internal/fetch: its client (dialer, TLS settings,
// the run's resolver), its default headers, and fetch.Spend before every
// request, which applies the run's request budget and pace.
func NewSender(o HTTPOptions) Sender {
	base := fetch.Client(nil)
	tr := ledger.Unwrap(base.Transport).(*http.Transport).Clone()
	tr.ResponseHeaderTimeout = o.Timeout
	tr.TLSHandshakeTimeout = o.Timeout
	// One connection kept per thread: the default keeps two, and a sweep
	// would open a connection for most requests.
	tr.MaxIdleConnsPerHost = max(o.Threads, 2)
	tr.MaxIdleConns = 2 * max(o.Threads, 2)
	c := &http.Client{Transport: ledger.Wrap(tr), Timeout: o.Timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	if o.Follow {
		c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 || (o.Allow != nil && !o.Allow(req.URL.Hostname())) {
				return http.ErrUseLastResponse
			}
			return nil
		}
	}
	return &httpSender{client: c}
}

func (s *httpSender) Send(ctx context.Context, req *Request, keepBody bool) (*Response, error) {
	method := req.Method
	if method == "" {
		method = http.MethodGet
	}
	var start time.Time
	var first time.Duration
	trace := &httptrace.ClientTrace{
		WroteRequest:         func(httptrace.WroteRequestInfo) { start = time.Now() },
		GotFirstResponseByte: func() { first = time.Since(start) },
	}
	hr, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), method, req.URL, bytes.NewReader([]byte(req.Data)))
	if err != nil {
		return nil, err
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
	body, length, words, lines, ok := readCounting(resp.Body, keepBody)
	if ok {
		r.Length, r.Words, r.Lines, r.Body = length, words, lines, body
	}
	r.Duration = int64(first)
	return r, nil
}

// readCounting reads up to MaxBody, counting as it goes, and keeps the
// bytes only when asked: words are spaces plus one, lines newlines plus one.
// ok is false when the body was longer than the most read.
func readCounting(r io.Reader, keep bool) (body []byte, length, words, lines int64, ok bool) {
	buf := make([]byte, 32<<10)
	var spaces, newlines int64
	for {
		n, err := r.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			if length+int64(n) > MaxBody {
				return nil, 0, 0, 0, false
			}
			length += int64(n)
			spaces += int64(bytes.Count(chunk, []byte{' '}))
			newlines += int64(bytes.Count(chunk, []byte{'\n'}))
			if keep {
				body = append(body, chunk...)
			}
		}
		if err != nil {
			return body, length, spaces + 1, newlines + 1, err == io.EOF
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
