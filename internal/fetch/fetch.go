package fetch

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/trannghiach/azhaq/internal/timing"
)

type Hop struct {
	URL      string `json:"url"`
	Status   int    `json:"status"`
	Location string `json:"location,omitempty"`
}

const (
	UserAgent = "azhaq/0.3.1"
	MaxBody   = 512 << 10
)

type Result struct {
	RequestURL string
	Status     int // first hop: the requested URL's own status
	URL        string
	Header     http.Header // first hop headers
	Body       []byte      // final body (for title / forms)
	StatusLine string
	Hops       []Hop
	Truncated  bool
}

// Extra is copied onto every GET. Cookie values stay on the wire, not in Extra's docs.
var Extra http.Header

var (
	cacheMu  sync.Mutex
	cache    = map[string]cacheEnt{}
	inflight = map[string]chan struct{}{}
	hostSem  = map[string]chan struct{}{}
)

// HostParallel caps in-flight uncached GETs per host (crawl politeness).
var HostParallel = 2

// Delay is a pause before each uncached GET.
var Delay time.Duration

// Reset clears the process GET cache and host gates. Tests and bench call this.
func Reset() {
	cacheMu.Lock()
	cache = map[string]cacheEnt{}
	inflight = map[string]chan struct{}{}
	hostSem = map[string]chan struct{}{}
	Extra = nil
	Delay = 0
	cacheMu.Unlock()
}

type cacheEnt struct {
	res Result
	err error
}

func Client(c *http.Client) *http.Client {
	if c != nil {
		return c
	}
	// InsecureSkipVerify: we are observing whatever cert is presented (same as azhaq-tls).
	return &http.Client{
		Timeout: 8 * time.Second,
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
			TLSHandshakeTimeout:   5 * time.Second,
			ResponseHeaderTimeout: 5 * time.Second,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				MinVersion:         tls.VersionTLS12,
			},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func GET(ctx context.Context, c *http.Client, raw string) (*http.Response, []byte, error) {
	res, _, err := Do(ctx, c, raw)
	if err != nil {
		return nil, nil, err
	}
	final := res.URL
	if final == "" {
		final = res.RequestURL
	}
	resp := &http.Response{
		StatusCode: res.Status,
		Status:     res.StatusLine,
		Header:     res.Header.Clone(),
		Request:    &http.Request{URL: mustURL(final)},
	}
	return resp, res.Body, nil
}

func Do(ctx context.Context, c *http.Client, raw string) (Result, bool, error) {
	cacheMu.Lock()
	if e, ok := cache[raw]; ok {
		cacheMu.Unlock()
		return e.res, true, e.err
	}
	if wait, ok := inflight[raw]; ok {
		cacheMu.Unlock()
		done := timing.Start(ctx, "fetch.wait", raw)
		select {
		case <-ctx.Done():
			done()
			return Result{}, true, ctx.Err()
		case <-wait:
		}
		done()
		cacheMu.Lock()
		e := cache[raw]
		cacheMu.Unlock()
		return e.res, true, e.err
	}
	wait := make(chan struct{})
	inflight[raw] = wait
	cacheMu.Unlock()

	release, err := acquireHost(ctx, raw)
	if err != nil {
		cacheMu.Lock()
		cache[raw] = cacheEnt{err: err}
		delete(inflight, raw)
		close(wait)
		cacheMu.Unlock()
		return Result{}, false, err
	}
	if Delay > 0 {
		t := time.NewTimer(Delay)
		select {
		case <-ctx.Done():
			t.Stop()
			release()
			cacheMu.Lock()
			cache[raw] = cacheEnt{err: ctx.Err()}
			delete(inflight, raw)
			close(wait)
			cacheMu.Unlock()
			return Result{}, false, ctx.Err()
		case <-t.C:
		}
	}
	done := timing.Start(ctx, "fetch", raw)
	res, err := do(ctx, c, raw)
	done()
	release()

	cacheMu.Lock()
	cache[raw] = cacheEnt{res: res, err: err}
	if err == nil {
		cacheHopsLocked(res)
	}
	delete(inflight, raw)
	close(wait)
	cacheMu.Unlock()
	return res, false, err
}

// cacheHopsLocked records each hop URL so a redirect partner is not walked again.
func cacheHopsLocked(res Result) {
	for i, hop := range res.Hops {
		if hop.URL == "" {
			continue
		}
		if _, ok := cache[hop.URL]; ok {
			continue
		}
		rest := res.Hops[i:]
		status := 0
		if len(rest) > 0 {
			status = rest[0].Status
		}
		cache[hop.URL] = cacheEnt{res: Result{
			RequestURL: hop.URL,
			Status:     status,
			StatusLine: res.StatusLine,
			URL:        res.URL,
			Header:     res.Header,
			Body:       res.Body,
			Hops:       rest,
			Truncated:  res.Truncated,
		}}
	}
}

func do(ctx context.Context, c *http.Client, raw string) (Result, error) {
	c = noFollow(c)
	current := raw
	var hops []Hop
	var firstHeader http.Header
	var firstLine string
	var lastBody []byte
	var lastURL string
	var lastTrunc bool
	for i := 0; i < 6; i++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, current, nil)
		if err != nil {
			return Result{}, err
		}
		applyHeaders(req)
		resp, err := c.Do(req)
		if err != nil {
			return Result{}, err
		}
		body, truncated, err := readBody(resp.Body)
		resp.Body.Close()
		if err != nil {
			return Result{}, err
		}
		loc := strings.TrimSpace(resp.Header.Get("Location"))
		reqURL := current
		if resp.Request != nil && resp.Request.URL != nil {
			reqURL = resp.Request.URL.String()
		}
		hops = append(hops, Hop{URL: reqURL, Status: resp.StatusCode, Location: loc})
		if firstHeader == nil {
			firstHeader = resp.Header.Clone()
			firstLine = resp.Status
		}
		lastBody = body
		lastTrunc = truncated
		lastURL = reqURL
		if !isRedirect(resp.StatusCode) || loc == "" {
			break
		}
		next, err := resp.Request.URL.Parse(loc)
		if err != nil {
			break
		}
		current = next.String()
	}
	status := 0
	if len(hops) > 0 {
		status = hops[0].Status
	}
	return Result{
		RequestURL: raw,
		Status:     status,
		StatusLine: firstLine,
		URL:        lastURL,
		Header:     firstHeader,
		Body:       lastBody,
		Hops:       hops,
		Truncated:  lastTrunc,
	}, nil
}

func applyHeaders(req *http.Request) {
	for k, vs := range Extra {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", UserAgent)
	}
	if req.Header.Get("Accept") == "" {
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	}
}

func readBody(r io.Reader) ([]byte, bool, error) {
	body, err := io.ReadAll(io.LimitReader(r, MaxBody+1))
	if err != nil {
		return nil, false, err
	}
	if len(body) > MaxBody {
		return body[:MaxBody], true, nil
	}
	return body, false, nil
}

func noFollow(c *http.Client) *http.Client {
	if c == nil {
		c = Client(nil)
	}
	cp := *c
	cp.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &cp
}

func isRedirect(status int) bool {
	switch status {
	case 301, 302, 303, 307, 308:
		return true
	default:
		return false
	}
}

func acquireHost(ctx context.Context, raw string) (func(), error) {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return func() {}, nil
	}
	n := HostParallel
	if n <= 0 {
		n = 2
	}
	host := strings.ToLower(u.Hostname())
	cacheMu.Lock()
	sem, ok := hostSem[host]
	if !ok {
		sem = make(chan struct{}, n)
		hostSem[host] = sem
	}
	cacheMu.Unlock()
	select {
	case <-ctx.Done():
		return func() {}, ctx.Err()
	case sem <- struct{}{}:
		return func() { <-sem }, nil
	}
}

func mustURL(raw string) *url.URL {
	u, err := url.Parse(raw)
	if err != nil {
		return &url.URL{}
	}
	return u
}
