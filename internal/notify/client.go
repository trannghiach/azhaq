package notify

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/time/rate"
)

// Client posts every notification: one pace, one retry policy, one place
// where secrets are kept out of the errors.
type Client struct {
	HTTP *http.Client  // nil: a client with Go's proxy settings that does not follow a redirect to another host
	Rate *rate.Limiter // nil: no pacing
	// Tries is how many times a post is tried (default 3): a 429, a 5xx
	// and a connection that failed are tried again, any other answer is not.
	Tries    int
	Backoff  time.Duration // wait before the second try, doubled after each (default 1s)
	MaxWait  time.Duration // longest Retry-After honoured (default 60s)
	Timeout  time.Duration // one post, answer included (default 30s)
	Verbose  func(string)  // told about each retry
	secrets  []string
	attempts int // of the last post
}

// NewClient returns a client that sends at most perSecond requests a
// second (0: no pacing) through proxy ("" for the environment's).
func NewClient(perSecond float64, proxy string) (*Client, error) {
	c := &Client{}
	if perSecond > 0 {
		c.Rate = rate.NewLimiter(rate.Limit(perSecond), 1)
	}
	if proxy != "" {
		pu, err := url.Parse(proxy)
		if err != nil || pu.Host == "" {
			return nil, fmt.Errorf("-proxy %q is not a URL", redactProxy(proxy))
		}
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.Proxy = http.ProxyURL(pu)
		c.HTTP = &http.Client{Transport: tr, CheckRedirect: sameHost}
	}
	return c, nil
}

func redactProxy(p string) string {
	if u, err := url.Parse(p); err == nil && u.Host != "" {
		return u.Scheme + "://" + u.Host
	}
	return "(proxy)"
}

// AddSecrets tells the client strings (tokens, passwords) that must never
// appear in an error, whatever a server echoes back.
func (c *Client) AddSecrets(s ...string) {
	for _, x := range s {
		if len(x) >= 4 {
			c.secrets = append(c.secrets, x)
		}
	}
}

// Attempts is how many tries the last post took.
func (c *Client) Attempts() int { return c.attempts }

// sameHost keeps a token from following a redirect to another host.
func sameHost(req *http.Request, via []*http.Request) error {
	if len(via) >= 5 {
		return errors.New("too many redirects")
	}
	if !strings.EqualFold(req.URL.Hostname(), via[0].URL.Hostname()) {
		return http.ErrUseLastResponse
	}
	return nil
}

func (c *Client) http() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{CheckRedirect: sameHost}
}

func (c *Client) tries() int {
	if c.Tries > 0 {
		return c.Tries
	}
	return 3
}

func orDefault(d, def time.Duration) time.Duration {
	if d > 0 {
		return d
	}
	return def
}

// Result is what a post got back.
type Result struct {
	Status int
	Body   []byte // the first 64 KiB
}

// Do sends the request build makes, again if the answer says to wait or
// the server failed. accept says which statuses are a success. The error
// never holds the URL's path, query or user, nor a secret the client knows:
// webhook URLs are secrets.
func (c *Client) Do(ctx context.Context, build func() (*http.Request, error), accept func(int) bool) (Result, error) {
	if accept == nil {
		accept = func(s int) bool { return s >= 200 && s < 300 }
	}
	var last error
	var res Result
	wait := orDefault(c.Backoff, time.Second)
	n := c.tries()
	c.attempts = 0
	for try := 1; try <= n; try++ {
		if c.Rate != nil {
			if err := c.Rate.Wait(ctx); err != nil {
				return res, errors.New(c.scrub(err.Error(), nil))
			}
		}
		req, err := build()
		if err != nil {
			return res, errors.New(c.scrub(err.Error(), req))
		}
		c.attempts = try
		var retryAfter time.Duration
		res, last, retryAfter = c.once(ctx, req, accept)
		if last == nil {
			return res, nil
		}
		if !retryable(res.Status, last) || ctx.Err() != nil || try == n {
			break
		}
		pause := wait
		if retryAfter > 0 {
			if retryAfter > orDefault(c.MaxWait, time.Minute) {
				return res, fmt.Errorf("%w (Retry-After %s is longer than the %s waited)", last, retryAfter.Round(time.Second), orDefault(c.MaxWait, time.Minute))
			}
			pause = retryAfter
		}
		if c.Verbose != nil {
			c.Verbose(fmt.Sprintf("try %d of %d failed (%v), again in %s", try, n, last, pause.Round(time.Millisecond)))
		}
		select {
		case <-ctx.Done():
			return res, last
		case <-time.After(pause):
		}
		wait *= 2
	}
	if c.attempts > 1 {
		last = fmt.Errorf("%w (after %d tries)", last, c.attempts)
	}
	return res, last
}

// once is a single post. retryAfter is what the server asked for.
func (c *Client) once(ctx context.Context, req *http.Request, accept func(int) bool) (res Result, err error, retryAfter time.Duration) {
	ctx, cancel := context.WithTimeout(ctx, orDefault(c.Timeout, 30*time.Second))
	defer cancel()
	resp, err := c.http().Do(req.WithContext(ctx))
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err // the URL error holds the whole URL, token included
		}
		return res, fmt.Errorf("%s %s: %s", req.Method, hostOf(req.URL), c.scrub(err.Error(), req)), 0
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	res = Result{Status: resp.StatusCode, Body: body}
	if accept(resp.StatusCode) {
		return res, nil, 0
	}
	// Only a short error code of the answer is kept (Slack's
	// channel_not_found): a server may echo anything, secrets included.
	msg := strings.TrimSpace(string(body[:min(len(body), 64)]))
	text := fmt.Sprintf("%s %s: %s", req.Method, hostOf(req.URL), resp.Status)
	if errorCode.MatchString(msg) {
		text += " " + msg
	}
	return res, errors.New(c.scrub(text, req)), parseRetryAfter(resp.Header.Get("Retry-After"))
}

// retryable: a rate limit or a server failure, or a connection that
// did not hold. A rejected certificate or a refused request does not
// get better by asking again.
func retryable(status int, err error) bool {
	if status == http.StatusTooManyRequests || status >= 500 {
		return true
	}
	if status != 0 {
		return false
	}
	var ua x509.UnknownAuthorityError
	var he x509.HostnameError
	var ci x509.CertificateInvalidError
	if errors.As(err, &ua) || errors.As(err, &he) || errors.As(err, &ci) {
		return false
	}
	return true
}

func parseRetryAfter(v string) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	if s, err := strconv.ParseFloat(v, 64); err == nil && s >= 0 {
		return time.Duration(s * float64(time.Second))
	}
	if t, err := http.ParseTime(v); err == nil {
		return max(time.Until(t), 0)
	}
	return 0
}

func hostOf(u *url.URL) string {
	if u == nil {
		return "(webhook)"
	}
	return u.Scheme + "://" + u.Host + "/…"
}

// scrub removes from text everything that makes a request URL secret and
// the secrets the client was told.
func (c *Client) scrub(text string, req *http.Request) string {
	var bad []string
	if req != nil && req.URL != nil {
		u := req.URL
		bad = append(bad, u.String(), u.EscapedPath(), u.Path, u.RawQuery)
		if u.User != nil {
			bad = append(bad, u.User.String())
			if p, ok := u.User.Password(); ok {
				bad = append(bad, p)
			}
		}
		for _, seg := range strings.Split(u.Path, "/") {
			if len(seg) >= 8 && !commonSegment[seg] {
				bad = append(bad, seg)
			}
		}
	}
	bad = append(bad, c.secrets...)
	// Longest first, so a whole URL goes before the path inside it.
	sort.Slice(bad, func(i, j int) bool { return len(bad[i]) > len(bad[j]) })
	for _, b := range bad {
		if len(b) < 4 || b == "/" {
			continue
		}
		text = strings.ReplaceAll(text, b, "…")
	}
	return text
}

// commonSegment: path words that are not secrets and help a reader.
var commonSegment = map[string]bool{"services": true, "sendMessage": true, "webhooks": true, "messages": true, "workflows": true, "webhookb2": true}

// errorCode is an answer that is only a service's error code.
var errorCode = regexp.MustCompile(`^[a-z][a-z0-9_]{2,40}$`)
