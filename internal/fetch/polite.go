package fetch

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"

	"github.com/trannghiach/azhaq/internal/egress"
	"github.com/trannghiach/azhaq/internal/limit"
	"github.com/trannghiach/azhaq/internal/neterr"
)

// What a crawler does to be a good guest and to keep a session: wait when
// a host says it is overloaded (429, 503), ask again once after a hiccup,
// pace each host, count a host's pages, and carry the cookies a target sets.
// The backoff follows projectdiscovery/katana (pkg/engine/common/base.go,
// MIT): one second doubling to thirty, with jitter.
var (
	// Retry is how many times a request that got no answer from a host
	// that answered before is sent again (-retry).
	Retry int
	// Backoff retries a request answered 429 or 503 after a wait that
	// grows while the host keeps saying it (1 s doubling to 30 s).
	Backoff bool
	// RequestTimeout bounds one request (-request-timeout); zero keeps
	// the defaults: 10 s for headers, 30 s in all.
	RequestTimeout time.Duration
	// MaxPerHost caps the requests sent to one host (-max-host-requests).
	MaxPerHost int64
)

var backoffBase = time.Second

const (
	backoffTries = 3
	backoffMax   = 30 * time.Second
)

var (
	politeMu   sync.Mutex
	throttles  = map[string]*throttle{}
	answered   = map[string]bool{}
	hostSent   = map[string]int64{}
	hostPaces  = map[string]*rate.Limiter{}
	hostRate   float64
	jar        atomic.Pointer[cookiejar.Jar]
	capHit     = map[string]bool{}
	retriedOK  atomic.Int64
	retriedAll atomic.Int64
)

type throttle struct {
	consecutive int
	until       time.Time
	hits        int // answers of 429 or 503
	status      int
	gaveUp      int // requests that still got one after the retries
}

// UseJar makes the run carry the cookies targets set (the way a browser or
// katana does); -cookie and -header values still go first.
func UseJar(on bool) {
	if !on {
		jar.Store(nil)
		return
	}
	j, _ := cookiejar.New(nil)
	jar.Store(j)
}

// SetHostRate paces each host to perSecond requests (-host-rate), apart
// from the pace over all hosts.
func SetHostRate(perSecond float64) {
	politeMu.Lock()
	defer politeMu.Unlock()
	hostRate = perSecond
	hostPaces = map[string]*rate.Limiter{}
}

func resetPolite() {
	politeMu.Lock()
	throttles = map[string]*throttle{}
	answered = map[string]bool{}
	hostSent = map[string]int64{}
	hostPaces = map[string]*rate.Limiter{}
	capHit = map[string]bool{}
	hostRate = 0
	politeMu.Unlock()
	Retry, Backoff, RequestTimeout, MaxPerHost = 0, false, 0, 0
	jar.Store(nil)
	retriedOK.Store(0)
	retriedAll.Store(0)
	posts.Store(0)
}

func hostKey(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

// beforeSend waits for the host's own pace and for a backoff it asked
// for, and counts the request against its page cap.
func beforeSend(ctx context.Context, raw string) error {
	h := hostKey(raw)
	if h == "" {
		return nil
	}
	politeMu.Lock()
	if MaxPerHost > 0 && hostSent[h] >= MaxPerHost {
		capHit[h] = true
		politeMu.Unlock()
		egress.MarkRefused(ctx)
		return neterr.ErrBudget
	}
	hostSent[h]++
	var lim *rate.Limiter
	if hostRate > 0 {
		if lim = hostPaces[h]; lim == nil {
			lim = rate.NewLimiter(rate.Limit(hostRate), max(1, int(hostRate/5)))
			hostPaces[h] = lim
		}
	}
	var wait time.Duration
	if t := throttles[h]; t != nil {
		wait = time.Until(t.until)
	}
	politeMu.Unlock()
	if lim != nil {
		if err := limit.Wait(ctx, lim); err != nil {
			return err
		}
	}
	if wait > 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}
	return nil
}

// afterAnswer records a host's answer: a 429 or 503 slows the host down,
// anything else clears it. It says how long to wait before asking again.
func afterAnswer(raw string, status int, retryAfter string) (wait time.Duration, throttled bool) {
	h := hostKey(raw)
	politeMu.Lock()
	defer politeMu.Unlock()
	answered[h] = true
	t := throttles[h]
	if status != http.StatusTooManyRequests && status != http.StatusServiceUnavailable {
		if t != nil {
			t.consecutive = 0
			t.until = time.Time{}
		}
		return 0, false
	}
	if t == nil {
		t = &throttle{}
		throttles[h] = t
	}
	t.consecutive++
	t.hits++
	t.status = status
	wait = backoffBase << min(t.consecutive-1, 5)
	if secs, err := strconv.Atoi(strings.TrimSpace(retryAfter)); err == nil && secs > 0 {
		wait = time.Duration(secs) * time.Second
	}
	wait = min(wait, backoffMax)
	wait += time.Duration(rand.Int64N(int64(wait)/5 + 1)) // jitter
	t.until = time.Now().Add(wait)
	return wait, true
}

func gaveUp(raw string) {
	politeMu.Lock()
	if t := throttles[hostKey(raw)]; t != nil {
		t.gaveUp++
	}
	politeMu.Unlock()
}

func hostAnswered(raw string) bool {
	politeMu.Lock()
	defer politeMu.Unlock()
	return answered[hostKey(raw)]
}

// politeNotes say, in the run's summary, what the pace and the targets'
// answers did to it.
func politeNotes() []string {
	politeMu.Lock()
	defer politeMu.Unlock()
	var out []string
	var hosts []string
	for h := range throttles {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	for _, h := range hosts {
		t := throttles[h]
		line := fmt.Sprintf("%s answered %d with %d requests: azhaq waited (1 s doubling to 30 s) and asked again", h, t.status, t.hits)
		if t.gaveUp > 0 {
			line += fmt.Sprintf("; %d requests still got it after %d tries and are listed with that status", t.gaveUp, backoffTries)
		}
		out = append(out, line)
	}
	hosts = hosts[:0]
	for h := range capHit {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	for _, h := range hosts {
		out = append(out, fmt.Sprintf("%s reached -max-host-requests %d: the rest of its work is left for azhaq resume", h, MaxPerHost))
	}
	if n := posts.Load(); n > 0 {
		out = append(out, fmt.Sprintf("%d POST forms were submitted (-submit-forms) with neutral values: they may have changed data on the target", n))
	}
	if n := retriedAll.Load(); n > 0 {
		out = append(out, fmt.Sprintf("%d requests got no answer from a host that had answered and were sent again; %d of them then answered", n, retriedOK.Load()))
	}
	return out
}

// withJar adds the cookies the jar holds for the request's URL to the
// ones -cookie and -header gave.
func withJar(req *http.Request) {
	j := jar.Load()
	if j == nil {
		return
	}
	cs := j.Cookies(req.URL)
	if len(cs) == 0 {
		return
	}
	have := map[string]bool{}
	for _, c := range req.Cookies() {
		have[c.Name] = true
	}
	for _, c := range cs {
		if !have[c.Name] {
			req.AddCookie(c)
		}
	}
}

func keepCookies(resp *http.Response) {
	if j := jar.Load(); j != nil && resp.Request != nil && resp.Request.URL != nil {
		if cs := resp.Cookies(); len(cs) > 0 {
			j.SetCookies(resp.Request.URL, cs)
		}
	}
}

// attempt sends one GET and reads its answer: it spends a request of the
// run's budget for each try, waits when the host asked it to, and asks
// again after a 429 or 503 (and once after a hiccup of a host that had
// answered). rctx carries the connection trace of the first hop.
func attempt(ctx, rctx context.Context, c *http.Client, method, raw string, sent []byte, prep func(*http.Request), dump bool) (resp *http.Response, body []byte, trunc bool, reqDump []byte, err error) {
	var lastErr error
	for try := 0; ; try++ {
		if err := beforeSend(ctx, raw); err != nil {
			return nil, nil, false, nil, err
		}
		// Counted before the request is built: a new sign-in the count
		// brings about (the session check) is in the headers it carries.
		if err := egress.Spend(ctx); err != nil {
			return nil, nil, false, nil, err
		}
		var rd io.Reader
		if len(sent) > 0 {
			rd = bytes.NewReader(sent)
		}
		req, err := http.NewRequestWithContext(rctx, method, raw, rd)
		if err != nil {
			egress.Refund()
			return nil, nil, false, nil, err
		}
		ApplyHeaders(req)
		if prep != nil {
			prep(req)
		}
		withJar(req)
		if dump {
			reqDump = dumpRequest(req, sent)
		}
		resp, err = c.Do(req)
		body, trunc = nil, false
		if err == nil {
			body, trunc, err = readBody(resp.Body, bodyLimit(resp))
			resp.Body.Close()
		}
		if err != nil {
			lastErr = err
			// -retry (crawl) asks again a host that has answered before;
			// -retries (probe) asks again one that did not answer at all.
			if ctx.Err() == nil && (try < Retry && hostAnswered(raw) && retryable(err) || try < Retries && neterr.Unanswered(err)) {
				retriedAll.Add(1)
				continue
			}
			return nil, nil, false, reqDump, err
		}
		if try > 0 && lastErr != nil {
			retriedOK.Add(1)
		}
		keepCookies(resp)
		wait, throttled := afterAnswer(raw, resp.StatusCode, resp.Header.Get("Retry-After"))
		if throttled && Backoff {
			if try < backoffTries {
				select {
				case <-ctx.Done():
					return resp, body, trunc, reqDump, nil
				case <-time.After(wait):
				}
				continue
			}
			gaveUp(raw)
		}
		return resp, body, trunc, reqDump, nil
	}
}

// retryable says whether a failed request is worth asking again: a
// timeout or a reset, not a refusal or an answer of the run's own making.
func retryable(err error) bool {
	if neterr.Quiet(err) || err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "timeout") || strings.Contains(s, "reset") || strings.Contains(s, "eof") || strings.Contains(s, "deadline")
}
