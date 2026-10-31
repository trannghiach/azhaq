package subcol

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/trannghiach/azhaq/internal/answer"
)

// A source that answers 429 is asked again after the Retry-After it names
// (or a growing pause when it names none), up to maxRetries times, so a
// busy source costs time, not names. The sources are subfinder's: they
// give up at the first 429, so the wait is made one level down, in the
// transport every source's request goes through.
const (
	maxRetries = 3
	// maxRetryWait is the longest pause taken: a source that wants more is
	// not waited for, and says so in its row.
	maxRetryWait = 30 * time.Second
)

var firstPause = 2 * time.Second

type throttleKey struct{}

// throttle is what Run learns about a source's 429 answers, for its row.
type throttle struct {
	requests   atomic.Int32 // requests sent, retries included
	retried    atomic.Int32 // requests sent again after a 429
	mu         sync.Mutex
	waited     time.Duration
	gaveUp     bool          // still 429 after the retries, or asked for too long a wait
	retryAfter time.Duration // the longest Retry-After seen
}

func (t *throttle) note(wait time.Duration, asked time.Duration, gaveUp bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.waited += wait
	t.retryAfter = max(t.retryAfter, asked)
	t.gaveUp = t.gaveUp || gaveUp
}

// fields adds the row's keys: how many requests were retried and for how
// long, and whether the source was still refusing at the end.
func (t *throttle) fields(row map[string]any) {
	if n := t.requests.Load(); n > 0 {
		row["requests"] = int(n)
	}
	n := int(t.retried.Load())
	t.mu.Lock()
	defer t.mu.Unlock()
	if n == 0 && !t.gaveUp {
		return
	}
	row["rate_limited"] = true
	if n > 0 {
		row["retried_429"] = n
		row["waited_seconds"] = round(t.waited.Seconds())
	}
	if t.retryAfter > 0 {
		row["retry_after_seconds"] = round(t.retryAfter.Seconds())
	}
	if t.gaveUp {
		row["gave_up_429"] = true
	}
}

// retryTransport wraps a RoundTripper to answer 429 as above.
type retryTransport struct {
	next http.RoundTripper
}

func (t *retryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	th, _ := req.Context().Value(throttleKey{}).(*throttle)
	for attempt := 0; ; attempt++ {
		if th != nil {
			th.requests.Add(1)
		}
		resp, err := t.next.RoundTrip(req)
		if err != nil || resp.StatusCode != http.StatusTooManyRequests {
			if err == nil && resp.StatusCode == http.StatusOK {
				screenAnswer(req, resp)
			}
			return resp, err
		}
		if th == nil {
			th = &throttle{} // still counted for the decision below
		}
		asked, hinted := retryAfter(resp.Header.Get("Retry-After"))
		wait := asked
		if !hinted {
			wait = firstPause << attempt
		}
		// A body that cannot be sent again, no attempts left, or a wait that
		// is too long or past the source's deadline: hand back the 429.
		replay := req.Body == nil || req.Body == http.NoBody || req.GetBody != nil
		tooLong := wait > maxRetryWait
		if dl, ok := req.Context().Deadline(); ok && time.Until(dl) <= wait {
			tooLong = true
		}
		if attempt >= maxRetries || !replay || tooLong || req.Context().Err() != nil {
			th.note(0, asked, true)
			return resp, nil
		}
		io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
		resp.Body.Close()
		select {
		case <-req.Context().Done():
			return nil, req.Context().Err()
		case <-time.After(wait):
		}
		th.retried.Add(1)
		th.note(wait, asked, false)
		if req.GetBody != nil {
			body, err := req.GetBody()
			if err != nil {
				return nil, err
			}
			req = req.Clone(req.Context())
			req.Body = body
		}
	}
}

// retryAfter reads a Retry-After header: seconds, or an HTTP date.
func retryAfter(h string) (time.Duration, bool) {
	if h == "" {
		return 0, false
	}
	if s, err := strconv.Atoi(h); err == nil && s >= 0 {
		return time.Duration(s) * time.Second, true
	}
	if at, err := http.ParseTime(h); err == nil {
		return max(time.Until(at), 0), true
	}
	return 0, false
}

func withThrottle(ctx context.Context, t *throttle) context.Context {
	return context.WithValue(ctx, throttleKey{}, t)
}

type answerKey struct{}

// answerLog is what Run learns about a source's 200 answers that were
// errors (a quota page, a JSON error): a source that gave no names after
// one has failed, not found nothing.
type answerLog struct {
	mu   sync.Mutex
	what []string
}

func (l *answerLog) add(s string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.what) < 3 {
		l.what = append(l.what, s)
	}
}

func (l *answerLog) text() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.what, "; ")
}

// screenAnswer reads the start of a 200 answer and logs it when it is an
// error, for the source the request belongs to. The body is still the
// source's to read, whole.
func screenAnswer(req *http.Request, resp *http.Response) {
	l, _ := req.Context().Value(answerKey{}).(*answerLog)
	if l == nil || resp.Body == nil || resp.Body == http.NoBody {
		return
	}
	body, why := answer.Screen(resp.Body)
	resp.Body = body
	if why != "" {
		l.add(fmt.Sprintf("%s answered 200 with an error, not names: %s", req.URL.Host, why))
	}
}

// answeredWithError is what the source's requests were answered with, when
// an answer was an error page and not data.
func answeredWithError(ctx context.Context) string {
	if l, ok := ctx.Value(answerKey{}).(*answerLog); ok {
		return l.text()
	}
	return ""
}
