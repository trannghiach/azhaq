package subcol

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func fastPauses(t *testing.T) {
	old := firstPause
	firstPause = 10 * time.Millisecond
	t.Cleanup(func() { firstPause = old })
}

// A 429 is asked again after its Retry-After, and the row says so.
func TestRetryAfterIsWaitedOut(t *testing.T) {
	fastPauses(t)
	var n atomic.Int32
	var first, second time.Time
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch n.Add(1) {
		case 1:
			first = time.Now()
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
		default:
			second = time.Now()
			io.WriteString(w, "ok")
		}
	}))
	defer srv.Close()
	cl := &http.Client{Transport: &retryTransport{next: http.DefaultTransport}}
	th := &throttle{}
	req, _ := http.NewRequestWithContext(withThrottle(context.Background(), th), "GET", srv.URL, nil)
	resp, err := cl.Do(req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("%v %v", resp, err)
	}
	if gap := second.Sub(first); gap < 950*time.Millisecond {
		t.Errorf("asked again after %s, Retry-After said 1s", gap)
	}
	row := map[string]any{}
	th.fields(row)
	if row["retried_429"] != 1 || row["retry_after_seconds"] != 1.0 || row["gave_up_429"] != nil {
		t.Errorf("row %v", row)
	}
}

// Without a Retry-After the pause grows; a source that keeps refusing is
// handed back its 429 and the row says it gave up.
func TestRetryGivesUpAndSaysSo(t *testing.T) {
	fastPauses(t)
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()
	cl := &http.Client{Transport: &retryTransport{next: http.DefaultTransport}}
	th := &throttle{}
	req, _ := http.NewRequestWithContext(withThrottle(context.Background(), th), "GET", srv.URL, nil)
	resp, err := cl.Do(req)
	if err != nil || resp.StatusCode != 429 {
		t.Fatalf("%v %v", resp, err)
	}
	if n.Load() != maxRetries+1 {
		t.Errorf("%d requests, want %d", n.Load(), maxRetries+1)
	}
	row := map[string]any{}
	th.fields(row)
	if row["gave_up_429"] != true || row["retried_429"] != maxRetries {
		t.Errorf("row %v", row)
	}
}

// A Retry-After longer than the source has left, or than is worth taking,
// is not waited for: the 429 comes back at once with the wait it asked.
func TestRetryAfterTooLongIsNotWaitedFor(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "120")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()
	cl := &http.Client{Transport: &retryTransport{next: http.DefaultTransport}}
	th := &throttle{}
	t0 := time.Now()
	req, _ := http.NewRequestWithContext(withThrottle(context.Background(), th), "GET", srv.URL, nil)
	resp, err := cl.Do(req)
	if err != nil || resp.StatusCode != 429 || time.Since(t0) > time.Second {
		t.Fatalf("%v %v after %s", resp, err, time.Since(t0))
	}
	row := map[string]any{}
	th.fields(row)
	if row["retry_after_seconds"] != 120.0 || row["gave_up_429"] != true || row["retried_429"] != nil {
		t.Errorf("row %v", row)
	}
}

// A POST is sent again with its body.
func TestRetryResendsTheBody(t *testing.T) {
	fastPauses(t)
	var n atomic.Int32
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if n.Add(1) == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		got = string(b)
	}))
	defer srv.Close()
	cl := &http.Client{Transport: &retryTransport{next: http.DefaultTransport}}
	resp, err := cl.Post(srv.URL, "text/plain", strings.NewReader("payload"))
	if err != nil || resp.StatusCode != 200 || got != "payload" {
		t.Fatalf("%v %v %q", resp, err, got)
	}
}

func TestRetryAfterHeader(t *testing.T) {
	if d, ok := retryAfter("7"); !ok || d != 7*time.Second {
		t.Errorf("seconds: %v %v", d, ok)
	}
	at := time.Now().Add(5 * time.Second).UTC().Format(http.TimeFormat)
	if d, ok := retryAfter(at); !ok || d < 3*time.Second || d > 6*time.Second {
		t.Errorf("date: %v %v", d, ok)
	}
	if _, ok := retryAfter("soon"); ok {
		t.Error("junk accepted")
	}
}

// -source-rate caps every source, a source's own lower default stays, and
// -source-rates names one source and wins.
func TestSourceRates(t *testing.T) {
	took := func(o Options, name string, n int) time.Duration {
		c := New(o)
		t0 := time.Now()
		for range n {
			if err := c.limiter.Wait(context.Background(), name); err != nil {
				t.Fatal(err)
			}
		}
		return time.Since(t0)
	}
	if d := took(Options{}, "crtname", 5); d > 50*time.Millisecond {
		t.Errorf("no cap: %s", d)
	}
	if d := took(Options{SourceRate: 20}, "crtname", 4); d < 140*time.Millisecond {
		t.Errorf("-source-rate 20: 4 requests in %s", d)
	}
	// hackertarget's own 2/s is below 20/s and stays.
	if d := took(Options{SourceRate: 20}, "hackertarget", 2); d < 450*time.Millisecond {
		t.Errorf("own default lost: %s", d)
	}
	if d := took(Options{SourceRate: 2, SourceRates: map[string]float64{"crtname": 100}}, "crtname", 5); d > 100*time.Millisecond {
		t.Errorf("-source-rates did not win: %s", d)
	}
}
