package urlcol

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func quickBackoff(t *testing.T, d ...time.Duration) {
	old := backoff
	backoff = d
	t.Cleanup(func() { backoff = old })
}

// A 429 is asked again after the Retry-After the server names, in seconds
// or as a date, and the archive then answers.
func TestRetryAfterIsHonouredByTheArchive(t *testing.T) {
	quickBackoff(t, time.Millisecond) // the wait taken is the header's, not the table's
	for name, header := range map[string]struct {
		value func() string
		least time.Duration
	}{
		"seconds": {func() string { return "1" }, 900 * time.Millisecond},
		// An HTTP date has whole seconds: 1.5 s ahead is between 0.5 and 1.5 s.
		"date": {func() string { return time.Now().Add(1500 * time.Millisecond).UTC().Format(http.TimeFormat) }, 400 * time.Millisecond},
	} {
		var n atomic.Int32
		var first, second time.Time
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if n.Add(1) == 1 {
				first = time.Now()
				w.Header().Set("Retry-After", header.value())
				w.WriteHeader(http.StatusTooManyRequests)
				return
			}
			second = time.Now()
			fmt.Fprint(w, `{"has_next":false,"url_list":[{"url":"http://example.org/ok"}]}`)
		}))
		m := newMirror(t, pages)
		bases := m.bases()
		bases["otx"] = srv.URL
		summary, _, _, err := run(t, Options{Bases: bases, Client: srv.Client(), Only: []string{"otx"}}, context.Background())
		srv.Close()
		if err != nil {
			t.Fatal(err)
		}
		row := summary["sources"].(map[string]any)["otx"].(map[string]any)
		if gap := second.Sub(first); gap < header.least || row["error"] != nil || row["count"] != 1.0 || row["retried"] != 1.0 || row["requests"] != 2.0 {
			t.Errorf("%s: asked again after %s: %v", name, gap, row)
		}
	}
}

// Without -retries a 429 is asked again for as long as the source has
// time: more often than three times.
func TestRateLimitIsWaitedOutBeyondThreeTries(t *testing.T) {
	quickBackoff(t, time.Millisecond)
	m := newMirror(t, pages)
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if n.Add(1) <= 7 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		if r.URL.Query().Get("page") != "0" {
			w.WriteHeader(http.StatusBadRequest) // past the last page
			return
		}
		fmt.Fprint(w, `[["original"],["http://example.org/late"]]`)
	}))
	defer srv.Close()
	bases := m.bases()
	bases["wayback"] = srv.URL
	summary, _, _, err := run(t, Options{Bases: bases, Client: srv.Client(), Only: []string{"wayback"}}, context.Background())
	if err != nil {
		t.Fatal(err)
	}
	row := summary["sources"].(map[string]any)["wayback"].(map[string]any)
	if row["error"] != nil || row["count"] != 1.0 || row["retried"] != 7.0 {
		t.Errorf("row %v", row)
	}
}

// -retries N is a count: the failure says how many tries it took and what
// the server said.
func TestRefusalSaysTriesAndReason(t *testing.T) {
	quickBackoff(t, time.Millisecond)
	m := newMirror(t, pages)
	m.status["/wayback"] = http.StatusTooManyRequests
	three := 3
	summary, _, _, err := run(t, Options{Bases: m.bases(), Client: m.Client(), Only: []string{"wayback"}, Retries: &three}, context.Background())
	if err != nil {
		t.Fatal(err)
	}
	row := summary["sources"].(map[string]any)["wayback"].(map[string]any)
	if row["error"] != "failed after 4 tries, 429 Too Many Requests" || row["requests"] != 4.0 || row["retried"] != 3.0 {
		t.Errorf("row %v", row)
	}
}

// A connection that cannot be made is asked again three times by default,
// and the failure names the cause without the URL.
func TestConnectFailureIsRetriedAndSaid(t *testing.T) {
	quickBackoff(t, time.Millisecond)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close() // nothing listens: connection refused
	m := newMirror(t, pages)
	bases := m.bases()
	bases["commoncrawl"] = "http://" + addr + "/collinfo.json"
	summary, _, _, err := run(t, Options{Bases: bases, Client: m.Client(), Only: []string{"commoncrawl"}}, context.Background())
	if err != nil {
		t.Fatal(err)
	}
	row := summary["sources"].(map[string]any)["commoncrawl"].(map[string]any)
	e := fmt.Sprint(row["error"])
	if !strings.HasPrefix(e, "failed after 4 tries, ") || !strings.Contains(e, "connection refused") || strings.Contains(e, "http://") || row["requests"] != 4.0 {
		t.Errorf("row %v", row)
	}
}

// The source's time bounds the waiting: a Retry-After longer than what is
// left ends the request at once, and says so, instead of sleeping to the
// deadline and reporting only a timeout.
func TestRetryAfterLongerThanTheTimeLeftIsSaid(t *testing.T) {
	m := newMirror(t, pages)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "120")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()
	bases := m.bases()
	bases["wayback"] = srv.URL
	t0 := time.Now()
	summary, _, _, err := run(t, Options{Bases: bases, Client: srv.Client(), Only: []string{"wayback"}, Timeout: 5 * time.Second}, context.Background())
	if err != nil {
		t.Fatal(err)
	}
	row := summary["sources"].(map[string]any)["wayback"].(map[string]any)
	e := fmt.Sprint(row["error"])
	if !strings.Contains(e, "429 Too Many Requests, Retry-After 2m0s") || !strings.Contains(e, "the 2m0s to wait is more than the") || time.Since(t0) > 2*time.Second {
		t.Errorf("after %s: %v", time.Since(t0), row)
	}
}

// A source that keeps being refused, with waits that fit, stops at its own
// time and the failure still says what the server said.
func TestRefusalAtTheSourceDeadlineKeepsItsReason(t *testing.T) {
	quickBackoff(t, 100*time.Millisecond)
	m := newMirror(t, pages)
	m.status["/wayback"] = http.StatusServiceUnavailable
	summary, _, _, err := run(t, Options{Bases: m.bases(), Client: m.Client(), Only: []string{"wayback"}, Timeout: 350 * time.Millisecond}, context.Background())
	if err != nil {
		t.Fatal(err)
	}
	row := summary["sources"].(map[string]any)["wayback"].(map[string]any)
	e := fmt.Sprint(row["error"])
	if !strings.Contains(e, "503 Service Unavailable") || !strings.HasPrefix(e, "failed after ") {
		t.Errorf("row %v", row)
	}
}
