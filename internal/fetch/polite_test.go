package fetch

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/trannghiach/azhaq/internal/egress"
)

func TestBackoffAsksAgainAfter429(t *testing.T) {
	Reset()
	defer Reset()
	backoffBase = 5 * time.Millisecond
	defer func() { backoffBase = time.Second }()
	Backoff = true
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if n.Add(1) <= 2 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.Write([]byte("ok"))
	}))
	defer srv.Close()
	res, _, err := Do(context.Background(), srv.Client(), srv.URL+"/x")
	if err != nil || res.Status != 200 || n.Load() != 3 {
		t.Fatalf("%v %d after %d requests", err, res.Status, n.Load())
	}
	if notes := strings.Join(Notes(), "\n"); !strings.Contains(notes, "answered 429 with 2 requests") {
		t.Errorf("the summary does not say a host slowed the run: %q", notes)
	}
}

func TestBackoffGivesUpAndSaysSo(t *testing.T) {
	Reset()
	defer Reset()
	backoffBase = time.Millisecond
	defer func() { backoffBase = time.Second }()
	Backoff = true
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	res, _, err := Do(context.Background(), srv.Client(), srv.URL+"/x")
	if err != nil || res.Status != 503 || n.Load() != backoffTries+1 {
		t.Fatalf("%v %d after %d", err, res.Status, n.Load())
	}
	if notes := strings.Join(Notes(), "\n"); !strings.Contains(notes, "still got it after") {
		t.Errorf("a request that stays refused is not said: %q", notes)
	}
}

func TestWithoutBackoffA429IsTheAnswer(t *testing.T) {
	Reset()
	defer Reset()
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()
	if res, _, _ := Do(context.Background(), srv.Client(), srv.URL+"/x"); res.Status != 429 || n.Load() != 1 {
		t.Errorf("%d after %d requests", res.Status, n.Load())
	}
}

func TestCookieJarCarriesWhatTheTargetSets(t *testing.T) {
	Reset()
	defer Reset()
	UseJar(true)
	var got atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/first" {
			http.SetCookie(w, &http.Cookie{Name: "sid", Value: "abc"})
			return
		}
		got.Store(r.Header.Get("Cookie"))
	}))
	defer srv.Close()
	ctx := context.Background()
	_, _, _ = Do(ctx, srv.Client(), srv.URL+"/first")
	_, _, _ = Do(ctx, srv.Client(), srv.URL+"/second")
	if c, _ := got.Load().(string); c != "sid=abc" {
		t.Errorf("Cookie: %q", c)
	}
}

func TestMaxPerHostStopsWithTheBudgetError(t *testing.T) {
	Reset()
	defer Reset()
	MaxPerHost = 2
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	var last error
	for _, p := range []string{"/a", "/b", "/c"} {
		_, _, last = Do(context.Background(), srv.Client(), srv.URL+p)
	}
	if last == nil || !strings.Contains(last.Error(), "budget") {
		t.Errorf("third request: %v", last)
	}
	if !strings.Contains(strings.Join(Notes(), "\n"), "-max-host-requests 2") {
		t.Error("the cap is not in the summary")
	}
}

func TestSubmitFormIsCountedAndHeldToScope(t *testing.T) {
	Reset()
	defer Reset()
	var body atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := make([]byte, 100)
		n, _ := r.Body.Read(b)
		body.Store(r.Method + " " + string(b[:n]))
	}))
	defer srv.Close()
	if _, err := SubmitForm(context.Background(), srv.Client(), srv.URL+"/login", "u=azhaq"); err != nil {
		t.Fatal(err)
	}
	if v, _ := body.Load().(string); v != "POST u=azhaq" || Posts() != 1 {
		t.Errorf("%q, %d posts", v, Posts())
	}
	egress.SetScope(func(string) bool { return false })
	if _, err := SubmitForm(context.Background(), srv.Client(), srv.URL+"/login", "u=azhaq"); err == nil || Posts() != 1 {
		t.Errorf("a submission outside the scope was sent: %v", err)
	}
}
