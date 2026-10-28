package browser

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/trannghiach/azhaq/internal/fetch"
)

// A body gives its names, never its values: a JSON object's keys (also
// as a beacon's text/plain string), a form's fields; not an object keyed
// by data.
func TestBodyFields(t *testing.T) {
	multipart := "--XX\r\nContent-Disposition: form-data; name=\"title\"\r\n\r\nhello\r\n--XX\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.txt\"\r\n\r\nsecret\r\n--XX--\r\n"
	for _, c := range []struct {
		body, ct   string
		want       []string
		wantMedia  string
		mustNotSee string
	}{
		{`{"user":"alice","pass":"pw"}`, "application/json", []string{"pass", "user"}, "application/json", "alice"},
		{`{"event":"view"}`, "text/plain;charset=UTF-8", []string{"event"}, "text/plain", "view"},
		{`{"alice@x.test":1,"id":2}`, "", []string{"id"}, "application/json", "alice"},
		{"sid=abc&t=1", "application/x-www-form-urlencoded;charset=UTF-8", []string{"sid", "t"}, "application/x-www-form-urlencoded", "abc"},
		{"a=1&b=2&secretval", "application/x-www-form-urlencoded", []string{"a", "b"}, "application/x-www-form-urlencoded", "secretval"}, // a bare token is a value, not a name
		{"secretval", "application/x-www-form-urlencoded", nil, "", "secretval"},
		{multipart, "multipart/form-data; boundary=XX", []string{"file", "title"}, "multipart/form-data", "secret"},
		{"x", "text/plain;charset=UTF-8", nil, "", ""},
		{"40", "text/plain;charset=UTF-8", nil, "", ""}, // socket.io's polling
		{`[{"a":1}]`, "application/json", nil, "", ""},
		{"", "", nil, "", ""},
	} {
		got, media := bodyFields([]byte(c.body), c.ct)
		if !slices.Equal(got, c.want) || media != c.wantMedia {
			t.Errorf("%q (%s): %q %q, want %q %q", c.body, c.ct, got, media, c.want, c.wantMedia)
		}
		if c.mustNotSee != "" && strings.Contains(fmt.Sprint(got), c.mustNotSee) {
			t.Errorf("%q: a value kept: %q", c.body, got)
		}
	}
}

// The sign-in posts its form; the pages loaded after it, in the same
// Chrome, do not send their writes. One a page sends as its tab closes
// is the run's to list.
func TestSignInWrites(t *testing.T) {
	b := startChrome(t)
	const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJtZW1iZXIifQ.c2lnbmVk"
	srv := newRecorder(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/login":
			http.SetCookie(w, &http.Cookie{Name: "sid", Value: "abc123", Path: "/"})
			fmt.Fprintf(w, `{"token":%q,"bid":7}`, jwt)
		case "/app":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><body><script>fetch('/api/basket', {method: 'POST', body: '{"item":1}'});
addEventListener('pagehide', () => navigator.sendBeacon('/api/bye', 'x'));</script></body></html>`)
		default:
			fmt.Fprint(w, loginPage)
		}
	})
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	fetch.Reset()
	fetch.Allow = func(h string) bool { return h == "127.0.0.1" }
	if _, err := b.Login(ctx, srv.URL+"/login", "member@x.test", "s3cret"); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(srv.got(), "/api/login") {
		t.Fatalf("the sign-in did not post its form: %q", srv.got())
	}
	_ = fetch.Spend(ctx)
	p, err := b.Load(ctx, srv.URL+"/app", false)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(500 * time.Millisecond)
	if got := srv.got(); slices.Contains(got, "/api/basket") || slices.Contains(got, "/api/bye") {
		t.Errorf("a page loaded after the sign-in sent its writes: %q", got)
	}
	if len(p.Writes) != 1 || p.Writes[0].Target() != "POST "+srv.URL+"/api/basket" || p.Writes[0].Sent || !slices.Equal(p.Writes[0].Body, []string{"item"}) {
		t.Errorf("writes %+v", p.Writes)
	}
	if left := b.LeftoverWrites(); !slices.Equal(left, []string{"POST " + srv.URL + "/api/bye"}) {
		t.Errorf("leftover %q", left)
	}
}
