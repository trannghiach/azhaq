package fetch

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/trannghiach/azhaq/internal/egress"
)

// A request with a method or body of its own is asked, cached and kept
// apart from the plain GET of the same URL.
func TestDoReqKeepsWritesApartFromGETs(t *testing.T) {
	Reset()
	var mu sync.Mutex
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		seen = append(seen, r.Method+":"+string(b))
		mu.Unlock()
		_, _ = w.Write([]byte(r.Method))
	}))
	defer srv.Close()
	ctx := context.Background()
	get, _, err := Do(ctx, nil, srv.URL+"/x")
	if err != nil || string(get.Body) != "GET" {
		t.Fatalf("get %v %q", err, get.Body)
	}
	post, cached, err := DoReq(ctx, nil, srv.URL+"/x", &Req{Method: "post", Body: []byte("a=1")})
	if err != nil || cached || string(post.Body) != "POST" || post.Method != "POST" {
		t.Fatalf("post %v cached %v %q method %q", err, cached, post.Body, post.Method)
	}
	// The same request again is the cached answer; a different body is a new request.
	if _, cached, _ := DoReq(ctx, nil, srv.URL+"/x", &Req{Method: "POST", Body: []byte("a=1")}); !cached {
		t.Error("the same POST was sent twice")
	}
	if _, cached, _ := DoReq(ctx, nil, srv.URL+"/x", &Req{Method: "POST", Body: []byte("a=2")}); cached {
		t.Error("another body was taken for the same request")
	}
	if g, cached, _ := Do(ctx, nil, srv.URL+"/x"); !cached || string(g.Body) != "GET" {
		t.Errorf("the GET's answer was overwritten: %q", g.Body)
	}
	if got := strings.Join(seen, " "); got != "GET: POST:a=1 POST:a=2" {
		t.Errorf("server saw %q", got)
	}
	if egress.Sent() != 3 {
		t.Errorf("counted %d requests, sent 3", egress.Sent())
	}
}

func TestProbeSettings(t *testing.T) {
	Reset()
	defer Reset()
	var accept, referer, host string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		accept, referer, host = r.Header.Get("Accept"), r.Header.Get("Referer"), r.Host
		switch r.URL.Path {
		case "/a":
			http.Redirect(w, r, "/b", http.StatusFound)
		case "/b":
			http.Redirect(w, r, "/c", http.StatusFound)
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	ctx := context.Background()
	NoAccept, AutoReferer, KeepRaw = true, true, true
	res, _, err := DoReq(ctx, nil, srv.URL+"/c", &Req{Header: http.Header{"Host": {"vhost.example"}}})
	if err != nil {
		t.Fatal(err)
	}
	if accept != "" || referer != srv.URL+"/c" || host != "vhost.example" {
		t.Errorf("accept %q referer %q host %q", accept, referer, host)
	}
	if res.Raw == nil || !strings.HasPrefix(res.Raw.Head, "HTTP/1.1 200") || !strings.HasPrefix(string(res.Raw.Request), "GET /c HTTP/1.1\r\n") {
		t.Errorf("raw %+v", res.Raw)
	}
	// The chain stops at MaxRedirects, and NoFollow follows none.
	MaxRedirects = 1
	if res, _, _ := Do(ctx, nil, srv.URL+"/a"); len(res.Hops) != 2 || res.Hops[1].Status != 302 {
		t.Errorf("MaxRedirects 1: %+v", res.Hops)
	}
	NoFollow = true
	if res, _, _ := Do(ctx, nil, srv.URL+"/b"); len(res.Hops) != 1 {
		t.Errorf("NoFollow: %+v", res.Hops)
	}
}

// Req.IP connects to that address whatever the URL's host says.
func TestReqIPPinsTheConnection(t *testing.T) {
	Reset()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(r.Host))
	}))
	defer srv.Close()
	port := srv.Listener.Addr().String()[strings.LastIndex(srv.Listener.Addr().String(), ":"):]
	res, _, err := DoReq(context.Background(), nil, "http://nowhere.invalid"+port+"/", &Req{IP: "127.0.0.1"})
	if err != nil || string(res.Body) != "nowhere.invalid"+port || res.IP != "127.0.0.1" {
		t.Errorf("%v %q ip %q", err, res.Body, res.IP)
	}
}
