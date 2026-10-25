package fetch

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func catchAll(t *testing.T, srv *httptest.Server, path string) bool {
	t.Helper()
	res, _, err := Do(context.Background(), srv.Client(), srv.URL+path)
	if err != nil {
		t.Fatal(err)
	}
	return CatchAll(context.Background(), srv.Client(), res)
}

func TestCatchAllSPA(t *testing.T) {
	Reset()
	index := `<!doctype html><title>Shop</title><app-root></app-root><script src="main.js"></script>`
	mux := http.NewServeMux()
	mux.HandleFunc("/api/Users", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("No Authorization header was found"))
	})
	mux.HandleFunc("/ftp/", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`<title>listing /ftp</title><a href="legal.md">legal.md</a>`))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(index))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	for _, p := range []string{"/admin", "/.git/HEAD", "/assets/x.js", "/a/b/c"} {
		if !catchAll(t, srv, p) {
			t.Errorf("%s: want catch-all", p)
		}
	}
	for _, p := range []string{"/", "/api/Users", "/ftp/"} {
		if catchAll(t, srv, p) {
			t.Errorf("%s: real page reported as catch-all", p)
		}
	}
}

func TestCatchAllEchoesPath(t *testing.T) {
	Reset()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/rest/products" {
			_, _ = w.Write([]byte(`{"data":[]}`))
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "<h1>Error: Unexpected path: %s</h1><p>at %s</p>", r.URL.Path, r.URL.Path)
	}))
	t.Cleanup(srv.Close)

	if !catchAll(t, srv, "/rest/user/login") {
		t.Error("echoing error page: want catch-all")
	}
	if catchAll(t, srv, "/rest/products") {
		t.Error("real endpoint reported as catch-all")
	}
}

func TestCatchAllRedirect(t *testing.T) {
	Reset()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login":
			_, _ = w.Write([]byte("<title>Login</title>"))
		case "/account":
			http.Redirect(w, r, "/login?next=/account&reason=session", http.StatusFound)
		default:
			http.Redirect(w, r, "/login?next="+r.URL.Path, http.StatusFound)
		}
	}))
	t.Cleanup(srv.Close)

	if !catchAll(t, srv, "/wp-admin") {
		t.Error("redirect for every path: want catch-all")
	}
	if catchAll(t, srv, "/account") {
		t.Error("distinct redirect reported as catch-all")
	}
	if catchAll(t, srv, "/login") {
		t.Error("login page reported as catch-all")
	}
}

func TestCatchAllDynamicSoft404(t *testing.T) {
	Reset()
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/about" {
			_, _ = w.Write([]byte("<title>About</title><p>We sell juice since 2014.</p>"))
			return
		}
		fmt.Fprintf(w, "<title>Not found</title>\n<p>Sorry, nothing here.</p>\n<input name=csrf value=%d>", n.Add(1)*7919)
	}))
	t.Cleanup(srv.Close)

	if !catchAll(t, srv, "/backup") {
		t.Error("soft 404 with a changing token: want catch-all")
	}
	if catchAll(t, srv, "/about") {
		t.Error("real page reported as catch-all")
	}
}

func TestCatchAllPlain404Server(t *testing.T) {
	Reset()
	var probes atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, probeToken) {
			probes.Add(1)
		}
		if r.URL.Path == "/admin" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)

	if catchAll(t, srv, "/admin") {
		t.Error("403 on a server with real 404s reported as catch-all")
	}
	if catchAll(t, srv, "/missing") {
		t.Error("404 is not a catch-all")
	}
	catchAll(t, srv, "/admin")
	if probes.Load() != 1 {
		t.Errorf("baseline probes %d, want 1 per directory", probes.Load())
	}
}
