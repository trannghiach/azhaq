package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A library served from the app's own origin under a versioned name with an
// underscore (angular_1-7-7.js) holds no routes of the app: its strings are
// not read, as those of react-dom.development.js are not.
func TestCrawlDoesNotReadVersionedLibraryScripts(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		js := func(body string) {
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprint(w, body)
		}
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><body><script src="/resources/js/angular_1-7-7.js"></script><script src="/resources/js/stockCheck.js"></script></body></html>`)
		case "/resources/js/angular_1-7-7.js":
			js(`var MIME = "binary/"; var other = "/library-only";`)
		case "/resources/js/stockCheck.js":
			js(`fetch("/product/stock", {method: "POST", body: "x"});`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	out, _ := crawlOut(t, srv)
	if !strings.Contains(out, srv.URL+"/product/stock\n") {
		t.Errorf("the app's own script is read:\n%s", out)
	}
	for _, not := range []string{"/binary", "/library-only"} {
		if strings.Contains(out, srv.URL+not+"\n") {
			t.Errorf("a string of angular_1-7-7.js is listed as %s:\n%s", not, out)
		}
	}
	if !strings.Contains(out, srv.URL+"/resources/js/angular_1-7-7.js\n") {
		t.Errorf("the library's own URL is listed, as the page loads it:\n%s", out)
	}
}
