package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// A link that redirects to a page of the site (/my-account to /login) puts
// that page in the map at the link's own depth: the redirect is the link's
// answer, not another click.
func TestCrawlMapsWhereAnInDepthLinkRedirects(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><title>home</title><body><a href="/my-account">Account</a> <a href="/about">About</a></body></html>`)
		case "/my-account":
			http.Redirect(w, r, "/login", http.StatusFound)
		case "/login":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><title>login</title><body><form method=post><input name=user></form><a href="/deeper">more</a></body></html>`)
		case "/about":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><title>about</title><body>about us</body></html>`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	t.Chdir(t.TempDir())
	out, errOut, code := cli(t, "crawl", "-u", srv.URL+"/", "-d", "1", "-json", "-allow", "127.0.0.1")
	if code != exitOK {
		t.Fatalf("exit %d\n%s", code, errOut)
	}
	rows := map[string]map[string]any{}
	for _, r := range jsonRows(t, out) {
		rows[r["url"].(string)] = r
	}
	login := rows[srv.URL+"/login"]
	if login == nil {
		t.Fatalf("/login, where /my-account redirects, is not in the map: %v", rows)
	}
	if login["coverage"] == "hint" || login["coverage"] == "capped" {
		t.Errorf("/login was answered during the redirect but is listed as %v", login["coverage"])
	}
	if rows[srv.URL+"/deeper"] != nil && rows[srv.URL+"/deeper"]["coverage"] != "hint" {
		t.Errorf("/deeper is a step past -d 1: %v", rows[srv.URL+"/deeper"])
	}
}
