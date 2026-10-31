package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/trannghiach/azhaq/internal/browser"
)

// A site of many pages that link to each other and have buttons to click.
func manyPagesServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := 0
		if rest, ok := strings.CutPrefix(r.URL.Path, "/p/"); ok {
			n, _ = strconv.Atoi(rest)
		}
		var b strings.Builder
		for i := 1; i <= 12; i++ {
			fmt.Fprintf(&b, `<a href="/p/%d">page %d</a> `, (n*7+i)%400+1, i)
		}
		fmt.Fprintf(&b, `<button onclick="fetch('/api/n/%d')">load</button><button onclick="location.href='/p/%d'">go</button>`, n, n+1)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<html><title>p%d</title><body>%s</body></html>`, n, b.String())
	}))
}

// The budget is spent: the run ends at once, with exit 4 and its work left
// for resume, however many pages Chrome still has open.
func TestBrowserCrawlEndsWhenTheBudgetIsSpent(t *testing.T) {
	if _, err := browser.Find(); err != nil {
		t.Skip(err)
	}
	srv := manyPagesServer()
	defer srv.Close()
	t.Chdir(t.TempDir())
	type result struct {
		errOut string
		code   int
	}
	done := make(chan result, 1)
	go func() {
		_, errOut, code := cli(t, "crawl", "-u", srv.URL+"/", "-d", "2", "-browser", "-interact", "-interact-clicks", "30",
			"-no-map-guess", "-max-requests", "25", "-db", "c.db", "-allow", "127.0.0.1")
		done <- result{errOut, code}
	}()
	select {
	case r := <-done:
		if r.code != exitLimit {
			t.Errorf("exit %d, want %d (stopped by the budget)\n%s", r.code, exitLimit, r.errOut)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the crawl was still running 10 s after its budget of 25 requests was spent")
	}
}
