package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// A shop whose catalog page holds its category and item links in a
// script, as strings with complete queries.
func scriptLinksSite(t *testing.T) (*httptest.Server, func(string) int) {
	var mu sync.Mutex
	hits := map[string]int{}
	cats := []string{"Accessories", "Accompaniments", "Books", "Gin", "Juice"}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		if r.URL.RawQuery != "" {
			hits[r.URL.Path]++
		}
		mu.Unlock()
		w.Header().Set("Content-Type", "text/html")
		switch r.URL.Path {
		case "/":
			fmt.Fprint(w, `<html><body><a href="/catalog">catalog</a></body></html>`)
		case "/catalog":
			var js []string
			for _, c := range cats {
				js = append(js, fmt.Sprintf(`"/catalog?category=%s"`, c))
			}
			for i := 1; i <= 30; i++ {
				js = append(js, fmt.Sprintf(`"/item?id=%d"`, i))
			}
			js = append(js, `"/search?q="`)
			fmt.Fprintf(w, `<html><body><h1>%s</h1><script>var links=[%s];</script></body></html>`, r.URL.RawQuery, strings.Join(js, ","))
		case "/item":
			fmt.Fprintf(w, `<html><body>item %s</body></html>`, r.URL.Query().Get("id"))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, func(p string) int { // requests to p with a query
		mu.Lock()
		defer mu.Unlock()
		return hits[p]
	}
}

func urlRows(t *testing.T, out string) map[string]map[string]any {
	rows := map[string]map[string]any{}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		var row map[string]any
		if json.Unmarshal([]byte(line), &row) != nil {
			continue
		}
		if k, _ := row["url"].(string); k != "" {
			rows[k] = row
		} else if row["type"] == "URL" {
			rows[row["key"].(string)] = row
		}
	}
	return rows
}

func countCoverage(rows map[string]map[string]any, prefix, cov string) int {
	n := 0
	for k, r := range rows {
		if strings.Contains(k, prefix) && r["coverage"] == cov {
			n++
		}
	}
	return n
}

// Every URL a script names with a complete query is listed by crawl, plain
// and -json, and a name with no value (?q=) stays the route's.
func TestCrawlListsEveryLinkedQueryURL(t *testing.T) {
	srv, hits := scriptLinksSite(t)
	out, _, err := captureBoth(t, func() error {
		return cmdCrawl([]string{"-u", srv.URL + "/", "-allow", "127.0.0.1", "-db", filepath.Join(t.TempDir(), "w.db")})
	})
	if err != nil && exitCode(err) != exitPartial {
		t.Fatal(err)
	}
	lines := map[string]bool{}
	for _, l := range strings.Split(out, "\n") {
		lines[strings.TrimPrefix(l, srv.URL)] = true
	}
	for _, c := range []string{"Accessories", "Accompaniments", "Books", "Gin", "Juice"} {
		if !lines["/catalog?category="+c] {
			t.Errorf("crawl does not list /catalog?category=%s:\n%s", c, out)
		}
	}
	for i := 1; i <= 30; i++ {
		if !lines[fmt.Sprintf("/item?id=%d", i)] {
			t.Errorf("crawl does not list /item?id=%d", i)
		}
	}
	if lines["/search?q="] {
		t.Error("a name with no value is no URL of its own")
	}
	if n := hits("/item"); n != 30 {
		t.Errorf("a crawl asks every URL it lists: %d asked of 30", n)
	}
}

// -per-template bounds how many variants are asked; the rest are listed,
// as not asked.
func TestCrawlPerTemplateBoundsAsksNotTheList(t *testing.T) {
	srv, hits := scriptLinksSite(t)
	out, _, err := captureBoth(t, func() error {
		return cmdCrawl([]string{"-u", srv.URL + "/", "-allow", "127.0.0.1", "-per-template", "10", "-json", "-db", filepath.Join(t.TempDir(), "w.db")})
	})
	if err != nil && exitCode(err) != exitPartial {
		t.Fatal(err)
	}
	rows := urlRows(t, out)
	items := 0
	for k := range rows {
		if strings.HasPrefix(k, srv.URL+"/item?id=") {
			items++
		}
	}
	if items != 30 {
		t.Errorf("%d /item rows, want all 30", items)
	}
	if n := hits("/item"); n != 10 {
		t.Errorf("%d /item asked, want the bound of 10", n)
	}
	if n := countCoverage(rows, "/item?id=", "hint"); n != 20 {
		t.Errorf("%d /item rows say they were not asked, want 20", n)
	}
	for _, c := range []string{"Accessories", "Accompaniments", "Books", "Gin", "Juice"} {
		if r := rows[srv.URL+"/catalog?category="+c]; r == nil || r["coverage"] != "visited" {
			t.Errorf("/catalog?category=%s: %v", c, r)
		}
	}
}

// The same for run's map: each variant is a row, and a template's
// variants past -per-template are listed, not asked.
func TestRunListsEveryLinkedQueryURL(t *testing.T) {
	srv, hits := scriptLinksSite(t)
	out, _, err := captureBoth(t, func() error {
		return cmdRun([]string{"-url", srv.URL + "/", "-allow", "127.0.0.1", "-depth", "3", "-no-tech", "-json", "-db", filepath.Join(t.TempDir(), "w.db")})
	})
	if err != nil && exitCode(err) != exitPartial {
		t.Fatal(err)
	}
	rows := urlRows(t, out)
	for _, c := range []string{"Accessories", "Accompaniments", "Books", "Gin", "Juice"} {
		if rows[srv.URL+"/catalog?category="+c] == nil {
			t.Errorf("run does not map /catalog?category=%s", c)
		}
	}
	tmpl := rows[srv.URL+"/item?id={n}"]
	if tmpl == nil || tmpl["count"] != float64(30) || tmpl["not_asked"] != float64(27) {
		t.Errorf("the /item template row does not say 30 urls, 27 not asked: %v", tmpl)
	}
	if n := hits("/item"); n != 3 {
		t.Errorf("%d /item asked, want run's bound of 3", n)
	}
}
