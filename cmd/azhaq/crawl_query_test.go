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
	if tmpl == nil || tmpl["count"] != float64(30) || tmpl["not_asked"] != nil {
		t.Errorf("the /item template row does not say 30 urls, all asked: %v", tmpl)
	}
	if n := hits("/item"); n != 30 {
		t.Errorf("%d /item asked, want all 30", n)
	}
}

func itemsSite(t *testing.T, n int) (*httptest.Server, func() int) {
	var mu sync.Mutex
	asked := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		switch r.URL.Path {
		case "/":
			var a []string
			for i := 1; i <= n; i++ {
				a = append(a, fmt.Sprintf(`<a href="/item?id=%d">i%d</a>`, i, i))
			}
			fmt.Fprintf(w, `<html><body>%s</body></html>`, strings.Join(a, ""))
		case "/item":
			mu.Lock()
			asked++
			mu.Unlock()
			fmt.Fprintf(w, `<html><body>item %s</body></html>`, r.URL.Query().Get("id"))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, func() int { mu.Lock(); defer mu.Unlock(); return asked }
}

// run asks every URL of a template by default; -per-template N asks N and
// lists the rest.
func TestRunPerTemplateDefaultAsksAll(t *testing.T) {
	for _, tc := range []struct {
		args        []string
		asked, hint int
	}{{nil, 20, 0}, {[]string{"-per-template", "2"}, 2, 18}} {
		srv, asked := itemsSite(t, 20)
		args := append([]string{"-url", srv.URL + "/", "-allow", "127.0.0.1", "-depth", "3", "-no-tech", "-json", "-db", filepath.Join(t.TempDir(), "w.db")}, tc.args...)
		out, _, err := captureBoth(t, func() error { return cmdRun(args) })
		if err != nil && exitCode(err) != exitPartial {
			t.Fatal(err)
		}
		if n := asked(); n != tc.asked {
			t.Errorf("%v: %d asked, want %d", tc.args, n, tc.asked)
		}
		tmpl := urlRows(t, out)[srv.URL+"/item?id={n}"]
		if tmpl == nil || tmpl["count"] != float64(20) {
			t.Fatalf("%v: template row: %v", tc.args, tmpl)
		}
		got := 0
		if v, ok := tmpl["not_asked"].(float64); ok {
			got = int(v)
		}
		if got != tc.hint {
			t.Errorf("%v: %d not asked, want %d", tc.args, got, tc.hint)
		}
	}
}

// A shop shaped like ginandjuice.shop: product and blog links in anchors,
// a script object that names product URLs with one name and with two.
func templateSite(t *testing.T) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		switch r.URL.Path {
		case "/":
			fmt.Fprint(w, `<html><body><a href="/catalog">catalog</a><a href="/blog">blog</a></body></html>`)
		case "/catalog":
			var a, js []string
			for i := 1; i <= 6; i++ {
				a = append(a, fmt.Sprintf(`<a href="/catalog/product?productId=%d">p%d</a>`, i, i))
				js = append(js, fmt.Sprintf(`{"url":"/catalog/product?productId=%d&storeId=%d"}`, i, i))
			}
			fmt.Fprintf(w, `<html><body>%s<script>var products=[%s];</script></body></html>`, strings.Join(a, ""), strings.Join(js, ","))
		case "/blog":
			fmt.Fprint(w, `<html><body><a href="/blog/post?postId=1">1</a><a href="/blog/post?postId=2">2</a><a href="/blog/post?postId=3">3</a><a href="/blog/post?postId=4">4</a></body></html>`)
		case "/catalog/product", "/blog/post":
			fmt.Fprintf(w, `<html><body>%s</body></html>`, r.URL.RawQuery)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// Variants of one route are one template row in the map, each URL still
// asked up to -per-template, while crawl lists every distinct URL.
func TestRunFoldsQueryShapesOfOneRoute(t *testing.T) {
	srv := templateSite(t)
	out, _, err := captureBoth(t, func() error {
		return cmdRun([]string{"-url", srv.URL + "/", "-allow", "127.0.0.1", "-depth", "3", "-no-tech", "-db", filepath.Join(t.TempDir(), "w.db")})
	})
	if err != nil && exitCode(err) != exitPartial {
		t.Fatal(err)
	}
	product, blog := 0, 0
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "URL ") {
			if strings.Contains(l, "/catalog/product?productId=") {
				product++
			}
			if strings.Contains(l, "/blog/post?postId=") {
				blog++
			}
		}
	}
	if product != 1 || blog != 1 {
		t.Errorf("map lines: product %d, blog post %d, want one each:\n%s", product, blog, out)
	}

	crawl, _, err := captureBoth(t, func() error {
		return cmdCrawl([]string{"-u", srv.URL + "/", "-allow", "127.0.0.1", "-depth", "3", "-db", filepath.Join(t.TempDir(), "c.db")})
	})
	if err != nil && exitCode(err) != exitPartial {
		t.Fatal(err)
	}
	lines := map[string]bool{}
	for _, l := range strings.Split(crawl, "\n") {
		lines[strings.TrimPrefix(l, srv.URL)] = true
	}
	for i := 1; i <= 6; i++ {
		for _, u := range []string{fmt.Sprintf("/catalog/product?productId=%d", i), fmt.Sprintf("/catalog/product?productId=%d&storeId=%d", i, i)} {
			if !lines[u] {
				t.Errorf("crawl does not list %s:\n%s", u, crawl)
			}
		}
	}
}

// crawl fills GET forms by default, so -fill-forms is gone; the error names
// the flag that turns it off.
func TestCrawlFillFormsIsUsageError(t *testing.T) {
	for _, a := range []string{"-fill-forms", "--fill-forms=true"} {
		err := cmdCrawl([]string{"-u", "http://127.0.0.1:1/", a})
		if err == nil || exitCode(err) != exitUsage || !strings.Contains(err.Error(), "-no-form-fill") {
			t.Errorf("%s: %v", a, err)
		}
	}
}
