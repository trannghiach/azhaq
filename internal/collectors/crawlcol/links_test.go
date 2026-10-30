package crawlcol

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/trannghiach/azhaq/internal/crawlscope"
	"github.com/trannghiach/azhaq/types"
)

type seen struct {
	urls     map[string]map[string]string // url → payload
	rejected map[string]string            // string → reason
	offsite  []string
	hints    int
}

func crawl(t *testing.T, srv *httptest.Server, path string) seen {
	t.Helper()
	s := seen{urls: map[string]map[string]string{}, rejected: map[string]string{}}
	meta, err := New(srv.Client()).Run(context.Background(), types.Seed{
		Type: types.TypeURL, Keys: map[string]string{"url": srv.URL + path},
	}, func(o types.Observation) error {
		var p map[string]string
		_ = json.Unmarshal(o.Payload, &p)
		switch o.Kind {
		case "url":
			s.urls[strings.TrimPrefix(p["url"], srv.URL)] = p
		case "rejected":
			s.rejected[p["string"]] = p["reason"]
		case "offsite":
			s.offsite = append(s.offsite, p["url"])
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	s.hints = len(meta.NextHints)
	return s
}

// A page with many links lists and asks every one: no cap that drops them
// without a word.
func TestEveryLinkOfABigPageIsKept(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/index" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		var b strings.Builder
		for i := 0; i < 300; i++ {
			fmt.Fprintf(&b, `<a href="/item/%d">i</a>`, i)
		}
		fmt.Fprint(w, "<html><body>"+b.String()+"</body></html>")
	}))
	t.Cleanup(srv.Close)
	s := crawl(t, srv, "/index")
	if len(s.urls) != 300 || s.hints != 300 {
		t.Errorf("%d URLs, %d hints, want 300 each", len(s.urls), s.hints)
	}
}

func TestLinkSourceAndHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/index" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Link", "</hdr>; rel=preload")
		fmt.Fprint(w, `<html><body><img src="/pic"><a href="/a">a</a><p>see users.php and ./notes/x.html and /assets/s.css</p></body></html>`)
	}))
	t.Cleanup(srv.Close)
	s := crawl(t, srv, "/index")
	if p := s.urls["/pic"]; p["tag"] != "img" || p["attribute"] != "src" {
		t.Errorf("/pic: %v", p)
	}
	if p := s.urls["/hdr"]; p["tag"] != "header" || p["attribute"] != "link" {
		t.Errorf("/hdr: %v", p)
	}
	if _, ok := s.urls["/notes/x.html"]; !ok {
		t.Errorf("a path in the page's text is not found: %v", s.urls)
	}
	if r := s.rejected["/assets/s.css"]; r == "" {
		t.Errorf("a style named in text is neither a URL nor rejected: %v", s.rejected)
	}
}

func TestOtherHostsAreNotFollowedUnlessTheScopeSaysSo(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/index" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body><a href="/a">a</a><a href="http://elsewhere.test/x">x</a></body></html>`)
	}))
	t.Cleanup(srv.Close)
	crawlscope.Reset()
	if s := crawl(t, srv, "/index"); len(s.offsite) != 0 || len(s.urls) != 1 {
		t.Errorf("default: %v %v", s.urls, s.offsite)
	}
	if err := crawlscope.Set(crawlscope.Config{Field: "fqdn", Roots: []string{srv.URL}}); err != nil {
		t.Fatal(err)
	}
	defer crawlscope.Reset()
	if s := crawl(t, srv, "/index"); len(s.offsite) != 1 || s.offsite[0] != "http://elsewhere.test/x" {
		t.Errorf("a scope that can leave the origin says what it left: %v", s.offsite)
	}
}

func formSite(t *testing.T, posts *[]string) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			b := make([]byte, 200)
			n, _ := r.Body.Read(b)
			*posts = append(*posts, r.URL.Path+" "+string(b[:n]))
			return
		}
		if r.URL.Path != "/index" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body><form action="/search"><input name=q></form>
<form action="/login" method="post"><input name=user><input type=password name=pw></form>
<form action="/logout" method="post"><input name=x></form></body></html>`)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestGetFormIsAskedFilledAndPostIsNotSent(t *testing.T) {
	var posts []string
	srv := formSite(t, &posts)
	c := New(srv.Client())
	c.FillForms = true
	var hints []string
	meta, err := c.Run(context.Background(), types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": srv.URL + "/index"}},
		func(types.Observation) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range meta.NextHints {
		hints = append(hints, strings.TrimPrefix(h.Key(), srv.URL))
	}
	if strings.Join(hints, " ") != "/search?q=azhaq" || len(posts) != 0 {
		t.Errorf("hints %v, posts %v", hints, posts)
	}
}

func TestPostFormsAreSubmittedOnlyWhenAsked(t *testing.T) {
	var posts []string
	srv := formSite(t, &posts)
	c := New(srv.Client())
	c.SubmitForms = true
	var rows []map[string]any
	_, err := c.Run(context.Background(), types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": srv.URL + "/index"}},
		func(o types.Observation) error {
			var p map[string]any
			_ = json.Unmarshal(o.Payload, &p)
			if o.Kind == "url" {
				rows = append(rows, p)
			}
			return nil
		})
	if err != nil {
		t.Fatal(err)
	}
	// /logout is left alone by its name; /login goes with neutral values.
	if len(posts) != 1 || posts[0] != "/login user=azhaq&pw=azhaqP4ssw0rd" {
		t.Errorf("posts %v", posts)
	}
	var seenPost bool
	for _, r := range rows {
		if m, _ := r["methods"].([]any); len(m) == 1 && m[0] == "POST" && strings.HasSuffix(r["url"].(string), "/login") {
			seenPost = true
		}
	}
	if !seenPost {
		t.Errorf("the route is not listed with its method: %v", rows)
	}
}
