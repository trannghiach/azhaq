package pathscol

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"azhaq/internal/types"
)

func TestFindsInterestingPaths(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte("home"))
	})
	mux.HandleFunc("/login", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("login"))
	})
	mux.HandleFunc("/admin", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	col := &Collector{Client: srv.Client(), Wordlist: []string{"login", "admin", "nope"}}
	var found []string
	var statuses []int
	_, err := col.Run(context.Background(), types.Seed{
		Type: types.TypeURL,
		Keys: map[string]string{"url": srv.URL + "/"},
	}, func(o types.Observation) error {
		var p struct {
			URL    string `json:"url"`
			Status int    `json:"status"`
		}
		_ = json.Unmarshal(o.Payload, &p)
		found = append(found, p.URL)
		statuses = append(statuses, p.Status)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 2 {
		t.Fatalf("found %v statuses %v", found, statuses)
	}
}

func TestProbeUnderPrefix(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/app/sub/login", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("login"))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	col := &Collector{Client: srv.Client(), Wordlist: []string{"login", "nope"}}
	var found []string
	_, err := col.Run(context.Background(), types.Seed{
		Type: types.TypeURL,
		Keys: map[string]string{"url": srv.URL + "/app/sub"},
	}, func(o types.Observation) error {
		var p struct {
			URL string `json:"url"`
		}
		_ = json.Unmarshal(o.Payload, &p)
		found = append(found, p.URL)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 1 || !strings.HasSuffix(found[0], "/app/sub/login") {
		t.Fatalf("found %v", found)
	}
}

func TestRobotsPathsAreHinted(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("User-agent: *\nDisallow: /hidden\nSitemap: /sitemap.xml\n"))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	col := &Collector{Client: srv.Client(), Wordlist: []string{"robots.txt"}}
	meta, err := col.Run(context.Background(), types.Seed{
		Type: types.TypeURL, Keys: map[string]string{"url": srv.URL + "/"},
	}, func(types.Observation) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, h := range meta.NextHints {
		got = append(got, h.Key())
	}
	if !hasSuffix(got, "/hidden") || !hasSuffix(got, "/sitemap.xml") {
		t.Fatalf("hints %v", got)
	}
}

func hasSuffix(urls []string, frag string) bool {
	for _, u := range urls {
		if strings.HasSuffix(u, frag) {
			return true
		}
	}
	return false
}

func TestOncePerHost(t *testing.T) {
	var hits []string
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		hits = append(hits, r.URL.Path)
		if r.URL.Path == "/app/login" || r.URL.Path == "/login" {
			_, _ = w.Write([]byte("ok"))
			return
		}
		http.NotFound(w, r)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	col := &Collector{Client: srv.Client(), Wordlist: []string{"login"}}
	seed := func(path string) {
		_, err := col.Run(context.Background(), types.Seed{
			Type: types.TypeURL,
			Keys: map[string]string{"url": srv.URL + path},
		}, func(types.Observation) error { return nil })
		if err != nil {
			t.Fatal(err)
		}
	}
	seed("/app/sub")
	n := len(hits)
	seed("/other")
	if len(hits) != n {
		t.Fatalf("second seed re-probed: %v", hits)
	}
}
