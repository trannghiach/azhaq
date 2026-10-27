package crawlcol

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/trannghiach/azhaq/types"
)

func TestMarkdownLinksAreFollowed(t *testing.T) {
	// A lesson page whose links are Markdown, rendered in the browser.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/learn/a1" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body><a href="/learn">Learn</a><div class="markdown">
* [User Search](/app/usersearch)
* [Admin](/app/admin/users)
* [Learn again](/learn)
* [OWASP](https://www.owasp.org/)
</div><script src="/assets/showdown.min.js"></script></body></html>`))
	}))
	t.Cleanup(srv.Close)

	var vias []string
	var unrendered bool
	meta, err := New(srv.Client()).Run(context.Background(), types.Seed{
		Type: types.TypeURL, Keys: map[string]string{"url": srv.URL + "/learn/a1"},
	}, func(o types.Observation) error {
		var p struct {
			URL        string         `json:"url"`
			Via        string         `json:"via"`
			Unrendered map[string]int `json:"unrendered"`
		}
		_ = json.Unmarshal(o.Payload, &p)
		switch o.Kind {
		case "url":
			vias = append(vias, p.Via+" "+strings.TrimPrefix(p.URL, srv.URL))
		case "meta":
			unrendered = p.Unrendered["markdown"] == 4
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"html /learn", "markdown /app/usersearch", "markdown /app/admin/users"}
	if strings.Join(vias, "|") != strings.Join(want, "|") {
		t.Errorf("urls %q, want %q", vias, want)
	}
	if !unrendered {
		t.Error("no unrendered note for the page")
	}
	hinted := map[string]bool{}
	for _, h := range meta.NextHints {
		hinted[strings.TrimPrefix(h.Key(), srv.URL)] = true
	}
	if !hinted["/app/usersearch"] || !hinted["/app/admin/users"] {
		t.Errorf("Markdown links not requested: %v", hinted)
	}
}

func TestPOSTFormIsNotHinted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<form method="post" action="/auth"></form><form method="get" action="/search"></form>`))
	}))
	t.Cleanup(srv.Close)

	col := New(srv.Client())
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
	for _, u := range got {
		if u == srv.URL+"/auth" {
			t.Fatalf("POST action must not become a GET hint: %v", got)
		}
	}
	found := false
	for _, u := range got {
		if u == srv.URL+"/search" {
			found = true
		}
	}
	if !found {
		t.Fatalf("GET form should be hinted, got %v", got)
	}
}
