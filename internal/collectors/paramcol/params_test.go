package paramcol

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/trannghiach/azhaq/internal/fetch"
	"github.com/trannghiach/azhaq/types"
)

func TestFindsHiddenParameters(t *testing.T) {
	fetch.Reset()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("debug") != "" {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		body := "<html><body>results"
		if v := q.Get("search"); v != "" {
			body += " for " + v // reflected
		}
		if q.Get("limit") != "" {
			body += strings.Repeat(" <li>row</li>", 40) // a larger page
		}
		fmt.Fprint(w, body+"</body></html>")
	}))
	defer srv.Close()
	words := []string{"debug", "search", "limit"}
	for i := 0; i < 600; i++ {
		words = append(words, fmt.Sprintf("noise%d", i))
	}
	c := New(srv.Client(), Options{Words: words, Rate: 10000})
	var got map[string]any
	_, err := c.Run(context.Background(), types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": srv.URL + "/list"}}, func(o types.Observation) error {
		return json.Unmarshal(o.Payload, &got)
	})
	if err != nil {
		t.Fatal(err)
	}
	why, _ := got["why"].(map[string]any)
	if why["debug"] != "status" || why["search"] != "reflected" || why["limit"] != "size" || len(why) != 3 {
		t.Fatalf("found %v", got)
	}
	if n := got["requests"].(float64); n > 60 {
		t.Errorf("%v requests for 603 names", n)
	}
}

func TestSkipsNoisyPages(t *testing.T) {
	fetch.Reset()
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n++
		fmt.Fprint(w, strings.Repeat("x", n*500)) // a different size every time
	}))
	defer srv.Close()
	c := New(srv.Client(), Options{Words: []string{"a", "b"}, Rate: 10000})
	emitted := 0
	_, _ = c.Run(context.Background(), types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": srv.URL + "/"}}, func(types.Observation) error {
		emitted++
		return nil
	})
	if emitted != 0 {
		t.Error("a page that changes by itself must not report parameters")
	}
}

// echoServer answers like an Express error page: the whole query string
// comes back, twice, HTML-escaped; q is also printed in the page.
func echoServer(t *testing.T, status int) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		echo := html.EscapeString(r.URL.RequestURI())
		w.WriteHeader(status)
		body := "<html><head><title>Error: Unexpected path: " + echo + "</title></head><body><h2>" + echo + "</h2>"
		if v := r.URL.Query().Get("q"); v != "" {
			body += "<p>results for " + html.EscapeString(v) + "</p>"
		}
		fmt.Fprint(w, body+"</body></html>")
	}))
	t.Cleanup(srv.Close)
	return srv
}

func runOn(t *testing.T, c *Collector, raw string) map[string]any {
	t.Helper()
	var got map[string]any
	_, err := c.Run(context.Background(), types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": raw}}, func(o types.Observation) error {
		return json.Unmarshal(o.Payload, &got)
	})
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func TestEchoedQueryIsNoEvidence(t *testing.T) {
	fetch.Reset()
	srv := echoServer(t, http.StatusInternalServerError)
	words := []string{"q", "id", "search[]", "a"}
	for i := 0; i < 700; i++ {
		words = append(words, fmt.Sprintf("name%d", i))
	}
	c := New(srv.Client(), Options{Words: words, Rate: 10000})
	got := runOn(t, c, srv.URL+"/rest/track-order")
	why, _ := got["why"].(map[string]any)
	if len(why) != 1 || why["q"] != "reflected" {
		t.Fatalf("an echoed query string is not a parameter: %v", got)
	}
	if got["note"] != nil {
		t.Errorf("note on a page that tells names apart: %v", got["note"])
	}
	if n := got["requests"].(float64); n > 40 {
		t.Errorf("%v requests for %d names", n, len(words))
	}
}

func TestPageAnsweringEveryNameIsNoted(t *testing.T) {
	fetch.Reset()
	// Every name the page does not know is printed, a line per name, but
	// not the random names of a control: nothing tells the names it reads
	// from the rest.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<html><body>")
		for k := range r.URL.Query() {
			if !strings.HasPrefix(k, "~") && !strings.HasPrefix(k, "az") {
				fmt.Fprintf(w, "<p>unknown parameter %s</p>\n", html.EscapeString(k))
			}
		}
		fmt.Fprint(w, "</body></html>")
	}))
	defer srv.Close()
	var words []string
	for i := 0; i < 300; i++ {
		words = append(words, fmt.Sprintf("name%d", i))
	}
	c := New(srv.Client(), Options{Words: words, Rate: 10000})
	got := runOn(t, c, srv.URL+"/")
	if names, _ := got["params"].([]any); len(names) != 0 {
		t.Fatalf("%d names reported from a page that answers any name", len(names))
	}
	if note, _ := got["note"].(string); !strings.Contains(note, "answers names it does not read") {
		t.Fatalf("no note: %v", got)
	}
	if n := got["requests"].(float64); n > 100 {
		t.Errorf("%v requests before giving up on the page", n)
	}
}

// A short wordlist (names taken from the target's own scripts) on a page
// that reads most of them: every name it reads is a parameter, also when
// nearly every name tried alone is one.
func TestShortListOfRealNames(t *testing.T) {
	for _, reads := range [][]string{
		{"q", "page", "sort", "order", "limit", "category", "brand", "color"},
		strings.Fields("q page sort order limit category brand color size price min max from to tag type status lang view mode"),
	} {
		fetch.Reset()
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body := "<html><body>products"
			for i, n := range reads {
				if r.URL.Query().Get(n) != "" {
					body += strings.Repeat(fmt.Sprintf(" <li>%s</li>", n), 10+i) // each changes the page
				}
			}
			fmt.Fprint(w, body+"</body></html>")
		}))
		words := append(slices.Clone(reads), "utm_source", "fbclid")
		got := runOn(t, New(srv.Client(), Options{Words: words, Rate: 10000}), srv.URL+"/products")
		srv.Close()
		var names []string
		for _, n := range got["params"].([]any) {
			names = append(names, n.(string))
		}
		if want := slices.Sorted(slices.Values(reads)); !slices.Equal(names, want) || got["note"] != nil {
			t.Errorf("found %v, want %v", got, want)
		}
	}
}

// The page starts refusing every request partway (a rate limit): the
// group that floods is dropped, the names found before it stay.
func TestFloodKeepsEarlierGroups(t *testing.T) {
	fetch.Reset()
	var mu sync.Mutex
	limited := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.URL.Query().Has("flood0") {
			limited = true
		}
		if limited {
			http.Error(w, "slow down", http.StatusTooManyRequests)
			return
		}
		body := "<html><body>catalog"
		if r.URL.Query().Get("category") != "" {
			body += strings.Repeat(" <li>product</li>", 20)
		}
		fmt.Fprint(w, body+"</body></html>")
	}))
	defer srv.Close()
	words := []string{"category"}
	for i := 0; i < 9; i++ {
		words = append(words, fmt.Sprintf("name%d", i))
	}
	for i := 0; i < 20; i++ {
		words = append(words, fmt.Sprintf("flood%d", i))
	}
	got := runOn(t, New(srv.Client(), Options{Words: words, Chunk: 10, Rate: 10000}), srv.URL+"/catalog")
	why, _ := got["why"].(map[string]any)
	if len(why) != 1 || why["category"] != "size" {
		t.Errorf("found %v", got)
	}
	if note, _ := got["note"].(string); !strings.Contains(note, "answers names it does not read") || !strings.Contains(note, "not searched further") {
		t.Errorf("note %q", note)
	}
}

func TestLongQueriesAreSplit(t *testing.T) {
	fetch.Reset()
	// A server that refuses a query longer than 2 KB, whatever is in it.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.URL.RawQuery) > 2048 {
			http.Error(w, "URI too long", http.StatusRequestURITooLong)
			return
		}
		body := "<html><body>catalog"
		if r.URL.Query().Get("category") != "" {
			body += strings.Repeat(" <li>product</li>", 20)
		}
		fmt.Fprint(w, body+"</body></html>")
	}))
	defer srv.Close()
	var words []string
	for i := 0; i < 1000; i++ {
		words = append(words, fmt.Sprintf("parameter%d", i))
	}
	words = append(words[:600], append([]string{"category"}, words[600:]...)...)
	c := New(srv.Client(), Options{Words: words, Rate: 10000})
	got := runOn(t, c, srv.URL+"/catalog")
	why, _ := got["why"].(map[string]any)
	if len(why) != 1 || why["category"] != "size" {
		t.Fatalf("found %v", got)
	}
	// 1001 names in groups of at most 62 once the server refused 125.
	if n := got["requests"].(float64); n > 60 {
		t.Errorf("%v requests", n)
	}
}
