package paramcol

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"strings"
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
