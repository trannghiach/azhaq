package paramcol

import (
	"context"
	"encoding/json"
	"fmt"
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
