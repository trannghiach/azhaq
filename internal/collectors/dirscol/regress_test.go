package dirscol

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/trannghiach/azhaq/internal/fetch"
	"github.com/trannghiach/azhaq/types"
)

// PRB-11: the length of a hit is the whole body's, as ffuf reports it,
// not the megabyte that words and lines are counted on.
func TestRegressPRB11HitLengthIsTheWholeBody(t *testing.T) {
	fetch.Reset()
	defer fetch.Reset()
	const size = 3 << 20
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/video" {
			w.Write([]byte(strings.Repeat("x", size)))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	c := New(srv.Client(), Options{Words: []string{"video", "nothing"}, Rate: 1000})
	var length float64
	_, err := c.Run(context.Background(), types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": srv.URL + "/"}}, func(o types.Observation) error {
		var m map[string]any
		_ = json.Unmarshal(o.Payload, &m)
		if o.Kind == "url" && strings.HasSuffix(m["url"].(string), "/video") {
			length, _ = m["length"].(float64)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if int(length) != size {
		t.Errorf("/video reported as %d bytes, served %d", int(length), size)
	}
}
