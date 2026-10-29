package pathscol

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"

	"github.com/trannghiach/azhaq/internal/fetch"
	"github.com/trannghiach/azhaq/types"
)

const specJSON = `{"openapi":"3.0.0","info":{"title":"t","version":"1"},"paths":{"/pets":{"get":{}}}}`

// labServer serves spec at specPath (when not empty), a login page and
// 404 for the rest; hits records every path asked.
func labServer(t *testing.T, specPath string) (*httptest.Server, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var hits []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits = append(hits, r.URL.Path)
		mu.Unlock()
		switch {
		case specPath != "" && r.URL.Path == specPath:
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(specJSON))
		case r.URL.Path == "/login" || r.URL.Path == "/":
			_, _ = w.Write([]byte("page"))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(hits)
	}
}

func runRoot(t *testing.T, srv *httptest.Server, words []string) (urls []string, notes []types.Observation) {
	t.Helper()
	fetch.Reset()
	t.Cleanup(fetch.Reset)
	col := &Collector{Client: srv.Client(), Wordlist: words}
	_, err := col.Run(context.Background(), types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": srv.URL + "/"}}, func(o types.Observation) error {
		if o.Kind == "note" {
			notes = append(notes, o)
			return nil
		}
		var p struct{ Path string }
		_ = json.Unmarshal(o.Payload, &p)
		urls = append(urls, p.Path)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return urls, notes
}

func TestDescriptionFoundSkipsOtherLocations(t *testing.T) {
	srv, hits := labServer(t, "/swagger.json")
	words := []string{"login", "openapi.json", "swagger.json", "api-docs", "v3/api-docs", "v2/api-docs", "swagger"}
	urls, notes := runRoot(t, srv, words)
	for _, w := range []string{"/api-docs", "/v3/api-docs", "/v2/api-docs", "/swagger"} {
		if slices.Contains(hits(), w) {
			t.Errorf("%s asked after the description was found; asked: %v", w, hits())
		}
	}
	if !slices.Contains(urls, "/swagger.json") || !slices.Contains(urls, "/login") {
		t.Errorf("found %v: want /swagger.json and /login", urls)
	}
	if len(notes) != 1 {
		t.Fatalf("want one note, got %d", len(notes))
	}
	obs := []types.StoredObservation{{Observation: notes[0]}}
	got := Notes(obs)
	want := "path checks: 4 skipped (an API description was already found)"
	if len(got) != 1 || got[0] != want {
		t.Errorf("Notes = %v, want %q", got, want)
	}
}

func TestNoDescriptionSkipsNothing(t *testing.T) {
	srv, hits := labServer(t, "")
	words := []string{"login", "openapi.json", "swagger.json", "api-docs", "v3/api-docs", "swagger", "admin"}
	_, notes := runRoot(t, srv, words)
	for _, w := range []string{"/login", "/openapi.json", "/swagger.json", "/api-docs", "/v3/api-docs", "/swagger", "/admin"} {
		if !slices.Contains(hits(), w) {
			t.Errorf("%s was not asked; asked: %v", w, hits())
		}
	}
	if len(notes) != 0 {
		t.Errorf("a note without a skip: %v", notes)
	}
}

func TestOtherChecksRunAfterDescription(t *testing.T) {
	srv, hits := labServer(t, "/openapi.json")
	words := []string{"robots.txt", "login", "admin", "graphql", "health", "openapi.json", "swagger.json"}
	runRoot(t, srv, words)
	for _, w := range []string{"/robots.txt", "/login", "/admin", "/graphql", "/health", "/openapi.json"} {
		if !slices.Contains(hits(), w) {
			t.Errorf("%s was dropped; asked: %v", w, hits())
		}
	}
	if slices.Contains(hits(), "/swagger.json") {
		t.Errorf("/swagger.json asked after /openapi.json answered")
	}
}

func baseSweep(t *testing.T, described bool) (hits []string, skipped int) {
	t.Helper()
	srv, got := labServer(t, "")
	fetch.Reset()
	t.Cleanup(fetch.Reset)
	col := &Collector{Client: srv.Client()}
	col.owner(srv.URL, srv.URL+"/") // the root sweep belongs to the root URL
	if described {
		fetch.MarkDescribed(srv.URL)
	}
	_, err := col.Run(context.Background(), types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": srv.URL + "/rest/products"}}, func(o types.Observation) error {
		if o.Kind == "note" {
			var p struct {
				Skipped int `json:"skipped_checks"`
			}
			_ = json.Unmarshal(o.Payload, &p)
			skipped = p.Skipped
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return got(), skipped
}

func TestDescribedOriginSkipsAPIBaseSweep(t *testing.T) {
	hits, skipped := baseSweep(t, true)
	if len(hits) != 0 || skipped != len(specWords) {
		t.Errorf("a described origin: %d requests %v, %d skipped; want none and %d", len(hits), hits, skipped, len(specWords))
	}
	hits, skipped = baseSweep(t, false)
	if len(hits) < len(specWords) || skipped != 0 {
		t.Errorf("an origin with no description: %d requests, %d skipped; want every location asked", len(hits), skipped)
	}
}

func TestDescribes(t *testing.T) {
	for body, want := range map[string]bool{
		specJSON: true,
		"openapi: 3.0.0\npaths:\n  /a:\n    get: {}\n":       true,
		`<html><script src="swagger-ui-bundle.js"></script>`: true,
		`<html><body>hello</body></html>`:                    false,
		`{"openapi":"3.0.0"}`:                                false,
		`{"a":1}`:                                            false,
		"":                                                   false,
	} {
		if got := describes([]byte(body)); got != want {
			t.Errorf("describes(%q) = %v, want %v", body, got, want)
		}
	}
}
