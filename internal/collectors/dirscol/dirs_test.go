package dirscol

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/trannghiach/azhaq/internal/fetch"
	"github.com/trannghiach/azhaq/types"
)

// spa answers every unknown path with its index page, like Juice Shop,
// and has a few real paths.
func spa(t *testing.T) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin":
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("forbidden"))
		case "/backup.bak":
			w.Write([]byte("-- dump of the users table, many rows follow"))
		case "/files":
			http.Redirect(w, r, "/files/", http.StatusMovedPermanently)
		case "/files/report":
			w.Write([]byte("quarterly numbers"))
		case "/logout":
			w.Write([]byte("bye"))
		default:
			w.Write([]byte("<html><title>App</title><body>the same shell for every route</body></html>"))
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func sweepOf(t *testing.T, c *Collector, base string) ([]string, map[string]any) {
	t.Helper()
	var got []string
	var summary map[string]any
	_, err := c.Run(context.Background(), types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": base}}, func(o types.Observation) error {
		var m map[string]any
		_ = json.Unmarshal(o.Payload, &m)
		switch o.Kind {
		case "dirs":
			summary = m
		case "skipped": // guesses held back, listed in the summary
		default:
			got = append(got, strings.TrimPrefix(m["url"].(string), strings.TrimSuffix(base, "/")))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(got)
	return got, summary
}

func TestSweepCalibratesAndRecurses(t *testing.T) {
	fetch.Reset()
	srv := spa(t)
	c := New(srv.Client(), Options{Words: []string{"admin", "backup", "files", "report", "login", "index", "logout"}, Extensions: []string{"bak"}, Depth: 2, Rate: 1000})
	got, summary := sweepOf(t, c, srv.URL+"/")
	want := []string{"/admin", "/backup.bak", "/files", "/files/report", "/logout"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("hits %v, want %v", got, want)
	}
	if summary["filtered"].(float64) == 0 {
		t.Errorf("the catch-all answers were not filtered: %v", summary)
	}
	if !c.Skip(types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": srv.URL + "/admin"}}) {
		t.Error("a sweep starts at the front page")
	}
}

func TestSweepKeepsSessionAlive(t *testing.T) {
	fetch.Reset()
	defer fetch.Reset()
	fetch.Extra = http.Header{"Cookie": {"session=1"}}
	srv := spa(t)
	c := New(srv.Client(), Options{Words: []string{"logout", "admin"}, Rate: 1000})
	got, _ := sweepOf(t, c, srv.URL+"/")
	if strings.Join(got, " ") != "/admin" {
		t.Errorf("with a session, logout must not be requested: %v", got)
	}
}
