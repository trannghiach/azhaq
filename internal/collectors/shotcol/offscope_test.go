package shotcol

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/trannghiach/azhaq/internal/browser"
	"github.com/trannghiach/azhaq/internal/egress"
	"github.com/trannghiach/azhaq/internal/fetch"
	"github.com/trannghiach/azhaq/types"
)

func TestPartialWhy(t *testing.T) {
	for _, c := range []struct {
		unloaded, resources, blocked int
		hosts                        []string
		want                         string
	}{
		{0, 0, 0, nil, ""},
		{0, 40, 3, []string{"cdn.jsdelivr.net"}, "3 off-scope assets blocked: cdn.jsdelivr.net"},
		{0, 9, 1, []string{"fonts.gstatic.com"}, "1 off-scope asset blocked: fonts.gstatic.com"},
		{2, 40, 0, nil, "2 of 40 images, styles and scripts not loaded"},
		{2, 40, 3, []string{"a.test", "b.test"}, "3 off-scope assets blocked: a.test, b.test; 2 of 40 images, styles and scripts not loaded"},
		{0, 0, 9, []string{"a", "b", "c", "d", "e", "f", "g"}, "9 off-scope assets blocked: a, b, c, d, e, …"},
	} {
		if got := PartialWhy(c.unloaded, c.resources, c.blocked, c.hosts); got != c.want {
			t.Errorf("%+v: %q, want %q", c, got, c.want)
		}
	}
}

// A page that loads its styles, script and image from a host outside the
// scope is shot without them and says so, on every page that does: the
// row has partial, blocked and the hosts, the note how to allow them, and
// the host outside was never asked.
func TestPageWithOffScopeAssetsIsPartial(t *testing.T) {
	if _, err := browser.Find(); err != nil {
		t.Skip(err)
	}
	b := &browser.Browser{}
	t.Cleanup(fetch.Reset)
	if err := b.Start(); errors.Is(err, browser.ErrNoSandbox) {
		t.Skip(err)
	} else if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Close)

	var mu sync.Mutex
	var cdnGot []string
	cdn := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		cdnGot = append(cdnGot, r.URL.Path)
		mu.Unlock()
		w.Header().Set("Access-Control-Allow-Origin", "*")
		fmt.Fprint(w, "x")
	}))
	defer cdn.Close()
	cu, _ := url.Parse(cdn.URL)
	o := "http://localhost:" + cu.Port()
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<html><head><title>%s</title><link rel=stylesheet href="%s/bootstrap.css"><script src="%s/lib.js"></script></head><body><h1>hi</h1><img src="%s/logo.png"></body></html>`, r.URL.Path, o, o, o)
	}))
	defer site.Close()

	run := func(path string) map[string]any {
		t.Helper()
		var row map[string]any
		c := &Collector{Dir: t.TempDir(), Browser: b}
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		_, err := c.Run(ctx, types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": site.URL + path, types.GivenKey: "1"}}, func(ob types.Observation) error {
			if ob.Kind == "screenshot" {
				return json.Unmarshal(ob.Payload, &row)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		if row == nil {
			t.Fatal("no screenshot")
		}
		return row
	}
	hosts := func(row map[string]any) []string {
		var out []string
		for _, h := range row["blocked_hosts"].([]any) {
			out = append(out, h.(string))
		}
		return out
	}
	for _, scoped := range []bool{false, true} {
		fetch.Reset()
		if scoped {
			egress.SetScope(func(h string) bool { return h == "127.0.0.1" })
		}
		for _, path := range []string{"/", "/second"} { // the second page's are listed no more, and counted all the same
			row := run(path)
			if row["partial"] != true || row["blocked"] != float64(3) || !slices.Equal(hosts(row), []string{"localhost"}) {
				t.Fatalf("scoped %v, %s: partial %v, blocked %v, hosts %v", scoped, path, row["partial"], row["blocked"], row["blocked_hosts"])
			}
			if row["unloaded"] != nil {
				t.Errorf("a request refused for the scope is not an unloaded one: %v", row["unloaded"])
			}
			note, _ := row["note"].(string)
			want := "-allow 127.0.0.1 -allow localhost loads them"
			if scoped {
				want = "-allow localhost loads them"
			}
			if !strings.Contains(note, "is partial") || !strings.Contains(note, "outside the scope were blocked") || !strings.Contains(note, want) || strings.Contains(note, "images, styles and scripts were not loaded") {
				t.Errorf("scoped %v: note %q lacks %q", scoped, note, want)
			}
			if file, _ := row["file"].(string); file != "" {
				if st, err := os.Stat(file); err != nil || st.Size() == 0 {
					t.Errorf("the picture is still taken: %v", err)
				}
			}
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(cdnGot) != 0 {
		t.Errorf("a host outside the scope was asked for %q", cdnGot)
	}
}
