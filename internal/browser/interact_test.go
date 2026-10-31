package browser

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/trannghiach/azhaq/internal/fetch"
)

// Only what is not a page of the site is left alone, whatever its words say.
func TestOnlyDownloadsAndNonPageLinksAreLeftAlone(t *testing.T) {
	for _, c := range []candidate{
		{Text: "x", Href: "mailto:a@b.c"}, {Text: "x", Href: "javascript:void(0)"}, {Text: "x", Href: "tel:1"},
		{Text: "pdf", Download: true},
	} {
		if !skipCandidate(c) {
			t.Errorf("%+v would be clicked", c)
		}
	}
	for _, c := range []candidate{{Text: "Reports"}, {Text: "Inbox", Href: "/inbox"}, {Text: "Save"}, {Text: "", Tag: "button"},
		{Text: "Log out", Href: "/logout"}, {Text: "Delete all"}, {Text: "x", Href: "/items/remove?id=1"}} {
		if skipCandidate(c) {
			t.Errorf("%+v is left alone", c)
		}
	}
}

// Clicking finds what only a click brings, and sends no write: the GET a
// "Log out" click makes is requested like any other, and the writes the
// Delete and Save buttons send are refused by their method and mapped.
func TestInteractClicksAndSendsNoWrite(t *testing.T) {
	b := startChrome(t)
	b.Interact = 8
	var mu sync.Mutex
	var writes []string
	srv := newRecorder(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			mu.Lock()
			writes = append(writes, r.Method+" "+r.URL.Path)
			mu.Unlock()
		}
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><body><button onclick="fetch('/api/reports');history.pushState({},'','/reports')">Reports</button>
<button onclick="fetch('/api/delete-all',{method:'DELETE'})">Delete all</button>
<button onclick="fetch('/api/save',{method:'POST',body:'{}'})">Save</button><a href="#" onclick="fetch('/api/bye')">Log out</a></body></html>`)
			return
		}
		fmt.Fprint(w, "{}")
	})
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	fetch.Reset()
	fetch.Allow = func(h string) bool { return h == "127.0.0.1" }
	_ = fetch.Spend(ctx)
	p, err := b.Load(ctx, srv.URL+"/", false)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(srv.got(), " ")
	if !strings.Contains(got, "/api/reports") || !strings.Contains(got, "/api/bye") || strings.Contains(got, "/api/delete-all") {
		t.Errorf("requests %q", got)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(writes) != 0 {
		t.Errorf("writes sent: %v", writes)
	}
	if p.Interaction.Clicks < 3 || !slices.ContainsFunc(p.Interaction.Routes, func(r string) bool { return strings.HasSuffix(r, "/reports") }) {
		t.Errorf("%+v", p.Interaction)
	}
	if len(p.Writes) == 0 {
		t.Error("the refused write is not mapped")
	}
}
