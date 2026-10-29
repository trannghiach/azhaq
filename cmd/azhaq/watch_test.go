package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// capture runs f with stdout going to a pipe and returns what it wrote.
func capture(t *testing.T, f func() error) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout := os.Stdout
	os.Stdout = w
	done := make(chan string)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	ferr := f()
	os.Stdout = stdout
	w.Close()
	out := <-done
	if ferr != nil {
		t.Fatal(ferr)
	}
	return out
}

func TestWatchReportsOnlyWhatChanged(t *testing.T) {
	var mu sync.Mutex
	links := `<a href="/a">a</a>`
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch r.URL.Path {
		case "/":
			w.Write([]byte("<html><title>site</title><body>" + links + "</body></html>"))
		case "/a", "/b":
			w.Write([]byte("<html><title>" + r.URL.Path + "</title></html>"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer site.Close()
	var hooks []string
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var m map[string]any
		_ = json.NewDecoder(r.Body).Decode(&m)
		mu.Lock()
		hooks = append(hooks, m["text"].(string))
		mu.Unlock()
	}))
	defer hook.Close()

	db := filepath.Join(t.TempDir(), "ws.db")
	watch := func() map[string]any {
		out := capture(t, func() error {
			return cmdWatch([]string{"-db", db, "-json", "-notify", hook.URL, "--", "-url", site.URL + "/", "-skip", "azhaq-paths"})
		})
		var ch map[string]any
		if err := json.Unmarshal([]byte(out), &ch); err != nil {
			t.Fatalf("%v: %q", err, out)
		}
		return ch
	}
	if first := watch(); first["baseline"] != true {
		t.Fatalf("first run %v", first)
	}
	mu.Lock()
	links += `<a href="/b">b</a>`
	mu.Unlock()
	second := watch()
	urls, _ := second["urls"].([]any)
	if len(urls) != 1 || !strings.HasSuffix(urls[0].(string), "/b") || second["hosts"] != nil {
		t.Fatalf("second run %v", second)
	}
	third := watch()
	if third["urls"] != nil || third["services"] != nil {
		t.Fatalf("an unchanged run reported %v", third)
	}
	// /a goes away: the link and the page.
	mu.Lock()
	links = `<a href="/b">b</a>`
	mu.Unlock()
	fourth := watch()
	gone, _ := fourth["gone_urls"].([]any)
	if len(gone) != 1 || !strings.HasSuffix(gone[0].(string), "/a") {
		t.Fatalf("a removed page is reported: %v", fourth)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(hooks) != 2 || !strings.Contains(hooks[0], "+ 1 URLs") || !strings.Contains(hooks[1], "- 1 URLs gone") {
		t.Errorf("webhook calls %q (the baseline and the unchanged run must not notify)", hooks)
	}
}
