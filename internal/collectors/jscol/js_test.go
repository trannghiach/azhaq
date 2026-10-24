package jscol

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"azhaq/internal/types"
)

func TestOncePerOrigin(t *testing.T) {
	extracted = sync.Map{}
	var scripts atomic.Int32
	mux := http.NewServeMux()
	page := []byte(`<!doctype html><script src="/chunk.js"></script>`)
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write(page)
	})
	mux.HandleFunc("/other", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write(page)
	})
	mux.HandleFunc("/chunk.js", func(w http.ResponseWriter, _ *http.Request) {
		scripts.Add(1)
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = w.Write([]byte(`fetch("/api/Users")`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	col := New(srv.Client())
	emit := func(types.Observation) error { return nil }
	if _, err := col.Run(context.Background(), types.Seed{
		Type: types.TypeURL, Keys: map[string]string{"url": srv.URL + "/"},
	}, emit); err != nil {
		t.Fatal(err)
	}
	if _, err := col.Run(context.Background(), types.Seed{
		Type: types.TypeURL, Keys: map[string]string{"url": srv.URL + "/other"},
	}, emit); err != nil {
		t.Fatal(err)
	}
	if n := scripts.Load(); n != 1 {
		t.Fatalf("chunk.js fetched %d times", n)
	}
}
