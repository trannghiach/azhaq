package crawlcol

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"azhaq/internal/types"
)

func TestPOSTFormIsNotHinted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<form method="post" action="/auth"></form><form method="get" action="/search"></form>`))
	}))
	t.Cleanup(srv.Close)

	col := New(srv.Client())
	meta, err := col.Run(context.Background(), types.Seed{
		Type: types.TypeURL, Keys: map[string]string{"url": srv.URL + "/"},
	}, func(types.Observation) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, h := range meta.NextHints {
		got = append(got, h.Key())
	}
	for _, u := range got {
		if u == srv.URL+"/auth" {
			t.Fatalf("POST action must not become a GET hint: %v", got)
		}
	}
	found := false
	for _, u := range got {
		if u == srv.URL+"/search" {
			found = true
		}
	}
	if !found {
		t.Fatalf("GET form should be hinted, got %v", got)
	}
}
