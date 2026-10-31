package jscol

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/trannghiach/azhaq/internal/fetch"
	"github.com/trannghiach/azhaq/internal/webextract"
	"github.com/trannghiach/azhaq/types"
)

// A string that is only where a path starts ("/api/x/"+id, a base the
// calls extend) is no route: no row, no hint, and a rejected string with
// its reason. A string with a query, and a route a call makes, stay.
func TestStringPrefixesAreNotRoutes(t *testing.T) {
	fetch.Reset()
	mux := http.NewServeMux()
	mux.HandleFunc("/app", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<!doctype html><title>App</title><script src="/app.js"></script>`))
	})
	mux.HandleFunc("/app.js", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = w.Write([]byte("class A{hostServer=F.hostServer;host=this.hostServer+`/rest/admin`;v(){return this.http.get(this.host+`/application-version`)}}\n" +
			"class U{hostServer=F.hostServer;host=this.hostServer+`/rest/user`;w(){return this.http.get(this.host+`/whoami`)}l(p){return this.http.post(this.hostServer+`/rest/user/login`,p)}}\n" +
			`function r(userId){return fetch("/api/admin/users/" + userId + "/reset", {method:"PATCH", body: JSON.stringify({level: 1})})}` + "\n" +
			`var u="/api/orders/"+id; var s="/rest/products/search?q="+q; var k="/api/keys".concat(n); go("/profile");`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	routes := map[string]bool{}
	rejected := map[string]string{}
	emit := func(o types.Observation) error {
		var p map[string]any
		_ = json.Unmarshal(o.Payload, &p)
		switch o.Kind {
		case "url":
			routes[strings.TrimPrefix(p["url"].(string), srv.URL)] = true
		case "rejected":
			rejected[p["string"].(string)] = p["reason"].(string)
		}
		return nil
	}
	col := New(srv.Client())
	meta, err := col.Run(context.Background(), types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": srv.URL + "/app"}}, emit)
	if err != nil {
		t.Fatal(err)
	}
	for _, prefix := range []string{"/rest/admin", "/rest/user", "/api/admin/users", "/api/orders", "/api/keys"} {
		if routes[prefix] {
			t.Errorf("%s is the start of a path, not a route: %v", prefix, routes)
		}
		for _, h := range meta.NextHints {
			if strings.HasSuffix(h.Keys["url"], prefix) {
				t.Errorf("%s is requested as a hint", prefix)
			}
		}
	}
	for _, want := range []string{"/rest/admin/application-version", "/rest/user/whoami", "/rest/user/login", "/api/admin/users/{userId}/reset", "/rest/products/search", "/profile"} {
		if !routes[want] {
			t.Errorf("%s is a route: %v", want, routes)
		}
	}
	for _, s := range []string{"/api/admin/users/", "/api/orders/", "/rest/admin", "/rest/user", "/api/keys"} {
		if rejected[s] != webextract.ReasonPrefix {
			t.Errorf("%s: rejected as %q, want the prefix reason (%v)", s, rejected[s], rejected)
		}
	}
}
