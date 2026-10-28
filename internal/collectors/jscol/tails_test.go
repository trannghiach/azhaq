package jscol

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/trannghiach/azhaq/internal/fetch"
)

// A path a script joins to a base it does not spell out (this.host+
// `/nftMintListen`) is not a route of the root when a call builds it
// under a prefix; a root route the script names on its own, or calls at
// the root, stays. A path of an API description written into a script
// is the description's, under its servers.
func TestJoinedTailsAreNotRootRoutes(t *testing.T) {
	fetch.Reset()
	mux := http.NewServeMux()
	mux.HandleFunc("/app", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<!doctype html><title>App</title><script src="/app.js"></script><script src="/api-docs/swagger-ui-init.js"></script>`))
	})
	mux.HandleFunc("/app.js", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = w.Write([]byte("class K{hostServer=F.hostServer;host=this.hostServer+`/rest/web3`;list(){return this.http.get(this.host+`/nftMintListen`)}}\n" +
			`const login="/login";fetch(login);const base=window.API;fetch(base+"/health");var p="/privacy";`))
	})
	mux.HandleFunc("/api-docs/swagger-ui-init.js", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = w.Write([]byte(`var options = {"swaggerDoc": {"openapi": "3.0.0", "servers": [{"url": "/b2b/v2"}], "paths": {"/orders": {"post": {}}}}, "customOptions": {}}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	got := run(t, New(srv.Client()), srv.URL+"/app")
	for _, want := range []string{"/rest/web3/nftMintListen", "/login", "/health", "/privacy", "/b2b/v2"} {
		if !has(got, want) {
			t.Errorf("%s missing from %q", want, got)
		}
	}
	for _, junk := range []string{"/nftMintListen", "/orders"} {
		if has(got, junk) {
			t.Errorf("%s is not a route of the root: %q", junk, got)
		}
	}
}
