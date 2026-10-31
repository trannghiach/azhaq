package egress

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/trannghiach/azhaq/internal/ledger"
	"github.com/trannghiach/azhaq/internal/neterr"
)

// counting is a server that counts what reaches it.
func counting(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		fmt.Fprint(w, "ok")
	}))
	t.Cleanup(srv.Close)
	return srv, &n
}

// withLedger puts a ledger in use and returns what it holds, as "kind/class", once read.
func withLedger(t *testing.T) func() []string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "l.jsonl")
	l, err := ledger.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	ledger.Use(l)
	t.Cleanup(func() { ledger.Use(nil) })
	return func() []string {
		var got []string
		if err := ledger.Read(path, func(e ledger.Entry) error { got = append(got, e.Kind+"/"+e.Class); return nil }); err != nil {
			t.Fatal(err)
		}
		return got
	}
}

func get(c *http.Client, raw string, hdr ...string) error {
	req, _ := http.NewRequest("GET", raw, nil)
	for i := 0; i+1 < len(hdr); i += 2 {
		if hdr[i] == "Host" {
			req.Host = hdr[i+1]
		} else {
			req.Header.Set(hdr[i], hdr[i+1])
		}
	}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

func TestTargetClientRecordsAsATarget(t *testing.T) {
	Reset()
	defer Reset()
	entries := withLedger(t)
	srv, hits := counting(t)
	if err := get(TargetClient(TargetOptions{}), srv.URL); err != nil || hits.Load() != 1 {
		t.Fatalf("%v, %d hits", err, hits.Load())
	}
	if got := entries(); len(got) != 1 || got[0] != "http/target" {
		t.Fatalf("ledger %v", got)
	}
}

// The URL's host, the Host header, a header that names a host and the
// server name the handshake asks for are all held to the scope before
// anything leaves.
func TestTargetClientRefusesWhatLeavesTheScope(t *testing.T) {
	srv, hits := counting(t)
	u, _ := url.Parse(srv.URL)
	for _, tc := range []struct {
		name string
		hdr  []string
		open map[string]bool
		want bool // refused
	}{
		{"in scope", nil, nil, false},
		{"Host header outside", []string{"Host", "secret.lab"}, nil, true},
		{"Host header with a port outside", []string{"Host", "secret.lab:8443"}, nil, true},
		{"X-Forwarded-Host outside", []string{"X-Forwarded-Host", "a.test, secret.lab"}, nil, true},
		{"X-Original-Host outside", []string{"X-Original-Host", "secret.lab"}, nil, true},
		{"Host header inside", []string{"Host", "inside.test"}, nil, false},
		{"a header the user typed is open", []string{"X-Forwarded-Host", "secret.lab"}, map[string]bool{"x-forwarded-host": true}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			Reset()
			defer Reset()
			Current().SetScope(func(h string) bool { return h == u.Hostname() || h == "inside.test" || h == "a.test" }, tc.open)
			before := hits.Load()
			err := get(TargetClient(TargetOptions{}), srv.URL, tc.hdr...)
			if tc.want != errors.Is(err, neterr.ErrOutOfScope) || (err != nil && !tc.want) {
				t.Fatalf("err %v, want refused %v", err, tc.want)
			}
			if sent := hits.Load() - before; (sent == 1) == tc.want {
				t.Fatalf("server saw %d requests, refused %v", sent, tc.want)
			}
		})
	}
}

func TestTargetClientRefusesAnOutOfScopeURLAndServerName(t *testing.T) {
	Reset()
	defer Reset()
	srv, hits := counting(t)
	SetScope(func(h string) bool { return h == "inside.test" })
	if err := get(TargetClient(TargetOptions{}), srv.URL); !errors.Is(err, neterr.ErrOutOfScope) {
		t.Fatalf("a URL outside the scope: %v", err)
	}
	SetScope(func(h string) bool { return h == "127.0.0.1" })
	c := TargetClient(TargetOptions{TLS: tlsNamed("secret.lab")})
	if err := get(c, srv.URL); !errors.Is(err, neterr.ErrOutOfScope) {
		t.Fatalf("a server name outside the scope: %v", err)
	}
	if hits.Load() != 0 {
		t.Fatalf("%d requests reached the server", hits.Load())
	}
}

func TestTargetClientStopsAtTheKillFileAndDenyPath(t *testing.T) {
	Reset()
	defer Reset()
	srv, hits := counting(t)
	SetDenyPath(func(raw string) string {
		if u, _ := url.Parse(raw); u.Path == "/admin" {
			return "^/admin"
		}
		return ""
	})
	SetOnDenied(func(string, string) {})
	if err := get(TargetClient(TargetOptions{}), srv.URL+"/admin"); !errors.Is(err, neterr.ErrDenied) {
		t.Fatalf("a denied path: %v", err)
	}
	path := filepath.Join(t.TempDir(), "run.stop")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	defer SetKill(path)() // the file is seen at once
	if err := get(TargetClient(TargetOptions{}), srv.URL+"/x"); !errors.Is(err, neterr.ErrKilled) {
		t.Fatalf("with the kill file there: %v", err)
	}
	if hits.Load() != 0 {
		t.Fatalf("%d requests reached the server", hits.Load())
	}
}

func TestTargetClientGoesThroughTheTargetProxy(t *testing.T) {
	Reset()
	defer Reset()
	var viaProxy atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		viaProxy.Add(1)
		fmt.Fprint(w, "proxied")
	}))
	defer proxy.Close()
	pu, _ := url.Parse(proxy.URL)
	SetTargetProxy(pu)
	if err := get(TargetClient(TargetOptions{}), "http://target.invalid/x"); err != nil || viaProxy.Load() != 1 {
		t.Fatalf("%v, %d through the proxy", err, viaProxy.Load())
	}
}

// A source is asked about the targets, not sent to them: the scope does not
// hold it, the kill file does, and the ledger lists it as a source.
func TestSourceClientIsRecordedAndKilledButNotScoped(t *testing.T) {
	Reset()
	defer Reset()
	entries := withLedger(t)
	srv, hits := counting(t)
	SetScope(func(h string) bool { return h == "inside.test" })
	if err := get(SourceClient(SourceOptions{}), srv.URL); err != nil || hits.Load() != 1 {
		t.Fatalf("a source outside the target scope: %v, %d hits", err, hits.Load())
	}
	if got := entries(); len(got) != 1 || got[0] != "http/source" {
		t.Fatalf("ledger %v", got)
	}
	path := filepath.Join(t.TempDir(), "run.stop")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	defer SetKill(path)()
	if err := get(SourceClient(SourceOptions{}), srv.URL); !errors.Is(err, neterr.ErrKilled) {
		t.Fatalf("a source with the kill file there: %v", err)
	}
}

func TestOwnClientIsNotRecorded(t *testing.T) {
	Reset()
	defer Reset()
	entries := withLedger(t)
	srv, hits := counting(t)
	if err := get(OwnClient(OwnOptions{}), srv.URL); err != nil || hits.Load() != 1 {
		t.Fatalf("%v, %d hits", err, hits.Load())
	}
	if got := entries(); len(got) != 0 {
		t.Fatalf("ledger %v", got)
	}
}

// A client someone else made (a test's, or one injected) is held to the
// same controls once egress takes it.
func TestTargetFromHoldsAForeignClient(t *testing.T) {
	Reset()
	defer Reset()
	entries := withLedger(t)
	srv, hits := counting(t)
	SetScope(func(h string) bool { return h == "inside.test" })
	c := TargetFrom(srv.Client())
	if err := get(c, srv.URL); !errors.Is(err, neterr.ErrOutOfScope) || hits.Load() != 0 {
		t.Fatalf("%v, %d hits", err, hits.Load())
	}
	if TargetFrom(c) != c {
		t.Error("a held client is wrapped again")
	}
	SetScope(nil)
	if err := get(c, srv.URL); err != nil {
		t.Fatal(err)
	}
	if got := entries(); len(got) != 1 || got[0] != "http/target" {
		t.Fatalf("ledger %v", got)
	}
}

func TestPinnedConnectsToTheGivenAddress(t *testing.T) {
	Reset()
	defer Reset()
	srv, hits := counting(t)
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	c := Pinned(TargetClient(TargetOptions{}), "127.0.0.1")
	if err := get(c, "http://pinned.invalid:"+port+"/"); err != nil || hits.Load() != 1 {
		t.Fatalf("%v, %d hits", err, hits.Load())
	}
}

func TestDialTargetUsesTheRunsResolverAndTheScope(t *testing.T) {
	Reset()
	defer Reset()
	srv, _ := counting(t)
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	SetResolver(func(_ context.Context, host string) []string {
		if host == "app.test" {
			return []string{"127.0.0.1"}
		}
		return nil
	})
	c, err := DialTarget(context.Background(), "tcp", "app.test:"+port)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	SetScope(func(h string) bool { return h == "other.test" })
	if _, err := DialTarget(context.Background(), "tcp", "app.test:"+port); !errors.Is(err, neterr.ErrOutOfScope) {
		t.Fatalf("outside the scope: %v", err)
	}
	// A proxy is not a target.
	c, err = DialProxy(context.Background(), "tcp", "app.test:"+port)
	if err != nil {
		t.Fatalf("a proxy under a scope: %v", err)
	}
	c.Close()
}
