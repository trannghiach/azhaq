package rdapcol

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/trannghiach/azhaq/internal/ledger"
	"github.com/trannghiach/azhaq/types"
)

func TestDomainHintsOrg(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/domain/example.test" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{
			"ldhName":"example.test",
			"nameservers":[{"ldhName":"ns1.other.test"}],
			"entities":[{
				"roles":["registrant"],
				"vcardArray":["vcard",[["fn",{},"text","Example Org"]]]
			}],
			"events":[{"eventAction":"expiration","eventDate":"2027-01-01T00:00:00Z"}]
		}`))
	}))
	t.Cleanup(srv.Close)

	col := &Collector{Client: srv.Client(), BaseURL: srv.URL}
	var registrar string
	meta, err := col.Run(context.Background(), types.Seed{
		Type: types.TypeDomain, Keys: map[string]string{"domain": "example.test"},
	}, func(o types.Observation) error {
		if o.Kind == "rdap" {
			var p map[string]any
			_ = json.Unmarshal(o.Payload, &p)
			registrar, _ = p["registrant"].(string)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if registrar != "Example Org" {
		t.Fatalf("registrant %q", registrar)
	}
	if len(meta.NextHints) != 1 || meta.NextHints[0].Type != types.TypeOrganization {
		t.Fatalf("hints %+v", meta.NextHints)
	}
	for _, h := range meta.NextHints {
		if h.Type == types.TypeHostname {
			t.Fatal("must not hint nameservers")
		}
	}
}

func TestOrgFixtureDomains(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/entities" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"domains":["app.example.test"]}`))
	}))
	t.Cleanup(srv.Close)

	col := &Collector{Client: srv.Client(), BaseURL: srv.URL}
	meta, err := col.Run(context.Background(), types.Seed{
		Type: types.TypeOrganization, Keys: map[string]string{"name": "Example Org"},
	}, func(types.Observation) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if len(meta.NextHints) != 1 || meta.NextHints[0].Key() != "app.example.test" {
		t.Fatalf("hints %+v", meta.NextHints)
	}
}

func TestBusyIsNotError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	t.Cleanup(srv.Close)
	col := &Collector{Client: srv.Client(), BaseURL: srv.URL}
	_, err := col.Run(context.Background(), types.Seed{
		Type: types.TypeDomain, Keys: map[string]string{"domain": "example.test"},
	}, func(types.Observation) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
}

func TestFollowsBootstrapRedirect(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/domain/example.com", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/registry/example.com", http.StatusFound)
	})
	mux.HandleFunc("/registry/example.com", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{
			"ldhName":"example.com",
			"entities":[{
				"roles":["registrar"],
				"vcardArray":["vcard",[["fn",{},"text","IANA"]]]
			}]
		}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	cli := srv.Client()
	cli.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	col := &Collector{Client: cli, BaseURL: srv.URL}
	var registrar string
	_, err := col.Run(context.Background(), types.Seed{
		Type: types.TypeDomain, Keys: map[string]string{"domain": "example.com"},
	}, func(o types.Observation) error {
		if o.Kind == "rdap" {
			var p map[string]any
			_ = json.Unmarshal(o.Payload, &p)
			registrar, _ = p["registrar"].(string)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if registrar != "IANA" {
		t.Fatalf("registrar %q (bootstrap 302 not followed)", registrar)
	}
}

func TestLiveOrgExtractsNothing(t *testing.T) {
	col := New(nil)
	var extracted float64
	var note string
	meta, err := col.Run(context.Background(), types.Seed{
		Type: types.TypeOrganization, Keys: map[string]string{"name": "IANA"},
	}, func(o types.Observation) error {
		var p map[string]any
		_ = json.Unmarshal(o.Payload, &p)
		extracted, _ = p["extracted"].(float64)
		note, _ = p["note"].(string)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if extracted != 0 || note == "" || len(meta.NextHints) != 0 {
		t.Fatalf("extracted=%v note=%q hints=%+v", extracted, note, meta.NextHints)
	}
}

func TestSkipReservedLive(t *testing.T) {
	c := New(nil)
	var skipped string
	_, err := c.Run(context.Background(), types.Seed{
		Type: types.TypeDomain, Keys: map[string]string{"domain": "example.test"},
	}, func(o types.Observation) error {
		var p struct {
			Skipped string `json:"skipped"`
		}
		_ = json.Unmarshal(o.Payload, &p)
		skipped = p.Skipped
		return nil
	})
	if err != nil || skipped != "reserved" {
		t.Fatalf("skipped=%q err=%v", skipped, err)
	}
}

// A registry asked about the domain is no request to the target: the
// ledger lists it as a source's.
func TestRegistryIsInTheLedgerAsASource(t *testing.T) {
	path := filepath.Join(t.TempDir(), "l.jsonl")
	l, err := ledger.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	ledger.Use(l)
	defer ledger.Use(nil)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"ldhName":"example.test"}`))
	}))
	t.Cleanup(srv.Close)
	col := New(nil)
	col.BaseURL = srv.URL
	if _, err := col.Run(context.Background(), types.Seed{Type: types.TypeDomain, Keys: map[string]string{"domain": "example.test"}}, func(types.Observation) error { return nil }); err != nil {
		t.Fatal(err)
	}
	l.Close()
	var targets, sources int
	_ = ledger.Read(path, func(e ledger.Entry) error {
		if e.IsTarget() {
			targets++
		} else if e.Class == ledger.ClassSource {
			sources++
		}
		return nil
	})
	if targets != 0 || sources != 1 {
		t.Errorf("%d target and %d source lines in the ledger, want 0 and 1", targets, sources)
	}
}
