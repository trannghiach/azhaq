package urlcol

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/trannghiach/azhaq/internal/egress"
	"github.com/trannghiach/azhaq/internal/ledger"
)

// An archive is asked through egress's source client: in the ledger as a
// source, and not held to the target scope.
func TestArchiveRequestsAreInTheLedgerAsSources(t *testing.T) {
	egress.Reset()
	defer egress.Reset()
	egress.SetScope(func(string) bool { return false })
	path := filepath.Join(t.TempDir(), "l.jsonl")
	l, err := ledger.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	ledger.Use(l)
	defer ledger.Use(nil)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) }))
	defer srv.Close()
	resp, err := New(Options{}).opts.Client.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	l.Close()
	var got []string
	_ = ledger.Read(path, func(e ledger.Entry) error { got = append(got, e.Kind+"/"+e.Class); return nil })
	if len(got) != 1 || got[0] != "http/source" {
		t.Fatalf("ledger %v", got)
	}
}
