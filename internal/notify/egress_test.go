package notify

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/trannghiach/azhaq/internal/egress"
	"github.com/trannghiach/azhaq/internal/ledger"
)

// A notification is sent to a third party, not a target: the target scope
// does not hold it, and the ledger lists it as a source's.
func TestNotificationIsInTheLedgerAsASource(t *testing.T) {
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
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()
	c, err := NewClient(0, "")
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.http().Post(srv.URL, "text/plain", strings.NewReader("hi"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	l.Close()
	var got []string
	_ = ledger.Read(path, func(e ledger.Entry) error { got = append(got, e.Kind+"/"+e.Class+"/"+e.Method); return nil })
	if len(got) != 1 || got[0] != "http/source/POST" {
		t.Fatalf("ledger %v", got)
	}
}
