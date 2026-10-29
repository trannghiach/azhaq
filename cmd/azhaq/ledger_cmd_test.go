package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/trannghiach/azhaq/internal/ledger"
)

func TestLedgerCommandVerify(t *testing.T) {
	path := filepath.Join(t.TempDir(), "l.jsonl")
	l, err := ledger.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"http://a.test/1", "http://a.test/2", "http://a.test/3"} {
		l.Record(ledger.Entry{Kind: "http", Method: "GET", Target: target, Host: "a.test"})
	}
	l.Close()
	if err := cmdLedger([]string{"-verify", path}); err != nil {
		t.Fatalf("intact ledger: %v", err)
	}
	raw, _ := os.ReadFile(path)
	os.WriteFile(path, []byte(strings.Replace(string(raw), "a.test/2", "a.test/9", 1)), 0o644)
	err = cmdLedger([]string{"-verify", path})
	if exitCode(err) != exitPartial || !strings.Contains(err.Error(), "line 2") {
		t.Fatalf("edited ledger: exit %d, %v", exitCode(err), err)
	}
	if exitCode(cmdLedger(nil)) != exitUsage {
		t.Error("no file given is a usage error")
	}
}
