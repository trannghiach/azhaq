package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/trannghiach/azhaq/internal/ledger"
	"github.com/trannghiach/azhaq/scope"
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
	lines := strings.SplitAfter(string(raw), "\n")
	os.WriteFile(path, []byte(strings.Join(lines[:3], "")), 0o644)
	if err := cmdLedger([]string{"-verify", path}); exitCode(err) != exitPartial || !strings.Contains(err.Error(), "cut from the end") {
		t.Fatalf("ledger without its seal: exit %d, %v", exitCode(err), err)
	}
	os.WriteFile(path, []byte(strings.Replace(string(raw), "a.test/2", "a.test/9", 1)), 0o644)
	err = cmdLedger([]string{"-verify", path})
	if exitCode(err) != exitPartial || !strings.Contains(err.Error(), "line 2") {
		t.Fatalf("edited ledger: exit %d, %v", exitCode(err), err)
	}
	if exitCode(cmdLedger(nil)) != exitUsage {
		t.Error("no file given is a usage error")
	}
}

// -verify alone cannot tell a ledger whose middle was cut and the rest
// re-chained from an intact one; -verify -seal, given the seal taken when
// the run ended, catches it.
func TestLedgerCommandVerifySealCatchesARechainedForgery(t *testing.T) {
	path := filepath.Join(t.TempDir(), "l.jsonl")
	l, err := ledger.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		l.Record(ledger.Entry{Kind: "http", Method: "GET", Target: fmt.Sprintf("http://a.test/%d", i), Host: "a.test"})
	}
	l.Close()
	trueSeal := l.Last()

	if err := cmdLedger([]string{"-verify", path, "-seal", trueSeal}); err != nil {
		t.Fatalf("the true seal should verify: %v", err)
	}

	// A forger able only to edit the file drops lines 4-15 and re-chains
	// (Seq, Prev, Hash) what remains, exactly as -record would: the result
	// is internally consistent, as a run that only ever sent 8 requests
	// would be.
	var kept []ledger.Entry
	i := 0
	if err := ledger.Read(path, func(e ledger.Entry) error {
		i++
		if i <= 3 || i > 15 {
			kept = append(kept, e)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	forged := filepath.Join(t.TempDir(), "l.jsonl")
	fl, err := ledger.Open(forged)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range kept {
		fl.Record(ledger.Entry{Kind: e.Kind, Method: e.Method, Target: e.Target, Host: e.Host})
	}
	fl.Close()

	// Plain -verify is fooled: the re-chained file is internally consistent.
	if err := cmdLedger([]string{"-verify", forged}); err != nil {
		t.Fatalf("a re-chained forgery should still look intact to plain -verify: %v", err)
	}
	err = cmdLedger([]string{"-verify", forged, "-seal", trueSeal})
	if exitCode(err) != exitPartial || !strings.Contains(err.Error(), "removed") {
		t.Fatalf("-verify -seal should catch the forgery: exit %d, %v", exitCode(err), err)
	}

	// -seal also takes a file of seals, such as -seal-to writes.
	sealFile := filepath.Join(t.TempDir(), "seals.jsonl")
	os.WriteFile(sealFile, []byte(`{"time":"2026-01-01T00:00:00Z","ledger":"x","seal":"`+trueSeal+`","entries":20}`+"\n"), 0o644)
	err = cmdLedger([]string{"-verify", forged, "-seal", sealFile})
	if exitCode(err) != exitPartial {
		t.Fatalf("a seal file naming the removed seal should still catch the forgery: %v", err)
	}
}

// -seal-to writes the seal where the run's own files are not, to a file or
// to a URL, so -verify -seal has something to check against that a forger
// who can only edit the ledger's own files cannot also change.
func TestSealToWritesAFileAndPostsToAURL(t *testing.T) {
	dir := t.TempDir()
	ledgerPath := filepath.Join(dir, "run.ledger.jsonl")
	sealFile := filepath.Join(dir, "seals.jsonl")

	led, err := startLedger(ledgerPath, "", dir, false, scope.Rules{}, sealFile)
	if err != nil {
		t.Fatal(err)
	}
	led.l.Record(ledger.Entry{Kind: "http", Method: "GET", Target: "http://a.test/", Host: "a.test"})
	rep := newReport("run")
	led.close(rep)

	raw, err := os.ReadFile(sealFile)
	if err != nil {
		t.Fatalf("-seal-to did not write %s: %v", sealFile, err)
	}
	var rec struct {
		Ledger  string `json:"ledger"`
		Seal    string `json:"seal"`
		Entries int    `json:"entries"`
	}
	if err := json.Unmarshal(raw[:len(raw)-1], &rec); err != nil {
		t.Fatalf("not one JSON line: %q: %v", raw, err)
	}
	if rec.Ledger != ledgerPath || rec.Entries != 1 || rec.Seal == "" {
		t.Errorf("seal record %+v", rec)
	}
	found := false
	for _, n := range rep.Notes {
		if strings.Contains(n, "-seal "+rec.Seal) {
			found = true
		}
	}
	if !found {
		t.Errorf("the summary note does not print the exact verify command: %v", rep.Notes)
	}
	if err := cmdLedger([]string{"-verify", ledgerPath, "-seal", sealFile}); err != nil {
		t.Errorf("the seal -seal-to wrote does not verify: %v", err)
	}

	var posted []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posted, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	ledgerPath2 := filepath.Join(dir, "run2.ledger.jsonl")
	led2, err := startLedger(ledgerPath2, "", dir, false, scope.Rules{}, srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	led2.l.Record(ledger.Entry{Kind: "http", Method: "GET", Target: "http://a.test/", Host: "a.test"})
	led2.close(newReport("run"))
	if len(posted) == 0 || !strings.Contains(string(posted), `"seal"`) {
		t.Errorf("the URL did not receive the seal: %q", posted)
	}
}

func TestLedgerSummaryCountsByClass(t *testing.T) {
	path := filepath.Join(t.TempDir(), "l.jsonl")
	l, err := ledger.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	l.Record(ledger.Entry{Kind: "http", Method: "GET", Target: "http://a.test/", Host: "a.test"})
	l.Record(ledger.Entry{Kind: "http", Class: ledger.ClassSource, Method: "GET", Target: "https://web.archive.org/x", Host: "web.archive.org"})
	l.Record(ledger.Entry{Kind: "dns", Class: ledger.ClassDNS, Method: "A", Target: "127.0.0.1:53", Host: "a.test"})
	l.Close()
	out, err := captureStdout(t, func() error { return ledgerSummary(path, true) })
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Classes map[string]int `json:"classes"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if got.Classes["target"] != 1 || got.Classes["source"] != 1 || got.Classes["dns"] != 1 {
		t.Fatalf("classes %v", got.Classes)
	}
}
