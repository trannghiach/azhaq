package main

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/trannghiach/azhaq/internal/ledger"
)

// A run that asks a target over HTTP and also connects to its ports: the
// summary's requests are the ledger's lines to targets, requests and
// connections both, and the note names what the ledger holds by class.
func TestRunPortsSummaryReconcilesWithLedger(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			fmt.Fprint(w, `<html><title>home</title><a href="/a">a</a> <a href="/go">go</a></html>`)
		case "/go":
			http.Redirect(w, r, "/a", http.StatusFound)
		case "/a":
			fmt.Fprint(w, `<html><title>a</title></html>`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	shut, _ := net.Listen("tcp", "127.0.0.1:0") // a port nothing listens on, once closed
	shutPort := fmt.Sprint(shut.Addr().(*net.TCPAddr).Port)
	shut.Close()
	dir := t.TempDir()
	led := filepath.Join(dir, "run.ledger.jsonl")
	_, errOut, code := cli(t, "run", "-url", srv.URL+"/", "-cidr", "127.0.0.1/32", "-ports", u.Port()+","+shutPort, "-port-detect", "none",
		"-ledger", led, "-db", filepath.Join(dir, "run.db"), "-json")
	rep := lastReport(t, errOut)
	if code != exitOK && code != exitPartial {
		t.Fatalf("exit %d: %+v", code, rep)
	}
	targets, conns := 0, 0
	_ = ledger.Read(led, func(e ledger.Entry) error {
		if e.IsTarget() && e.Kind != ledger.KindSeal {
			targets++
			if e.Kind == "tcp" {
				conns++
			}
		}
		return nil
	})
	if conns == 0 {
		t.Fatalf("no port connect in the ledger")
	}
	if int64(targets) != rep.Requests {
		t.Errorf("the summary says %d requests, the ledger lists %d lines to targets", rep.Requests, targets)
	}
	want := fmt.Sprintf("ledger: %d recorded in ", targets)
	var found bool
	for _, n := range rep.Notes {
		found = found || strings.HasPrefix(n, want)
		if strings.Contains(n, "the summary counts") {
			t.Errorf("a note says the counts differ: %s", n)
		}
	}
	detail := fmt.Sprintf(": %d to targets (%d requests, %d connections), sealed ", targets, targets-conns, conns)
	if !found || !strings.Contains(strings.Join(rep.Notes, "\n"), detail) {
		t.Errorf("no note starts %q and holds %q: %q", want, detail, rep.Notes)
	}
}

// The note names each class the ledger holds, so a DNS query or a source's
// request is not taken for a request to a target.
func TestLedgerNoteNamesTheClasses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.ledger.jsonl")
	l, err := ledger.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	add := func(n int, e ledger.Entry) {
		for range n {
			l.Record(e)
		}
	}
	add(210, ledger.Entry{Kind: "http", Class: ledger.ClassTarget, Method: "GET", Target: "http://127.0.0.1/"})
	add(4, ledger.Entry{Kind: "tcp", Class: ledger.ClassTarget, Target: "127.0.0.1:80"})
	add(1, ledger.Entry{Kind: "dns", Class: ledger.ClassDNS, Method: "A", Target: "1.1.1.1:53", Host: "a.example.org"})
	add(2, ledger.Entry{Kind: "http", Class: ledger.ClassSource, Method: "GET", Target: "https://crt.sh/"})
	r := &runLedger{l: l, owned: true, stopKill: func() {}}
	rep := &report{Requests: 213}
	r.close(rep)
	got := strings.Join(rep.Notes, "\n")
	for _, want := range []string{
		"ledger: 217 recorded in ",
		": 214 to targets (210 requests, 4 connections), 2 to third-party sources, 1 DNS query, sealed ",
		"the summary counts 213 requests to targets and the ledger lists 214 lines to them",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("no note says %q:\n%s", want, got)
		}
	}
	// A second run in the same file counts its own lines, and says the file holds more.
	l2, err := ledger.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	l2.Record(ledger.Entry{Kind: "http", Class: ledger.ClassTarget, Method: "GET", Target: "http://127.0.0.1/"})
	r2 := &runLedger{l: l2, owned: true, stopKill: func() {}, from: l2.Count() - 1}
	rep2 := &report{Requests: 1}
	r2.close(rep2)
	got = strings.Join(rep2.Notes, "\n")
	if !strings.Contains(got, "ledger: 1 recorded in ") || !strings.Contains(got, ": 1 to targets (1 request, 0 connections), sealed ") || !strings.Contains(got, " holds 220 lines in all, the lines of the runs before this one included") {
		t.Errorf("the second run's note: %s", got)
	}
	if strings.Contains(got, "the summary counts") {
		t.Errorf("the counts agree: %s", got)
	}
}
