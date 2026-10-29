package ledger

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func open(t *testing.T) (*Ledger, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "l.jsonl")
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	return l, path
}

func TestVerifyCatchesAnEditedLine(t *testing.T) {
	l, path := open(t)
	for i := 0; i < 10; i++ {
		l.Record(Entry{Kind: "http", Method: "GET", Target: fmt.Sprintf("http://a.test/%d", i), Host: "a.test"})
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if c, err := Verify(path); c.Entries != 10 || c.BadLine != 0 || c.Seals != 1 || c.Unsealed != 0 || err != nil {
		t.Fatalf("intact: %+v %v", c, err)
	}
	raw, _ := os.ReadFile(path)
	lines := strings.Split(string(raw), "\n")
	edited := append([]string(nil), lines...)
	edited[4] = strings.Replace(edited[4], "a.test/4", "a.test/5", 1)
	os.WriteFile(path, []byte(strings.Join(edited, "\n")), 0o644)
	if c, err := Verify(path); c.BadLine != 5 || c.Entries != 4 || err == nil {
		t.Fatalf("edited line 5: %+v %v", c, err)
	}
	// A removed line breaks the chain at the line after it.
	removed := append(append([]string(nil), lines[:2]...), lines[3:]...)
	os.WriteFile(path, []byte(strings.Join(removed, "\n")), 0o644)
	if c, _ := Verify(path); c.BadLine != 3 {
		t.Fatalf("removed line 3: bad line %d", c.BadLine)
	}
	// Lines cut from the end leave the chain whole but take the seal.
	cut := append(append([]string(nil), lines[:9]...), "")
	os.WriteFile(path, []byte(strings.Join(cut, "\n")), 0o644)
	if c, err := Verify(path); err != nil || c.BadLine != 0 || c.Unsealed != 9 || c.Seals != 0 {
		t.Fatalf("cut after line 9: %+v %v", c, err)
	}
}

func TestConcurrentRecordsKeepTheChain(t *testing.T) {
	l, path := open(t)
	var wg sync.WaitGroup
	for g := 0; g < 50; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				l.Record(Entry{Kind: "tcp", Target: fmt.Sprintf("127.0.0.1:%d", g*100+i)})
			}
		}()
	}
	wg.Wait()
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if c, err := Verify(path); c.Entries != 5000 || c.BadLine != 0 || err != nil {
		t.Fatalf("%+v %v", c, err)
	}
}

func TestOpenContinuesTheChain(t *testing.T) {
	l, path := open(t)
	l.Record(Entry{Kind: "tcp", Target: "127.0.0.1:1"})
	l.Close()
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	l.Record(Entry{Kind: "tcp", Target: "127.0.0.1:2"})
	seal := l.Last()
	l.Close()
	c, err := Verify(path)
	if c.Entries != 2 || c.Seals != 2 || c.Unsealed != 0 || c.BadLine != 0 || err != nil {
		t.Fatalf("%+v %v", c, err)
	}
	if c.Seal == seal || c.Seal != l.Last() {
		t.Errorf("the seal %s is not the last line written %s", c.Seal, l.Last())
	}
	// A run that sent nothing does not seal twice.
	l, _ = Open(path)
	l.Close()
	if c2, _ := Verify(path); c2.Seals != 2 {
		t.Errorf("seals %d after an empty run, want 2", c2.Seals)
	}
}

func TestTransportRecordsARequestThatFails(t *testing.T) {
	l, path := open(t)
	l.Match = func(h string) string {
		if h == "127.0.0.1" {
			return "127.0.0.1"
		}
		return ""
	}
	Use(l)
	defer Use(nil)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close() // nothing listens there now
	c := &http.Client{Transport: Wrap(nil)}
	req, _ := http.NewRequestWithContext(WithCollector(context.Background(), "azhaq-http"), http.MethodPost, "http://"+addr+"/x?y=1", nil)
	if _, err := c.Do(req); err == nil {
		t.Fatal("the connect to a closed port succeeded")
	}
	l.Close()
	var got []Entry
	if err := Read(path, func(e Entry) error { got = append(got, e); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("%d entries, want 1", len(got))
	}
	e := got[0]
	if e.Kind != "http" || e.Method != "POST" || e.Target != "http://"+addr+"/x?y=1" || e.Host != "127.0.0.1" || e.Rule != "127.0.0.1" || e.Collector != "azhaq-http" {
		t.Fatalf("%+v", e)
	}
}

func TestHooksAreNoOpsWithoutALedger(t *testing.T) {
	Use(nil)
	req, _ := http.NewRequest("GET", "http://a.test/", nil)
	HTTP(req)
	TCP(context.Background(), "a.test", "127.0.0.1:1")
	Chrome(nil, "GET", "http://a.test/")
}

func TestWrapOnce(t *testing.T) {
	rt := Wrap(nil)
	if Wrap(rt) != rt || Unwrap(rt) != http.DefaultTransport {
		t.Fatal("Wrap wraps twice or Unwrap does not unwrap")
	}
}
