package ledger

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/trannghiach/azhaq/internal/neterr"
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

// Deleting a run of lines from the middle and re-chaining the rest (new
// Seq, Prev and Hash from there on, so Verify alone calls it intact) still
// changes every hash from the deletion on, including the seal's: VerifySeal
// catches that the seal taken when the run ended is no longer in the file.
func TestVerifySealCatchesLinesRemovedAndRechained(t *testing.T) {
	l, path := open(t)
	for i := 0; i < 30; i++ {
		l.Record(Entry{Kind: "http", Method: "GET", Target: fmt.Sprintf("http://a.test/%d", i), Host: "a.test"})
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	trueSeal := l.Last()
	if c, _, err := VerifySeal(path, []string{trueSeal}); err != nil || c.BadLine != 0 {
		t.Fatalf("intact chain: %+v %v", c, err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	forged := forgeChain(append(lines[:5], lines[25:]...))
	if err := os.WriteFile(path, []byte(forged), 0o644); err != nil {
		t.Fatal(err)
	}

	// Verify alone, recomputing the chain from what is left, calls the
	// forged file intact and sealed: it has no way to know 20 lines and
	// their original seal are gone.
	if c, err := Verify(path); err != nil || c.BadLine != 0 || c.Seals != 1 {
		t.Fatalf("forged chain looked broken to plain Verify: %+v %v", c, err)
	}
	c, matched, err := VerifySeal(path, []string{trueSeal})
	if err != nil {
		t.Fatalf("VerifySeal errored on a chain that is internally consistent: %v", err)
	}
	if matched != "" {
		t.Errorf("the original seal %q matched the forged chain", matched)
	}
	if c.Seal == trueSeal {
		t.Error("the forged file still ends in the original seal")
	}
}

// forgeChain drops the Seq, Prev and Hash of entries, a re-chain tool
// would recompute, and sets them again as Record does, so the result
// passes Verify despite the lines removed before it ran.
func forgeChain(lines []string) string {
	prev := ""
	var out strings.Builder
	for i, line := range lines {
		var e Entry
		_ = json.Unmarshal([]byte(line), &e)
		e.Seq, e.Prev = int64(i+1), prev
		e.Hash = e.sum()
		raw, _ := json.Marshal(e)
		out.Write(raw)
		out.WriteByte('\n')
		prev = e.Hash
	}
	return out.String()
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

// A file with no seal at its end is a run that was killed: its writes are
// held back, its reads may be asked again (and are counted), another body
// to the same URL is a new request.
func TestGuardHoldsTheWritesOfAKilledRun(t *testing.T) {
	var hits sync.Map
	srv := newCountingServer(&hits)
	defer srv.Close()
	path := filepath.Join(t.TempDir(), "l.jsonl")
	l, _ := Open(path)
	Use(l)
	c := &http.Client{Transport: Wrap(nil)}
	post := func(body string) error {
		resp, err := c.Post(srv.URL+"/pay", "text/plain", strings.NewReader(body))
		if err == nil {
			resp.Body.Close()
		}
		return err
	}
	if err := post("a"); err != nil {
		t.Fatal(err)
	}
	if resp, err := c.Get(srv.URL + "/page"); err == nil {
		resp.Body.Close()
	}
	// Killed: the file is left without its seal.
	Use(nil)
	l.mu.Lock()
	l.f.Close()
	l.f = nil
	l.mu.Unlock()
	hits = sync.Map{}

	l, err := Open(path)
	if err != nil || len(l.Unsealed()) != 2 {
		t.Fatalf("open: %v, %d unsealed", err, len(l.Unsealed()))
	}
	if w := l.Guard(nil); len(w) != 1 || w[0].Method != "POST" {
		t.Fatalf("writes held: %+v", w)
	}
	Use(l)
	defer Use(nil)
	var unsent int
	Unsent = func() { unsent++ }
	defer func() { Unsent = nil }()
	if err := post("a"); !errors.Is(err, neterr.ErrNotRepeated) {
		t.Errorf("the same POST: %v", err)
	}
	if err := post("b"); err != nil {
		t.Errorf("a POST with another body: %v", err)
	}
	if resp, err := c.Get(srv.URL + "/page"); err != nil {
		t.Errorf("GET: %v", err)
	} else {
		resp.Body.Close()
	}
	if n := countOf(&hits, "POST /pay"); n != 1 {
		t.Errorf("the server saw %d POSTs, want only the one with a new body", n)
	}
	if countOf(&hits, "GET /page") != 1 || l.Again() != 1 || unsent != 1 {
		t.Errorf("GET /page %d, asked again %d, given back %d", countOf(&hits, "GET /page"), l.Again(), unsent)
	}
	if !Held("POST", srv.URL+"/pay") || Held("GET", srv.URL+"/page") || Held("POST", srv.URL+"/other") {
		t.Error("Held (Chrome's check) is wrong")
	}
}

func newCountingServer(hits *sync.Map) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		k := r.Method + " " + r.URL.Path
		n, _ := hits.LoadOrStore(k, new(int32))
		atomic.AddInt32(n.(*int32), 1)
	}))
}

func countOf(hits *sync.Map, k string) int {
	if n, ok := hits.Load(k); ok {
		return int(atomic.LoadInt32(n.(*int32)))
	}
	return 0
}

func TestEntriesCarryTheirClass(t *testing.T) {
	path := filepath.Join(t.TempDir(), "l.jsonl")
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	Use(l)
	defer Use(nil)
	req, _ := http.NewRequest("GET", "http://a.test/x", nil)
	HTTP(req)
	HTTPAs(ClassSource, req)
	TCPAs(context.Background(), ClassSource, "smtp.test", "127.0.0.1:25")
	DNS(context.Background(), "a.test", "A", "127.0.0.1:53")
	l.Record(Entry{Kind: "tcp", Target: "127.0.0.1:1"}) // no class given: a target
	l.Close()
	var got []string
	if err := Read(path, func(e Entry) error { got = append(got, e.Kind+"/"+e.Class); return nil }); err != nil {
		t.Fatal(err)
	}
	want := []string{"http/target", "http/source", "tcp/source", "dns/dns", "tcp/target"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	if c, err := Verify(path); err != nil || c.Entries != 5 || c.Unsealed != 0 {
		t.Fatalf("%+v %v", c, err)
	}
}

// A ledger written before classes has no class on its lines: it still
// verifies, and its entries are targets.
func TestALedgerFromBeforeClassesStillVerifies(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.jsonl")
	var lines []string
	prev := ""
	for i, kind := range []string{"http", "tcp", KindSeal} {
		e := Entry{Seq: int64(i + 1), Time: time.Unix(1700000000, 0).UTC(), Kind: kind, Target: "a.test", Prev: prev}
		e.Hash = e.sum()
		prev = e.Hash
		raw, _ := json.Marshal(e)
		if strings.Contains(string(raw), "class") {
			t.Fatalf("an entry without a class writes none: %s", raw)
		}
		lines = append(lines, string(raw))
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := Verify(path)
	if err != nil || c.Entries != 2 || c.Seals != 1 || c.Unsealed != 0 {
		t.Fatalf("%+v %v", c, err)
	}
	if err := Read(path, func(e Entry) error {
		if !e.IsTarget() {
			t.Errorf("%+v is not a target", e)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// Only what was sent to a target is held back after a kill: a source's
// write (a notification) is not a target's, and a resume never sees it.
func TestGuardLeavesOtherClassesAlone(t *testing.T) {
	l, err := Open(filepath.Join(t.TempDir(), "l.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	l.Record(Entry{Kind: "http", Class: ClassSource, Method: "POST", Target: "https://hooks.test/x"})
	l.Record(Entry{Kind: "http", Method: "POST", Target: "http://a.test/x"})
	// Not closed: the run was killed.
	l2, err := Open(l.Path())
	if err != nil {
		t.Fatal(err)
	}
	Use(l2)
	defer Use(nil)
	w := l2.Guard(nil)
	if len(w) != 1 || w[0].Target != "http://a.test/x" {
		t.Fatalf("held %v, want only the target's write", w)
	}
	if !Held("POST", "http://a.test/x") || Held("POST", "https://hooks.test/x") {
		t.Fatal("only the target's write is held")
	}
}
